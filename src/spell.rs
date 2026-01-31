#[cfg(feature = "prover")]
use crate::utils::block_on;
use crate::{
    PROOF_WRAPPER_BINARY, SPELL_CHECKER_BINARY, SPELL_CHECKER_VK, app,
    cli::{charms_fee_settings, prove_impl},
    tx::{bitcoin_tx, bitcoin_tx::from_spell, cardano_tx},
    utils,
    utils::{BoxedSP1Prover, Shared, TRANSIENT_PROVER_FAILURE},
};
use anyhow::{Context, anyhow, bail, ensure};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, ToConstraintField};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::{
    lc, r1cs,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable::One},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use bitcoin::{Amount, Network, hashes::Hash};
use charms_app_runner::AppRunner;
pub use charms_client::{
    CURRENT_VERSION, NormalizedCharms, NormalizedSpell, NormalizedTransaction, Proof,
    SpellProverInput, to_tx,
};
use charms_client::{
    MOCK_SPELL_VK,
    tx::{Chain, Tx, by_txid},
};
use charms_data::{
    App, AppInput, B32, Charms, Data, NativeOutput, Transaction, TxId, UtxoId, is_simple_transfer,
    util,
};
use charms_lib::SPELL_VK;
use const_format::formatcp;
#[cfg(feature = "prover")]
use redis::AsyncCommands;
#[cfg(feature = "prover")]
use redis_macros::{FromRedisValue, ToRedisArgs};
#[cfg(not(feature = "prover"))]
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, IfIsHumanReadable, base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use sp1_prover::{HashableKey, SP1ProvingKey, SP1VerifyingKey};
use sp1_sdk::{SP1Proof, SP1ProofMode, SP1Stdin};
#[cfg(feature = "prover")]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};
#[cfg(not(feature = "prover"))]
use utils::retry;

/// Charm as represented in a spell.
/// Map of `$KEY: data`.
pub type KeyedCharms = BTreeMap<String, Data>;

/// UTXO as represented in a spell.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Input {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utxo_id: Option<UtxoId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charms: Option<KeyedCharms>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beamed_from: Option<UtxoId>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Output {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(
        alias = "sats",
        alias = "coin",
        alias = "coins",
        skip_serializing_if = "Option::is_none"
    )]
    pub amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charms: Option<KeyedCharms>,
    #[serde(alias = "beamed_to", skip_serializing_if = "Option::is_none")]
    pub beam_to: Option<B32>,
}

/// Defines how spells are represented in their source form and in CLI outputs,
/// in both human-friendly (JSON/YAML) and machine-friendly (CBOR) formats.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spell {
    /// Version of the protocol.
    pub version: u32,

    /// Apps used in the spell. Map of `$KEY: App`.
    /// Keys are arbitrary strings. They just need to be unique (inside the spell).
    pub apps: BTreeMap<String, App>,

    /// Public inputs to the apps for this spell. Map of `$KEY: Data`.
    #[serde(alias = "public_inputs", skip_serializing_if = "Option::is_none")]
    pub public_args: Option<BTreeMap<String, Data>>,

    /// Private inputs to the apps for this spell. Map of `$KEY: Data`.
    #[serde(alias = "private_inputs", skip_serializing_if = "Option::is_none")]
    pub private_args: Option<BTreeMap<String, Data>>,

    /// Transaction inputs.
    pub ins: Vec<Input>,
    /// Reference inputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<Input>>,
    /// Transaction outputs.
    pub outs: Vec<Output>,
}

impl Spell {
    /// New empty spell.
    pub fn new() -> Self {
        Self {
            version: CURRENT_VERSION,
            apps: BTreeMap::new(),
            public_args: None,
            private_args: None,
            ins: vec![],
            refs: None,
            outs: vec![],
        }
    }

    pub fn strings_of_charms(&self, inputs: &Vec<Input>) -> anyhow::Result<Vec<(UtxoId, Charms)>> {
        inputs
            .iter()
            .map(|input| {
                let utxo_id = input
                    .utxo_id
                    .as_ref()
                    .ok_or(anyhow!("missing input utxo_id"))?;
                let charms = self.charms(&input.charms)?;
                Ok((utxo_id.clone(), charms))
            })
            .collect::<Result<_, _>>()
    }

    pub fn charms(&self, charms_opt: &Option<KeyedCharms>) -> anyhow::Result<Charms> {
        charms_opt
            .as_ref()
            .ok_or(anyhow!("missing charms field"))?
            .iter()
            .map(|(k, v)| {
                let app = self.apps.get(k).ok_or(anyhow!("missing app {}", k))?;
                Ok((app.clone(), Data::from(v)))
            })
            .collect::<Result<Charms, _>>()
    }

    /// Get a [`NormalizedSpell`] and apps' private inputs for the spell.
    pub fn normalized(
        &self,
        mock: bool,
    ) -> anyhow::Result<(
        NormalizedSpell,
        BTreeMap<App, Data>,
        BTreeMap<usize, UtxoId>,
    )> {
        ensure!(self.version == CURRENT_VERSION);

        let empty_map = BTreeMap::new();
        let keyed_public_inputs = self.public_args.as_ref().unwrap_or(&empty_map);

        let keyed_apps = &self.apps;
        let apps: BTreeSet<App> = keyed_apps.values().cloned().collect();
        let app_to_index: BTreeMap<App, u32> = apps.iter().cloned().zip(0..).collect();
        ensure!(apps.len() == keyed_apps.len(), "duplicate apps");

        let app_public_inputs: BTreeMap<App, Data> = app_inputs(keyed_apps, keyed_public_inputs);

        let ins: Vec<UtxoId> = self
            .ins
            .iter()
            .map(|utxo| utxo.utxo_id.clone().ok_or(anyhow!("missing input utxo_id")))
            .collect::<Result<_, _>>()?;
        ensure!(
            ins.iter().collect::<BTreeSet<_>>().len() == ins.len(),
            "duplicate inputs"
        );
        let ins = Some(ins);

        let refs = self
            .refs
            .as_ref()
            .map(|refs| {
                refs.iter()
                    .map(|utxo| utxo.utxo_id.clone().ok_or(anyhow!("missing input utxo_id")))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        let empty_charm = KeyedCharms::new();

        let outs: Vec<NormalizedCharms> = self
            .outs
            .iter()
            .map(|utxo| {
                let n_charms = utxo
                    .charms
                    .as_ref()
                    .unwrap_or(&empty_charm)
                    .iter()
                    .map(|(k, v)| {
                        let app = keyed_apps.get(k).ok_or(anyhow!("missing app key"))?;
                        let i = *app_to_index
                            .get(app)
                            .ok_or(anyhow!("app is expected to be in app_to_index"))?;
                        Ok((i, v.clone()))
                    })
                    .collect::<anyhow::Result<NormalizedCharms>>()?;
                Ok(n_charms)
            })
            .collect::<anyhow::Result<_>>()?;

        let beamed_outs: BTreeMap<_, _> = self
            .outs
            .iter()
            .zip(0u32..)
            .filter_map(|(o, i)| o.beam_to.as_ref().map(|b32| (i, b32.clone())))
            .collect();
        let beamed_outs = Some(beamed_outs).filter(|m| !m.is_empty());

        let coins = get_coin_outs(&self.outs)?;

        let norm_spell = NormalizedSpell {
            version: self.version,
            tx: NormalizedTransaction {
                ins,
                refs,
                outs,
                beamed_outs,
                coins: Some(coins),
            },
            app_public_inputs,
            mock,
        };

        let keyed_private_inputs = self.private_args.as_ref().unwrap_or(&empty_map);
        let app_private_inputs = app_inputs(keyed_apps, keyed_private_inputs);

        let tx_ins_beamed_source_utxos = self
            .ins
            .iter()
            .enumerate()
            .filter_map(|(i, input)| {
                input
                    .beamed_from
                    .as_ref()
                    .map(|beam_source_utxo_id| (i, beam_source_utxo_id.clone()))
            })
            .collect();

        Ok((norm_spell, app_private_inputs, tx_ins_beamed_source_utxos))
    }

    /// De-normalize a normalized spell.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn denormalized(norm_spell: &NormalizedSpell) -> anyhow::Result<Self> {
        let apps = (0..)
            .zip(norm_spell.app_public_inputs.keys())
            .map(|(i, app)| (utils::str_index(&i), app.clone()))
            .collect();

        let public_inputs = match norm_spell
            .app_public_inputs
            .values()
            .enumerate()
            .filter_map(|(i, data)| match data {
                data if data.is_empty() => None,
                data => Some((utils::str_index(&(i as u32)), data.clone())),
            })
            .collect::<BTreeMap<_, _>>()
        {
            map if map.is_empty() => None,
            map => Some(map),
        };

        let Some(norm_spell_ins) = &norm_spell.tx.ins else {
            bail!("spell must have inputs");
        };
        let ins = norm_spell_ins
            .iter()
            .map(|utxo_id| Input {
                utxo_id: Some(utxo_id.clone()),
                charms: None,
                beamed_from: None,
            })
            .collect();

        let refs = norm_spell.tx.refs.as_ref().map(|refs| {
            refs.iter()
                .map(|utxo_id| Input {
                    utxo_id: Some(utxo_id.clone()),
                    charms: None,
                    beamed_from: None,
                })
                .collect::<Vec<_>>()
        });

        let outs = norm_spell
            .tx
            .outs
            .iter()
            .zip(0u32..)
            .map(|(n_charms, i)| Output {
                address: None,
                amount: None,
                charms: match n_charms
                    .iter()
                    .map(|(i, data)| (utils::str_index(i), data.clone()))
                    .collect::<KeyedCharms>()
                {
                    charms if charms.is_empty() => None,
                    charms => Some(charms),
                },
                beam_to: norm_spell
                    .tx
                    .beamed_outs
                    .as_ref()
                    .and_then(|beamed_to| beamed_to.get(&i).cloned()),
            })
            .collect();

        Ok(Self {
            version: norm_spell.version,
            apps,
            public_args: public_inputs,
            private_args: None,
            ins,
            refs,
            outs,
        })
    }
}

fn get_coin_outs(outs: &[Output]) -> anyhow::Result<Vec<NativeOutput>> {
    outs.iter()
        .map(|output| {
            Ok(NativeOutput {
                amount: output.amount.unwrap_or(DEFAULT_COIN_AMOUNT),
                dest: from_bech32(&output.address.as_ref().expect("address is expected"))?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

fn from_bech32(address: &str) -> anyhow::Result<Vec<u8>> {
    // Bitcoin
    if let Ok(addr) = bitcoin::Address::from_str(address) {
        return Ok(addr.assume_checked().script_pubkey().to_bytes());
    }
    // Cardano
    if let Ok(addr) = cml_chain::address::Address::from_bech32(address) {
        return Ok(addr.to_raw_bytes());
    }
    bail!("invalid address: {}", address);
}

fn app_inputs(
    keyed_apps: &BTreeMap<String, App>,
    keyed_inputs: &BTreeMap<String, Data>,
) -> BTreeMap<App, Data> {
    keyed_apps
        .iter()
        .map(|(k, app)| {
            (
                app.clone(),
                keyed_inputs.get(k).cloned().unwrap_or_default(),
            )
        })
        .collect()
}

pub trait Prove: Send + Sync {
    /// Prove the correctness of a spell, generate the proof.
    ///
    /// This function generates a proof that a spell (`NormalizedSpell`) is correct.
    /// It processes application binaries, private inputs,
    /// previous transactions, and input/output mappings, and finally generates a proof
    /// of correctness for the given spell. Additionally, it calculates the
    /// cycles consumed during the process if applicable.
    ///
    /// # Parameters
    /// - `norm_spell`: A `NormalizedSpell` object representing the normalized spell that needs to
    ///   be proven.
    /// - `app_binaries`: A map containing application VKs (`B32`) as keys and their binaries as
    ///   values.
    /// - `app_private_inputs`: A map of application-specific private inputs, containing `App` keys
    ///   and associated `Data` values.
    /// - `prev_txs`: A list of previous transactions (`Tx`) that have created the outputs consumed
    ///   by the spell.
    /// - `tx_ins_beamed_source_utxos`: A mapping of input UTXOs to their beaming source UTXOs (if
    ///   the input UTXO has been beamed from another chain).
    /// - `expected_cycles`: An optional vector of cycles (`u64`) that represents the desired
    ///   execution cycles or constraints for the proof. If `None`, no specific cycle limit is
    ///   applied.
    ///
    /// # Returns
    /// - `Ok((NormalizedSpell, Proof, u64))`: On success, returns a tuple containing:
    ///   * The original `NormalizedSpell` object that was proven in its onchain form (i.e. without
    ///     the inputs, since they are already specified by the transaction).
    ///   * The generated `Proof` object, which provides evidence of correctness for the spell.
    ///   * A `u64` value indicating the total number of cycles consumed during the proving process.
    /// - `Err(anyhow::Error)`: Returns an error if the proving process fails due to validation
    ///   issues, computation errors, or other runtime problems.
    ///
    /// # Errors
    /// The function will return an error if:
    /// - Validation of the `NormalizedSpell` or its components fails.
    /// - The proof generation process encounters computation errors.
    /// - Any of the dependent data (e.g., transactions, binaries, private inputs) is inconsistent,
    ///   invalid, or missing required information.
    /// ```
    fn prove(
        &self,
        norm_spell: NormalizedSpell,
        app_binaries: BTreeMap<B32, Vec<u8>>,
        app_private_inputs: BTreeMap<App, Data>,
        prev_txs: Vec<Tx>,
        tx_ins_beamed_source_utxos: BTreeMap<usize, UtxoId>,
    ) -> anyhow::Result<(NormalizedSpell, Proof, u64)>;
}

impl Prove for Prover {
    fn prove(
        &self,
        norm_spell: NormalizedSpell,
        app_binaries: BTreeMap<B32, Vec<u8>>,
        app_private_inputs: BTreeMap<App, Data>,
        prev_txs: Vec<Tx>,
        tx_ins_beamed_source_utxos: BTreeMap<usize, UtxoId>,
    ) -> anyhow::Result<(NormalizedSpell, Proof, u64)> {
        ensure!(
            !norm_spell.mock,
            "trying to prove a mock spell with a real prover"
        );

        let app_input = match app_binaries.is_empty() {
            true => None,
            false => Some(AppInput {
                app_binaries,
                app_private_inputs,
            }),
        };

        let prover_input = SpellProverInput {
            self_spell_vk: SPELL_VK.to_string(),
            prev_txs,
            spell: norm_spell.clone(),
            tx_ins_beamed_source_utxos,
            app_input,
        };

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(util::write(&prover_input)?);

        let (proof, _) = self.spell_prover_client.get().prove(
            &self.spell_checker_pk,
            &stdin,
            SP1ProofMode::Compressed,
        )?;
        let SP1Proof::Compressed(compressed_proof) = proof.proof else {
            unreachable!()
        };
        tracing::info!("spell proof generated");

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(proof.public_values.to_vec());
        stdin.write_proof(*compressed_proof, self.spell_checker_vk.vk.clone());

        let (proof, spell_cycles) = self
            .wrapper_prover_client
            .get()
            .prove(&self.proof_wrapper_pk, &stdin, SP1ProofMode::Groth16)
            .map_err(|e| anyhow!("{} SNARK wrapper: {}", TRANSIENT_PROVER_FAILURE, e))?;
        let norm_spell = clear_inputs_and_coins(norm_spell);
        let proof = proof.bytes();

        // TODO app_cycles might turn out to be much more expensive than spell_cycles
        Ok((norm_spell, proof, spell_cycles))
    }
}

fn make_mock(mut norm_spell: NormalizedSpell) -> NormalizedSpell {
    norm_spell.mock = true;
    norm_spell
}

fn clear_inputs_and_coins(mut norm_spell: NormalizedSpell) -> NormalizedSpell {
    norm_spell.tx.ins = None;
    norm_spell.tx.coins = None;
    norm_spell
}

impl Prove for MockProver {
    fn prove(
        &self,
        norm_spell: NormalizedSpell,
        app_binaries: BTreeMap<B32, Vec<u8>>,
        app_private_inputs: BTreeMap<App, Data>,
        prev_txs: Vec<Tx>,
        tx_ins_beamed_source_utxos: BTreeMap<usize, UtxoId>,
    ) -> anyhow::Result<(NormalizedSpell, Proof, u64)> {
        let norm_spell = make_mock(norm_spell);

        let app_input = match app_binaries.is_empty() {
            true => None,
            false => Some(AppInput {
                app_binaries,
                app_private_inputs,
            }),
        };

        // Run the zkVM guest program (charms-spell-checker) instead of running apps directly
        let prover_input = SpellProverInput {
            self_spell_vk: SPELL_VK.to_string(),
            prev_txs,
            spell: norm_spell.clone(),
            tx_ins_beamed_source_utxos,
            app_input,
        };

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(util::write(&prover_input)?);

        let (_, report) = self
            .spell_prover_client
            .get()
            .execute(SPELL_CHECKER_BINARY, &stdin)?;

        tracing::info!(
            "mock spell checker executed with {} cycles",
            report.total_instruction_count()
        );
        let spell_cycles = report.total_instruction_count();

        // Generate mock Groth16 proof
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let pk = load_pk()?;

        let committed_data = util::write(&(MOCK_SPELL_VK, norm_spell.clone()))?;

        let field_elements = Sha256::digest(&committed_data)
            .to_field_elements()
            .expect("non-empty vector is expected");
        let circuit = DummyCircuit {
            a: Some(field_elements[0]),
        };

        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)?;
        let mut proof_bytes = vec![];
        proof.serialize_compressed(&mut proof_bytes)?;

        let norm_spell = clear_inputs_and_coins(norm_spell);

        Ok((norm_spell, proof_bytes, spell_cycles))
    }
}

fn load_pk<E: Pairing>() -> anyhow::Result<ProvingKey<E>> {
    ProvingKey::deserialize_compressed(MOCK_GROTH16_PK)
        .map_err(|e| anyhow!("Failed to deserialize proving key: {}", e))
}

const MOCK_GROTH16_PK: &[u8] = include_bytes!("./bin/mock-groth16-pk.bin");

#[derive(Default)]
pub struct DummyCircuit<F>
where
    F: Field,
{
    a: Option<F>,
}

impl<ConstraintF> ConstraintSynthesizer<ConstraintF> for DummyCircuit<ConstraintF>
where
    ConstraintF: Field,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> r1cs::Result<()> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + a, lc!() + One, lc!() + c)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use charms_client::tx::EnchantedTx;

    #[test]
    fn deserialize_keyed_charm() {
        let y = r#"
$TOAD_SUB: 10
$TOAD: 9
"#;

        let charms: KeyedCharms = serde_yaml::from_str(y).unwrap();
        dbg!(&charms);

        let utxo_id_0 =
            UtxoId::from_str("f72700ac56bd4dd61f2ccb4acdf21d0b11bb294fc3efa9012b77903932197d2f:2")
                .unwrap();
        let buf = util::write(&utxo_id_0).unwrap();

        let utxo_id_data: Data = util::read(buf.as_slice()).unwrap();

        let utxo_id: UtxoId = utxo_id_data.value().unwrap();
        assert_eq!(utxo_id_0, dbg!(utxo_id));
    }

    #[test]
    fn txs_from_strings() {
        let b_tx_hex = "!bitcoin {tx: 0200000000010236c4d581d18b974562cf32e835c2c1e5d2590cd7c070e5ece35ebcb672216ae00000000000ffffffff36c4d581d18b974562cf32e835c2c1e5d2590cd7c070e5ece35ebcb672216ae00400000000ffffffff042302000000000000160014b9698eae2e61774bd88749e0f9b169acc50f99fb23020000000000001600144b1f883dd56c33fb7300dc27fc125eab88a462cf0000000000000000fd01036a057370656c6c4df70282a36776657273696f6e09627478a2646f75747382a1001a05f5e100a1001b00000001954fc4006b6265616d65645f6f757473a1009820189b18d30f18460718be1833181b18bc18a518b318ae18fa18bc18c9185b18b1185618c2185218e618a912182718d318cb18ac182a18b6184418ab189e716170705f7075626c69635f696e70757473a18361749820183d187f18e718e418ce18a6121819184718af187318d70e1851181918be18bd188a18a518b718ed18fe187418bf18af186e1877189a1818184718bd189b982018c9187518d418e018c2189218fb189518ef18bd18a518c118331218d618ac181d188b185a18ef18f718f018f118e518571886184518a218da187018ff185ff699010418a41859184c185909186c18de186e18ca18a818a618b81318201841185118df1827183718ad18ed18501866185418f1182f18e41861185c08182d185318da182418dc1883181a187918b018c6183c0f02185218c416186818c918a518c91865182118a618af18fc184018e218ba18f518cd181b1318dc18a0184d184a18e418da0b188c18c0184718691835185f18e018b218ce18ba189b18fe188118d918d4185b1845183b18e5188218b818f71865182f0218bb185318330e187518581819181909182d18cd18271898188b182f18d018571881183b18e218d818e918b4185418ed184c1832186e091218e1030918fd18e7187d187c0d1820187b18f5182118621834182818ff183b187c18c71867186b183818631876182618d918e218a018d918ad121893181d18f5181918a913184e183700171818182d189e18b118520418b1187718a318e818ea1882184118fd183818830e181a18b3184018cf18ab18d7185c18a218e3182e1825183718fb18a50b184718b6185b184e001866188e184c1898188518b518a8183e189618e0185d15186718c8185c18e3188618cf18f6189718b418d5184f186618df040d00183f18351855188918c1182b18c9181d18dc0418d31882186114181b188817181b185018e318d618ae1847182116186b18b618d8185f1877db0e000000000000160014542e0cd4e07fa3d919cf5aa5f8242612d4a3b3550247304402202bd582e27041fc7ae426853826e9c52cf8a5c8e5755026a6ba21892bdbcf51cb02201fef093148d7e5fa8ad7a10c8f953398db4a7efca4003d6a5c7cbbb58e468d84012103d5453d402d158c84de22dd20caf3cc1968178b5f674f5ec6d063d9fe8675fb27024730440220344cf2c2812b1c086c931bb6c1643bc91f33f4347011c594c37f54c4b23ea16a022049fad130880b7e88fc20e267cf151e23d32ed2669d94937e066658defea8c97b012103d5453d402d158c84de22dd20caf3cc1968178b5f674f5ec6d063d9fe8675fb2700000000, proof: 00000020e67d17e26a835ef6908dc53d3df10ec11447ff2e2cf401000000000000000000a5edec1fb14884f4d91dd3670135e4351aaec3c8e976b9ed13318d367875197d9d487c69a1fc01179e3678ef670b00000de18f42fa5fbce803e39c85b79c0b12e3ac41aaf57391184e96718e7f5406862614b4b7625aab6d003128248c31431c16e93e2cda808d7a9a63eaacfa79ae6a175578cb388029709c71f5590c03e6d254cd7068910251f30c10ceaba4f3748e46d6184d3b3dd743ef6033f2664830103881059ae8c26e792592e4b2db93acb6ab0e01f2312e73d2fb918b1977ac45c631066a1fbff4cededc4394c8eea8c1f6994fcf8eac574db5bcca603e56d142dca3a07fd83733faeb164e700fd82a3e821da3332e71ad3cd8f0f3843f8f80f16c9c668d03c6fd76fbcf845dced13a83708d29f1ba8550143e4841a10205a30202ec2ca8163a5e3fef928536e64612110b86ecd1cbbfe8c1c496346a46760edc33723e472ed9d8b35dd30f9dbefa4cac3f86f8eec2bc997cbef3136cbe4a7f21303efa55e7b04ac5bd1532419b82cc752ba53306d2a97e3f498d53ddcfe95c87e831c780ed513c3438b5e64db4d98d67796fba6fbb641ff92c51aaecb15d6df48b7993d966a3df0fe066e5a3dabe2e4ce639d5178235b0e05389a6d12cb4be8acf7770f955a73a7844732561c60f84cae52f04ebab0600, headers: [0020092042685204c1d593020a0e4a04fcaae7cbd146662c105c010000000000000000000f9d569050c3db02605efe19a24f50ebb6cc0567154662993ff682aaeeb8d9fccf487c69a1fc0117c8e0d65a, 00600624fe6344692b6693004e3ba99eb240402e4061ac015ef9000000000000000000008cc52b45e82d205b486314723fe865f196e84ec4fb247ddbea5b42e8fda23351fc4a7c69a1fc01178d3ae452, 0000eb23416b11e4c80cbb1d03c22b7957e108ccb958aef2fdc70100000000000000000013e9da44cbd9dd81b8c4269a5c8a88e850fb5af075e714991504d4e815fe95ac184b7c69a1fc011714370fe6, 00000034c603010c44c62e293b4e9476f4176dcd50c590c942a201000000000000000000b79acf6981a4cadcac7b843e4e4c7f155f87fc6add4ce2ea800fb77b4685cb26bd4e7c69a1fc01177e66ec4c, 04a0da26722d4343dc67afbc27aacff592d9ab2a0f7584df56fb01000000000000000000c315a0ca900f1d334523a4e5aeffbae7f95d69e60eb12c331e7a2ad5da2870fe5f507c69a1fc0117932dd198, 0080072070d9db116f24106e39b4da8a205725cfc701cfe141d400000000000000000000ee5e2b33f543016f8588935dbe972f36365b6db1c663d883f703f7e4f69c2426c8507c69a1fc01173560a4cb]}".to_string();

        let txs = from_strings(&[b_tx_hex]).unwrap();
        let Tx::Bitcoin(tx) = &txs[0] else {
            unreachable!()
        };
        assert!(tx.proven_final());
    }
}

pub trait ProveSpellTx: Send + Sync {
    fn new(mock: bool) -> Self;

    fn prove_spell_tx(
        &self,
        prove_request: ProveRequest,
    ) -> impl Future<Output = anyhow::Result<Vec<Tx>>>;
}

pub struct ProveSpellTxImpl {
    pub mock: bool,

    pub charms_fee_settings: Option<CharmsFee>,
    pub charms_prove_api_url: String,

    #[cfg(feature = "prover")]
    pub cache_client: Option<(redis::Client, rslock::LockManager)>,

    pub prover: Box<dyn Prove>,
    #[cfg(not(feature = "prover"))]
    pub client: Client,
}

pub type FeeAddressForNetwork = BTreeMap<String, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CharmsFee {
    /// Fee addresses for each chain (bitcoin, cardano, etc.) further broken down by network
    /// (mainnet, testnet, etc.).
    pub fee_addresses: BTreeMap<Chain, FeeAddressForNetwork>,
    /// Fee rate in sats per mega cycle.
    pub fee_rate: u64,
    /// Base fee in sats.
    pub fee_base: u64,
}

impl CharmsFee {
    pub fn fee_address(&self, chain: &Chain, network: &str) -> Option<&str> {
        self.fee_addresses.get(chain).and_then(|fee_addresses| {
            fee_addresses
                .get(network)
                .map(|fee_address| fee_address.as_str())
        })
    }
}

serde_with::serde_conv!(
    NormalizedSpellHex,
    NormalizedSpell,
    |data: &NormalizedSpell| hex::encode(util::write(data).expect("failed to write Data")),
    |s: String| util::read(hex::decode(&s)?.as_slice())
);

serde_with::serde_conv!(
    DataHex,
    Data,
    |data: &Data| hex::encode(util::write(data).expect("failed to write Data")),
    |s: String| util::read(hex::decode(&s)?.as_slice())
);

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProveRequest {
    #[serde_as(as = "IfIsHumanReadable<NormalizedSpellHex>")]
    pub spell: NormalizedSpell,
    #[serde_as(as = "IfIsHumanReadable<BTreeMap<DisplayFromStr, DataHex>>")]
    pub app_private_inputs: BTreeMap<App, Data>,
    #[serde_as(as = "IfIsHumanReadable<BTreeMap<DisplayFromStr, DisplayFromStr>>")]
    pub tx_ins_beamed_source_utxos: BTreeMap<usize, UtxoId>,
    #[serde_as(as = "IfIsHumanReadable<BTreeMap<_, Base64>>")]
    pub binaries: BTreeMap<B32, Vec<u8>>,
    pub prev_txs: Vec<Tx>,
    pub funding_utxo: UtxoId,
    pub funding_utxo_value: u64,
    pub change_address: String,
    pub fee_rate: f64,
    pub chain: Chain,
    pub collateral_utxo: Option<UtxoId>,
}

pub struct Prover {
    pub spell_prover_client: Arc<Shared<BoxedSP1Prover>>,
    pub wrapper_prover_client: Arc<Shared<BoxedSP1Prover>>,
    pub spell_checker_pk: SP1ProvingKey,
    pub spell_checker_vk: SP1VerifyingKey,
    pub proof_wrapper_pk: SP1ProvingKey,
}

impl Prover {
    pub fn new(app_prover: Arc<app::Prover>, prover_client: Arc<Shared<BoxedSP1Prover>>) -> Self {
        let (spell_checker_pk, spell_checker_vk) = prover_client.get().setup(SPELL_CHECKER_BINARY);
        assert_eq!(SPELL_CHECKER_VK, spell_checker_vk.hash_u32());
        let (proof_wrapper_pk, vk) = prover_client.get().setup(PROOF_WRAPPER_BINARY);
        assert_eq!(SPELL_VK, vk.bytes32().as_str());
        Self {
            spell_prover_client: app_prover.sp1_client.clone(),
            wrapper_prover_client: prover_client,
            spell_checker_pk,
            spell_checker_vk,
            proof_wrapper_pk,
        }
    }
}

pub struct MockProver {
    pub spell_prover_client: Arc<Shared<BoxedSP1Prover>>,
}

impl ProveSpellTxImpl {
    async fn do_prove_spell_tx(
        &self,
        prove_request: ProveRequest,
        app_cycles: u64,
    ) -> anyhow::Result<Vec<Tx>> {
        let total_app_cycles = app_cycles;
        let ProveRequest {
            spell: norm_spell,
            app_private_inputs,
            tx_ins_beamed_source_utxos,
            binaries,
            prev_txs,
            funding_utxo,
            funding_utxo_value,
            change_address,
            fee_rate,
            chain,
            collateral_utxo,
        } = prove_request;

        if chain == Chain::Cardano && collateral_utxo.is_none() {
            bail!("Collateral UTXO is required for Cardano spells");
        }

        let prev_txs_by_id = by_txid(&prev_txs);

        let (truncated_norm_spell, proof, proof_app_cycles) = self.prover.prove(
            norm_spell.clone(),
            binaries,
            app_private_inputs,
            prev_txs,
            tx_ins_beamed_source_utxos,
        )?;

        let total_cycles = if !self.mock {
            total_app_cycles
        } else {
            proof_app_cycles // mock prover computes app run cycles
        };

        tracing::info!("proof generated. total app cycles: {}", total_cycles);

        // Serialize spell into CBOR
        let spell_data = util::write(&(&truncated_norm_spell, &proof))?;

        let charms_fee = self.charms_fee_settings.clone();

        match chain {
            Chain::Bitcoin => {
                let txs = bitcoin_tx::make_transactions(
                    &norm_spell,
                    funding_utxo,
                    funding_utxo_value,
                    &change_address,
                    &prev_txs_by_id,
                    &spell_data,
                    fee_rate,
                    charms_fee,
                    total_cycles,
                )?;
                Ok(txs)
            }
            Chain::Cardano => {
                let txs = cardano_tx::make_transactions(
                    &norm_spell,
                    funding_utxo,
                    funding_utxo_value,
                    &change_address,
                    &spell_data,
                    &prev_txs_by_id,
                    None,
                    charms_fee,
                    total_cycles,
                    collateral_utxo,
                )
                .await?;
                Ok(txs)
            }
        }
    }
}

const CHARMS_PROVE_API_URL: &'static str =
    formatcp!("https://v{CURRENT_VERSION}.charms.dev/spells/prove");

#[cfg(feature = "prover")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestData {
    committed_data_hash: [u8; 32],
}

#[cfg(feature = "prover")]
#[derive(Clone, Debug, Serialize, Deserialize, FromRedisValue, ToRedisArgs)]
pub enum ProofState {
    Processing {
        request_data: RequestData,
    },
    Done {
        request_data: RequestData,
        result: Vec<Tx>,
    },
}

pub fn committed_data_hash(normalized_spell: &NormalizedSpell) -> anyhow::Result<[u8; 32]> {
    let bytes =
        util::write(&normalized_spell).context("Failed to serialize normalized spell for hash")?;
    Ok(Sha256::digest(&bytes).into())
}

impl ProveSpellTx for ProveSpellTxImpl {
    #[tracing::instrument(level = "debug")]
    fn new(mock: bool) -> Self {
        let charms_fee_settings = charms_fee_settings();

        let charms_prove_api_url = std::env::var("CHARMS_PROVE_API_URL")
            .ok()
            .unwrap_or(CHARMS_PROVE_API_URL.to_string());
        tracing::info!(charms_prove_api_url);

        let prover = prove_impl(mock);

        #[cfg(feature = "prover")]
        let cache_client: Option<(_, _)> = {
            std::env::var("REDIS_URL").ok().and_then(|redis_url| {
                match redis::Client::open(redis_url) {
                    Ok(redis_client) => {
                        let lock_manager =
                            rslock::LockManager::from_clients(vec![redis_client.clone()]);
                        Some((redis_client, lock_manager))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create Redis client, caching disabled: {}", e);
                        None
                    }
                }
            })
        };

        #[cfg(not(feature = "prover"))]
        let client = Client::builder()
            .use_rustls_tls() // avoids system OpenSSL issues
            .http2_prior_knowledge()
            .http2_adaptive_window(true)
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("HTTP client should be created successfully");

        Self {
            mock,
            charms_fee_settings,
            charms_prove_api_url,
            #[cfg(feature = "prover")]
            cache_client,
            prover,
            #[cfg(not(feature = "prover"))]
            client,
        }
    }

    #[cfg(feature = "prover")]
    async fn prove_spell_tx(&self, prove_request: ProveRequest) -> anyhow::Result<Vec<Tx>> {
        let (norm_spell, app_cycles) = self.validate_prove_request(&prove_request)?;

        if let Some((cache_client, lock_manager)) = self.cache_client.as_ref() {
            let request_key = prove_request.funding_utxo.to_string();
            let lock_key = format!("LOCK_{}", request_key.as_str());
            let committed_data_hash = committed_data_hash(&norm_spell)?;

            let mut con = cache_client.get_multiplexed_async_connection().await?;

            match con.get(request_key.as_str()).await? {
                Some(ProofState::Done { request_data, .. })
                | Some(ProofState::Processing { request_data, .. })
                    if request_data.committed_data_hash != committed_data_hash =>
                {
                    bail!("duplicate funding UTXO spend with different spell");
                }
                Some(ProofState::Done { result, .. }) => Ok(result),
                _ => {
                    const LOCK_TTL: Duration = Duration::from_secs(5);

                    let mut con = con.clone();
                    let request_key = request_key.clone();

                    let result: Vec<Tx> = lock_manager
                        .using(lock_key.as_bytes(), LOCK_TTL, || async move {
                            match con.get(request_key.as_str()).await? {
                                Some(ProofState::Done { request_data, .. })
                                | Some(ProofState::Processing { request_data, .. })
                                    if request_data.committed_data_hash != committed_data_hash =>
                                {
                                    bail!("duplicate funding UTXO spend with different spell");
                                }
                                Some(ProofState::Done { result, .. }) => {
                                    return Ok(result);
                                }
                                _ => {}
                            };

                            let _: () = block_on(con.set(
                                request_key.as_str(),
                                ProofState::Processing {
                                    request_data: RequestData {
                                        committed_data_hash,
                                    },
                                },
                            ))?;

                            let r: Vec<Tx> =
                                self.do_prove_spell_tx(prove_request, app_cycles).await?;

                            let _: () = block_on(con.set(
                                request_key.as_str(),
                                ProofState::Done {
                                    request_data: RequestData {
                                        committed_data_hash,
                                    },
                                    result: r.clone(),
                                },
                            ))?;

                            Ok::<_, anyhow::Error>(r)
                        })
                        .await??;

                    // TODO save permanent error to the cache

                    Ok(result)
                }
            }
        } else {
            self.do_prove_spell_tx(prove_request, app_cycles).await
        }
    }

    #[cfg(not(feature = "prover"))]
    #[tracing::instrument(level = "info", skip_all)]
    async fn prove_spell_tx(&self, prove_request: ProveRequest) -> anyhow::Result<Vec<Tx>> {
        let (_norm_spell, app_cycles) = self.validate_prove_request(&prove_request)?;
        if self.mock {
            return Self::do_prove_spell_tx(self, prove_request, app_cycles).await;
        }

        let response = retry(0, || async {
            let cbor_body = util::write(&prove_request)?;
            let response = self
                .client
                .post(&self.charms_prove_api_url)
                .header("Content-Type", "application/cbor")
                .body(cbor_body)
                .send()
                .await?;
            if response.status().is_server_error() {
                bail!("server error: {}", response.status());
            }
            Ok(response)
        })
        .await?;
        if response.status().is_client_error() {
            let status = response.status();
            let body = response.text().await?;
            bail!("client error: {}: {}", status, body);
        }
        let bytes = response.bytes().await?;
        let txs: Vec<Tx> = util::read(&bytes[..])?;
        Ok(txs)
    }
}

pub fn ensure_exact_app_binaries(
    norm_spell: &NormalizedSpell,
    app_private_inputs: &BTreeMap<App, Data>,
    tx: &Transaction,
    binaries: &BTreeMap<B32, Vec<u8>>,
) -> anyhow::Result<()> {
    let required_vks: BTreeSet<_> = norm_spell
        .app_public_inputs
        .iter()
        .filter(|(app, data)| {
            !data.is_empty()
                || !app_private_inputs
                    .get(app)
                    .is_none_or(|data| data.is_empty())
                || !is_simple_transfer(app, tx)
        })
        .map(|(app, _)| &app.vk)
        .collect();

    let provided_vks: BTreeSet<_> = binaries.keys().collect();

    ensure!(
        required_vks == provided_vks,
        "binaries must contain exactly the required app binaries.\n\
         Required VKs: {:?}\n\
         Provided VKs: {:?}",
        required_vks,
        provided_vks
    );

    Ok(())
}

pub fn ensure_all_prev_txs_are_present(
    spell: &NormalizedSpell,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, UtxoId>,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> anyhow::Result<()> {
    let spell_ins = spell
        .tx
        .ins
        .as_ref()
        .ok_or_else(|| anyhow!("spell.tx.ins must be present"))?;

    ensure!(
        spell_ins
            .iter()
            .all(|utxo_id| prev_txs_by_id.contains_key(&utxo_id.0)),
        "prev_txs MUST contain transactions creating input UTXOs"
    );
    ensure!(
        spell.tx.refs.as_ref().is_none_or(|ins| {
            ins.iter()
                .all(|utxo_id| prev_txs_by_id.contains_key(&utxo_id.0))
        }),
        "prev_txs MUST contain transactions creating ref UTXOs"
    );
    ensure!(
        tx_ins_beamed_source_utxos
            .iter()
            .all(|(&i, beaming_source_utxo_id)| {
                spell_ins.get(i).is_some_and(|utxo_id| {
                    prev_txs_by_id.contains_key(&utxo_id.0)
                        && prev_txs_by_id.contains_key(&beaming_source_utxo_id.0)
                })
            }),
        "prev_txs MUST contain transactions creating beaming source and destination UTXOs"
    );

    // Ensure prev_txs contains ONLY the required transactions (no extras)
    let mut required_txids = BTreeSet::new();

    // Add transaction IDs from spell inputs
    required_txids.extend(spell_ins.iter().map(|utxo_id| &utxo_id.0));

    // Add transaction IDs from spell refs
    if let Some(refs) = spell.tx.refs.as_ref() {
        required_txids.extend(refs.iter().map(|utxo_id| &utxo_id.0));
    }

    // Add transaction IDs from beaming source UTXOs
    required_txids.extend(
        tx_ins_beamed_source_utxos
            .values()
            .map(|utxo_id| &utxo_id.0),
    );

    // Check that prev_txs contains exactly the required transactions
    let provided_txids: BTreeSet<_> = prev_txs_by_id.keys().collect();

    ensure!(
        required_txids == provided_txids,
        "prev_txs must contain exactly the transactions producing spell inputs and beaming sources.\n\
         Required: {:?}\n\
         Provided: {:?}",
        required_txids,
        provided_txids
    );

    Ok(())
}

const DEFAULT_COIN_AMOUNT: u64 = 547;

impl ProveSpellTxImpl {
    pub fn validate_prove_request(
        &self,
        prove_request: &ProveRequest,
    ) -> anyhow::Result<(NormalizedSpell, u64)> {
        ensure!(
            prove_request.spell.mock == self.mock,
            "cannot prove a mock=={} spell on a mock=={} prover",
            prove_request.spell.mock,
            self.mock
        );

        let prev_txs = &prove_request.prev_txs;
        let prev_txs_by_id = by_txid(prev_txs);

        let norm_spell = &prove_request.spell;
        let app_private_inputs = &prove_request.app_private_inputs;
        let tx_ins_beamed_source_utxos = &prove_request.tx_ins_beamed_source_utxos;

        ensure_all_prev_txs_are_present(norm_spell, tx_ins_beamed_source_utxos, &prev_txs_by_id)?;

        let prev_spells = charms_client::prev_spells(prev_txs, SPELL_VK, norm_spell.mock);

        let tx = to_tx(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos,
            &prev_txs,
        );

        ensure_exact_app_binaries(
            &norm_spell,
            &app_private_inputs,
            &tx,
            &prove_request.binaries,
        )?;

        let app_input = match prove_request.binaries.is_empty() {
            true => None,
            false => Some(AppInput {
                app_binaries: prove_request.binaries.clone(),
                app_private_inputs: app_private_inputs.clone(),
            }),
        };

        ensure!(
            charms_client::is_correct(
                &norm_spell,
                &prev_txs,
                app_input.clone(),
                SPELL_VK,
                &tx_ins_beamed_source_utxos,
            ),
            "spell verification failed"
        );

        // Calculate cycles for fee estimation
        let total_cycles = if let Some(app_input) = &app_input {
            let cycles = AppRunner::new(true).run_all(
                &app_input.app_binaries,
                &tx,
                &norm_spell.app_public_inputs,
                &app_input.app_private_inputs,
            )?;
            cycles.iter().sum()
        } else {
            0
        };

        match prove_request.chain {
            Chain::Bitcoin => {
                let change_address = bitcoin::Address::from_str(&prove_request.change_address)?;

                let network = match &change_address {
                    a if a.is_valid_for_network(Network::Bitcoin) => Network::Bitcoin,
                    a if a.is_valid_for_network(Network::Testnet4) => Network::Testnet4,
                    a if a.is_valid_for_network(Network::Regtest) && self.mock => Network::Regtest,
                    _ => bail!(
                        "Unsupported network of change address: {:?}",
                        change_address
                    ),
                };
                let coin_outs = (norm_spell.tx.coins.as_ref()).expect("coin outputs are expected");

                // Validate that all output addresses are valid for the network
                ensure!(
                    coin_outs.iter().all(|o| {
                        bitcoin::Address::from_script(
                            &bitcoin::ScriptBuf::from_bytes(o.dest.clone()),
                            network,
                        )
                        .is_ok()
                    }),
                    "all output addresses must be valid for the network"
                );

                let charms_fee = get_charms_fee(&self.charms_fee_settings, total_cycles).to_sat();

                let spell_ins = norm_spell
                    .tx
                    .ins
                    .as_ref()
                    .expect("spell inputs are expected");
                let total_sats_in: u64 = spell_ins
                    .iter()
                    .map(|utxo_id| {
                        prev_txs_by_id
                            .get(&utxo_id.0)
                            .and_then(|prev_tx| {
                                if let Tx::Bitcoin(bitcoin_tx) = prev_tx {
                                    bitcoin_tx
                                        .inner()
                                        .output
                                        .get(utxo_id.1 as usize)
                                        .map(|o| o.value.to_sat())
                                } else {
                                    None
                                }
                            })
                            .ok_or(anyhow!("utxo not found in prev_txs: {}", utxo_id))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?
                    .iter()
                    .sum();
                let total_sats_out: u64 = coin_outs.iter().map(|o| o.amount).sum();

                let funding_utxo_sats = prove_request.funding_utxo_value;

                let bitcoin_tx = from_spell(&norm_spell)?;
                let tx_size = bitcoin_tx.inner().vsize();
                let mut norm_spell_for_size = norm_spell.clone();
                norm_spell_for_size.tx.ins = None;
                let proof_dummy: Vec<u8> = vec![0xff; 128];
                let spell_cbor = util::write(&(norm_spell_for_size, proof_dummy))?;
                let num_inputs = bitcoin_tx.inner().input.len();
                let estimated_bitcoin_fee: u64 = (111
                    + (spell_cbor.len() as u64 + 372) / 4
                    + tx_size as u64
                    + 28 * num_inputs as u64)
                    * prove_request.fee_rate as u64;

                tracing::info!(
                    total_sats_in,
                    funding_utxo_sats,
                    total_sats_out,
                    charms_fee,
                    estimated_bitcoin_fee
                );

                ensure!(
                    total_sats_in + funding_utxo_sats
                        > total_sats_out + charms_fee + estimated_bitcoin_fee,
                    "total inputs value must be greater than total outputs value plus fees"
                );
            }
            Chain::Cardano => {
                // TODO
                tracing::warn!("spell validation for cardano is not yet implemented");
            }
        }
        Ok((norm_spell.clone(), total_cycles))
    }
}

pub fn from_strings(prev_txs: &[String]) -> anyhow::Result<Vec<Tx>> {
    prev_txs
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|tx_hex| {
            Tx::try_from(tx_hex)
                .context("failed to convert from hex")
                .or_else(|_| serde_json::from_str(tx_hex).context("failed to convert from JSON"))
                .or_else(|_| serde_yaml::from_str(tx_hex).context("failed to convert from YAML"))
        })
        .collect()
}

pub fn get_charms_fee(charms_fee: &Option<CharmsFee>, total_cycles: u64) -> Amount {
    charms_fee
        .as_ref()
        .map(|charms_fee| {
            Amount::from_sat(total_cycles * charms_fee.fee_rate / 1000000 + charms_fee.fee_base)
        })
        .unwrap_or_default()
}

pub fn align_spell_to_tx(
    norm_spell: NormalizedSpell,
    tx: &bitcoin::Transaction,
) -> anyhow::Result<NormalizedSpell> {
    let mut norm_spell = norm_spell;
    let spell_ins = norm_spell.tx.ins.as_ref().ok_or(anyhow!("no inputs"))?;

    ensure!(
        spell_ins.len() <= tx.input.len(),
        "spell inputs exceed transaction inputs"
    );
    ensure!(
        norm_spell.tx.outs.len() <= tx.output.len(),
        "spell outputs exceed transaction outputs"
    );

    for i in 0..spell_ins.len() {
        let utxo_id = &spell_ins[i];
        let out_point = tx.input[i].previous_output;
        ensure!(
            utxo_id.0 == TxId(out_point.txid.to_byte_array()),
            "input {} txid mismatch: {} != {}",
            i,
            utxo_id.0,
            out_point.txid
        );
        ensure!(
            utxo_id.1 == out_point.vout,
            "input {} vout mismatch: {} != {}",
            i,
            utxo_id.1,
            out_point.vout
        );
    }

    for i in spell_ins.len()..tx.input.len() {
        let out_point = tx.input[i].previous_output;
        let utxo_id = UtxoId(TxId(out_point.txid.to_byte_array()), out_point.vout);
        norm_spell.tx.ins.get_or_insert_with(Vec::new).push(utxo_id);
    }

    Ok(norm_spell)
}
