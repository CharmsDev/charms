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
    well_formed,
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
use serde_with::{IfIsHumanReadable, base64::Base64, serde_as};
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
            mock: false,
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

        let prev_spells = charms_client::prev_spells(&prev_txs, SPELL_VK, false);
        let tx = to_tx(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos,
            &prev_txs,
        );

        let app_binaries = filter_app_binaries(&norm_spell, app_binaries, &tx)?;

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

        let prev_spells = charms_client::prev_spells(&prev_txs, SPELL_VK, true);
        let tx = to_tx(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos,
            &prev_txs,
        );

        let app_binaries = filter_app_binaries(&norm_spell, app_binaries, &tx)?;

        let cycles = self.app_runner.run_all(
            &app_binaries,
            &tx,
            &norm_spell.app_public_inputs,
            &app_private_inputs,
        )?;

        let app_cycles: u64 = cycles.iter().sum();

        // prove charms-spell-checker run
        ensure!(
            charms_client::well_formed(&norm_spell, &prev_spells, &tx_ins_beamed_source_utxos),
            "spell is not well-formed"
        );

        // replace with good randomness in non-mock mode
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        // Create parameters for our circuit
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

        let (proof, spell_cycles) = (proof_bytes, 0);

        let norm_spell = clear_inputs_and_coins(norm_spell);

        Ok((norm_spell, proof, app_cycles + spell_cycles))
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
        let b_tx_hex = "!bitcoin {tx: 0200000000010165b98e0ce9db5268f4de7f3545fa42ab594ccf78a282014c48d806005ef362940100000000ffffffff0400000000000000000c6a0a393130383639313336354d01000000000000225120c2b8776ceb04af97fcbd92ef76a7af85fa483d88ad9489d3bc2bbbfdb4c062214d01000000000000225120c2b8776ceb04af97fcbd92ef76a7af85fa483d88ad9489d3bc2bbbfdb4c062214e91000000000000225120c2b8776ceb04af97fcbd92ef76a7af85fa483d88ad9489d3bc2bbbfdb4c06221014065f6712381b7dbbc87a129dc150f1ad66fe137e6c7cf2d8407ea73fe94d028f8834dd4ac0db8673fc45504ef15ec30618070be7b3ca04cf83f764efd8e9ce30d00000000, proof: 002087237a2bfc69e8248912184c61b71454f491e18477d962ac000000000000000000005c0a215272c6f9e4c70a9060a4292644a0bcf770bebec3af980057585dff35cbdec4ee68b4dd01176f151dab050b00000d71615b2c36e03d443a8e991c7e57786ee3b4f7c848a321b386451751d6e60f30c9adc4d899a7d88cfcc7ff776d6d11c61c9d28b57bc7bb8746924127240506fd16e101bea52e2e1c40bd00a3775ff06eb89e6615a01fdb403842c62fb61c990a82d38eb94a1f37f4de95d1248a600614cd3e748cbf67281e7acc01c0533cbf2fa64fc22c14c4a47b361cc94be2d464641d46e6f7be5a5ec1ee66c326b0b04f0daa916cde8315fcc22ecc3fd3cc40ada06f7ec60f5161d3575c9f2d0ce694e35b7e0e4c74b9fac2634193851095132ebd50844568f7645e5db18780580d6e767772b39864e8f1b62c05dd10c725aeae037c8dd2e9cb891607414ca1f3e4e28d4ffd1d785a0188a53cecf3c4a5ff9df532076f2d7a175b0cc45618393be0f4d9f4b995cd78551cdc0cc82708ffc3411b8b7576db612adf3268be663b53654b5a1c5e57583e45e8ace058634110b5193786114819486dbecee5b1972c5869c010cacecad4b673308d4eb0604cd7fdb1b270201d46153b72766fbba145adeb5d57eadc39a648ae13a164c72cef13fc7172a3782d45e7e96b607e8a05364dd8f5b56404776f0100, headers: [0020052086ea8a5bd82f6f49c344bfe6e48490b078e7e59121c801000000000000000000a472c8691309fa1d5665554f38a8c23577ea7fe2bf5bad4467455fa6887eb11623c6ee68b4dd01170a691af2, 0000fe29d2621d904fb368a0e6f9180dd24e013f395b31084b360100000000000000000058f30077f9b33ffbbda650ac03c853edafe3b616033e3f4896b0c408184093cf83caee68b4dd0117781a6834, 04006b2aed6e4c65e5f23dd04fbd0169e638cacee420ba993923000000000000000000009bce3ef950e3c5bc83edb3800ddeeabee3d9edec90d8591660ef4b992a9411c05fd1ee68b4dd011740808b6f, 0000402042f98a3955ce49c03cdd239570cd694ac7e916c235f000000000000000000000ad854142feb9661e2c3a83187d240bdbf307c7af3db45e33fb2bb434c88e0d60e9d3ee68b4dd01175e66f050, 00008731d2b6cf3f2dcab82626b9e9ab187c55a540787872b24a01000000000000000000b0474629e38f87f484f73d3e6325f655079ab9ff09047cafe497861f089fb2daa9d4ee68b4dd011747dcebe4]}".to_string();

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

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProveRequest {
    pub spell: Spell,
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
    pub app_runner: Arc<AppRunner>,
}

impl ProveSpellTxImpl {
    fn do_prove_spell_tx(
        &self,
        prove_request: ProveRequest,
        app_cycles: u64,
    ) -> anyhow::Result<Vec<Tx>> {
        let total_app_cycles = app_cycles;
        let ProveRequest {
            spell,
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

        let (norm_spell, app_private_inputs, tx_ins_beamed_source_utxos) = spell.normalized()?;

        let (norm_spell, proof, proof_app_cycles) = self.prover.prove(
            norm_spell,
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
        let spell_data = util::write(&(&norm_spell, &proof))?;

        let charms_fee = self.charms_fee_settings.clone();

        match chain {
            Chain::Bitcoin => {
                let txs = bitcoin_tx::make_transactions(
                    &spell,
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
                    &spell,
                    funding_utxo,
                    funding_utxo_value,
                    &change_address,
                    &spell_data,
                    &prev_txs_by_id,
                    None,
                    charms_fee,
                    total_cycles,
                    collateral_utxo,
                )?;
                Ok(txs)
            }
        }
    }
}

fn filter_app_binaries(
    norm_spell: &NormalizedSpell,
    app_binaries: BTreeMap<B32, Vec<u8>>,
    tx: &Transaction,
) -> anyhow::Result<BTreeMap<B32, Vec<u8>>> {
    let vks = norm_spell
        .app_public_inputs
        .keys()
        .filter(|app| !is_simple_transfer(app, tx))
        .map(|app| &app.vk)
        .collect::<BTreeSet<_>>();
    let app_binaries: BTreeMap<_, _> = app_binaries
        .into_iter()
        .filter(|(vk, _)| vks.contains(vk))
        .collect();
    if app_binaries.len() != vks.len() {
        let missing_vks = vks
            .into_iter()
            .filter(|&vk| app_binaries.get(vk).is_none())
            .collect::<Vec<_>>();
        bail!("missing app binaries for vks: {:?}", missing_vks);
    }
    Ok(app_binaries)
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

pub fn committed_data_hash(normalized_spell: &NormalizedSpell) -> [u8; 32] {
    Sha256::digest(&util::write(&normalized_spell).unwrap()).into()
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
            let redis_opt = std::env::var("REDIS_URL").ok().map(|redis_url| {
                let redis_client = redis::Client::open(redis_url)
                    .map_err(|e| {
                        tracing::warn!("failed to create a Redis client: {}", e);
                        e
                    })
                    .unwrap();
                let lock_manager = rslock::LockManager::from_clients(vec![redis_client.clone()]);
                (redis_client, lock_manager)
            });
            redis_opt
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
            let committed_data_hash = committed_data_hash(&norm_spell);

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

                            let r: Vec<Tx> = self.do_prove_spell_tx(prove_request, app_cycles)?;

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
            self.do_prove_spell_tx(prove_request, app_cycles)
        }
    }

    #[cfg(not(feature = "prover"))]
    #[tracing::instrument(level = "info", skip_all)]
    async fn prove_spell_tx(&self, prove_request: ProveRequest) -> anyhow::Result<Vec<Tx>> {
        let (_norm_spell, app_cycles) = self.validate_prove_request(&prove_request)?;
        if self.mock {
            return Self::do_prove_spell_tx(self, prove_request, app_cycles);
        }

        let response = retry(0, || async {
            let response = self
                .client
                .post(&self.charms_prove_api_url)
                .json(&prove_request)
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
        let txs: Vec<Tx> = response.json().await?;
        Ok(txs)
    }
}

pub fn ensure_all_prev_txs_are_present(
    spell: &NormalizedSpell,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, UtxoId>,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> anyhow::Result<()> {
    ensure!(
        dbg!(spell.tx.ins.as_ref()).is_some_and(|ins| {
            ins.iter()
                .all(|utxo_id| prev_txs_by_id.contains_key(&utxo_id.0))
        }),
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
                let utxo_id = &spell.tx.ins.as_ref().unwrap()[i];
                prev_txs_by_id.contains_key(&utxo_id.0)
                    && prev_txs_by_id.contains_key(&beaming_source_utxo_id.0)
            }),
        "prev_txs MUST contain transactions creating beaming source and destination UTXOs"
    );
    Ok(())
}

const DEFAULT_COIN_AMOUNT: u64 = 1000;

impl ProveSpellTxImpl {
    pub fn validate_prove_request(
        &self,
        prove_request: &ProveRequest,
    ) -> anyhow::Result<(NormalizedSpell, u64)> {
        let prev_txs = &prove_request.prev_txs;
        let prev_txs_by_id = by_txid(prev_txs);

        let (norm_spell, app_private_inputs, tx_ins_beamed_source_utxos) =
            prove_request.spell.normalized()?;
        charms_client::ensure_no_zero_amounts(&norm_spell)?;
        ensure_all_prev_txs_are_present(&norm_spell, &tx_ins_beamed_source_utxos, &prev_txs_by_id)?;

        let prev_spells = charms_client::prev_spells(prev_txs, SPELL_VK, self.mock);

        ensure!(well_formed(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos
        ));

        let tx = to_tx(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos,
            &prev_txs,
        );
        // prove charms-app-checker run
        let cycles = AppRunner::new(true).run_all(
            &prove_request.binaries,
            &tx,
            &norm_spell.app_public_inputs,
            &app_private_inputs,
        )?;
        let total_cycles = cycles.iter().sum();

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
                ensure!(prove_request.spell.outs.iter().all(|o| {
                    o.address.as_ref().is_some_and(|a| {
                        bitcoin::Address::from_str(a).is_ok_and(|a| a.is_valid_for_network(network))
                    })
                }));

                let charms_fee = get_charms_fee(&self.charms_fee_settings, total_cycles).to_sat();

                let total_sats_in: u64 = (&prove_request.spell.ins)
                    .iter()
                    .map(|i| {
                        let utxo_id = i.utxo_id.as_ref().expect("utxo_id is expected to be Some");
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
                let total_sats_out: u64 = (&prove_request.spell.outs)
                    .iter()
                    .map(|o| o.amount.unwrap_or(DEFAULT_COIN_AMOUNT))
                    .sum();

                let funding_utxo_sats = prove_request.funding_utxo_value;

                let bitcoin_tx = from_spell(&prove_request.spell)?;
                let tx_size = bitcoin_tx.inner().vsize();
                let (mut norm_spell, ..) = prove_request.spell.normalized()?;
                norm_spell.tx.ins = None;
                let proof_dummy: Vec<u8> = vec![0xff; 128];
                let spell_cbor = util::write(&(norm_spell, proof_dummy))?;
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
        Ok((norm_spell, total_cycles))
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
