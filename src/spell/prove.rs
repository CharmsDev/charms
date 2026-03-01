use crate::{
    PROOF_WRAPPER_BINARY, SPELL_CHECKER_BINARY,
    utils::{BoxedSP1Prover, Shared},
};
use anyhow::{anyhow, ensure};
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
use charms_client::{BeamSource, MOCK_SPELL_VK, NormalizedSpell, Proof, SpellProverInput};
use charms_data::{App, AppInput, B32, Data, util};
use charms_lib::SPELL_VK;
use sha2::{Digest, Sha256};
use sp1_prover::{HashableKey, SP1ProvingKey, SP1VerifyingKey};
use sp1_sdk::{SP1Proof, SP1ProofMode, SP1Stdin};
use std::{collections::BTreeMap, sync::Arc};

use crate::{app, utils::TRANSIENT_PROVER_FAILURE};

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
        prev_txs: Vec<charms_client::tx::Tx>,
        tx_ins_beamed_source_utxos: BTreeMap<usize, BeamSource>,
    ) -> anyhow::Result<(NormalizedSpell, Proof, u64)>;
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
        assert_eq!(crate::SPELL_CHECKER_VK, spell_checker_vk.hash_u32());
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

impl Prove for Prover {
    fn prove(
        &self,
        norm_spell: NormalizedSpell,
        app_binaries: BTreeMap<B32, Vec<u8>>,
        app_private_inputs: BTreeMap<App, Data>,
        prev_txs: Vec<charms_client::tx::Tx>,
        tx_ins_beamed_source_utxos: BTreeMap<usize, BeamSource>,
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

pub struct MockProver {
    pub spell_prover_client: Arc<Shared<BoxedSP1Prover>>,
}

impl Prove for MockProver {
    fn prove(
        &self,
        norm_spell: NormalizedSpell,
        app_binaries: BTreeMap<B32, Vec<u8>>,
        app_private_inputs: BTreeMap<App, Data>,
        prev_txs: Vec<charms_client::tx::Tx>,
        tx_ins_beamed_source_utxos: BTreeMap<usize, BeamSource>,
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

fn make_mock(mut norm_spell: NormalizedSpell) -> NormalizedSpell {
    norm_spell.mock = true;
    norm_spell
}

pub(super) fn clear_inputs_and_coins(mut norm_spell: NormalizedSpell) -> NormalizedSpell {
    norm_spell.tx.ins = None;
    norm_spell.tx.coins = None;
    norm_spell
}

fn load_pk<E: Pairing>() -> anyhow::Result<ProvingKey<E>> {
    ProvingKey::deserialize_compressed(MOCK_GROTH16_PK)
        .map_err(|e| anyhow!("Failed to deserialize proving key: {}", e))
}

const MOCK_GROTH16_PK: &[u8] = include_bytes!("../bin/mock-groth16-pk.bin");

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
