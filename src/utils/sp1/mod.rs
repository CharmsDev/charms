//! # SP1 CUDA Prover
//!
//! A prover that uses the CUDA to execute and prove programs.

use anyhow::{Result, anyhow};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1Prover, components::CpuProverComponents};

use crate::utils::{TRANSIENT_PROVER_FAILURE, prover::CharmsSP1Prover, sp1::cuda::SP1CudaProver};
use sp1_sdk::{
    ExecutionReport, Prover, SP1Proof, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
    install::try_install_circuit_artifacts,
};

pub mod cuda;

/// A prover that uses the CPU for execution and the CUDA for proving.
pub struct CudaProver {
    pub cpu_prover: SP1Prover<CpuProverComponents>,
    pub cuda_prover: SP1CudaProver,
}

impl CudaProver {
    /// Creates a new [`CudaProver`].
    pub fn new(cpu_prover: SP1Prover, cuda_prover: SP1CudaProver) -> Self {
        // let cuda_prover = Mutex::new(cuda_prover);
        Self {
            cpu_prover,
            cuda_prover,
        }
    }

    /// Proves the given program on the given input in the given proof mode.
    ///
    /// Returns the cycle count in addition to the proof.
    pub fn prove_with_cycles(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> Result<(SP1ProofWithPublicValues, u64)> {
        self.cuda_prover.ready()?;

        // Generate the core proof.
        let proof = self.cuda_prover.prove_core_stateless(pk, stdin)?;
        let cycles = proof.cycles;
        if kind == SP1ProofMode::Core {
            unreachable!()
        }

        // Generate the compressed proof.
        let deferred_proofs = stdin
            .proofs
            .iter()
            .map(|(reduce_proof, _)| reduce_proof.clone())
            .collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.cuda_prover.compress(&pk.vk, proof, deferred_proofs)?;
        if kind == SP1ProofMode::Compressed {
            let proof_with_pv = SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                public_values,
                sp1_version: self.version().to_string(),
                tee_proof: None,
            };
            return Ok((proof_with_pv, cycles));
        }

        // Generate the shrink proof.
        let compress_proof = self.cuda_prover.shrink(reduce_proof)?;

        // Generate the wrap proof.
        let outer_proof = self.cuda_prover.wrap_bn254(compress_proof)?;

        // Generate the gnark proof.
        match kind {
            SP1ProofMode::Groth16 => {
                let groth16_bn254_artifacts = try_install_circuit_artifacts("groth16");

                let proof = self
                    .cpu_prover
                    .wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
                Ok((
                    SP1ProofWithPublicValues {
                        proof: SP1Proof::Groth16(proof),
                        public_values,
                        sp1_version: self.version().to_string(),
                        tee_proof: None,
                    },
                    0,
                ))
            }
            _ => unreachable!(),
        }
    }
}

impl Prover<CpuProverComponents> for CudaProver {
    fn inner(&self) -> &SP1Prover<CpuProverComponents> {
        &self.cpu_prover
    }

    #[tracing::instrument(level = "info", skip_all)]
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let (pk, _, _, vk) = self.cpu_prover.setup(elf);
        (pk, vk)
    }

    #[tracing::instrument(level = "info", skip_all)]
    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prove_with_cycles(pk, stdin, kind).map(|(p, _)| p)
    }
}

impl CharmsSP1Prover for CudaProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let (pk, _, _, vk) = self.cpu_prover.setup(elf);
        (pk, vk)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> anyhow::Result<(SP1ProofWithPublicValues, u64)> {
        self.prove_with_cycles(pk, stdin, kind)
            .map_err(|e| anyhow!("{}: CUDA: {}", TRANSIENT_PROVER_FAILURE, e))
    }

    fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> anyhow::Result<(sp1_sdk::SP1PublicValues, ExecutionReport)> {
        // Use the sp1_sdk::Prover trait method, not the SP1Prover method
        Ok(sp1_sdk::Prover::execute(self as &dyn sp1_sdk::Prover<CpuProverComponents>, elf, stdin)?)
    }
}
