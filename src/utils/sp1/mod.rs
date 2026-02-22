//! # SP1 CUDA Prover
//!
//! A prover that uses CUDA to execute and prove programs.

use anyhow::anyhow;
use sp1_cuda::CudaProvingKey;
use sp1_sdk::{
    CudaProver, Elf, ExecutionReport, LightProver, ProveRequest, Prover, ProvingKey, SP1ProofMode,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::collections::HashMap;
use std::future::IntoFuture;
use std::sync::Mutex;

use crate::utils::{TRANSIENT_PROVER_FAILURE, block_on, prover::CharmsSP1Prover};

/// Wrapper around sp1_sdk::CudaProver that implements CharmsSP1Prover.
///
/// The sp1_sdk::CudaProver uses CudaProvingKey (a reference to a key held by the CUDA server),
/// while CharmsSP1Prover uses SP1ProvingKey. This wrapper uses a LightProver to produce
/// SP1ProvingKeys and caches CudaProvingKeys for use in prove calls.
pub struct CharmsCudaProver {
    cuda_prover: CudaProver,
    light_prover: LightProver,
    /// Cache of CudaProvingKey, keyed by ELF bytes.
    cuda_pks: Mutex<HashMap<Vec<u8>, CudaProvingKey>>,
}

impl CharmsCudaProver {
    pub fn new(cuda_prover: CudaProver, light_prover: LightProver) -> Self {
        Self {
            cuda_prover,
            light_prover,
            cuda_pks: Mutex::new(HashMap::new()),
        }
    }
}

impl CharmsSP1Prover for CharmsCudaProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        // Get SP1ProvingKey from the light prover (cheap, only does verification setup)
        let sp1_pk: SP1ProvingKey = block_on(Prover::setup(&self.light_prover, Elf::from(elf)))
            .expect("light setup failed");
        let vk = sp1_pk.verifying_key().clone();

        // Get CudaProvingKey from the CUDA prover (sends ELF to GPU server)
        let cuda_pk: CudaProvingKey = block_on(Prover::setup(&self.cuda_prover, Elf::from(elf)))
            .expect("CUDA setup failed");

        // Cache the CudaProvingKey for later prove calls
        self.cuda_pks
            .lock()
            .unwrap()
            .insert(elf.to_vec(), cuda_pk);

        (sp1_pk, vk)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> anyhow::Result<(SP1ProofWithPublicValues, u64)> {
        let elf_bytes: &[u8] = pk.elf();
        let cuda_pk = {
            let cache = self.cuda_pks.lock().unwrap();
            cache
                .get(elf_bytes)
                .cloned()
                .ok_or_else(|| anyhow!("CudaProvingKey not found; call setup first"))?
        };

        let proof = block_on(
            Prover::prove(&self.cuda_prover, &cuda_pk, stdin.clone())
                .mode(kind)
                .into_future(),
        )
        .map_err(|e| anyhow!("{}: CUDA: {}", TRANSIENT_PROVER_FAILURE, e))?;
        Ok((proof, 0))
    }

    fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> anyhow::Result<(sp1_sdk::SP1PublicValues, ExecutionReport)> {
        // Execute on the CUDA prover (which delegates to its internal light node)
        Ok(block_on(
            Prover::execute(&self.cuda_prover, Elf::from(elf), stdin.clone()).into_future(),
        )?)
    }
}
