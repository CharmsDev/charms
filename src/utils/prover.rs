use sp1_sdk::{
    CpuProver, Elf, ExecutionReport, NetworkProver, ProveRequest, Prover, ProvingKey, SP1ProofMode,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
    network::FulfillmentStrategy,
};
use std::future::IntoFuture;

use super::block_on;

pub trait CharmsSP1Prover: Send + Sync {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey);
    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> anyhow::Result<(SP1ProofWithPublicValues, u64)>;
    fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> anyhow::Result<(sp1_sdk::SP1PublicValues, ExecutionReport)>;
}

impl CharmsSP1Prover for CpuProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let pk: SP1ProvingKey =
            block_on(Prover::setup(self, Elf::from(elf))).expect("setup failed");
        let vk = pk.verifying_key().clone();
        (pk, vk)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> anyhow::Result<(SP1ProofWithPublicValues, u64)> {
        let proof =
            block_on(Prover::prove(self, pk, stdin.clone()).mode(kind).into_future())?;
        Ok((proof, 0))
    }

    fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> anyhow::Result<(sp1_sdk::SP1PublicValues, ExecutionReport)> {
        Ok(block_on(
            Prover::execute(self, Elf::from(elf), stdin.clone()).into_future(),
        )?)
    }
}

impl CharmsSP1Prover for NetworkProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let pk: SP1ProvingKey =
            block_on(Prover::setup(self, Elf::from(elf))).expect("setup failed");
        let vk = pk.verifying_key().clone();
        (pk, vk)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> anyhow::Result<(SP1ProofWithPublicValues, u64)> {
        let proof = block_on(
            Prover::prove(self, pk, stdin.clone())
                .mode(kind)
                .skip_simulation(true)
                .strategy(FulfillmentStrategy::Auction)
                .into_future(),
        )?;
        Ok((proof, 0))
    }

    fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> anyhow::Result<(sp1_sdk::SP1PublicValues, ExecutionReport)> {
        Ok(block_on(
            Prover::execute(self, Elf::from(elf), stdin.clone()).into_future(),
        )?)
    }
}
