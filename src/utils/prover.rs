use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1ProvingKey, SP1VerifyingKey, components::CpuProverComponents};
use sp1_sdk::{
    CpuProver, ExecutionReport, NetworkProver, Prover, SP1ProofMode, SP1ProofWithPublicValues,
    network::FulfillmentStrategy,
};

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
        let (pk, _, _, vk) = <Self as Prover<CpuProverComponents>>::inner(self).setup(elf);
        (pk, vk)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> anyhow::Result<(SP1ProofWithPublicValues, u64)> {
        let proof = self.prove(pk, stdin).mode(kind).run()?;
        Ok((proof, 0))
    }

    fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> anyhow::Result<(sp1_sdk::SP1PublicValues, ExecutionReport)> {
        Ok(sp1_sdk::Prover::execute(self, elf, stdin)?)
    }
}

impl CharmsSP1Prover for NetworkProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let (pk, _, _, vk) = <Self as Prover<CpuProverComponents>>::inner(self).setup(elf);
        (pk, vk)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> anyhow::Result<(SP1ProofWithPublicValues, u64)> {
        let proof = self
            .prove(pk, stdin)
            .mode(kind)
            .gas_limit(16_000_000_000)
            .cycle_limit(16_000_000_000)
            .max_price_per_pgu(500_000_000)
            .skip_simulation(true)
            .strategy(FulfillmentStrategy::Auction)
            .run()?;
        Ok((proof, 0))
    }

    fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> anyhow::Result<(sp1_sdk::SP1PublicValues, ExecutionReport)> {
        Ok(sp1_sdk::Prover::execute(self, elf, stdin)?)
    }
}
