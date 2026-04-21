pub mod app;
pub mod cli;
pub mod script;
pub mod spell;
pub mod tx;
pub mod utils;

use crate::spell::{ProveRequest, ProveSpellTx, ProveSpellTxImpl};
use charms_client::tx::Tx;
pub use charms_proof_wrapper::SPELL_CHECKER_VK;

/// RISC-V binary compiled from `charms-spell-checker`.
pub const SPELL_CHECKER_BINARY: &[u8] = include_bytes!("./bin/charms-spell-checker");
/// RISC-V binary compiled from `charms-proof-wrapper`.
pub const PROOF_WRAPPER_BINARY: &[u8] = include_bytes!("./bin/charms-proof-wrapper");

/// Prove a spell and return the resulting chain-specific transactions, ready to sign and broadcast.
///
/// - Bitcoin: returns `[spell_tx]` with spell and proof in an OP_RETURN output.
/// - Cardano: returns `[spell_tx]` with spell and proof in a Charms fee output datum. Requires
///   `collateral_utxo`.
///
/// Set `req.spell.mock = true` to use the mock prover (skips proof generation) — useful
/// for tests that exercise the full transaction-building pipeline without real proving.
pub async fn prove(req: ProveRequest) -> anyhow::Result<Vec<Tx>> {
    ProveSpellTxImpl::new(req.spell.mock)
        .prove_spell_tx(req)
        .await
}

#[cfg(test)]
mod test {
    use super::*;
    use charms_lib::SPELL_VK;
    use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey};

    #[tokio::test]
    async fn test_spell_vk() {
        let a = std::fs::metadata("./src/bin/charms-spell-checker")
            .unwrap()
            .modified()
            .unwrap();
        let b = std::fs::metadata("./src/bin/charms-proof-wrapper")
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            a <= b,
            "charms-spell-checker MUST NOT be NEWER than charms-proof-wrapper"
        );

        let client = ProverClient::builder().light().build().await;

        let pk = client
            .setup(Elf::Static(PROOF_WRAPPER_BINARY))
            .await
            .unwrap();
        let s = pk.verifying_key().bytes32();
        assert_eq!(SPELL_VK, s.as_str());
    }
}
