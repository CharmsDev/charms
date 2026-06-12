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
/// Cached SP1 verifying key for `charms-spell-checker`.
pub const SPELL_CHECKER_VK_BYTES: &[u8] = include_bytes!("./bin/charms-spell-checker-vk.bin");
/// Cached SP1 verifying key for `charms-proof-wrapper`.
pub const PROOF_WRAPPER_VK_BYTES: &[u8] = include_bytes!("./bin/charms-proof-wrapper-vk.bin");

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
    use charms_client::{NormalizedSpell, SpellProverInput};
    use charms_data::util;
    use charms_lib::SPELL_VK;
    use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin, SP1VerifyingKey};
    use std::{collections::BTreeMap, time::SystemTime};

    const SPELL_CHECKER_VK_PATH: &str = "./src/bin/charms-spell-checker-vk.bin";
    const PROOF_WRAPPER_VK_PATH: &str = "./src/bin/charms-proof-wrapper-vk.bin";

    fn file_modified(path: &str) -> SystemTime {
        std::fs::metadata(path)
            .unwrap_or_else(|_| panic!("missing file: {path}"))
            .modified()
            .unwrap()
    }

    fn cached_vk_is_stale(elf_path: &str, vk_path: &str) -> bool {
        match std::fs::metadata(vk_path) {
            Ok(vk_meta) if vk_meta.len() > 0 => {
                file_modified(elf_path) > vk_meta.modified().unwrap()
            }
            _ => true,
        }
    }

    async fn ensure_cached_vk(elf_path: &str, vk_path: &str, elf: Elf) -> SP1VerifyingKey {
        if cached_vk_is_stale(elf_path, vk_path) {
            let client = ProverClient::builder().light().build().await;
            let pk = client.setup(elf).await.unwrap();
            let vk = pk.verifying_key().clone();
            let bytes = bincode::serialize(&vk).unwrap();
            std::fs::write(vk_path, bytes).unwrap();
            vk
        } else {
            let bytes = std::fs::read(vk_path).unwrap();
            bincode::deserialize(&bytes).unwrap()
        }
    }

    #[tokio::test]
    async fn ensure_cached_sp1_vks() {
        let spell_checker_elf_modified = file_modified("./src/bin/charms-spell-checker");
        let proof_wrapper_elf_modified = file_modified("./src/bin/charms-proof-wrapper");
        assert!(
            spell_checker_elf_modified <= proof_wrapper_elf_modified,
            "charms-spell-checker MUST NOT be NEWER than charms-proof-wrapper"
        );

        let spell_checker_vk = ensure_cached_vk(
            "./src/bin/charms-spell-checker",
            SPELL_CHECKER_VK_PATH,
            Elf::Static(SPELL_CHECKER_BINARY),
        )
        .await;
        assert_eq!(SPELL_CHECKER_VK, spell_checker_vk.hash_u32());

        let proof_wrapper_vk = ensure_cached_vk(
            "./src/bin/charms-proof-wrapper",
            PROOF_WRAPPER_VK_PATH,
            Elf::Static(PROOF_WRAPPER_BINARY),
        )
        .await;
        assert_eq!(
            charms_client::tx::vk_hex(&SPELL_VK)[2..],
            proof_wrapper_vk.bytes32()[2..]
        );

        assert_eq!(
            bincode::serialize(&spell_checker_vk).unwrap(),
            SPELL_CHECKER_VK_BYTES
        );
        assert_eq!(
            bincode::serialize(&proof_wrapper_vk).unwrap(),
            PROOF_WRAPPER_VK_BYTES
        );
    }

    #[tokio::test]
    async fn programs_run_in_zkvm() {
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![]);

        let input = SpellProverInput {
            self_spell_vk: SPELL_VK,
            prev_txs: vec![],
            spell: spell.clone(),
            tx_ins_beamed_source_utxos: BTreeMap::new(),
            app_input: None,
            scroll_outputs: None,
        };

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(util::write(&input).unwrap());

        let client = ProverClient::builder().light().build().await;
        let (pv, _report) = client
            .execute(Elf::Static(SPELL_CHECKER_BINARY), stdin)
            .await
            .expect("spell-checker should execute successfully");

        let (committed_vk, committed_spell): ([u8; 32], NormalizedSpell) =
            util::read(pv.as_slice()).unwrap();
        assert_eq!(committed_vk, SPELL_VK);
        assert_eq!(committed_spell, spell);

        let input = b"charms-proof-wrapper smoke test".to_vec();

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input.clone());

        let (pv, _report) = client
            .execute(Elf::Static(PROOF_WRAPPER_BINARY), stdin)
            .deferred_proof_verification(false)
            .await
            .expect("proof-wrapper should execute successfully");

        assert_eq!(pv.as_slice(), input.as_slice());
    }
}
