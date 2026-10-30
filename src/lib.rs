pub mod app;
pub mod cli;
pub mod ethereum_raw;
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
    use charms_client::{
        NormalizedCharms, NormalizedSpell, NormalizedTransaction, SpellProverInput,
        ethereum_tx::EthereumTx,
        tx::{EnchantedTx, Tx},
    };
    use charms_data::{NativeOutput, UtxoId, util};
    use charms_lib::SPELL_VK;
    use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin, SP1VerifyingKey};
    use std::collections::BTreeMap;

    const SPELL_CHECKER_ELF_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/charms-spell-checker");
    const PROOF_WRAPPER_ELF_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/charms-proof-wrapper");
    const SPELL_CHECKER_VK_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bin/charms-spell-checker-vk.bin"
    );
    const PROOF_WRAPPER_VK_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bin/charms-proof-wrapper-vk.bin"
    );

    fn read_cached_vk(vk_path: &str) -> Option<SP1VerifyingKey> {
        let bytes = std::fs::read(vk_path).ok()?;
        bincode::deserialize(&bytes).ok()
    }

    async fn ensure_cached_vk(
        vk_path: &str,
        elf: Elf,
        expected_vk: impl Fn(&SP1VerifyingKey) -> bool,
    ) -> SP1VerifyingKey {
        if let Some(vk) = read_cached_vk(vk_path) {
            if expected_vk(&vk) {
                return vk;
            }
        }

        let client = ProverClient::builder().light().build().await;
        let pk = client.setup(elf).await.unwrap();
        let vk = pk.verifying_key().clone();
        let bytes = bincode::serialize(&vk).unwrap();
        std::fs::write(vk_path, bytes).unwrap();
        vk
    }

    #[test]
    fn cached_sp1_vks_match_embedded() {
        let spell_checker_vk: SP1VerifyingKey =
            bincode::deserialize(SPELL_CHECKER_VK_BYTES).expect("spell-checker VK bytes");
        assert_eq!(SPELL_CHECKER_VK, spell_checker_vk.hash_u32());

        let proof_wrapper_vk: SP1VerifyingKey =
            bincode::deserialize(PROOF_WRAPPER_VK_BYTES).expect("proof-wrapper VK bytes");
        assert_eq!(
            charms_client::tx::vk_hex(&SPELL_VK)[2..],
            proof_wrapper_vk.bytes32()[2..]
        );
    }

    #[tokio::test]
    #[ignore = "regenerates src/bin cache files; run: cargo test ensure_cached_sp1_vks -- --ignored --nocapture"]
    async fn ensure_cached_sp1_vks() {
        let spell_checker_elf_modified = std::fs::metadata(SPELL_CHECKER_ELF_PATH)
            .expect("spell-checker ELF")
            .modified()
            .unwrap();
        let proof_wrapper_elf_modified = std::fs::metadata(PROOF_WRAPPER_ELF_PATH)
            .expect("proof-wrapper ELF")
            .modified()
            .unwrap();
        assert!(
            spell_checker_elf_modified <= proof_wrapper_elf_modified,
            "charms-spell-checker MUST NOT be NEWER than charms-proof-wrapper"
        );

        let spell_checker_vk = ensure_cached_vk(
            SPELL_CHECKER_VK_PATH,
            Elf::Static(SPELL_CHECKER_BINARY),
            |vk| vk.hash_u32() == SPELL_CHECKER_VK,
        )
        .await;

        let proof_wrapper_vk = ensure_cached_vk(
            PROOF_WRAPPER_VK_PATH,
            Elf::Static(PROOF_WRAPPER_BINARY),
            |vk| vk.bytes32()[2..] == charms_client::tx::vk_hex(&SPELL_VK)[2..],
        )
        .await;

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

    // The spell-checker guest asserts this. `programs_run_in_zkvm` covers guest execution.
    #[test]
    #[ignore = "needs a regenerated charms-lib/test/ethereum-spell.hex"]
    fn checks_an_ethereum_source_proof() {
        let hex = include_str!("../charms-lib/test/ethereum-spell.hex");
        let Tx::Ethereum(record) = Tx::try_from(hex.trim()).unwrap() else {
            panic!("fixture is an Ethereum record");
        };
        let verified = record
            .extract_and_verify_spell(&SPELL_VK, false)
            .expect("host accepts the ethereum proof");
        assert_eq!(verified.version, charms_client::CURRENT_VERSION);
        assert!(record.proof.starts_with(&hex_literal::hex!("4388a21c")));

        let mut claim = NormalizedSpell::default();
        claim.tx.ins = Some(vec![UtxoId(record.tx_id(), 0)]);
        claim.tx.outs = vec![NormalizedCharms::new()];
        claim.tx.coins = Some(vec![NativeOutput {
            amount: 0,
            dest: vec![3; 20],
            content: None,
        }]);
        let prev_txs = vec![Tx::Ethereum(record)];
        assert!(
            charms_client::is_correct(&claim, &prev_txs, None, &SPELL_VK, &BTreeMap::new(), None,)
                .expect("ethereum source proof checks")
        );
    }

    fn ethereum_claim(amount: u64, dest: Vec<u8>) -> (NormalizedSpell, Tx) {
        let mut salt = [0u8; 32];
        salt[31] = 9;
        let carried: NormalizedSpell = serde_yaml::from_str(
            r#"
version: 16
tx:
  outs:
    - {}
  coins:
    - amount: 0
      dest: "0102030405060708090a0b0c0d0e0f1011121314"
app_public_inputs: {}
"#,
        )
        .unwrap();
        let plan = charms_client::ethereum_tx::plan_placeholder(
            &carried,
            &charms_client::ethereum_tx::PlaceholderRequest {
                chain_id: 1,
                charms: [0x33; 20],
                caller: [0x11; 20],
                salt,
                nonce: None,
            },
        )
        .unwrap();
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![UtxoId(plan.record.tx_id(), 0)]);
        spell.tx.outs = vec![NormalizedCharms::new()];
        spell.tx.coins = Some(vec![NativeOutput {
            amount,
            dest,
            content: None,
        }]);
        (spell, Tx::Ethereum(plan.record))
    }

    async fn guest_runs_ethereum_claim(amount: u64, dest: Vec<u8>) -> (u64, usize) {
        let (spell, prev) = ethereum_claim(amount, dest);
        let input = SpellProverInput {
            self_spell_vk: SPELL_VK,
            prev_txs: vec![prev],
            spell,
            tx_ins_beamed_source_utxos: BTreeMap::new(),
            app_input: None,
            scroll_outputs: None,
        };
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(util::write(&input).unwrap());
        let client = ProverClient::builder().light().build().await;
        let (pv, report) = client
            .execute(Elf::Static(SPELL_CHECKER_BINARY), stdin)
            .await
            .expect("guest execution returns a report");
        (report.exit_code, pv.as_slice().len())
    }

    #[tokio::test]
    async fn guest_rejects_an_ethereum_spell_with_a_bad_output() {
        let (code, committed) = guest_runs_ethereum_claim(0, vec![1; 20]).await;
        assert_eq!(code, 0);
        assert!(committed > 0);
        for (amount, dest) in [(1u64, vec![1; 20]), (0, vec![1; 19])] {
            let (code, committed) = guest_runs_ethereum_claim(amount, dest).await;
            assert_eq!(code, 1);
            assert_eq!(committed, 0);
        }
    }

    pub(crate) fn v16_deploy_claim() -> (NormalizedSpell, EthereumTx) {
        let caller = [0x11; 20];
        let reference = [0x22; 20];
        let next = [0x33; 20];
        let charms = [
            0x72, 0x69, 0xcc, 0x77, 0x8b, 0x9b, 0x90, 0xee, 0xe6, 0x71, 0x7b, 0x3d, 0x30, 0x50,
            0xe3, 0x72, 0xe3, 0x99, 0xd8, 0xe7,
        ];
        let mut salt = [0u8; 32];
        salt[31] = 1;
        let carried = NormalizedSpell {
            version: 16,
            tx: NormalizedTransaction {
                outs: vec![NormalizedCharms::new(), NormalizedCharms::new()],
                coins: Some(vec![
                    NativeOutput {
                        amount: 0,
                        dest: caller.to_vec(),
                        content: None,
                    },
                    NativeOutput {
                        amount: 0,
                        dest: reference.to_vec(),
                        content: None,
                    },
                ]),
                ..Default::default()
            },
            ..Default::default()
        };
        let plan = charms_client::ethereum_tx::plan_placeholder(
            &carried,
            &charms_client::ethereum_tx::PlaceholderRequest {
                chain_id: 31_337,
                charms,
                caller,
                salt,
                nonce: None,
            },
        )
        .unwrap();
        let tx_id = plan.record.tx_id();
        let claim = NormalizedSpell {
            version: 16,
            tx: NormalizedTransaction {
                ins: Some(vec![UtxoId(tx_id, 0)]),
                refs: Some(vec![UtxoId(tx_id, 1)]),
                outs: vec![NormalizedCharms::new()],
                coins: Some(vec![NativeOutput {
                    amount: 0,
                    dest: next.to_vec(),
                    content: None,
                }]),
                ..Default::default()
            },
            ..Default::default()
        };
        let expected = hex::decode(include_str!(
            "../ethereum/test/vectors/v16-deploy-claim.hex"
        ))
        .unwrap();
        assert_eq!(util::write(&claim).unwrap(), expected);
        (claim, plan.record)
    }

    #[tokio::test]
    async fn guest_accepts_the_v16_deploy_claim() {
        let (claim, record) = v16_deploy_claim();
        let input = SpellProverInput {
            self_spell_vk: SPELL_VK,
            prev_txs: vec![Tx::Ethereum(record)],
            spell: claim.clone(),
            tx_ins_beamed_source_utxos: BTreeMap::new(),
            app_input: None,
            scroll_outputs: None,
        };
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(util::write(&input).unwrap());
        let client = ProverClient::builder().light().build().await;
        let (pv, report) = client
            .execute(Elf::Static(SPELL_CHECKER_BINARY), stdin)
            .await
            .expect("guest execution returns a report");
        assert_eq!(report.exit_code, 0);
        let (committed_vk, committed_spell): ([u8; 32], NormalizedSpell) =
            util::read(pv.as_slice()).unwrap();
        assert_eq!(committed_vk, SPELL_VK);
        assert_eq!(committed_spell, claim);
    }

    fn v15_placeholder_spend() -> (NormalizedSpell, EthereumTx, Vec<u8>) {
        let mut salt = [0u8; 32];
        salt[31] = 15;
        let carried: NormalizedSpell = serde_yaml::from_str(
            r#"
version: 15
tx:
  outs:
    - {}
  coins:
    - amount: 0
      dest: "0102030405060708090a0b0c0d0e0f1011121314"
app_public_inputs: {}
"#,
        )
        .unwrap();
        let plan = charms_client::ethereum_tx::plan_placeholder(
            &carried,
            &charms_client::ethereum_tx::PlaceholderRequest {
                chain_id: 1,
                charms: [0x33; 20],
                caller: [0x11; 20],
                salt,
                nonce: None,
            },
        )
        .unwrap();
        let bytes = plan.record.spell.clone();
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![UtxoId(plan.record.tx_id(), 0)]);
        spell.tx.outs = vec![NormalizedCharms::new()];
        spell.tx.coins = Some(vec![NativeOutput {
            amount: 0,
            dest: vec![3; 20],
            content: None,
        }]);
        (spell, plan.record, bytes)
    }

    #[tokio::test]
    async fn guest_accepts_a_v15_placeholder_as_an_input() {
        let (claim, record, bytes) = v15_placeholder_spend();
        let extracted = record
            .extract_and_verify_spell(&SPELL_VK, false)
            .expect("v15 placeholder extracts");
        assert_eq!(extracted.version, 15);
        assert_eq!(util::write(&extracted).unwrap(), bytes);
        assert_eq!(record.spell, bytes);
        let input = SpellProverInput {
            self_spell_vk: SPELL_VK,
            prev_txs: vec![Tx::Ethereum(record)],
            spell: claim.clone(),
            tx_ins_beamed_source_utxos: BTreeMap::new(),
            app_input: None,
            scroll_outputs: None,
        };
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(util::write(&input).unwrap());
        let client = ProverClient::builder().light().build().await;
        let (pv, report) = client
            .execute(Elf::Static(SPELL_CHECKER_BINARY), stdin)
            .await
            .expect("guest execution returns a report");
        assert_eq!(report.exit_code, 0);
        let (committed_vk, committed_spell): ([u8; 32], NormalizedSpell) =
            util::read(pv.as_slice()).unwrap();
        assert_eq!(committed_vk, SPELL_VK);
        assert_eq!(committed_spell, claim);
    }
}

#[cfg(all(test, feature = "prover"))]
mod ethereum_spell_proof {
    use super::*;
    use charms_client::{
        NormalizedCharms, NormalizedSpell,
        ethereum_tx::{PlaceholderRequest, plan_placeholder, record_with_proof},
        tx::EnchantedTx,
    };
    use charms_data::{NativeOutput, UtxoId};
    use charms_lib::SPELL_VK;

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "network Groth16 proof; CHARMS_PROVE_ETHEREUM=1"]
    async fn prove_an_ethereum_spell() {
        if std::env::var("CHARMS_PROVE_ETHEREUM").ok().as_deref() != Some("1") {
            return;
        }
        let mut salt = [0u8; 32];
        salt[31] = 7;
        let request = PlaceholderRequest {
            chain_id: 1,
            charms: [0x33; 20],
            caller: [0x11; 20],
            salt,
            nonce: None,
        };
        let spell: NormalizedSpell = serde_yaml::from_str(
            r#"
version: 16
tx:
  outs:
    - {}
  coins:
    - amount: 0
      dest: "0102030405060708090a0b0c0d0e0f1011121314"
app_public_inputs: {}
"#,
        )
        .unwrap();
        let source = plan_placeholder(&spell, &request).unwrap().record;
        let mut claim = NormalizedSpell::default();
        claim.tx.ins = Some(vec![UtxoId(source.tx_id(), 0)]);
        claim.tx.outs = vec![NormalizedCharms::new()];
        claim.tx.coins = Some(vec![NativeOutput {
            amount: 0,
            dest: vec![3; 20],
            content: None,
        }]);
        let prover = crate::cli::prove_impl(false);
        let (committed, proof, _) = prover
            .prove(
                claim,
                Default::default(),
                Default::default(),
                Default::default(),
                vec![Tx::Ethereum(source)],
                Default::default(),
                None,
            )
            .expect("network proof");
        assert_eq!(committed.version, charms_client::CURRENT_VERSION);
        let record = record_with_proof(&committed, proof, 1, [0x33; 20]).unwrap();
        record
            .extract_and_verify_spell(&SPELL_VK, false)
            .expect("host verifies the network proof");
        let path = "charms-lib/test/ethereum-spell.hex";
        std::fs::write(path, record.hex()).unwrap();
        println!("wrote {path} proof_bytes {}", record.proof.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "network Groth16 proof; CHARMS_PROVE_DEPLOY=1"]
    async fn prove_the_v16_deploy_claim() {
        if std::env::var("CHARMS_PROVE_DEPLOY").ok().as_deref() != Some("1") {
            return;
        }
        let (claim, record) = crate::test::v16_deploy_claim();
        let prover = crate::cli::prove_impl(false);
        let (committed, proof, _) = prover
            .prove(
                claim,
                Default::default(),
                Default::default(),
                Default::default(),
                vec![Tx::Ethereum(record)],
                Default::default(),
                None,
            )
            .expect("network proof");
        assert_eq!(committed.version, charms_client::CURRENT_VERSION);
        assert_eq!(&proof[..4], &hex_literal::hex!("4388a21c"));
        let json = format!("{{\n  \"proof\": \"0x{}\"\n}}\n", hex::encode(proof));
        let path = "ethereum/test/vectors/v16-deploy-proof.json";
        std::fs::write(path, json).unwrap();
        println!("wrote {path}");
    }
}
