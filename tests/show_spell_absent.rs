use std::process::{Command, Output};

const NO_SPELL: &str = "No spell found in the transaction";

const BITCOIN_TX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

fn show_spell(chain: &str, tx: &str, json: bool) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_charms"));
    cmd.args(["tx", "show-spell", "--chain", chain, "--tx", tx]);
    if json {
        cmd.arg("--json");
    }
    cmd.output().expect("run charms")
}

fn charm_token_transfer() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ethereum/0xddbd6e2afd317aff3a761c273c0d7b0b7c33af23538dab5d5cc97e4e41f0999d.raw.txt"
    ))
    .expect("transfer fixture")
}

#[test]
fn a_charm_token_transfer_matches_a_bitcoin_transaction_with_no_spell() {
    let transfer = charm_token_transfer();
    for json in [false, true] {
        let bitcoin = show_spell("bitcoin", BITCOIN_TX, json);
        let ethereum = show_spell("ethereum", transfer.trim(), json);
        assert!(
            bitcoin.status.success(),
            "bitcoin exit {json}: {}",
            String::from_utf8_lossy(&bitcoin.stderr)
        );
        assert!(
            ethereum.status.success(),
            "ethereum exit {json}: {}",
            String::from_utf8_lossy(&ethereum.stderr)
        );
        let ethereum_stderr = String::from_utf8_lossy(&ethereum.stderr);
        assert!(
            !ethereum_stderr.to_ascii_lowercase().contains("panic"),
            "{ethereum_stderr}"
        );
        assert_eq!(bitcoin.stdout, b"", "bitcoin stdout {json}");
        assert_eq!(ethereum.stdout, b"", "ethereum stdout {json}");
        assert_eq!(
            String::from_utf8_lossy(&bitcoin.stderr).trim(),
            NO_SPELL,
            "bitcoin stderr {json}"
        );
        assert_eq!(bitcoin.stderr, ethereum.stderr, "stderr {json}");
    }
}
