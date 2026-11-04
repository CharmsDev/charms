//! Demo helper. Builds a CHET record for a native Ethereum
//! Charms transaction whose spell lives only in the `Transaction` event (a facade
//! ERC-20 `transfer`), so `charms tx show-spell --chain ethereum` can read it. Usage:
//!   eth_record <proxy_hex20> <event_spell_cbor_hex> <expected_tx_id_hex> <creator_record_hex>...
//! Each creator record is a CHET hex of a tx that created one input, in input order.
use charms_client::ethereum_tx::{EthereumTx, InputSource, from_envelope_hex};
use charms_client::tx::{EnchantedTx, Tx};

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a[1] == "--sign" {
        // eth_record --sign <record_hex> <sig_hex64>: attach the scrolls_ethereum finality signature.
        let mut rec = from_envelope_hex(&a[2])?.expect("CHET record");
        let sig: [u8; 64] = hex::decode(a[3].trim_start_matches("0x"))?.try_into().unwrap();
        rec.signature = Some(sig);
        anyhow::ensure!(rec.proven_final(), "signature does not verify against the demo finality key");
        println!("{}", Tx::Ethereum(rec).hex());
        return Ok(());
    }
    let charms: [u8; 20] = hex::decode(a[1].trim_start_matches("0x"))?.try_into().unwrap();
    let spell = hex::decode(a[2].trim_start_matches("0x"))?;
    let expected = a[3].trim_start_matches("0x").to_lowercase();
    let mut input_sources = Vec::new();
    for h in &a[4..] {
        let c = from_envelope_hex(h)?.expect("CHET record");
        input_sources.push(InputSource { chain_id: c.chain_id, charms: c.charms, anchor: c.anchor, spell: c.spell.clone() });
    }
    let rec = EthereumTx { chain_id: 1, charms, anchor: None, spell, proof: vec![], caller: None, salt: None, signature: None, input_sources };
    let id = hex::encode(rec.eth_tx_id());
    anyhow::ensure!(id == expected, "tx id {id} != event {expected}");
    let tx = Tx::Ethereum(rec.clone());
    rec.extract_and_verify_spell(&[0u8; 32], false)?;
    println!("{}", tx.hex());
    Ok(())
}
