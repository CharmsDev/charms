use charms_client::tx::Tx;
pub use charms_client::{
    CHARMS_PROVE_API_URL, CURRENT_VERSION, NormalizedCharms, NormalizedSpell,
    NormalizedTransaction, bitcoin_tx, cardano_tx, request, tx,
};
use hex_literal::hex;
#[cfg(feature = "wasm")]
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

/// Verification key for the current `charms-spell-checker` binary
/// (and the current protocol version).
pub const SPELL_VK: [u8; 32] =
    hex!("00b355b648d4efac98ca94aa15ad24300452b40762a269c599cd682d14b001c0");

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = "extractAndVerifySpell")]
pub fn extract_and_verify_spell_js(tx: JsValue, mock: bool) -> Result<JsValue, JsValue> {
    let tx: Tx = serde_wasm_bindgen::from_value(tx)?;
    let norm_spell = extract_and_verify_spell(&tx, mock)?;
    let value = serde_wasm_bindgen::to_value(&norm_spell)?;
    Ok(value)
}

pub fn extract_and_verify_spell(tx: &Tx, mock: bool) -> Result<NormalizedSpell, String> {
    let norm_spell = charms_client::tx::committed_normalized_spell(&SPELL_VK, tx, mock)
        .map_err(|e| e.to_string())?;
    Ok(norm_spell)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_and_verify_spell_bitcoin() {
        let tx_json = include_str!("../test/bitcoin-tx.json");
        let tx: Tx = serde_json::from_str(tx_json).unwrap();
        let norm_spell = extract_and_verify_spell(&tx, true).unwrap();
        println!("{}", serde_json::to_string_pretty(&norm_spell).unwrap());
    }

    #[test]
    #[ignore = "needs a regenerated test/ethereum-spell.hex"]
    fn test_extract_and_verify_spell_ethereum() {
        let hex = include_str!("../test/ethereum-spell.hex");
        let tx = Tx::try_from(hex.trim()).unwrap();
        let Tx::Ethereum(record) = &tx else {
            panic!("fixture is an Ethereum record");
        };
        assert!(!record.proof.is_empty());
        let norm_spell = extract_and_verify_spell(&tx, false).unwrap();
        assert_eq!(norm_spell.version, CURRENT_VERSION);
        assert_eq!(norm_spell.tx.ins.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_extract_and_verify_spell_cardano() {
        let tx_json = include_str!("../test/cardano-tx.json");
        let tx: Tx = serde_json::from_str(tx_json).unwrap();
        let norm_spell = extract_and_verify_spell(&tx, true).unwrap();
        println!("{}", serde_json::to_string_pretty(&norm_spell).unwrap());
    }
}
