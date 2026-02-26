use charms_client::tx::Tx;
pub use charms_client::{
    NormalizedCharms, NormalizedSpell, NormalizedTransaction, bitcoin_tx, cardano_tx, tx,
};
#[cfg(feature = "wasm")]
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

/// Verification key for the current `charms-spell-checker` binary
/// (and the current protocol version).
pub const SPELL_VK: &str = "0x006f3be7356722860f8568ab049d6ea4caac1237d01f098fb742e0aad1b1c0b3";

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = "extractAndVerifySpell")]
pub fn extract_and_verify_spell_js(tx: JsValue, mock: bool) -> Result<JsValue, JsValue> {
    let tx: Tx = serde_wasm_bindgen::from_value(tx)?;
    let norm_spell = extract_and_verify_spell(&tx, mock)?;
    let value = serde_wasm_bindgen::to_value(&norm_spell)?;
    Ok(value)
}

pub fn extract_and_verify_spell(tx: &Tx, mock: bool) -> Result<NormalizedSpell, String> {
    let norm_spell = charms_client::tx::committed_normalized_spell(SPELL_VK, tx, mock)
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
    fn test_extract_and_verify_spell_cardano() {
        let tx_json = include_str!("../test/cardano-tx.json");
        let tx: Tx = serde_json::from_str(tx_json).unwrap();
        let norm_spell = extract_and_verify_spell(&tx, true).unwrap();
        println!("{}", serde_json::to_string_pretty(&norm_spell).unwrap());
    }
}
