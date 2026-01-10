use charms_client::bitcoin_tx::{BitcoinTx, parse_spell_and_proof, spell_with_committed_ins_and_coins};
use charms_client::tx::Tx;
pub use charms_client::{
    NormalizedCharms, NormalizedSpell, NormalizedTransaction, bitcoin_tx, cardano_tx, tx,
};
#[cfg(feature = "wasm")]
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

/// Verification key for the current `charms-spell-checker` binary
/// (and the current protocol version).
pub const SPELL_VK: &str = "0x00e440d40e331c16bc4c78d2dbc6bb35876e6ea944e943de359a075e07385abc";

/// Extract and verify a spell from a transaction (WASM binding).
#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = "extractAndVerifySpell")]
pub fn extract_and_verify_spell_js(tx: JsValue, mock: bool) -> Result<JsValue, JsValue> {
    let tx: Tx = serde_wasm_bindgen::from_value(tx)?;
    let norm_spell = extract_and_verify_spell(&tx, mock)?;
    let value = serde_wasm_bindgen::to_value(&norm_spell)?;
    Ok(value)
}

/// Extract and verify a spell from a transaction.
#[tracing::instrument(level = "debug", skip_all)]
pub fn extract_and_verify_spell(tx: &Tx, mock: bool) -> Result<NormalizedSpell, String> {
    let norm_spell = charms_client::tx::committed_normalized_spell(SPELL_VK, tx, mock)
        .map_err(|e| e.to_string())?;
    Ok(norm_spell)
}

/// Extract a spell from a transaction without verification (WASM binding).
///
/// This is useful for mock proofs in WASM environments where the
/// cryptographic verification libraries are not fully supported.
#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = "extractSpellOnly")]
pub fn extract_spell_only_js(tx: JsValue) -> Result<JsValue, JsValue> {
    let tx: Tx = serde_wasm_bindgen::from_value(tx)?;
    let norm_spell = extract_spell_only(&tx)?;
    let value = serde_wasm_bindgen::to_value(&norm_spell)?;
    Ok(value)
}

/// Extract a spell from a transaction without verification.
///
/// This function parses the spell data from the transaction but does not
/// verify the cryptographic proof. Useful for mock proofs in environments
/// where the verification libraries are not available.
#[tracing::instrument(level = "debug", skip_all)]
pub fn extract_spell_only(tx: &Tx) -> Result<NormalizedSpell, String> {
    match tx {
        Tx::Bitcoin(btx) => extract_spell_only_bitcoin(btx),
        Tx::Cardano(_) => Err("Cardano extraction not yet supported".to_string()),
    }
}

#[tracing::instrument(level = "debug", skip_all)]
fn extract_spell_only_bitcoin(btx: &BitcoinTx) -> Result<NormalizedSpell, String> {
    let tx = btx.inner();

    let Some((spell_tx_in, _)) = tx.input.split_last() else {
        return Err("transaction does not have inputs".to_string());
    };

    let (spell, _proof) = parse_spell_and_proof(spell_tx_in)
        .map_err(|e| e.to_string())?;

    Ok(spell_with_committed_ins_and_coins(btx, spell))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_and_verify_spell() {
        let tx_json = include_str!("../test/bitcoin-tx.json");
        let tx: Tx = serde_json::from_str(tx_json).unwrap();
        let norm_spell = extract_and_verify_spell(&tx, true).unwrap();
        println!("{}", serde_json::to_string_pretty(&norm_spell).unwrap());
    }
}
