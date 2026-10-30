use crate::{
    cli,
    cli::{ShowSpellParams, TxBuildParams},
    tx,
};
use anyhow::{Result, bail, ensure};
use charms_client::{
    bitcoin_tx::BitcoinTx,
    cardano_tx::CardanoTx,
    ethereum_tx::ENVELOPE_PREFIX,
    tx::{Chain, Tx},
};

pub fn tx_show_spell(params: ShowSpellParams) -> Result<()> {
    let ShowSpellParams {
        chain,
        tx,
        json,
        mock,
    } = params;
    match chain {
        Chain::Bitcoin => show_verified_spell(&Tx::Bitcoin(BitcoinTx::from_hex(&tx)?), json, mock),
        Chain::Cardano => show_verified_spell(&Tx::Cardano(CardanoTx::from_hex(&tx)?), json, mock),
        Chain::Ethereum => show_ethereum_spell(&tx, json, mock),
    }
}

fn show_verified_spell(tx: &Tx, json: bool, mock: bool) -> Result<()> {
    match tx::spell(tx, mock) {
        Some(spell) => cli::print_output(&spell, json)?,
        None => eprintln!("No spell found in the transaction"),
    }
    Ok(())
}

/// CHET records keep the proof check. A raw transaction prints the spell in its calldata.
fn show_ethereum_spell(tx: &str, json: bool, mock: bool) -> Result<()> {
    let hex_str = tx.trim();
    let hex_str = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|_| anyhow::anyhow!("invalid hex"))?;
    if bytes.starts_with(ENVELOPE_PREFIX) {
        let Some(eth) = charms_client::ethereum_tx::from_envelope_hex(hex_str)? else {
            bail!("invalid hex");
        };
        return show_verified_spell(&Tx::Ethereum(eth), json, mock);
    }
    let spell = crate::ethereum_raw::spell_from_raw_transaction(&bytes)?;
    cli::print_output(&spell, json)?;
    Ok(())
}

pub fn tx_build(params: TxBuildParams) -> Result<()> {
    ensure!(
        params.chain == Chain::Ethereum,
        "tx build is implemented for ethereum"
    );
    println!("{}", ethereum_transact_json(&params.tx)?);
    Ok(())
}

pub(crate) fn ethereum_transact_json(tx_hex: &str) -> Result<String> {
    let Some(record) = charms_client::ethereum_tx::from_envelope_hex(tx_hex)? else {
        bail!("expected the Ethereum record hex");
    };
    let call = charms_client::ethereum_tx::transact_call(&record)?;
    Ok(serde_json::to_string(&call)?)
}
