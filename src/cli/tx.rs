use crate::{
    cli,
    cli::{BITCOIN, CARDANO},
    tx,
};
use anyhow::Result;
use bitcoin::{consensus::encode::serialize_hex, Transaction};
use charms_client::{bitcoin_tx::BitcoinTx, cardano_tx::CardanoTx, tx::Tx, BitcoinFinalityInput};
use charms_data::TxId;
use serde::Serialize;
use std::{fs::File, io::Write, path::PathBuf, process::Command};

pub fn tx_show_spell(chain: String, tx: String, json: bool) -> Result<()> {
    let tx = match chain.as_str() {
        BITCOIN => Tx::Bitcoin(BitcoinTx::from_hex(&tx)?),
        CARDANO => Tx::Cardano(CardanoTx::from_hex(&tx)?),
        _ => unimplemented!(),
    };

    match tx::spell(&tx) {
        Some(spell) => cli::print_output(&spell, json)?,
        None => eprintln!("No spell found in the transaction"),
    }

    Ok(())
}

pub(crate) fn get_prev_txs(tx: &Transaction) -> Result<Vec<String>> {
    let cmd_output = Command::new("bash")
        .args(&[
            "-c", format!("bitcoin-cli decoderawtransaction {} | jq -r '.vin[].txid' | sort | uniq | xargs -I {{}} bitcoin-cli getrawtransaction {{}} | paste -sd, -", serialize_hex(tx)).as_str()
        ])
        .output()?;
    String::from_utf8(cmd_output.stdout)?
        .split(',')
        .map(|s| Ok(s.to_string()))
        .collect()
}
