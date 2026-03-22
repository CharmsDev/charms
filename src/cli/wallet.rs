use crate::{cli::WalletListParams, tx};
use anyhow::{Result, ensure};
use bitcoin::Transaction;
use charms_client::{NormalizedCharms, bitcoin_tx::BitcoinTx, tx::Tx};
use charms_data::{App, Data, TxId, UtxoId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, process::Command, str::FromStr};

pub trait List {
    fn list(&self, params: WalletListParams) -> Result<()>;
}

pub struct WalletCli {
    // pub app_prover: Rc<app::Prover>,
    // pub sp1_client: Rc<Box<dyn Prover<CpuProverComponents>>>,
    // pub spell_prover: Rc<spell::Prover>,
}

#[derive(Debug, Deserialize)]
struct BListUnspentItem {
    txid: String,
    vout: u32,
    amount: f64,
    confirmations: u32,
    solvable: bool,
}

#[derive(Debug, Serialize)]
struct OutputWithCharms {
    utxo_id: UtxoId,
    confirmations: u32,
    sats: u64,
    charms: BTreeMap<String, Data>,
}

type ParsedCharms = BTreeMap<App, Data>;

impl List for WalletCli {
    fn list(&self, params: WalletListParams) -> Result<()> {
        let output = Command::new("bitcoin-cli")
            .args(&["listunspent", "0"]) // include outputs with 0 confirmations
            .output()?;
        let b_list_unspent: Vec<BListUnspentItem> = serde_json::from_slice(&output.stdout)?;

        // Group by txid
        let mut by_txid: BTreeMap<String, Vec<BListUnspentItem>> = BTreeMap::new();
        for item in b_list_unspent {
            by_txid.entry(item.txid.clone()).or_default().push(item);
        }

        // let stdout = io::stdout();
        // let mut out = stdout.lock();

        // Process each txid group: fetch tx, check for spell, output charms immediately
        for (txid, utxos) in by_txid {
            eprintln!("Looking at tx {}...", txid);
            let tx: Transaction = match get_tx(&txid) {
                Ok(tx) => tx,
                Err(_) => continue,
            };
            let spell = match tx::spell(&Tx::Bitcoin(BitcoinTx::Simple(tx)), params.mock) {
                Some(s) => s,
                None => continue,
            };

            let apps: Vec<App> = spell.app_public_inputs.keys().cloned().collect();

            for utxo in utxos {
                if !utxo.solvable {
                    continue;
                }
                let txid =
                    TxId::from_str(&utxo.txid).expect("txids from bitcoin-cli should be valid");
                let n_charms = match spell.tx.outs.get(utxo.vout as usize) {
                    Some(c) if !c.is_empty() => c,
                    _ => continue,
                };

                let charms = parsed_charms(n_charms, &apps);
                let charms_display: BTreeMap<String, Data> = charms
                    .iter()
                    .map(|(app, value)| (app.to_string(), value.clone()))
                    .collect();

                let sats = (utxo.amount * 100_000_000f64) as u64;
                let entry = OutputWithCharms {
                    utxo_id: UtxoId(txid, utxo.vout),
                    confirmations: utxo.confirmations,
                    sats,
                    charms: charms_display,
                };

                if params.json {
                    let s = serde_json::to_string_pretty(&entry)?;
                    println!("{}", s);
                } else {
                    println!("---");
                    let s = serde_yaml::to_string(&entry)?;
                    println!("{}", s);
                }
            }
        }

        Ok(())
    }
}

/// Convert NormalizedCharms (u32-indexed) to ParsedCharms (App-keyed)
/// by looking up each app index in the sorted app list.
fn parsed_charms(n_charms: &NormalizedCharms, apps: &[App]) -> ParsedCharms {
    n_charms
        .iter()
        .filter_map(|(&idx, v)| apps.get(idx as usize).map(|app| (app.clone(), v.clone())))
        .collect()
}

fn get_tx(txid: &str) -> Result<Transaction> {
    let output = Command::new("bitcoin-cli")
        .args(&["getrawtransaction", txid])
        .output()?;
    ensure!(
        output.status.success(),
        "bitcoin-cli getrawtransaction failed"
    );
    let tx_hex = String::from_utf8(output.stdout)?;
    let tx_hex = tx_hex.trim();
    let tx = bitcoin::consensus::encode::deserialize_hex(&(tx_hex))?;
    Ok(tx)
}

pub const MIN_SATS: u64 = 1000;
