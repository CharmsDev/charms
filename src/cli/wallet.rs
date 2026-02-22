use crate::{cli, cli::WalletListParams, tx, utils::str_index};
use anyhow::{Result, ensure};
use bitcoin::{Transaction, hashes::Hash};
use charms_client::{NormalizedCharms, NormalizedSpell, bitcoin_tx::BitcoinTx, tx::Tx};
use charms_data::{App, Data, TxId, UtxoId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::{Command, Stdio},
    str::FromStr,
};

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
    confirmations: u32,
    sats: u64,
    charms: BTreeMap<String, Data>,
}

type ParsedCharms = BTreeMap<App, Data>;

#[derive(Debug, Serialize)]
struct AppsAndCharmsOutputs {
    apps: BTreeMap<String, App>,
    outputs: BTreeMap<UtxoId, OutputWithCharms>,
}

impl List for WalletCli {
    fn list(&self, params: WalletListParams) -> Result<()> {
        let b_cli = Command::new("bitcoin-cli")
            .args(&["listunspent", "0"]) // include outputs with 0 confirmations
            .stdout(Stdio::piped())
            .spawn()?;
        let output = b_cli.wait_with_output()?;
        let b_list_unspent: Vec<BListUnspentItem> = serde_json::from_slice(&output.stdout)?;

        let unspent_charms_outputs = outputs_with_charms(b_list_unspent, params.mock)?;

        cli::print_output(&unspent_charms_outputs, params.json)?;
        Ok(())
    }
}

fn outputs_with_charms(
    b_list_unspent: Vec<BListUnspentItem>,
    mock: bool,
) -> Result<AppsAndCharmsOutputs> {
    let txid_set = b_list_unspent
        .iter()
        .map(|item| item.txid.clone())
        .collect::<BTreeSet<_>>();
    let spells = txs_with_spells(txid_set.into_iter(), mock)?;
    let utxos_with_charms: BTreeMap<UtxoId, (BListUnspentItem, ParsedCharms)> =
        utxos_with_charms(&spells, b_list_unspent);
    let apps = collect_apps(&utxos_with_charms);

    Ok(AppsAndCharmsOutputs {
        apps: enumerate_apps(&apps),
        outputs: pretty_outputs(utxos_with_charms, &apps),
    })
}

fn txs_with_spells(
    txid_iter: impl Iterator<Item = String>,
    mock: bool,
) -> Result<BTreeMap<TxId, NormalizedSpell>> {
    let txs_with_spells = txid_iter
        .map(|txid| {
            let tx: Transaction = get_tx(&txid)?;
            Ok(tx)
        })
        .map(|tx_result: Result<Transaction>| {
            let tx = tx_result?;
            let txid = tx.compute_txid();
            let norm_spell_opt = tx::spell(&Tx::Bitcoin(BitcoinTx::Simple(tx)), mock);
            Ok(norm_spell_opt.map(|ns| (TxId(txid.to_byte_array()), ns)))
        })
        .filter_map(|tx_result| match tx_result {
            Ok(Some(v)) => Some(Ok(v)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<_>>()?;

    Ok(txs_with_spells)
}

fn utxos_with_charms(
    spells: &BTreeMap<TxId, NormalizedSpell>,
    b_list_unspent: Vec<BListUnspentItem>,
) -> BTreeMap<UtxoId, (BListUnspentItem, ParsedCharms)> {
    b_list_unspent
        .into_iter()
        .filter(|item| item.solvable)
        .filter_map(|b_utxo| {
            let txid =
                TxId::from_str(&b_utxo.txid).expect("txids from bitcoin-cli should be valid");
            let i = b_utxo.vout;
            spells
                .get(&txid)
                .and_then(|ns| ns.tx.outs.get(i as usize))
                .filter(|n_charms| !n_charms.is_empty())
                .map(|n_charms| {
                    let apps: Vec<App> = spells[&txid].app_public_inputs.keys().cloned().collect();
                    (UtxoId(txid, i), (b_utxo, parsed_charms(n_charms, &apps)))
                })
        })
        .collect()
}

/// Convert NormalizedCharms (u32-indexed) to ParsedCharms (App-keyed)
/// by looking up each app index in the sorted app list.
fn parsed_charms(n_charms: &NormalizedCharms, apps: &[App]) -> ParsedCharms {
    n_charms
        .iter()
        .filter_map(|(&idx, v)| apps.get(idx as usize).map(|app| (app.clone(), v.clone())))
        .collect()
}

fn collect_apps(
    strings_of_charms: &BTreeMap<UtxoId, (BListUnspentItem, ParsedCharms)>,
) -> BTreeMap<App, String> {
    let apps: BTreeSet<App> = strings_of_charms
        .iter()
        .flat_map(|(_utxo, (_sats, charms))| charms.keys())
        .cloned()
        .collect();
    apps.into_iter()
        .zip(0..)
        .map(|(app, i)| (app, str_index(&i)))
        .collect()
}

fn enumerate_apps(apps: &BTreeMap<App, String>) -> BTreeMap<String, App> {
    apps.iter()
        .map(|(app, i)| (i.clone(), app.clone()))
        .collect()
}

fn pretty_outputs(
    utxos_with_charms: BTreeMap<UtxoId, (BListUnspentItem, ParsedCharms)>,
    apps: &BTreeMap<App, String>,
) -> BTreeMap<UtxoId, OutputWithCharms> {
    utxos_with_charms
        .into_iter()
        .map(|(utxo_id, (utxo, charms))| {
            let charms = charms
                .iter()
                .map(|(app, value)| (apps[app].clone(), value.clone()))
                .collect();
            let confirmations = utxo.confirmations;
            let sats = (utxo.amount * 100000000f64) as u64;
            (
                utxo_id.clone(),
                OutputWithCharms {
                    confirmations,
                    sats,
                    charms,
                },
            )
        })
        .collect()
}

fn get_tx(txid: &str) -> Result<Transaction> {
    let b_cli = Command::new("bitcoin-cli")
        .args(&["getrawtransaction", txid])
        .stdout(Stdio::piped())
        .spawn()?;
    let output = b_cli.wait_with_output()?;
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
