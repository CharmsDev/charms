use crate::{
    spell,
    spell::{CharmsFee, KeyedCharms, Spell},
};
use anyhow::{Error, anyhow, bail, ensure};
use charms_client::{
    cardano_tx::{CardanoTx, tx_hash, tx_id},
    tx::Tx,
};
use charms_data::{App, Data, NFT, TOKEN, TxId, UtxoId};
use cml_chain::{
    Coin, PolicyId, Rational, SetTransactionInput, Value,
    address::Address,
    assets::{AssetBundle, AssetName, ClampedSub, MultiAsset},
    builders::{
        input_builder::SingleInputBuilder,
        tx_builder::{TransactionBuilder, TransactionBuilderConfigBuilder},
    },
    fees::{LinearFee, min_no_script_fee},
    plutus::{ExUnitPrices, PlutusData, PlutusV3Script},
    transaction::{
        DatumOption, Transaction, TransactionBody, TransactionInput, TransactionOutput,
        TransactionWitnessSet,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn tx_inputs(
    tx_b: &mut TransactionBuilder,
    ins: &[spell::Input],
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> anyhow::Result<()> {
    for input in ins.iter() {
        let Some(utxo_id) = &input.utxo_id else {
            bail!("no utxo_id in spell input {:?}", &input);
        };
        let input = tx_input(utxo_id);
        let output = tx_output(prev_txs_by_id, utxo_id)?;
        let input_builder = SingleInputBuilder::new(input, output);
        let in_b_result = input_builder.payment_key()?; // TODO impl spending from other addresses
        tx_b.add_input(in_b_result)?;
    }

    Ok(())
}

fn tx_input(utxo_id: &UtxoId) -> TransactionInput {
    TransactionInput::new(tx_hash(utxo_id.0), utxo_id.1 as u64)
}

fn tx_output(
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
    utxo_id: &UtxoId,
) -> anyhow::Result<TransactionOutput> {
    let tx = prev_txs_by_id
        .get(&utxo_id.0)
        .ok_or_else(|| anyhow!("could not find prev_tx by id {}", utxo_id.0))?;
    let Tx::Cardano(CardanoTx(tx)) = tx else {
        bail!("expected CardanoTx, got {:?}", tx);
    };
    let output = tx
        .body
        .outputs
        .get(utxo_id.1 as usize)
        .cloned()
        .ok_or_else(|| anyhow!("could not find output by index {}", utxo_id.1))?;
    Ok(output)
}

pub const ONE_ADA: u64 = 1000000;

pub const MINT_SCRIPT: &[u8] = include_bytes!("../../bin/free_mint.free_mint.mint.flat.cbor");

fn tx_outputs(
    p_tx: &mut TransactionBuilder,
    outs: &[spell::Output],
    apps: &BTreeMap<String, App>,
) -> anyhow::Result<()> {
    // let mut scripts = BTreeSet::new();
    let tx_out = outs
        .iter()
        .map(|output| {
            let Some(address) = output.address.as_ref() else {
                bail!("no address in spell output {:?}", &output);
            };
            let address = Address::from_bech32(address)?;
            let amount = output.amount.unwrap_or(ONE_ADA);
            let (multiasset, more_scripts) = multi_asset(p_tx, &output.charms, apps)?;
            // TODO add script to p_tx scripts.extend(more_scripts);
            let value = Value::new(amount.into(), multiasset);
            Ok(TransactionOutput::new(address, value, None, None))
        })
        .collect::<anyhow::Result<_>>()?;
    Ok((tx_out, scripts))
}

fn multi_asset(
    p_tx: &mut StagingTransaction,
    spell_output: &Option<KeyedCharms>,
    apps: &BTreeMap<String, App>,
) -> anyhow::Result<(MultiAsset, BTreeSet<PlutusV3Script>)> {
    let mut multi_asset = MultiAsset::new();
    let mut scripts = BTreeSet::new();
    if let Some(charms) = spell_output {
        for (k, data) in charms {
            let Some(app) = apps.get(k) else {
                bail!("no app present for the key: {}", k);
            };
            if app.tag != TOKEN && app.tag != NFT {
                continue; // TODO figure what to do with other tags
            }
            let (policy_id, script) = policy_id(app)?;
            let asset_name = asset_name(app)?;
            let value = get_value(app, data)?;
            scripts.insert(script);
            multi_asset.set(policy_id, asset_name, value);
        }
    };
    Ok((multi_asset, scripts))
}

fn policy_id(app: &App) -> anyhow::Result<(PolicyId, PlutusV3Script)> {
    let program = uplc::tx::apply_params_to_script(app.vk.as_ref(), MINT_SCRIPT)
        .map_err(|e| anyhow!("error applying app.vk to Charms token policy: {}", e))?;
    let script = PlutusV3Script::new(program);
    let policy_id = script.hash();
    Ok((policy_id, script))
}

fn asset_name(app: &App) -> anyhow::Result<AssetName> {
    const FT_LABEL: &[u8] = &[0x00, 0x14, 0xdf, 0x10];
    const NFT_LABEL: &[u8] = &[0x00, 0x0d, 0xe1, 0x40];
    let label = match app.tag {
        TOKEN => FT_LABEL,
        NFT => NFT_LABEL,
        _ => unreachable!("unsupported tag: {}", app.tag),
    };
    Ok(AssetName::new([label, &app.identity.0[4..]].concat())
        .map_err(|e| anyhow!("error converting to Cardano AssetName: {}", e))?)
}

fn get_value(app: &App, data: &Data) -> anyhow::Result<u64> {
    match app.tag {
        TOKEN => Ok(data.value()?),
        NFT => Ok(1),
        _ => unreachable!("unsupported tag: {}", app.tag),
    }
}

/// Build a transaction only dealing with Charms tokens
pub fn from_spell(
    spell: &Spell,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> anyhow::Result<Transaction> {
    let mut p_tx = transaction_builder();

    tx_inputs(&mut p_tx, &spell.ins, prev_txs_by_id)?;

    tx_outputs(&mut p_tx, &spell.outs, &spell.apps)?;

    let fee: Coin = 0;

    // let body = TransactionBody::new(inputs, outputs, fee);
    // let body = add_mint(prev_txs_by_id, body)?;

    let mut witness_set = TransactionWitnessSet::new();
    if !scripts.is_empty() {
        witness_set.plutus_v3_scripts = Some(scripts.into_iter().collect::<Vec<_>>().into());
    }

    let tx = Transaction::new(body, witness_set, true, None);

    let tx_builder: TransactionBuilder = transaction_builder();

    Ok(tx)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProtocolParams {
    tx_fee_per_byte: u64,
    tx_fee_fixed: u64,
    min_fee_ref_script_cost_per_byte: u64,
    stake_pool_deposit: u64,
    stake_address_deposit: u64,
    max_value_size: u32,
    max_tx_size: u32,
    utxo_cost_per_byte: u64,
    collateral_percentage: u32,
    max_collateral_inputs: u32,
}

fn transaction_builder() -> TransactionBuilder {
    const PROTOCOL_JSON: &[u8] = include_bytes!("./protocol.json");
    let protocol_params: ProtocolParams = serde_json::from_slice(PROTOCOL_JSON).unwrap();

    let transaction_builder_config = TransactionBuilderConfigBuilder::new()
        .fee_algo(LinearFee::new(
            protocol_params.tx_fee_per_byte,
            protocol_params.tx_fee_fixed,
            protocol_params.min_fee_ref_script_cost_per_byte,
        ))
        .pool_deposit(protocol_params.stake_pool_deposit)
        .key_deposit(protocol_params.stake_address_deposit)
        .max_value_size(protocol_params.max_value_size)
        .max_tx_size(protocol_params.max_tx_size)
        .coins_per_utxo_byte(protocol_params.utxo_cost_per_byte)
        .ex_unit_prices(ExUnitPrices::new(
            Rational::new(577, 100),
            Rational::new(721, 100000),
        ))
        .collateral_percentage(protocol_params.collateral_percentage)
        .max_collateral_inputs(protocol_params.max_collateral_inputs)
        .build()
        .expect("failed to build transaction builder config");
    TransactionBuilder::new(transaction_builder_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_builder_does_not_panic() {
        let _ = transaction_builder();
    }
}

fn add_mint(
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
    mut body: TransactionBody,
) -> anyhow::Result<TransactionBody> {
    let out_assets_iter = body.outputs.iter().map(|o| o.amount().multiasset.clone());
    let in_assets_iter = body.inputs.iter().map(|i| {
        let prev_tx = prev_txs_by_id.get(&TxId(i.transaction_id.into())).unwrap();
        let Tx::Cardano(CardanoTx(prev_tx)) = prev_tx else {
            unreachable!()
        };
        prev_tx.body.outputs[i.index as usize]
            .amount()
            .multiasset
            .clone()
    });

    let out_assets = total_assets(out_assets_iter);
    let in_assets = total_assets(in_assets_iter);

    let minted_assets: AssetBundle<u64> = out_assets.clamped_sub(&in_assets);
    let burned_assets: AssetBundle<u64> = in_assets.clamped_sub(&out_assets);

    check_asset_amounts(&minted_assets)?;
    check_asset_amounts(&burned_assets)?;

    let minted_assets: AssetBundle<i64> = unsafe { std::mem::transmute(minted_assets) };
    let burned_assets: AssetBundle<i64> = unsafe { std::mem::transmute(burned_assets) };

    let mint = minted_assets.clamped_sub(&burned_assets);
    if !mint.is_empty() {
        body.mint = Some(mint);
    }

    Ok(body)
}

fn total_assets(assets_iter: impl Iterator<Item = MultiAsset>) -> MultiAsset {
    assets_iter.fold(MultiAsset::new(), |acc, assets| {
        acc.checked_add(&assets).unwrap()
    })
}

fn check_asset_amounts(assets: &AssetBundle<u64>) -> anyhow::Result<()> {
    for (_, assets) in assets.iter() {
        for (_, amount) in assets.iter() {
            ensure!(*amount < (1u64 << 63));
        }
    }
    Ok(())
}

fn add_spell(
    tx: Transaction,
    spell_data: &[u8],
    funding_utxo: UtxoId,
    funding_utxo_value: u64,
    change_address: Address,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> Vec<Transaction> {
    let tx_body = &tx.body;

    let mut tx_inputs = tx_body.inputs.to_vec();
    let orig_inputs_amount = inputs_total_amount(&tx_body.inputs, prev_txs_by_id);

    let mut tx_outputs = tx_body.outputs.clone();
    let orig_outputs_count = tx_outputs.len() as u64;
    let mut temp_tx_outputs = tx_body.outputs.clone();

    let funding_utxo_input = TransactionInput::new(tx_hash(funding_utxo.0), funding_utxo.1.into());
    tx_inputs.push(funding_utxo_input);

    let temp_data_output = change_output(spell_data, &change_address, 0u64);

    temp_tx_outputs.push(temp_data_output);

    let temp_tx_body =
        TransactionBody::new(tx_inputs.clone().into(), temp_tx_outputs, ONE_ADA.into());
    let temp_tx_witness_set = TransactionWitnessSet::new();
    let temp_tx = Transaction::new(temp_tx_body, temp_tx_witness_set, true, None);

    let min_fee_a: u64 = 44; // lovelace/byte
    let min_fee_b: u64 = 155381 + 50000; // lovelace
    let linear_fee = LinearFee::new(min_fee_a.into(), min_fee_b.into(), 0u64.into());

    let fee = min_no_script_fee(&temp_tx, &linear_fee).unwrap();

    let change = Coin::from(funding_utxo_value + orig_inputs_amount - orig_outputs_count * ONE_ADA)
        .checked_sub(fee)
        .unwrap();

    let data_output = change_output(spell_data, &change_address, change);

    tx_outputs.push(data_output);

    let tx_body = TransactionBody::new(tx_inputs.into(), tx_outputs, fee);
    let tx_witness_set = TransactionWitnessSet::new();
    let tx = Transaction::new(tx_body, tx_witness_set, true, None);

    vec![tx]
}

fn change_output(spell_data: &[u8], change_address: &Address, change: u64) -> TransactionOutput {
    TransactionOutput::new(
        change_address.clone(),
        change.into(),
        Some(DatumOption::Datum {
            datum: PlutusData::Bytes {
                bytes: spell_data.to_vec(),
                bytes_encoding: Default::default(),
            },
            len_encoding: Default::default(),
            tag_encoding: None,
            datum_tag_encoding: None,
            datum_bytes_encoding: Default::default(),
        }),
        None,
    )
}

fn inputs_total_amount(
    tx_inputs: &SetTransactionInput,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> u64 {
    tx_inputs
        .iter()
        .map(|tx_input| {
            let tx_id = tx_id(tx_input.transaction_id);
            let Some(Tx::Cardano(CardanoTx(tx))) = prev_txs_by_id.get(&tx_id) else {
                unreachable!("we should already have the tx in the map")
            };
            let prev_tx_out = tx.body.outputs.get(tx_input.index as usize).unwrap();
            let amount: u64 = prev_tx_out.amount().coin.into();
            amount
        })
        .sum()
}

pub fn make_transactions(
    spell: &Spell,
    funding_utxo: UtxoId,
    funding_utxo_value: u64,
    change_address: &String,
    spell_data: &[u8],
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
    underlying_tx: Option<Tx>,
    _charms_fee: Option<CharmsFee>,
    _total_cycles: u64,
) -> Result<Vec<Tx>, Error> {
    let underlying_tx = underlying_tx
        .map(|tx| {
            let Tx::Cardano(CardanoTx(tx)) = tx else {
                bail!("not a Cardano transaction");
            };
            Ok(tx)
        })
        .transpose()?;
    let change_address =
        Address::from_bech32(change_address).map_err(|e| anyhow::anyhow!("{}", e))?;

    let tx = from_spell(spell, prev_txs_by_id)?;

    let tx = match underlying_tx {
        Some(u_tx) => combine(u_tx, tx),
        None => tx,
    };

    let transactions = add_spell(
        tx,
        spell_data,
        funding_utxo,
        funding_utxo_value,
        change_address,
        prev_txs_by_id,
    );
    Ok(transactions
        .into_iter()
        .map(|tx| Tx::Cardano(CardanoTx(tx)))
        .collect())
}

fn combine(base_tx: Transaction, tx: Transaction) -> Transaction {
    todo!()
}
