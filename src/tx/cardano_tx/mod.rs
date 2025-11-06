use crate::{
    spell,
    spell::{CharmsFee, KeyedCharms, Spell},
};
use anyhow::{Context, Error, anyhow, bail, ensure};
use charms_client::{
    cardano_tx::{CardanoTx, tx_hash},
    tx::Tx,
};
use charms_data::{App, Data, NFT, TOKEN, TxId, UtxoId};
use cml_chain::{
    OrderedHashMap, PolicyId, Rational, Serialize as CmlChainSerialize, Value,
    address::Address,
    assets::{AssetBundle, AssetName, ClampedSub, MultiAsset},
    builders::{
        input_builder::{InputBuilderResult, SingleInputBuilder},
        mint_builder::SingleMintBuilder,
        output_builder::TransactionOutputBuilder,
        redeemer_builder::RedeemerWitnessKey,
        tx_builder::{
            ChangeSelectionAlgo, TransactionBuilder, TransactionBuilderConfigBuilder,
            add_change_if_needed,
        },
        witness_builder::{PartialPlutusWitness, PlutusScriptWitness},
    },
    fees::LinearFee,
    plutus::{
        CostModels, ExUnitPrices, ExUnits, PlutusData, PlutusMap, PlutusV3Script, RedeemerTag,
    },
    transaction::{
        ConwayFormatTxOut, DatumOption, Transaction, TransactionInput, TransactionOutput,
    },
};
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn tx_inputs(
    tx_b: &mut TransactionBuilder,
    ins: &[spell::Input],
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> anyhow::Result<()> {
    for input in ins {
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
pub const TWO_ADA: u64 = 2000000;

pub const MINT_SCRIPT: &[u8] = &hex!(
    "5859010100229800aba2aba1aab9eaab9dab9a9bae00248888896600264653001300700198039804000cc01c0092225980099b8748000c020dd500144c9289bae300a3009375400516401c30070013004375400f149a26cac80101"
);

fn tx_outputs(
    tx_b: &mut TransactionBuilder,
    outs: &[spell::Output],
    apps: &BTreeMap<String, App>,
) -> anyhow::Result<BTreeMap<PolicyId, PlutusV3Script>> {
    let mut scripts = BTreeMap::new();

    for output in outs {
        let Some(address) = output.address.as_ref() else {
            bail!("no address in spell output {:?}", &output);
        };
        let address =
            Address::from_bech32(address).map_err(|e| anyhow!("Failed to parse address: {}", e))?;
        let amount = output.amount.unwrap_or(TWO_ADA);
        let (multiasset, more_scripts) = multi_asset(&output.charms, apps)?;

        let value = Value::new(amount.into(), multiasset);
        scripts.extend(more_scripts);
        let out_b = TransactionOutputBuilder::new()
            .with_address(address)
            .next()?
            .with_value(value);
        tx_b.add_output(out_b.build()?)?;
    }

    Ok(scripts)
}

fn multi_asset(
    spell_output: &Option<KeyedCharms>,
    apps: &BTreeMap<String, App>,
) -> anyhow::Result<(MultiAsset, BTreeMap<PolicyId, PlutusV3Script>)> {
    let mut multi_asset = MultiAsset::new();
    let mut scripts = BTreeMap::new();
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
            scripts.insert(policy_id, script);
            multi_asset.set(policy_id, asset_name, value);
        }
    };
    Ok((multi_asset, scripts))
}

fn policy_id(app: &App) -> anyhow::Result<(PolicyId, PlutusV3Script)> {
    let param_data = PlutusData::new_list(vec![PlutusData::new_bytes(app.vk.0.to_vec())]);
    let program = uplc::tx::apply_params_to_script(&param_data.to_cbor_bytes(), MINT_SCRIPT)
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
    change_address: &Address,
    spell_data: &[u8],
    funding_utxo: UtxoId,
    funding_utxo_value: u64,
    collateral_utxo: Option<UtxoId>,
) -> anyhow::Result<Transaction> {
    let Some(collateral_utxo) = collateral_utxo else {
        unreachable!()
    };
    let mut tx_b = transaction_builder();

    tx_inputs(&mut tx_b, &spell.ins, prev_txs_by_id)?;

    let scripts = tx_outputs(&mut tx_b, &spell.outs, &spell.apps)?;
    let scripts_count = scripts.len() as u64;

    add_mint(&mut tx_b, scripts)?;

    let funding_input = input_builder_result(change_address, funding_utxo, funding_utxo_value)?;
    let collateral_input = input_builder_result(change_address, collateral_utxo, 10_000_000)?;
    tx_b.add_input(funding_input)?;

    add_spell_data(&mut tx_b, spell_data, change_address)?;

    tx_b.add_collateral(collateral_input)?;

    let input_total = tx_b.get_total_input()?;
    let output_total = tx_b.get_total_output()?;

    for i in 0..scripts_count {
        tx_b.set_exunits(
            RedeemerWitnessKey::new(RedeemerTag::Mint, i as u64),
            ExUnits::new(14000000, 10000000000),
        );
    }

    let fee = tx_b
        .min_fee(true)
        .with_context(|| format!("Failed to calculate minimum fee. tx builder: {:?}", &tx_b))?;

    ensure!(
        input_total.partial_cmp(&output_total.checked_add(&fee.into())?)
            == Some(std::cmp::Ordering::Greater)
    );
    add_change_if_needed(&mut tx_b, change_address, true)?; // MUST add an output

    let tx = tx_b
        .build(ChangeSelectionAlgo::Default, change_address)?
        .build_unchecked();

    Ok(tx)
}

fn input_builder_result(
    address: &Address,
    utxo_id: UtxoId,
    utxo_value: u64,
) -> Result<InputBuilderResult, Error> {
    let funding_utxo_input = TransactionInput::new(tx_hash(utxo_id.0), utxo_id.1 as u64);
    let funding_utxo_output = TransactionOutput::ConwayFormatTxOut(ConwayFormatTxOut::new(
        address.clone(),
        utxo_value.into(),
    ));
    let funding_input =
        SingleInputBuilder::new(funding_utxo_input, funding_utxo_output).payment_key()?;
    Ok(funding_input)
}

fn add_spell_data(
    tx_b: &mut TransactionBuilder,
    spell_data: &[u8],
    change_address: &Address,
) -> anyhow::Result<()> {
    let spell_data_output = TransactionOutputBuilder::new()
        .with_address(change_address.clone())
        .with_data(DatumOption::new_datum(PlutusData::new_bytes(
            spell_data.to_vec(),
        )))
        .next()?
        .with_value(4310 * (227 + spell_data.len() as u64))
        .build()?;

    tx_b.add_output(spell_data_output)?;
    Ok(())
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
    cost_models: BTreeMap<String, Vec<i64>>,
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
            Rational::new(577, 10000),
            Rational::new(721, 10000000),
        ))
        .collateral_percentage(protocol_params.collateral_percentage)
        .max_collateral_inputs(protocol_params.max_collateral_inputs)
        .cost_models(CostModels::new({
            let mut r = OrderedHashMap::new();
            protocol_params
                .cost_models
                .iter()
                .enumerate()
                .for_each(|(i, (_k, v))| {
                    r.insert(i as u64, v.clone());
                });
            r
        }))
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
    tx_b: &mut TransactionBuilder,
    scripts: BTreeMap<PolicyId, PlutusV3Script>,
) -> anyhow::Result<()> {
    let out_v = tx_b.get_explicit_output()?.multiasset;
    let in_v = tx_b.get_explicit_input()?.multiasset;
    let minted_assets = out_v.clamped_sub(&in_v);
    let burned_assets = in_v.clamped_sub(&out_v);

    check_asset_amounts(&minted_assets)?;
    check_asset_amounts(&burned_assets)?;
    let minted_assets: AssetBundle<i64> = unsafe { std::mem::transmute(minted_assets) };
    let burned_assets: AssetBundle<i64> = unsafe { std::mem::transmute(burned_assets) };

    let mint = minted_assets.clamped_sub(&burned_assets);

    for (policy_id, assets) in mint.iter() {
        let mint_b = SingleMintBuilder::new(assets.clone());
        let script = scripts[policy_id].clone(); // scripts MUST have all token policies at this point
        let psw = PlutusScriptWitness::Script(script.into());
        let ppw = PartialPlutusWitness::new(psw, PlutusData::new_map(PlutusMap::new()));
        tx_b.add_mint(mint_b.plutus_script(ppw, vec![].into()))?;
    }

    Ok(())
}

fn check_asset_amounts(assets: &AssetBundle<u64>) -> anyhow::Result<()> {
    for (_, assets) in assets.iter() {
        for (_, amount) in assets.iter() {
            ensure!(*amount < (1u64 << 63));
        }
    }
    Ok(())
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
    collateral_utxo: Option<UtxoId>,
) -> Result<Vec<Tx>, Error> {
    let underlying_tx = underlying_tx
        .map(|tx| {
            let Tx::Cardano(CardanoTx(tx)) = tx else {
                bail!("not a Cardano transaction");
            };
            Ok(tx)
        })
        .transpose()?;
    let change_address = Address::from_bech32(change_address).map_err(|e| anyhow!("{}", e))?;

    let tx = from_spell(
        spell,
        prev_txs_by_id,
        &change_address,
        spell_data,
        funding_utxo,
        funding_utxo_value,
        collateral_utxo,
    )?;

    let tx = match underlying_tx {
        Some(u_tx) => combine(u_tx, tx),
        None => tx,
    };

    Ok(vec![tx]
        .into_iter()
        .map(|tx| Tx::Cardano(CardanoTx(tx)))
        .collect())
}

fn combine(_base_tx: Transaction, _tx: Transaction) -> Transaction {
    todo!()
}
