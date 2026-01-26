use crate::spell::CharmsFee;
use anyhow::{Context, Error, anyhow, bail, ensure};
use candid::{Decode, Encode, Principal};
use charms_client::{
    NormalizedSpell,
    cardano_tx::{CardanoTx, multi_asset, tx_hash},
    charms,
    tx::Tx,
};
use charms_data::{TxId, UtxoId};
use cml_chain::{
    OrderedHashMap, PolicyId, Rational, Serialize, Value,
    address::Address,
    assets::{AssetBundle, ClampedSub},
    builders::{
        input_builder::{InputBuilderResult, SingleInputBuilder},
        mint_builder::SingleMintBuilder,
        output_builder::TransactionOutputBuilder,
        redeemer_builder::RedeemerWitnessKey,
        tx_builder::{
            ChangeSelectionAlgo, TransactionBuilder, TransactionBuilderConfigBuilder,
            TransactionUnspentOutput, add_change_if_needed,
        },
        withdrawal_builder::SingleWithdrawalBuilder,
        witness_builder::{PartialPlutusWitness, PlutusScriptWitness},
    },
    certs::Credential,
    crypto::ScriptHash,
    fees::LinearFee,
    min_ada::min_ada_required,
    plutus::{CostModels, ExUnitPrices, ExUnits, PlutusData, PlutusV3Script, RedeemerTag},
    transaction::{
        ConwayFormatTxOut, DatumOption, Transaction, TransactionInput, TransactionOutput,
    },
};
use cml_core::serialization::RawBytesEncoding;
use hex_literal::hex;
use ic_agent::Agent;
use serde::{Deserialize, Serialize as SerdeSerialize};
use std::collections::BTreeMap;

fn tx_inputs(
    tx_b: &mut TransactionBuilder,
    ins: &[UtxoId],
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> anyhow::Result<()> {
    for utxo_id in ins {
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

fn tx_outputs(
    tx_b: &mut TransactionBuilder,
    spell: &NormalizedSpell,
) -> anyhow::Result<BTreeMap<PolicyId, PlutusV3Script>> {
    let outs = &spell.tx.outs;
    let coin_outs = spell.tx.coins.as_ref().expect("spell coins are expected");

    let mut scripts = BTreeMap::new();

    for (output, coin) in outs.iter().zip(coin_outs.iter()) {
        let address = Address::from_raw_bytes(&coin.dest)
            .map_err(|e| anyhow!("Failed to convert address: {}", e))?;
        let amount = coin.amount;
        let (multiasset, more_scripts) = multi_asset(&charms(spell, output))?;

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

const V10_NFT_TX_HASH: [u8; 32] =
    hex!("dbc3c04cc77036130183a33e6dad60951c679b004f83a167f7ee285a1a20759d");
const V10_NFT_OUTPUT_INDEX: u64 = 0;

const SCROLLS_V10_SCRIPT_HASH: [u8; 28] =
    hex!("944b39378927530026312d267179720519d203f7bc5a6730411fb9ef");

const SCROLLS_V10_CANISTER_ID: &str = "tty7k-waaaa-aaaak-qvngq-cai";

/// Call ICP canister to sign the transaction
async fn call_scrolls_sign(tx: &Transaction) -> anyhow::Result<Transaction> {
    // Create ICP agent
    let agent = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .context("Failed to create ICP agent")?;

    // Encode final transaction to hex CBOR
    let tx_cbor = tx.to_cbor_bytes();
    let tx_hex = hex::encode(&tx_cbor);

    // Prepare Candid arguments
    let canister_id =
        Principal::from_text(SCROLLS_V10_CANISTER_ID).context("Failed to parse canister ID")?;

    let args = Encode!(&tx_hex).context("Failed to encode Candid arguments")?;

    // Call the canister
    let response = agent
        .update(&canister_id, "sign")
        .with_arg(args)
        .call_and_wait()
        .await
        .context("Failed to call ICP canister sign method")?;

    // Decode response as byte array
    let signed_tx_hex = Decode!(&response, anyhow::Result<String, String>)
        .context("Failed to decode signature from canister response")?
        .map_err(|e| anyhow!("Canister returned error: {}", e))?;

    Ok(CardanoTx::from_hex(&signed_tx_hex)?.0)
}

/// Build a transaction only dealing with Charms tokens
pub fn from_spell(
    spell: &NormalizedSpell,
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
    let (mut tx_b, tx_b_c) = transaction_builder();

    tx_inputs(
        &mut tx_b,
        spell.tx.ins.as_ref().expect("tx ins are expected"),
        prev_txs_by_id,
    )?;

    let scripts = tx_outputs(&mut tx_b, spell)?;
    let scripts_count = scripts.len() as u64;

    add_mint(&mut tx_b, scripts, spell.version)?;

    let funding_input = input_builder_result(change_address, funding_utxo, funding_utxo_value)?;
    let collateral_input = input_builder_result(change_address, collateral_utxo, 10_000_000)?;
    tx_b.add_input(funding_input)?;

    add_spell_data(&mut tx_b, spell_data, change_address, &tx_b_c)?;

    tx_b.add_collateral(collateral_input)?;

    // Add reference input
    let ref_tx_hash = cml_chain::crypto::TransactionHash::from_raw_bytes(&V10_NFT_TX_HASH)
        .expect("valid reference input tx hash");
    let ref_input = TransactionInput::new(ref_tx_hash, V10_NFT_OUTPUT_INDEX);
    // Create a dummy output for the reference input (actual output details don't matter for
    // reference inputs)
    let ref_output = TransactionOutput::ConwayFormatTxOut(ConwayFormatTxOut::new(
        change_address.clone(),
        0u64.into(),
    ));
    let ref_utxo = TransactionUnspentOutput::new(ref_input, ref_output);
    tx_b.add_reference_input(ref_utxo);

    // Add 0 ADA withdrawal from script
    let script_hash =
        ScriptHash::from_raw_bytes(&SCROLLS_V10_SCRIPT_HASH).expect("valid hex script hash");
    let network_id = change_address
        .network_id()
        .map_err(|e| anyhow!("Failed to get network_id: {}", e))?;
    let stake_credential = Credential::new_script(script_hash);
    let reward_address = cml_chain::address::RewardAddress::new(network_id, stake_credential);
    let withdrawal_builder = SingleWithdrawalBuilder::new(reward_address, 0u64.into());

    // Use dummy 64-byte signature as redeemer (will be replaced with real signature later)
    let dummy_signature = vec![0u8; 64];
    let withdraw_redeemer = PlutusData::new_bytes(dummy_signature);
    let psw = PlutusScriptWitness::Ref(script_hash);
    let ppw = PartialPlutusWitness::new(psw, withdraw_redeemer);

    tx_b.add_withdrawal(withdrawal_builder.plutus_script(ppw, vec![].into())?);

    let input_total = tx_b.get_total_input()?;
    let output_total = tx_b.get_total_output()?;

    for i in 0..scripts_count {
        tx_b.set_exunits(
            RedeemerWitnessKey::new(RedeemerTag::Mint, i as u64),
            ExUnits::new(14000000, 10000000000),
        );
    }

    // Set execution units for withdrawal redeemer
    tx_b.set_exunits(
        RedeemerWitnessKey::new(RedeemerTag::Reward, 0),
        ExUnits::new(14000000, 10000000000),
    );

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
    tx_b_c: &ProtocolParams,
) -> anyhow::Result<()> {
    let mut spell_data_output = TransactionOutputBuilder::new()
        .with_address(change_address.clone())
        .with_data(DatumOption::new_datum(PlutusData::new_bytes(
            spell_data.to_vec(),
        )))
        .next()?
        .with_value(0)
        .build()?;
    let ada_value = min_ada_required(&spell_data_output.output, tx_b_c.utxo_cost_per_byte)?;
    spell_data_output.output.set_amount(ada_value.into());

    tx_b.add_output(spell_data_output)?;
    Ok(())
}

#[derive(Debug, Deserialize, SerdeSerialize)]
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

fn transaction_builder() -> (TransactionBuilder, ProtocolParams) {
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
    (
        TransactionBuilder::new(transaction_builder_config.clone()),
        protocol_params,
    )
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
    protocol_version: u32,
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

    // Create protocol version NFT asset_name as redeemer
    // Format: NFT_LABEL (000de140) + "v<protocol_version>" as bytes
    const NFT_LABEL: &[u8] = &[0x00, 0x0d, 0xe1, 0x40];
    let version_string = format!("v{}", protocol_version);
    let mut redeemer_bytes = NFT_LABEL.to_vec();
    redeemer_bytes.extend_from_slice(version_string.as_bytes());
    let redeemer = PlutusData::new_bytes(redeemer_bytes);

    for (policy_id, assets) in mint.iter() {
        let mint_b = SingleMintBuilder::new(assets.clone());
        let script = scripts[policy_id].clone(); // scripts MUST have all token policies at this point
        let psw = PlutusScriptWitness::Script(script.into());
        let ppw = PartialPlutusWitness::new(psw, redeemer.clone());
        tx_b.add_mint(mint_b.plutus_script(ppw, vec![].into()))?;
    }

    Ok(())
}

fn check_asset_amounts(assets: &AssetBundle<u64>) -> anyhow::Result<()> {
    const ASSET_AMOUNT_BOUND: u64 = 1u64 << 63;
    for (_, assets) in assets.iter() {
        for (_, amount) in assets.iter() {
            ensure!(*amount < ASSET_AMOUNT_BOUND, "asset amount exceeds bound");
        }
    }
    Ok(())
}

pub async fn make_transactions(
    spell: &NormalizedSpell,
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

    // Get the real Schnorr signature from ICP canister
    let tx = call_scrolls_sign(&tx).await?;

    Ok(vec![tx]
        .into_iter()
        .map(|tx| Tx::Cardano(CardanoTx(tx)))
        .collect())
}

fn combine(_base_tx: Transaction, _tx: Transaction) -> Transaction {
    todo!()
}
