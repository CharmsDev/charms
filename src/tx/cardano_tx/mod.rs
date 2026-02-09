use crate::spell::CharmsFee;
use anyhow::{Context, Error, anyhow, bail};
use candid::{Decode, Encode, Principal};
use charms_client::{NormalizedSpell, cardano_tx::CardanoTx, charms, tx::Tx};
use charms_data::{TxId, util};
use cml_chain::{
    Deserialize as CmlDeserialize, PolicyId as CmlPolicyId, Serialize as CmlSerialize,
    assets::MultiAsset, plutus::PlutusV3Script as CmlPlutusV3Script,
    transaction::Transaction as CmlTransaction,
};
use cml_core::serialization::RawBytesEncoding;
use hex_literal::hex;
use ic_agent::Agent;
use pallas_codec::minicbor;
use pallas_primitives::conway::{
    self, BoundedBytes, ExUnits, MaybeIndefArray, NonEmptyKeyValuePairs, PlutusData, PlutusScript,
    PostAlonzoTransactionOutput, PseudoTransactionOutput, Redeemer, RedeemerTag, Redeemers, Value,
    WitnessSet,
};
use pallas_txbuilder::{BuildConway, Input, Output, ScriptKind, StagingTransaction};
use serde::{Deserialize, Serialize as SerdeSerialize};
use std::collections::BTreeMap;

// Re-export UtxoId from charms_data
pub use charms_data::UtxoId;

// Pallas types for internal use
type PallasPolicyId = pallas_crypto::hash::Hash<28>;
type PallasAssetName = pallas_primitives::conway::Bytes;
type PallasPlutusV3Script = PlutusScript<3>;
type PallasMultiasset = pallas_primitives::conway::Multiasset<u64>;

pub const ONE_ADA: u64 = 1000000;
pub const TWO_ADA: u64 = 2000000;

const V10_NFT_TX_HASH: [u8; 32] =
    hex!("49d1f96be0002bcd0241917142aa6a58344923eda8ed54fb46da4ec5f4e3bff2");
const V10_NFT_OUTPUT_INDEX: u64 = 0;

const SCROLLS_V10_CANISTER_ID: &str = "tty7k-waaaa-aaaak-qvngq-cai";

/// Script hash for the Scrolls withdraw validator (parameterized with the required vkey_hash)
const SCROLLS_WITHDRAW_SCRIPT_HASH: [u8; 28] =
    hex!("29764648940a3b7208bc99a246bc96a69817bea017560972432f076f");

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

fn load_protocol_params() -> ProtocolParams {
    const PROTOCOL_JSON: &[u8] = include_bytes!("./protocol.json");
    serde_json::from_slice(PROTOCOL_JSON).expect("valid protocol.json")
}

/// Call ICP canister to sign the transaction
async fn call_scrolls_sign(tx: &conway::Tx) -> anyhow::Result<conway::Tx> {
    let agent = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .context("Failed to create ICP agent")?;

    let mut tx_cbor = Vec::new();
    minicbor::encode(tx, &mut tx_cbor).expect("CBOR encoding should not fail");
    let tx_hex = hex::encode(&tx_cbor);
    dbg!(&tx_hex);

    let canister_id =
        Principal::from_text(SCROLLS_V10_CANISTER_ID).context("Failed to parse canister ID")?;

    let args = Encode!(&tx_hex).context("Failed to encode Candid arguments")?;

    let response = agent
        .update(&canister_id, "sign")
        .with_arg(args)
        .call_and_wait()
        .await
        .context("Failed to call ICP canister sign method")?;

    let signed_tx_hex = Decode!(&response, anyhow::Result<String, String>)
        .context("Failed to decode signature from canister response")?
        .map_err(|e| anyhow!("Canister returned error: {}", e))?;

    // Parse the signed transaction back to pallas
    let signed_tx_bytes = hex::decode(&signed_tx_hex)?;
    let signed_tx: conway::Tx = minicbor::decode(&signed_tx_bytes)
        .map_err(|e| anyhow!("failed to decode signed tx: {}", e))?;
    Ok(signed_tx)
}

/// Convert pallas Tx to cml-chain Transaction via CBOR
fn pallas_to_cml_tx(pallas_tx: &conway::Tx) -> anyhow::Result<CmlTransaction> {
    let mut cbor_bytes = Vec::new();
    minicbor::encode(pallas_tx, &mut cbor_bytes).expect("CBOR encoding should not fail");
    CmlTransaction::from_cbor_bytes(&cbor_bytes)
        .map_err(|e| anyhow!("failed to decode as cml tx: {:?}", e))
}

/// Convert TxId to pallas transaction hash
fn pallas_tx_hash(tx_id: TxId) -> pallas_crypto::hash::Hash<32> {
    let mut txid_bytes = tx_id.0;
    txid_bytes.reverse(); // Charms use Bitcoin's reverse byte order for txids
    pallas_crypto::hash::Hash::new(txid_bytes)
}

fn txbuilder_input(utxo_id: &UtxoId) -> Input {
    let hash_bytes: [u8; 32] = *pallas_tx_hash(utxo_id.0);
    Input::new(pallas_crypto::hash::Hash::new(hash_bytes), utxo_id.1 as u64)
}

/// Convert cml-chain CardanoTx to pallas Tx via CBOR
fn cml_to_pallas_tx(cardano_tx: &CardanoTx) -> anyhow::Result<conway::Tx> {
    let cbor_bytes = cardano_tx.inner().to_cbor_bytes();
    let pallas_tx: conway::Tx = minicbor::decode(&cbor_bytes)
        .map_err(|e| anyhow!("failed to decode as pallas tx: {}", e))?;
    Ok(pallas_tx)
}

fn get_prev_output(
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
    utxo_id: &UtxoId,
) -> anyhow::Result<conway::TransactionOutput> {
    let tx = prev_txs_by_id
        .get(&utxo_id.0)
        .ok_or_else(|| anyhow!("could not find prev_tx by id {}", utxo_id.0))?;
    let Tx::Cardano(cardano_tx) = tx else {
        bail!("expected CardanoTx, got {:?}", tx);
    };
    let pallas_tx = cml_to_pallas_tx(cardano_tx)?;
    let output = pallas_tx
        .transaction_body
        .outputs
        .get(utxo_id.1 as usize)
        .cloned()
        .ok_or_else(|| anyhow!("could not find output by index {}", utxo_id.1))?;
    Ok(output)
}

fn txbuilder_output(address: &[u8], lovelace: u64, assets: Option<&PallasMultiasset>) -> Output {
    let mut output = Output::new(
        pallas_addresses::Address::from_bytes(address).expect("valid address"),
        lovelace,
    );
    if let Some(ma) = assets {
        for (policy_id, asset_names) in ma.iter() {
            for (asset_name, amount) in asset_names.iter() {
                output = output
                    .add_asset(*policy_id, asset_name.to_vec(), *amount)
                    .expect("valid asset");
            }
        }
    }
    output
}

/// Calculate minimum ADA for an output based on protocol parameters
fn min_ada_for_output(output_size_bytes: usize, utxo_cost_per_byte: u64) -> u64 {
    // Cardano minimum UTXO formula: max(lovelace_per_utxo_byte * (utxo_size + 160), min_utxo)
    // The 160 is the constant overhead
    let size_with_overhead = output_size_bytes as u64 + 160;
    utxo_cost_per_byte * size_with_overhead
}

/// Convert cml-chain MultiAsset to pallas Multiasset
fn cml_to_pallas_multiasset(cml_ma: &MultiAsset) -> PallasMultiasset {
    let pairs: Vec<_> = cml_ma
        .iter()
        .filter_map(|(policy, assets)| {
            let policy_bytes: [u8; 28] = policy
                .to_raw_bytes()
                .try_into()
                .expect("policy id is 28 bytes");
            let pallas_policy = PallasPolicyId::new(policy_bytes);
            let asset_pairs: Vec<_> = assets
                .iter()
                .map(|(name, amount)| {
                    let pallas_name = PallasAssetName::from(name.inner.clone());
                    (pallas_name, *amount)
                })
                .collect();
            NonEmptyKeyValuePairs::from_vec(asset_pairs)
                .map(|assets_kvp| (pallas_policy, assets_kvp))
        })
        .collect();

    NonEmptyKeyValuePairs::from_vec(pairs).unwrap_or_else(|| NonEmptyKeyValuePairs::Def(vec![]))
}

/// Convert cml-chain PlutusV3Script to pallas PlutusScript<3>
fn cml_to_pallas_script(cml_script: &CmlPlutusV3Script) -> PallasPlutusV3Script {
    // cml_script.inner contains the flat-encoded script bytes
    // The Cardano ledger expects scripts in the witness set to be CBOR-wrapped:
    // script_hash = blake2b-224(0x03 || cbor_bytes)
    // where cbor_bytes = CBOR-encode(flat_bytes) as a bytestring
    // to_cbor_bytes() returns the CBOR-wrapped bytes
    PlutusScript(pallas_primitives::conway::Bytes::from(
        cml_script.to_cbor_bytes(),
    ))
}

/// Convert cml-chain PolicyId to pallas Hash<28>
fn cml_to_pallas_policy_id(cml_policy: &CmlPolicyId) -> PallasPolicyId {
    let policy_bytes: [u8; 28] = cml_policy
        .to_raw_bytes()
        .try_into()
        .expect("policy id is 28 bytes");
    PallasPolicyId::new(policy_bytes)
}

/// Get multi-asset and scripts for charms using cml-chain's multi_asset, converting to pallas types
fn pallas_multi_asset(
    charms: &charms_data::Charms,
    beamed_out: bool,
) -> anyhow::Result<(
    PallasMultiasset,
    BTreeMap<PallasPolicyId, PallasPlutusV3Script>,
)> {
    let (cml_ma, cml_scripts) = charms_client::cardano_tx::multi_asset(charms, beamed_out)?;

    let pallas_ma = cml_to_pallas_multiasset(&cml_ma);

    let pallas_scripts: BTreeMap<PallasPolicyId, PallasPlutusV3Script> = cml_scripts
        .into_iter()
        .map(|(policy, script)| {
            let pallas_policy = cml_to_pallas_policy_id(&policy);
            let pallas_script = cml_to_pallas_script(&script);
            (pallas_policy, pallas_script)
        })
        .collect();

    Ok((pallas_ma, pallas_scripts))
}

/// Computes the permutation mapping original spell input order to Cardano's sorted order.
/// Returns a vector where `permutation[i]` = position of original spell input `i` in sorted tx.
fn compute_input_permutation(spell_ins: &[UtxoId]) -> Vec<u32> {
    // Create (original_index, utxo_id) pairs and sort by Cardano's canonical order
    let mut indexed: Vec<(usize, &UtxoId)> = spell_ins.iter().enumerate().collect();
    indexed.sort_by_key(|(_, utxo)| {
        // Cardano uses big-endian tx hash, Charms uses little-endian (Bitcoin style)
        let mut tx_hash = utxo.0.0;
        tx_hash.reverse();
        (tx_hash, utxo.1)
    });

    // Build permutation mapping original index to sorted position
    let mut permutation = vec![0u32; spell_ins.len()];
    for (sorted_pos, (original_idx, _)) in indexed.iter().enumerate() {
        permutation[*original_idx] = sorted_pos as u32;
    }
    permutation
}

/// Build a transaction using pallas
pub fn from_spell(
    spell: &NormalizedSpell,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
    change_address: &[u8],
    spell_data: &[u8],
    collateral_utxo: Option<UtxoId>,
) -> anyhow::Result<conway::Tx> {
    let protocol_params = load_protocol_params();
    let collateral_utxo = collateral_utxo.ok_or_else(|| anyhow!("collateral_utxo is required"))?;

    let spell_ins = spell.tx.ins.as_ref().expect("tx ins are expected");
    let spell_outs = &spell.tx.outs;
    let coin_outs = spell.tx.coins.as_ref().expect("spell coins are expected");

    // Collect all scripts for minting
    let mut all_scripts: BTreeMap<PallasPolicyId, PallasPlutusV3Script> = BTreeMap::new();

    // Calculate minted/burned assets by comparing inputs and outputs
    let mut input_assets: BTreeMap<PallasPolicyId, BTreeMap<PallasAssetName, u64>> =
        BTreeMap::new();
    let mut output_assets: BTreeMap<PallasPolicyId, BTreeMap<PallasAssetName, u64>> =
        BTreeMap::new();

    // Collect input assets
    for utxo_id in spell_ins {
        let prev_output = get_prev_output(prev_txs_by_id, utxo_id)?;
        if let Some(ma) = get_output_multiasset(&prev_output) {
            for (policy, assets) in ma.iter() {
                for (name, amount) in assets.iter() {
                    *input_assets
                        .entry(*policy)
                        .or_default()
                        .entry(name.clone())
                        .or_default() += u64::from(*amount);
                }
            }
        }
    }

    // Collect output assets and scripts
    for (i, (spell_out, _coin)) in spell_outs.iter().zip(coin_outs.iter()).enumerate() {
        let beamed_out = (spell.tx.beamed_outs)
            .as_ref()
            .is_some_and(|beamed| beamed.contains_key(&(i as u32)));

        let (multiasset, scripts) = pallas_multi_asset(&charms(spell, spell_out), beamed_out)?;
        all_scripts.extend(scripts);
        for (policy, assets) in multiasset.iter() {
            for (name, amount) in assets.iter() {
                *output_assets
                    .entry(*policy)
                    .or_default()
                    .entry(name.clone())
                    .or_default() += *amount;
            }
        }
    }

    // Build the transaction using pallas-txbuilder
    let mut staging_tx = StagingTransaction::new();

    // Add spell inputs
    for utxo_id in spell_ins {
        staging_tx = staging_tx.input(txbuilder_input(utxo_id));
    }

    // Add spell outputs
    for (i, (spell_out, coin)) in spell_outs.iter().zip(coin_outs.iter()).enumerate() {
        let beamed_out = (spell.tx.beamed_outs)
            .as_ref()
            .is_some_and(|beamed| beamed.contains_key(&(i as u32)));

        let (multiasset, _) = pallas_multi_asset(&charms(spell, spell_out), beamed_out)?;
        let output = txbuilder_output(&coin.dest, coin.amount.into(), Some(&multiasset));
        staging_tx = staging_tx.output(output);
    }

    // Add spell data output
    // Wrap spell_data in PlutusData::BoundedBytes and CBOR-encode it
    let spell_datum = PlutusData::BoundedBytes(BoundedBytes::from(spell_data.to_vec()));
    let mut spell_datum_cbor = Vec::new();
    minicbor::encode(&spell_datum, &mut spell_datum_cbor).expect("CBOR encoding should not fail");

    // Calculate min ADA for the spell data output
    // The output size includes: address (57 bytes) + datum + overhead
    // Use a more conservative estimate to ensure we meet minimum requirements
    let spell_output_size = change_address.len() + spell_datum_cbor.len() + 50;
    let spell_data_min_ada =
        min_ada_for_output(spell_output_size, protocol_params.utxo_cost_per_byte);
    // Add 10% buffer to ensure we meet minimum
    let spell_data_min_ada = spell_data_min_ada + spell_data_min_ada / 10;

    let spell_data_output = Output::new(
        pallas_addresses::Address::from_bytes(change_address).expect("valid address"),
        spell_data_min_ada,
    )
    .set_inline_datum(spell_datum_cbor);
    staging_tx = staging_tx.output(spell_data_output);

    // Add collateral input
    staging_tx = staging_tx.collateral_input(txbuilder_input(&collateral_utxo));

    // Add reference input (V10 NFT with script)
    let ref_input = Input::new(
        pallas_crypto::hash::Hash::new(V10_NFT_TX_HASH),
        V10_NFT_OUTPUT_INDEX,
    );
    staging_tx = staging_tx.reference_input(ref_input);

    // Calculate mint (output - input for each asset)
    let mut mint_map: BTreeMap<PallasPolicyId, BTreeMap<PallasAssetName, i64>> = BTreeMap::new();

    // Add positive amounts (minted)
    for (policy, assets) in &output_assets {
        for (name, out_amount) in assets {
            let in_amount = input_assets
                .get(policy)
                .and_then(|a| a.get(name))
                .copied()
                .unwrap_or(0);
            let diff = *out_amount as i64 - in_amount as i64;
            if diff != 0 {
                *mint_map
                    .entry(*policy)
                    .or_default()
                    .entry(name.clone())
                    .or_default() = diff;
            }
        }
    }

    // Add negative amounts (burned)
    for (policy, assets) in &input_assets {
        for (name, in_amount) in assets {
            if !output_assets
                .get(policy)
                .map_or(false, |a| a.contains_key(name))
            {
                let diff = -(*in_amount as i64);
                *mint_map
                    .entry(*policy)
                    .or_default()
                    .entry(name.clone())
                    .or_default() = diff;
            }
        }
    }

    // Add mint assets
    for (policy, assets) in &mint_map {
        for (name, amount) in assets {
            staging_tx = staging_tx
                .mint_asset(*policy, name.to_vec(), *amount)
                .map_err(|e| anyhow!("mint error: {:?}", e))?;
        }
    }

    // Add mint scripts and redeemers (only if there's actual minting/burning)
    if !mint_map.is_empty() {
        // Create redeemer as CBOR-encoded PlutusData::BoundedBytes
        let redeemer_raw = create_mint_redeemer(spell.version);
        let redeemer_plutus_data = PlutusData::BoundedBytes(BoundedBytes::from(redeemer_raw));
        let mut redeemer_cbor = Vec::new();
        minicbor::encode(&redeemer_plutus_data, &mut redeemer_cbor)
            .expect("CBOR encoding should not fail");

        for (policy, script) in &all_scripts {
            // Pass raw script bytes - pallas-txbuilder will hash them with the appropriate tag
            let script_bytes = script.0.to_vec();

            staging_tx = staging_tx
                .script(ScriptKind::PlutusV3, script_bytes)
                .add_mint_redeemer(
                    *policy,
                    redeemer_cbor.clone(),
                    Some(pallas_txbuilder::ExUnits {
                        mem: 250000,
                        steps: 150000000,
                    }),
                );
        }
    }

    // Set network ID from change address
    let network_id = if change_address[0] & 0x0F == 0x01 {
        1u8
    } else {
        0u8
    };
    staging_tx = staging_tx.network_id(network_id);

    // Set language view for PlutusV3 cost model (only if there are scripts)
    if !mint_map.is_empty() {
        if let Some(v3_costs) = protocol_params.cost_models.get("PlutusV3") {
            staging_tx = staging_tx.language_view(ScriptKind::PlutusV3, v3_costs.clone());
        }
    }

    // Set fee (will be adjusted later)
    staging_tx = staging_tx.fee(500000); // Initial estimate

    // Set change address
    staging_tx = staging_tx.change_address(
        pallas_addresses::Address::from_bytes(change_address).expect("valid address"),
    );

    // Require signature by VKey (32-byte public key, hashed to 28-byte key hash)
    // TODO enforce in the Charms main (mint and spend) validator
    let required_vkey: [u8; 32] =
        hex!("30e99359bc028dbf5a369df63744eb2a2e0e99512d8f6bdb0124ef2f5c7cf80a");
    let vkey_hash = pallas_crypto::hash::Hasher::<224>::hash(&required_vkey);
    dbg!(hex::encode(&vkey_hash));
    staging_tx = staging_tx.disclosed_signer(vkey_hash);

    // Build the transaction with pallas-txbuilder
    let built_tx = staging_tx
        .build_conway_raw()
        .map_err(|e| anyhow!("build error: {:?}", e))?;

    // Decode the built transaction bytes back to conway::Tx so we can modify it
    let mut tx: conway::Tx = minicbor::decode(&built_tx.tx_bytes.0)
        .map_err(|e| anyhow!("failed to decode built tx: {}", e))?;

    // Add Scrolls withdraw-0 redeemer for the reference script
    // The Scrolls validator just checks that the required vkey is in extra_signatories
    let scrolls_reward_account = create_reward_account(&SCROLLS_WITHDRAW_SCRIPT_HASH, network_id);
    tx.transaction_body.withdrawals = Some(
        NonEmptyKeyValuePairs::from_vec(vec![(
            scrolls_reward_account,
            0, // withdraw 0 coins
        )])
        .expect("non-empty withdrawals"),
    );

    // Compute input permutation and store in the withdraw redeemer
    let permutation = compute_input_permutation(spell_ins);
    let permutation_bytes = util::write(&permutation)?;
    let withdraw_redeemer_data = PlutusData::BoundedBytes(BoundedBytes::from(permutation_bytes));
    let withdraw_redeemer = Redeemer {
        tag: RedeemerTag::Reward,
        index: 0, // First (and only) withdrawal
        data: withdraw_redeemer_data,
        ex_units: ExUnits {
            mem: 50000,
            steps: 30000000,
        },
    };

    // Add the withdraw redeemer to the existing redeemers
    match &mut tx.transaction_witness_set.redeemer {
        Some(Redeemers::List(MaybeIndefArray::Def(list))) => {
            list.push(withdraw_redeemer);
        }
        Some(Redeemers::List(MaybeIndefArray::Indef(list))) => {
            list.push(withdraw_redeemer);
        }
        None => {
            tx.transaction_witness_set.redeemer =
                Some(Redeemers::List(MaybeIndefArray::Def(vec![
                    withdraw_redeemer,
                ])));
        }
        _ => bail!("Unexpected redeemer format"),
    }

    // Recompute script_data_hash since we added a redeemer
    let new_script_data_hash =
        compute_script_data_hash(&tx.transaction_witness_set, &protocol_params)?;
    tx.transaction_body.script_data_hash = Some(new_script_data_hash);

    // Calculate total input value from spell inputs
    let total_input: u64 = spell_ins
        .iter()
        .map(|id| {
            get_prev_output(prev_txs_by_id, id)
                .map(|o| get_output_coin(&o))
                .unwrap_or(0)
        })
        .sum();

    // Calculate fee
    // The base fee formula is: txFeeFixed + txFeePerByte * tx_size
    // Plus reference script fee which follows a tiered formula based on script size
    // The Scrolls V10 reference script is ~4700 bytes on-chain (the full PlutusV3 script),
    // which results in approximately 70000 lovelace of reference script fees.
    const REF_SCRIPT_FEE_ESTIMATE: u64 = 75000; // Conservative estimate for V10 ref script

    // Signature overhead: payment key vkeywitness (~102 bytes)
    const SIGNATURE_OVERHEAD: u64 = 110;

    // Calculate current tx size
    let tx_size = {
        let mut buf = Vec::new();
        minicbor::encode(&tx, &mut buf).expect("CBOR encoding should not fail");
        buf.len() as u64
    };

    // Base fee for tx body + signature overhead + change output overhead
    let base_fee = protocol_params.tx_fee_fixed
        + (protocol_params.tx_fee_per_byte * (tx_size + SIGNATURE_OVERHEAD + 70));

    // Total fee including reference script
    let fee = base_fee + REF_SCRIPT_FEE_ESTIMATE;

    tx.transaction_body.fee = fee;

    // Calculate outputs total
    let total_output: u64 = tx
        .transaction_body
        .outputs
        .iter()
        .map(|o| get_output_coin(o))
        .sum();

    // Add change output if needed
    if total_input > total_output + fee {
        let change_amount = total_input - total_output - fee;
        let change_output = PseudoTransactionOutput::PostAlonzo(PostAlonzoTransactionOutput {
            address: pallas_primitives::conway::Bytes::from(change_address.to_vec()),
            value: Value::Coin(change_amount),
            datum_option: None,
            script_ref: None,
        });
        tx.transaction_body.outputs.push(change_output);
    }

    Ok(tx)
}

fn get_output_coin(output: &conway::TransactionOutput) -> u64 {
    match output {
        PseudoTransactionOutput::Legacy(legacy) => match &legacy.amount {
            pallas_primitives::alonzo::Value::Coin(c) => *c,
            pallas_primitives::alonzo::Value::Multiasset(c, _) => *c,
        },
        PseudoTransactionOutput::PostAlonzo(post) => match &post.value {
            Value::Coin(c) => *c,
            Value::Multiasset(c, _) => *c,
        },
    }
}

fn get_output_multiasset(
    output: &conway::TransactionOutput,
) -> Option<conway::Multiasset<pallas_primitives::conway::PositiveCoin>> {
    match output {
        PseudoTransactionOutput::Legacy(legacy) => match &legacy.amount {
            pallas_primitives::alonzo::Value::Coin(_) => None,
            pallas_primitives::alonzo::Value::Multiasset(_, ma) => {
                // Convert alonzo to conway format
                let pairs: Vec<_> = ma
                    .iter()
                    .filter_map(|(p, assets)| {
                        let converted: Vec<_> = assets
                            .iter()
                            .filter_map(|(n, a)| {
                                pallas_primitives::conway::PositiveCoin::try_from(*a)
                                    .ok()
                                    .map(|pc| (n.clone(), pc))
                            })
                            .collect();
                        NonEmptyKeyValuePairs::from_vec(converted).map(|kvp| (*p, kvp))
                    })
                    .collect();
                NonEmptyKeyValuePairs::from_vec(pairs)
            }
        },
        PseudoTransactionOutput::PostAlonzo(post) => match &post.value {
            Value::Coin(_) => None,
            Value::Multiasset(_, ma) => Some(ma.clone()),
        },
    }
}

fn create_reward_account(
    script_hash: &[u8; 28],
    network_id: u8,
) -> pallas_primitives::conway::Bytes {
    // Reward address format: header byte (0xF0 for mainnet script, 0xF1 for testnet script) +
    // 28-byte script hash
    let header = if network_id == 1 { 0xF1u8 } else { 0xF0u8 }; // script credential
    let mut account = Vec::with_capacity(29);
    account.push(header);
    account.extend_from_slice(script_hash);
    pallas_primitives::conway::Bytes::from(account)
}

fn create_mint_redeemer(protocol_version: u32) -> Vec<u8> {
    // Format: NFT_LABEL (000de140) + "v<protocol_version>" as bytes
    const NFT_LABEL: &[u8] = &[0x00, 0x0d, 0xe1, 0x40];
    let version_string = format!("v{}", protocol_version);
    let mut redeemer_bytes = NFT_LABEL.to_vec();
    redeemer_bytes.extend_from_slice(version_string.as_bytes());
    redeemer_bytes
}

fn compute_script_data_hash(
    witness_set: &WitnessSet,
    protocol_params: &ProtocolParams,
) -> anyhow::Result<pallas_crypto::hash::Hash<32>> {
    // script_data_hash = hash(redeemers || datums || language_views)
    // Following the pallas-txbuilder ScriptData::hash() implementation

    let mut hash_input = Vec::new();

    // Encode redeemers
    if let Some(ref redeemers) = witness_set.redeemer {
        minicbor::encode(redeemers, &mut hash_input).expect("CBOR encoding should not fail");
    }

    // Encode datums only if present (NOT an empty array when absent)
    if let Some(ref datums) = witness_set.plutus_data {
        let datums_vec: Vec<_> = datums.iter().cloned().collect();
        minicbor::encode(&datums_vec, &mut hash_input).expect("CBOR encoding should not fail");
    }

    // Encode language views (cost models)
    // For PlutusV3 (version 2 in CBOR), format is: { 2: [cost_model_values] }
    if let Some(v3_costs) = protocol_params.cost_models.get("PlutusV3") {
        // Use minicbor Encoder to build the language view CBOR
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.map(1).expect("map encoding");
        encoder.u8(2).expect("key encoding"); // PlutusV3 = 2
        encoder.encode(v3_costs).expect("cost model encoding");
        hash_input.extend_from_slice(encoder.writer());
    }

    Ok(pallas_crypto::hash::Hasher::<256>::hash(&hash_input))
}

pub async fn make_transactions(
    spell: &NormalizedSpell,
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
            let Tx::Cardano(cardano_tx) = tx else {
                bail!("not a Cardano transaction");
            };
            Ok(cardano_tx.inner().clone())
        })
        .transpose()?;

    // Parse bech32 address to bytes
    let change_address_parsed = pallas_addresses::Address::from_bech32(change_address)
        .map_err(|e| anyhow!("invalid bech32 address: {:?}", e))?;
    let change_address_bytes = change_address_parsed.to_vec();

    let tx = from_spell(
        spell,
        prev_txs_by_id,
        &change_address_bytes,
        spell_data,
        collateral_utxo,
    )?;

    let tx = match underlying_tx {
        Some(u_tx) => {
            // Convert cml-chain Transaction to pallas Tx for combining
            let pallas_u_tx = cml_to_pallas_tx(&CardanoTx::Simple(u_tx))?;
            combine(pallas_u_tx, tx)
        }
        None => tx,
    };

    // Get the real Schnorr signature from ICP canister.
    // The canister signs tx_body.hash() BEFORE replacing the redeemer, then replaces
    // the dummy redeemer with the actual signature.
    let signed_tx = call_scrolls_sign(&tx).await?;

    // Convert pallas Tx back to cml-chain Transaction for CardanoTx
    let cml_tx = pallas_to_cml_tx(&signed_tx)?;

    Ok(vec![Tx::Cardano(CardanoTx::Simple(cml_tx))])
}

fn combine(_base_tx: conway::Tx, _tx: conway::Tx) -> conway::Tx {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_params_load() {
        let params = load_protocol_params();
        assert!(params.tx_fee_per_byte > 0);
        assert!(params.utxo_cost_per_byte > 0);
    }

    #[test]
    fn test_analyze_saved_tx() {
        // Load the saved transaction from the test file
        let tx_json = std::fs::read_to_string("tmp/bro/tx.draft.json");
        if tx_json.is_err() {
            eprintln!("Skipping test - no saved transaction found");
            return;
        }
        let tx_json = tx_json.unwrap();

        // Parse JSON to get cborHex
        let parsed: serde_json::Value = serde_json::from_str(&tx_json).unwrap();
        let cbor_hex = parsed["cborHex"].as_str().unwrap();
        let tx_bytes = hex::decode(cbor_hex).unwrap();

        // Parse as pallas Tx
        let tx: conway::Tx = minicbor::decode(&tx_bytes).unwrap();

        eprintln!("\n=== Transaction Analysis ===");
        eprintln!("Inputs: {}", tx.transaction_body.inputs.len());
        eprintln!("Outputs: {}", tx.transaction_body.outputs.len());

        if let Some(ref scripts) = tx.transaction_witness_set.plutus_v3_script {
            eprintln!("\nPlutusV3 scripts: {} scripts", scripts.len());
            for (i, script) in scripts.iter().enumerate() {
                let script_bytes = &script.0;
                eprintln!("  Script {}: {} bytes", i, script_bytes.len());
                eprintln!(
                    "    First 20 bytes: {}",
                    hex::encode(&script_bytes[..20.min(script_bytes.len())])
                );
                if script_bytes.len() >= 3 {
                    eprintln!(
                        "    UPLC Version: {}.{}.{}",
                        script_bytes[0], script_bytes[1], script_bytes[2]
                    );
                }

                // Compute hash
                let hash = {
                    use pallas_crypto::hash::Hasher;
                    let mut data = vec![0x03u8]; // PlutusV3 namespace
                    data.extend_from_slice(script_bytes);
                    Hasher::<224>::hash(&data)
                };
                eprintln!("    Script hash: {}", hex::encode(hash));
            }
        } else {
            eprintln!("\nNo PlutusV3 scripts in witness set");
        }

        if let Some(ref redeemers) = tx.transaction_witness_set.redeemer {
            match redeemers {
                Redeemers::List(list) => {
                    eprintln!("\nRedeemers (List): {} redeemers", list.len());
                    for r in list.iter() {
                        eprintln!("  Tag: {:?}, Index: {}", r.tag, r.index);
                    }
                }
                Redeemers::Map(map) => {
                    eprintln!("\nRedeemers (Map): {} redeemers", map.len());
                }
            }
        }

        // Check CBOR encoding
        eprintln!("\n=== CBOR Encoding Check ===");

        // Re-encode and compare
        let mut re_encoded = Vec::new();
        minicbor::encode(&tx, &mut re_encoded).unwrap();
        eprintln!("Original tx bytes: {}", tx_bytes.len());
        eprintln!("Re-encoded bytes: {}", re_encoded.len());
        eprintln!("Match: {}", tx_bytes == re_encoded);

        if tx_bytes != re_encoded {
            eprintln!("Difference found:");
            for (i, (a, b)) in tx_bytes.iter().zip(re_encoded.iter()).enumerate() {
                if a != b {
                    eprintln!(
                        "  First diff at byte {}: original=0x{:02x}, re-encoded=0x{:02x}",
                        i, a, b
                    );
                    eprintln!(
                        "  Context: original[{}..{}] = {}",
                        i.saturating_sub(5),
                        (i + 10).min(tx_bytes.len()),
                        hex::encode(&tx_bytes[i.saturating_sub(5)..(i + 10).min(tx_bytes.len())])
                    );
                    eprintln!(
                        "  Context: re-encoded[{}..{}] = {}",
                        i.saturating_sub(5),
                        (i + 10).min(re_encoded.len()),
                        hex::encode(
                            &re_encoded[i.saturating_sub(5)..(i + 10).min(re_encoded.len())]
                        )
                    );
                    break;
                }
            }
            if tx_bytes.len() != re_encoded.len() {
                eprintln!("  Length diff: {} vs {}", tx_bytes.len(), re_encoded.len());
            }
        }

        // Encode witness set specifically
        let mut ws_encoded = Vec::new();
        minicbor::encode(&tx.transaction_witness_set, &mut ws_encoded).unwrap();
        eprintln!("\nWitness set CBOR: {} bytes", ws_encoded.len());
        eprintln!(
            "  First 30 bytes: {}",
            hex::encode(&ws_encoded[..30.min(ws_encoded.len())])
        );

        // Check if the script appears correctly in the witness set
        if let Some(ref scripts) = tx.transaction_witness_set.plutus_v3_script {
            // Search for where script bytes appear in the witness set encoding
            let script_bytes = &scripts[0].0;
            let script_start = hex::encode(&script_bytes[..10]);
            let ws_hex = hex::encode(&ws_encoded);
            if let Some(pos) = ws_hex.find(&script_start) {
                eprintln!("\nScript found in witness set at hex position: {}", pos);
                // Check what's before the script bytes
                let before_start = pos.saturating_sub(20);
                eprintln!("  Bytes before script: {}", &ws_hex[before_start..pos]);
            }
        }

        eprintln!("\n=== End Analysis ===\n");
    }

    #[test]
    fn test_script_data_hash_computation() {
        // Load the saved transaction
        let tx_json = std::fs::read_to_string("tmp/tx.draft.json");
        if tx_json.is_err() {
            eprintln!("Skipping test - no saved transaction found");
            return;
        }
        let tx_json = tx_json.unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&tx_json).unwrap();
        let cbor_hex = parsed["cborHex"].as_str().unwrap();
        let tx_bytes = hex::decode(cbor_hex).unwrap();

        let tx: conway::Tx = minicbor::decode(&tx_bytes).unwrap();

        // Get script_data_hash from tx body
        let body_script_data_hash = tx.transaction_body.script_data_hash;
        eprintln!(
            "\nscript_data_hash in tx body: {:?}",
            body_script_data_hash.map(|h| hex::encode(h))
        );

        // Compute script_data_hash from witness set
        let protocol_params = load_protocol_params();
        let computed_hash =
            compute_script_data_hash(&tx.transaction_witness_set, &protocol_params).unwrap();
        eprintln!("Computed script_data_hash: {}", hex::encode(computed_hash));

        // Check if they match
        if let Some(body_hash) = body_script_data_hash {
            if body_hash == computed_hash {
                eprintln!("✓ script_data_hash MATCHES!");
            } else {
                eprintln!("✗ script_data_hash MISMATCH!");
                eprintln!("  Body:     {}", hex::encode(body_hash));
                eprintln!("  Computed: {}", hex::encode(computed_hash));
            }
        }

        // Print redeemer details
        if let Some(ref redeemers) = tx.transaction_witness_set.redeemer {
            eprintln!("\nRedeemer details:");
            match redeemers {
                Redeemers::List(list) => {
                    for (i, r) in list.iter().enumerate() {
                        let mut data_cbor = Vec::new();
                        minicbor::encode(&r.data, &mut data_cbor).unwrap();
                        eprintln!(
                            "  Redeemer {}: tag={:?}, index={}, data_len={}, data_hex={}",
                            i,
                            r.tag,
                            r.index,
                            data_cbor.len(),
                            if data_cbor.len() <= 100 {
                                hex::encode(&data_cbor)
                            } else {
                                format!("{}...", hex::encode(&data_cbor[..50]))
                            }
                        );
                    }
                }
                Redeemers::Map(map) => {
                    eprintln!("  Map format with {} entries", map.len());
                }
            }
        }

        // Compute tx body hash
        let mut body_cbor = Vec::new();
        minicbor::encode(&tx.transaction_body, &mut body_cbor).unwrap();
        let tx_body_hash = pallas_crypto::hash::Hasher::<256>::hash(&body_cbor);
        eprintln!("\nTx body hash (txid): {}", hex::encode(tx_body_hash));

        // Now simulate what the canister saw:
        // Replace the signature with dummy (64 bytes of zeros) and recompute
        let mut tx_with_dummy = tx.clone();
        if let Some(Redeemers::List(ref list)) = tx_with_dummy.transaction_witness_set.redeemer {
            let mut new_redeemers: Vec<Redeemer> = Vec::new();
            for r in list.iter() {
                let mut new_r = r.clone();
                if r.tag == RedeemerTag::Reward {
                    new_r.data = PlutusData::BoundedBytes(BoundedBytes::from(vec![0u8; 64]));
                }
                new_redeemers.push(new_r);
            }
            tx_with_dummy.transaction_witness_set.redeemer =
                Some(Redeemers::List(MaybeIndefArray::Def(new_redeemers)));
        }

        // Compute script_data_hash with dummy redeemer
        let dummy_script_data_hash =
            compute_script_data_hash(&tx_with_dummy.transaction_witness_set, &protocol_params)
                .unwrap();
        eprintln!(
            "\nscript_data_hash with DUMMY redeemer: {}",
            hex::encode(dummy_script_data_hash)
        );

        // Update body with dummy script_data_hash
        tx_with_dummy.transaction_body.script_data_hash = Some(dummy_script_data_hash);

        // Compute tx body hash (what the canister signed)
        let mut dummy_body_cbor = Vec::new();
        minicbor::encode(&tx_with_dummy.transaction_body, &mut dummy_body_cbor).unwrap();
        let dummy_tx_body_hash = pallas_crypto::hash::Hasher::<256>::hash(&dummy_body_cbor);
        eprintln!(
            "Tx body hash with dummy (canister signed this): {}",
            hex::encode(dummy_tx_body_hash)
        );

        eprintln!(
            "\nThe signature verifies over: {}",
            hex::encode(dummy_tx_body_hash)
        );
        eprintln!(
            "But the on-chain script sees:  {}",
            hex::encode(tx_body_hash)
        );
        eprintln!("These are DIFFERENT, so signature verification fails!");
    }
}
