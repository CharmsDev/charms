use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::{
    Address, CompressedPublicKey, EcdsaSighashType, Network, ScriptBuf, SegwitV0Sighash,
    Transaction, Txid,
    consensus::encode::{deserialize_hex, serialize_hex},
    ecdsa::Signature,
    hashes::Hash,
    secp256k1,
    sighash::SighashCache,
};
use candid::{CandidType, Principal};
use charms_data::util;
use charms_lib::{
    CURRENT_VERSION, SPELL_VK,
    bitcoin_tx::BitcoinTx,
    extract_and_verify_spell,
    tx::{Tx, UnsupportedSpellVersion, committed_normalized_spell},
};
use getrandom::register_custom_getrandom;
use ic_cdk::{
    call::Call,
    management_canister::{
        EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, SignWithEcdsaArgs, ecdsa_public_key,
        sign_with_ecdsa,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
    string::ToString,
    sync::LazyLock,
};

const SCROLLS: &'static [u8; 7] = b"scrolls";

/// Canister ID of the `scrolls_bitcoin` canister for the *next* major Charms version.
///
/// `verify_spell` delegates verification of spells with versions higher than those
/// supported by this canister's linked `charms-client` to the `verify_spell_delegated`
/// method on that next canister. This allows older `scrolls_bitcoin` canisters to
/// support newer spell versions by forwarding to the dedicated canister for the next
/// major version.
///
/// Each hop appends its own canister ID to the `seen` list passed downstream, so a
/// misconfigured chain (A → B → A, A → B → C → A, etc.) is detected before the
/// forwarding inter-canister call is made.
const NEXT_SCROLLS_BITCOIN_CANISTER_ID: &str = "";

pub type BitcoinAddresses = BTreeMap<String, String>;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub fee_address: BitcoinAddresses,

    pub fee_per_input: u64,
    pub fee_basis_points: u64,
    pub fixed_cost: u64,
}

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let config_bytes = include_bytes!("../config.yaml");
    let config: Config = serde_yaml::from_slice(config_bytes).unwrap();
    config
});

#[ic_cdk::init]
fn init() {
    do_init();
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    do_init();
}

fn do_init() {
    for network in vec!["main", "testnet4"] {
        let address = &CONFIG.fee_address[network];
        let network = bitcoin::Network::from_core_arg(network).unwrap();
        let address = Address::from_str(address)
            .unwrap()
            .require_network(network)
            .unwrap();
        let _ = address.witness_program().unwrap();
    }
}

#[ic_cdk::query]
pub fn config() -> Config {
    CONFIG.clone()
}

/// Verify that a Bitcoin transaction carries a correct spell.
///
/// Returns the extracted `NormalizedSpell` (as hex-encoded CBOR) on success.
/// Returns an error string on failure.
///
/// For higher spell versions (not supported by this canister's `charms-client`),
/// delegates to the `verify_spell_delegated` method of the canister specified by
/// `NEXT_SCROLLS_BITCOIN_CANISTER_ID`, threading the spell version and a list of
/// already-visited canister IDs to prevent multi-hop delegation cycles.
///
/// The `mock` parameter controls whether mock spells are accepted:
/// - `mock = true`: accepts mock spells (for testing)
/// - `mock = false`: requires real (non-mock) spells
#[ic_cdk::update]
pub async fn verify_spell(tx: String, mock: bool) -> Result<String, String> {
    verify_spell_impl(tx, mock, None, Vec::new())
        .await
        .map_err(|e| e.to_string())
}

/// Inter-canister entry point for delegated `verify_spell` calls.
///
/// `spell_version` is the version learned from a previous hop. If it exceeds
/// this canister's `CURRENT_VERSION`, local verification is skipped and the
/// request is forwarded directly to the next canister.
///
/// `seen` is the list of canister IDs already in the delegation chain (the
/// initiator plus every intermediate hop). On an `UnsupportedSpellVersion`
/// error, this canister refuses to forward to `NEXT_SCROLLS_BITCOIN_CANISTER_ID`
/// if that next ID equals this canister's own ID (A → A) or already appears
/// in `seen` (A → B → ... → A). After the checks pass, this canister appends
/// its own ID to `seen` before calling the next hop.
#[ic_cdk::update]
pub async fn verify_spell_delegated(
    tx: String,
    mock: bool,
    spell_version: u32,
    seen: Vec<String>,
) -> Result<String, String> {
    verify_spell_impl(tx, mock, Some(spell_version), seen)
        .await
        .map_err(|e| e.to_string())
}

async fn verify_spell_impl(
    tx: String,
    mock: bool,
    spell_version: Option<u32>,
    seen: Vec<String>,
) -> anyhow::Result<String> {
    // If a previous hop already established the version is beyond what we support,
    // skip local verification and forward directly.
    if let Some(v) = spell_version
        && v > CURRENT_VERSION
    {
        return delegate_to_next(tx, mock, v, seen).await;
    }
    match verify_spell_locally(&tx, mock) {
        Ok(hex) => Ok(hex),
        Err(e) => match e.downcast_ref::<UnsupportedSpellVersion>() {
            Some(&UnsupportedSpellVersion(v)) => delegate_to_next(tx, mock, v, seen).await,
            None => Err(e),
        },
    }
}

fn verify_spell_locally(tx_hex: &str, mock: bool) -> anyhow::Result<String> {
    let tx: Tx = BitcoinTx::from_hex(tx_hex)
        .map_err(|e| anyhow!("Input error: parsing tx: {}", e))?
        .into();

    let spell = committed_normalized_spell(SPELL_VK, &tx, mock).map_err(|e| {
        if e.is::<UnsupportedSpellVersion>() {
            e
        } else {
            anyhow!("Input error: extracting and verifying spell: {}", e)
        }
    })?;

    let spell_bytes =
        util::write(&spell).map_err(|e| anyhow!("System error: serializing spell: {}", e))?;
    let spell_hex = hex::encode(spell_bytes);

    Ok(spell_hex)
}

async fn delegate_to_next(
    tx: String,
    mock: bool,
    spell_version: u32,
    mut seen: Vec<String>,
) -> anyhow::Result<String> {
    let next_id = NEXT_SCROLLS_BITCOIN_CANISTER_ID;
    if next_id.is_empty() {
        bail!(
            "Input error: unsupported spell version {} (NEXT_SCROLLS_BITCOIN_CANISTER_ID not set)",
            spell_version
        );
    }

    let self_id = ic_cdk::api::canister_self().to_string();
    if next_id == self_id {
        bail!(
            "Input error: unsupported spell version {} (next canister ID points to self)",
            spell_version
        );
    }
    if seen.iter().any(|id| id == next_id) {
        bail!(
            "Input error: delegation cycle detected (next canister {} already in chain {:?})",
            next_id,
            seen
        );
    }
    seen.push(self_id);

    let principal = Principal::from_text(next_id)
        .context("System error: parsing NEXT_SCROLLS_BITCOIN_CANISTER_ID")?;

    let response = Call::unbounded_wait(principal, "verify_spell_delegated")
        .with_args(&(tx, mock, spell_version, seen))
        .await
        .map_err(|e| anyhow!("System error: inter-canister call failed: {}", e))?;

    let (inner,): (Result<String, String>,) = response
        .candid_tuple()
        .map_err(|e| anyhow!("System error: decoding next canister response: {}", e))?;

    match inner {
        Ok(spell_hex) => Ok(spell_hex),
        Err(e) => bail!("Input error: next canister: {}", e),
    }
}

#[ic_cdk::update]
pub async fn address(network: String, nonce: u64) -> Result<String, String> {
    address_impl(network, nonce)
        .await
        .map_err(|e| e.to_string())
}

async fn address_impl(network: String, nonce: u64) -> anyhow::Result<String> {
    let network = check_network(&network)?;
    let public_key = derive_public_key(nonce).await?;

    let address = bitcoin::Address::p2wpkh(&public_key, network).to_string();
    Ok(address)
}

fn derivation_path(nonce: u64) -> Vec<Vec<u8>> {
    vec![SCROLLS.to_vec(), nonce.to_le_bytes().to_vec()]
}

fn key_id() -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "key_1".to_string(),
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SignInput {
    pub index: usize,
    pub nonce: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SignRequest {
    sign_inputs: Vec<SignInput>,
    prev_txs: Vec<String>,
    tx_to_sign: String,
}

#[ic_cdk::update]
pub async fn sign(network: String, sign_request: SignRequest) -> Result<String, String> {
    do_sign(network, sign_request)
        .await
        .map_err(|e| e.to_string())
}

async fn do_sign(network_str: String, sign_request: SignRequest) -> anyhow::Result<String> {
    let network = check_network(&network_str)?;
    let SignRequest {
        sign_inputs,
        prev_txs,
        tx_to_sign,
    } = sign_request;

    let tx: Tx = BitcoinTx::from_hex(&tx_to_sign)
        .map_err(|e| anyhow!("Input error: parsing tx: {}", e))?
        .into();

    let Tx::Bitcoin(BitcoinTx::Simple(bitcoin_tx)) = tx.clone() else {
        unreachable!()
    };

    // Ensure transaction has at least one input to prevent underflow in signable_inputs calculation
    ensure!(
        !bitcoin_tx.input.is_empty(),
        "Input error: transaction must have at least one input"
    );

    let prev_txs: BTreeMap<Txid, Transaction> = txid_to_tx(&bitcoin_tx, prev_txs)?;
    let spell = extract_and_verify_spell(&tx, true)
        .map_err(|e| anyhow!("Input error: extracting and verifying spell: {}", e))?;
    check_prev_txs_mock(&prev_txs, spell.mock)?;

    check_fee(network, &prev_txs, &bitcoin_tx)?;

    let bitcoin_tx = sign_tx(sign_inputs, prev_txs, bitcoin_tx).await?;

    Ok(serialize_hex(&bitcoin_tx))
}

fn check_network(network: &str) -> anyhow::Result<bitcoin::Network> {
    let bitcoin_network = bitcoin::Network::from_core_arg(&network)
        .map_err(|e| anyhow!("Input error: parsing 'network': {}", e))?;
    let _ = CONFIG
        .fee_address
        .get(network)
        .ok_or_else(|| anyhow!("Input error: unsupported network: {}", network))?;
    Ok(bitcoin_network)
}

fn check_prev_txs_mock(
    prev_txs: &BTreeMap<Txid, Transaction>,
    spell_mock: bool,
) -> anyhow::Result<()> {
    if !spell_mock {
        return Ok(());
    };
    // mock is set to true at this point
    // ensure all spells in prev_txs (where they exist) are mock spells
    for (_, prev_tx) in prev_txs {
        // Try to extract and verify the spell as a mock spell.
        // If the tx has a spell but it's not a mock spell, this will fail.
        // If the tx has no spell, extract_and_verify_spell returns an error, which we ignore.
        let prev_tx = Tx::Bitcoin(BitcoinTx::Simple(prev_tx.clone()));
        if let Ok(_) = extract_and_verify_spell(&prev_tx, false) {
            // The spell verified with mock=false, meaning it's a real spell, not a mock spell
            bail!("Input error: mock=true but prev_tx contains a non-mock spell");
        }
    }
    Ok(())
}

fn check_fee(
    network: Network,
    prev_txs: &BTreeMap<Txid, Transaction>,
    tx: &Transaction,
) -> anyhow::Result<()> {
    let expected_fee_script_pubkey = configured_fee_script_pubkey(network);

    let fee: u64 = tx
        .output
        .iter()
        .filter(|&o| o.script_pubkey == expected_fee_script_pubkey)
        .map(|o| o.value.to_sat())
        .sum();

    let inputs_count = signable_inputs(tx);

    let expected_fee = compute_expected_fee(inputs_count, prev_txs, tx);

    ensure!(fee >= expected_fee, "Input error: insufficient fee");
    Ok(())
}

fn compute_expected_fee(
    inputs_count: usize,
    prev_txs: &BTreeMap<Txid, Transaction>,
    tx: &Transaction,
) -> u64 {
    let input_sats: u64 = tx.input[..]
        .iter()
        .map(|tx_in| {
            let out_point = tx_in.previous_output;
            prev_txs[&out_point.txid].output[out_point.vout as usize]
                .value
                .to_sat()
        })
        .sum();
    // Use saturating arithmetic to prevent overflow
    input_sats
        .saturating_mul(CONFIG.fee_basis_points)
        .saturating_div(10000)
        .saturating_add(CONFIG.fee_per_input.saturating_mul(inputs_count as u64))
        .saturating_add(CONFIG.fixed_cost)
}

fn signable_inputs(tx: &Transaction) -> usize {
    tx.input.len()
}

fn configured_fee_script_pubkey(network: Network) -> ScriptBuf {
    let expected_fee_script_pubkey = Address::from_str(&CONFIG.fee_address[network.to_core_arg()])
        .unwrap()
        .assume_checked()
        .script_pubkey();
    expected_fee_script_pubkey
}

async fn sign_tx(
    sign_inputs: Vec<SignInput>,
    prev_txs: BTreeMap<Txid, Transaction>,
    mut bitcoin_tx: Transaction,
) -> anyhow::Result<Transaction> {
    // Validate input indices: must be unique and within signable range
    let signable_count = signable_inputs(&bitcoin_tx);
    let mut seen_indices: HashSet<usize> = HashSet::new();
    for sign_input in &sign_inputs {
        let idx = sign_input.index;
        ensure!(
            idx < signable_count,
            "Input error: input_index {} is out of signable range [0, {})",
            idx,
            signable_count
        );
        ensure!(
            seen_indices.insert(idx),
            "Input error: duplicate input_index: {}",
            idx
        );
    }

    for sign_input in sign_inputs {
        let input_index = sign_input.index;
        let nonce = sign_input.nonce;

        let public_key = derive_public_key(nonce).await?;

        let out_point = bitcoin_tx
            .input
            .get(input_index)
            .ok_or_else(|| anyhow!("Input error: invalid input_index: {}", input_index))?
            .previous_output;
        let tx_out = prev_txs
            .get(&out_point.txid)
            .ok_or_else(|| anyhow!("Input error: missing prev_tx with txid: {}", out_point.txid))?
            .output
            .get(out_point.vout as usize)
            .ok_or_else(|| {
                anyhow!(
                    "Input error: prev_tx {} missing output with index: {}",
                    out_point.txid,
                    out_point.vout
                )
            })?;
        let script_pubkey = &tx_out.script_pubkey;
        let value = tx_out.value;

        let tx_sighash = SighashCache::new(&bitcoin_tx)
            .p2wpkh_signature_hash(input_index, script_pubkey, value, EcdsaSighashType::All)
            .map_err(|e| anyhow!("System error: computing sighash: {}", e))?;

        let ecdsa_signature = sign_tx_sighash(nonce, &tx_sighash).await?;

        let witness = &mut bitcoin_tx.input[input_index].witness;
        witness.push_ecdsa_signature(&ecdsa_signature);
        witness.push(&public_key.to_bytes());
    }
    Ok(bitcoin_tx)
}

async fn sign_tx_sighash(nonce: u64, tx_sighash: &SegwitV0Sighash) -> anyhow::Result<Signature> {
    let message_hash = tx_sighash.to_byte_array().to_vec();
    let sign_with_ecdsa_arg = SignWithEcdsaArgs {
        message_hash,
        derivation_path: derivation_path(nonce),
        key_id: key_id(),
    };
    let sign_result = sign_with_ecdsa(&sign_with_ecdsa_arg)
        .await
        .context("System error: signing valid tx")?;
    let signature = secp256k1::ecdsa::Signature::from_compact(&sign_result.signature)
        .context("System error: parsing signature")?;
    let ecdsa_signature = Signature {
        signature,
        sighash_type: EcdsaSighashType::All,
    };
    Ok(ecdsa_signature)
}

async fn derive_public_key(nonce: u64) -> anyhow::Result<CompressedPublicKey> {
    let ecdsa_public_key_args = EcdsaPublicKeyArgs {
        canister_id: None,
        derivation_path: derivation_path(nonce),
        key_id: key_id(),
    };
    let ecdsa_public_key_result = ecdsa_public_key(&ecdsa_public_key_args)
        .await
        .map_err(|e| anyhow!("System error: getting ECDSA public key: {}", e))?;
    let public_key = CompressedPublicKey::from_slice(&ecdsa_public_key_result.public_key)
        .map_err(|e| anyhow!("System error: parsing user public key: {}", e))?;
    Ok(public_key)
}

fn txid_to_tx(
    tx: &Transaction,
    prev_txs: Vec<String>,
) -> anyhow::Result<BTreeMap<Txid, Transaction>> {
    let si = signable_inputs(tx);
    ensure!(
        prev_txs.len() <= si,
        "Input error: too many prev_txs (max: {})",
        si
    );

    let prev_txs: BTreeMap<Txid, Transaction> = prev_txs
        .into_iter()
        .map(|tx| {
            let tx: bitcoin::Transaction =
                deserialize_hex(&tx).map_err(|e| anyhow!("Input error: parsing prev_tx: {}", e))?;
            Ok((tx.compute_txid(), tx))
        })
        .collect::<anyhow::Result<_>>()?;
    for tx_in in tx.input[..].iter() {
        ensure!(
            prev_txs.contains_key(&tx_in.previous_output.txid),
            "Input error: missing prev_tx for txid: {}",
            tx_in.previous_output.txid
        );
    }
    Ok(prev_txs)
}

// Enable Candid export
ic_cdk::export_candid!();

register_custom_getrandom!(custom_getrandom);
fn custom_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
