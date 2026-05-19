use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::{
    Address, CompressedPublicKey, EcdsaSighashType, Network, ScriptBuf, SegwitV0Sighash,
    Transaction, TxIn, Txid,
    consensus::encode::{deserialize_hex, serialize},
    ecdsa::Signature,
    hashes::Hash,
    secp256k1,
    sighash::SighashCache,
};
use candid::{CandidType, Principal};
use charms_data::{TxId, UtxoId, util};
use charms_lib::{
    CURRENT_VERSION, NormalizedSpell, SPELL_VK,
    bitcoin_tx::BitcoinTx,
    extract_and_verify_spell,
    tx::{Tx, UnsupportedSpellVersion, committed_normalized_spell},
};
use getrandom::register_custom_getrandom;
use ic_cdk::call::Call;
use ic_cdk_bitcoin_canister::{
    Network as BtcNetwork, SendTransactionRequest, bitcoin_send_transaction,
};
use ic_cdk_management_canister::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, SchnorrAlgorithm, SchnorrKeyId, SignWithEcdsaArgs,
    SignWithSchnorrArgs, ecdsa_public_key, sign_with_ecdsa, sign_with_schnorr,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
    sync::LazyLock,
};

const SCROLLS: &'static [u8; 7] = b"scrolls";
const SIGN: &'static [u8; 4] = b"sign";

/// Minimum cycles accepted by `deposit_cycles`. Once the canister is blackholed
/// it can never be topped up by its (now non-existent) controllers, so anybody
/// must be able to add cycles to keep it alive — but a minimum keeps the
/// endpoint from being spammed with dust.
const MIN_DEPOSIT_CYCLES: u128 = 1_000_000_000_000;

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

/// Current cycle balance of this canister.
///
/// Exposed as a query so anyone can monitor the canister after blackholing —
/// `canister_status` on the management canister is controller-only and is
/// unreachable once the controller list is empty.
#[ic_cdk::query]
pub fn cycles_balance() -> u128 {
    ic_cdk::api::canister_cycle_balance()
}

/// Accept cycles attached to this call (at least `MIN_DEPOSIT_CYCLES`) and
/// return the new balance. If fewer cycles are attached, nothing is accepted
/// and the system refunds the caller automatically.
#[ic_cdk::update]
pub fn deposit_cycles() -> Result<u128, String> {
    let available = ic_cdk::api::msg_cycles_available();
    if available < MIN_DEPOSIT_CYCLES {
        return Err(format!(
            "Input error: insufficient cycles attached: provided {}, minimum {}",
            available, MIN_DEPOSIT_CYCLES
        ));
    }
    let _ = ic_cdk::api::msg_cycles_accept(available);
    Ok(ic_cdk::api::canister_cycle_balance())
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
    let spell = verify_spell_impl(tx, mock, None, Vec::new())
        .await
        .map_err(|e| e.to_string())?;
    spell_to_hex(spell)
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
    let spell = verify_spell_impl(tx, mock, Some(spell_version), seen)
        .await
        .map_err(|e| e.to_string())?;
    spell_to_hex(spell)
}

async fn verify_spell_impl(
    tx: String,
    mock: bool,
    spell_version: Option<u32>,
    seen: Vec<String>,
) -> anyhow::Result<NormalizedSpell> {
    // If a previous hop already established the version is beyond what we support,
    // skip local verification and forward directly.
    if let Some(v) = spell_version
        && v > CURRENT_VERSION
    {
        return decode_delegated_spell(tx, mock, v, seen).await;
    }
    match verify_spell_locally(&tx, mock) {
        Ok(spell) => Ok(spell),
        Err(e) => match e.downcast_ref::<UnsupportedSpellVersion>() {
            Some(&UnsupportedSpellVersion(v)) => decode_delegated_spell(tx, mock, v, seen).await,
            None => Err(e),
        },
    }
}

fn verify_spell_locally(tx_hex: &str, mock: bool) -> anyhow::Result<NormalizedSpell> {
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

    Ok(spell)
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

async fn decode_delegated_spell(
    tx: String,
    mock: bool,
    spell_version: u32,
    seen: Vec<String>,
) -> anyhow::Result<NormalizedSpell> {
    let spell_hex = delegate_to_next(tx, mock, spell_version, seen).await?;
    let spell_bytes = hex::decode(&spell_hex)
        .map_err(|e| anyhow!("System error: decoding spell hex from next canister: {}", e))?;
    let spell: NormalizedSpell = util::read(spell_bytes.as_slice()).map_err(|e| {
        anyhow!(
            "System error: deserializing spell from next canister: {}",
            e
        )
    })?;
    Ok(spell)
}

/// Serialize a `NormalizedSpell` to its hex-encoded CBOR representation.
/// Used by the public `verify_spell*` endpoints to produce their `String` return value.
fn spell_to_hex(spell: NormalizedSpell) -> Result<String, String> {
    let spell_bytes =
        util::write(&spell).map_err(|e| format!("System error: serializing spell: {}", e))?;
    Ok(hex::encode(spell_bytes))
}

/// Result of [`addresses`]: the map from output index to derived P2WPKH address,
/// plus a BIP-340 Schnorr signature over the CBOR-serialized map produced by the
/// canister's chain key under derivation path `[b"sign"]`. The signature is
/// hex-encoded.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct AddressesResult {
    pub addresses: BTreeMap<u32, String>,
    pub signature: String,
}

#[ic_cdk::update]
/// Returns Scroll-controlled P2WPKH addresses for the given network and derivation anchor,
/// together with a BIP-340 Schnorr signature over the address map produced by the canister's
/// chain key under derivation path `[b"sign"]`.
///
/// `tx_in_0` is a string of the form `txid_hex:vout` (or block height for coinbase).
/// It identifies the unique "anchor" used for key derivation:
///
/// * For a normal (non-coinbase) output, this is the outpoint (`{txid}:{vout}`) of the *first
///   input* of the transaction that created the output(s) being addressed.
/// * For an output created by a **coinbase** transaction, use the all-zeros txid (the txid that
///   appears as the first input's `txid` of the coinbase transaction itself) together with the
///   block height (as a decimal integer) in place of the vout. Example:
///   `0000000000000000000000000000000000000000000000000000000000000000:123456`
///
/// `out_is` is a list of output indexes (within the creating transaction)
/// for which addresses should be generated. At most 256 indexes are accepted
/// per call.
pub async fn addresses(
    network: String,
    tx_in_0: String,
    out_is: Vec<u32>,
) -> Result<AddressesResult, String> {
    addresses_impl(network, tx_in_0, out_is)
        .await
        .map_err(|e| e.to_string())
}

async fn addresses_impl(
    network: String,
    tx_in_0: String,
    out_is: Vec<u32>,
) -> anyhow::Result<AddressesResult> {
    ensure!(
        out_is.len() <= 256,
        "Input error: too many output indexes requested (max: 256)"
    );

    let network = check_network(&network)?;
    let tx_in_0: UtxoId = tx_in_0
        .parse()
        .map_err(|e| anyhow!("Input error: invalid tx_in_0: {}", e))?;

    let mut addresses = BTreeMap::new();
    for out_i in out_is {
        let public_key = derive_public_key_for_output(&tx_in_0, out_i).await?;
        let address = bitcoin::Address::p2wpkh(&public_key, network).to_string();
        addresses.insert(out_i, address);
    }

    let signature = sign_addresses(&addresses).await?;

    Ok(AddressesResult {
        addresses,
        signature,
    })
}

/// Sign the CBOR serialization of `addresses` (after SHA-256 hashing) with the
/// canister's BIP-340/secp256k1 Schnorr chain key under derivation path
/// `[b"sign"]`. Returns the hex-encoded signature.
async fn sign_addresses(addresses: &BTreeMap<u32, String>) -> anyhow::Result<String> {
    let message_bytes =
        util::write(addresses).context("System error: serializing addresses for signing")?;
    let message_hash = bitcoin::hashes::sha256::Hash::hash(&message_bytes)
        .to_byte_array()
        .to_vec();
    let args = SignWithSchnorrArgs {
        message: message_hash,
        derivation_path: vec![SIGN.to_vec()],
        key_id: schnorr_sign_key_id(),
        aux: None,
    };
    let result = sign_with_schnorr(&args)
        .await
        .map_err(|e| anyhow!("System error: signing addresses with Schnorr: {}", e))?;
    Ok(hex::encode(&result.signature))
}

fn schnorr_sign_key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340secp256k1,
        name: "key_1".to_string(),
    }
}

fn derivation_path_for_output(tx_in_0: &UtxoId, out_i: u32) -> anyhow::Result<Vec<Vec<u8>>> {
    let tx_in_0_bytes =
        util::write(tx_in_0).context("System error: serializing tx_in_0 for derivation path")?;
    let out_i_bytes =
        util::write(&out_i).context("System error: serializing out_i for derivation path")?;
    Ok(vec![SCROLLS.to_vec(), tx_in_0_bytes, out_i_bytes])
}

fn key_id() -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "key_1".to_string(),
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SignRequest {
    sign_inputs: Vec<u32>,
    prev_txs: Vec<String>,
    tx_to_sign: String,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SignAndSubmitResult {
    pub txid: String,
    pub wtxid: String,
}

#[ic_cdk::update]
pub async fn sign_and_submit(
    network: String,
    sign_request: SignRequest,
) -> Result<SignAndSubmitResult, String> {
    do_sign(network, sign_request)
        .await
        .map_err(|e| e.to_string())
}

async fn do_sign(
    network_str: String,
    sign_request: SignRequest,
) -> anyhow::Result<SignAndSubmitResult> {
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

    check_existing_witnesses(&bitcoin_tx, &sign_inputs)?;

    let prev_txs: BTreeMap<Txid, Transaction> = txid_to_tx(&bitcoin_tx, prev_txs)?;
    let spell = verify_spell_impl(tx_to_sign, true, None, Vec::new())
        .await
        .map_err(|e| anyhow!("Input error: extracting and verifying spell: {}", e))?;
    check_prev_txs_mock(&prev_txs, spell.mock)?;

    check_fee(network, &prev_txs, &bitcoin_tx)?;

    let signed_tx = sign_tx(sign_inputs, &prev_txs, bitcoin_tx).await?;

    submit_tx(network, &signed_tx).await?;

    Ok(SignAndSubmitResult {
        txid: signed_tx.compute_txid().to_string(),
        wtxid: signed_tx.compute_wtxid().to_string(),
    })
}

/// Validate `sign_inputs` and ensure every input that this call is NOT going to
/// sign already carries a signature (witness or `script_sig`). After the call,
/// every input must be spendable, and the only ones we will populate here are
/// those listed in `sign_inputs` — everything else must already be signed by
/// the caller.
///
/// Bounds and duplicate detection happen first so that an out-of-range or
/// repeated `sign_inputs` index produces an accurate error message instead of
/// a misleading "input N has no witness" report.
fn check_existing_witnesses(tx: &Transaction, sign_inputs: &[u32]) -> anyhow::Result<()> {
    let input_count = tx.input.len();
    let mut signing: HashSet<usize> = HashSet::new();
    for &idx in sign_inputs {
        let idx_usize = idx as usize;
        ensure!(
            idx_usize < input_count,
            "Input error: input_index {} is out of range [0, {})",
            idx,
            input_count
        );
        ensure!(
            signing.insert(idx_usize),
            "Input error: duplicate input_index: {}",
            idx
        );
    }
    for (i, input) in tx.input.iter().enumerate() {
        let is_signed = !input.witness.is_empty() || !input.script_sig.is_empty();
        if signing.contains(&i) {
            ensure!(
                !is_signed,
                "Input error: input {} already has a signature but is in sign_inputs",
                i
            );
        } else {
            ensure!(
                is_signed,
                "Input error: input {} has no signature and is not being signed",
                i
            );
        }
    }
    Ok(())
}

async fn submit_tx(network: Network, tx: &Transaction) -> anyhow::Result<()> {
    let btc_network = match network {
        Network::Bitcoin => BtcNetwork::Mainnet,
        Network::Testnet4 => BtcNetwork::Testnet,
        _ => bail!(
            "Input error: unsupported network for submission: {}",
            network
        ),
    };
    let request = SendTransactionRequest {
        transaction: serialize(tx),
        network: btc_network.into(),
    };
    bitcoin_send_transaction(&request)
        .await
        .map_err(|e| anyhow!("System error: bitcoin_send_transaction failed: {}", e))?;
    Ok(())
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

/// Extract the block height from a coinbase input's scriptSig.
/// The caller must pass `&tx.input[0]` of a coinbase transaction (i.e. after checking
/// `tx.is_coinbase()`). Returns `None` if the height could not be parsed.
fn extract_coinbase_height(coinbase_input: &TxIn) -> Option<u32> {
    let push = coinbase_input
        .script_sig
        .instructions_minimal()
        .next()?
        .ok()?;
    let bitcoin::script::Instruction::PushBytes(b) = push else {
        return None;
    };
    let h = bitcoin::script::read_scriptint(b.as_bytes()).ok()?;
    u32::try_from(h).ok()
}

fn configured_fee_script_pubkey(network: Network) -> ScriptBuf {
    let expected_fee_script_pubkey = Address::from_str(&CONFIG.fee_address[network.to_core_arg()])
        .unwrap()
        .assume_checked()
        .script_pubkey();
    expected_fee_script_pubkey
}

async fn sign_tx(
    sign_inputs: Vec<u32>,
    prev_txs: &BTreeMap<Txid, Transaction>,
    mut bitcoin_tx: Transaction,
) -> anyhow::Result<Transaction> {
    for input_index in sign_inputs {
        let input_index_usize = input_index as usize;
        let out_point = bitcoin_tx
            .input
            .get(input_index_usize)
            .ok_or_else(|| anyhow!("Input error: invalid input_index: {}", input_index))?
            .previous_output;

        // The UTXO we are spending was created as output `out_point.vout` in `creating_tx`.
        // Its controlling key was derived from (first input of that creating_tx, output index).
        // For coinbase-created outputs we instead use (coinbase_txid, block_height).
        let creating_tx = prev_txs
            .get(&out_point.txid)
            .ok_or_else(|| anyhow!("Input error: missing prev_tx with txid: {}", out_point.txid))?;

        let first_in = creating_tx.input.first().ok_or_else(|| {
            anyhow!(
                "Input error: prev_tx {} has no inputs; cannot derive address path",
                out_point.txid
            )
        })?;

        let second_field = if creating_tx.is_coinbase() {
            extract_coinbase_height(first_in).ok_or_else(|| {
                anyhow!(
                    "Input error: could not extract block height from coinbase {}",
                    out_point.txid
                )
            })?
        } else {
            first_in.previous_output.vout
        };
        let tx_in_0 = UtxoId(
            TxId(first_in.previous_output.txid.to_byte_array()),
            second_field,
        );
        let out_i = out_point.vout;

        let public_key = derive_public_key_for_output(&tx_in_0, out_i).await?;

        let tx_out = creating_tx.output.get(out_i as usize).ok_or_else(|| {
            anyhow!(
                "Input error: prev_tx {} missing output with index: {}",
                out_point.txid,
                out_i
            )
        })?;

        // Verify that the output actually pays to the key we just derived.
        // This prevents wasting an expensive threshold ECDSA call on malformed/adversarial
        // prev_txs.
        let expected_spk = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash());
        ensure!(
            tx_out.script_pubkey == expected_spk,
            "Input error: output script in prev_tx {} does not match the derived public key",
            out_point.txid
        );

        let tx_sighash = SighashCache::new(&bitcoin_tx)
            .p2wpkh_signature_hash(
                input_index_usize,
                &tx_out.script_pubkey,
                tx_out.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| anyhow!("System error: computing sighash: {}", e))?;

        let ecdsa_signature = sign_tx_sighash_for_output(&tx_in_0, out_i, &tx_sighash).await?;

        let witness = &mut bitcoin_tx.input[input_index_usize].witness;
        witness.push_ecdsa_signature(&ecdsa_signature);
        witness.push(&public_key.to_bytes());
    }
    Ok(bitcoin_tx)
}

async fn sign_tx_sighash_with_path(
    derivation_path: Vec<Vec<u8>>,
    tx_sighash: &SegwitV0Sighash,
) -> anyhow::Result<Signature> {
    let message_hash = tx_sighash.to_byte_array().to_vec();
    let sign_with_ecdsa_arg = SignWithEcdsaArgs {
        message_hash,
        derivation_path,
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

async fn sign_tx_sighash_for_output(
    tx_in_0: &UtxoId,
    out_i: u32,
    tx_sighash: &SegwitV0Sighash,
) -> anyhow::Result<Signature> {
    sign_tx_sighash_with_path(derivation_path_for_output(tx_in_0, out_i)?, tx_sighash).await
}

async fn derive_public_key_with_path(
    derivation_path: Vec<Vec<u8>>,
) -> anyhow::Result<CompressedPublicKey> {
    let ecdsa_public_key_args = EcdsaPublicKeyArgs {
        canister_id: None,
        derivation_path,
        key_id: key_id(),
    };
    let ecdsa_public_key_result = ecdsa_public_key(&ecdsa_public_key_args)
        .await
        .map_err(|e| anyhow!("System error: getting ECDSA public key: {}", e))?;
    let public_key = CompressedPublicKey::from_slice(&ecdsa_public_key_result.public_key)
        .map_err(|e| anyhow!("System error: parsing user public key: {}", e))?;
    Ok(public_key)
}

async fn derive_public_key_for_output(
    tx_in_0: &UtxoId,
    out_i: u32,
) -> anyhow::Result<CompressedPublicKey> {
    derive_public_key_with_path(derivation_path_for_output(tx_in_0, out_i)?).await
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
        let prev_tx = prev_txs.get(&tx_in.previous_output.txid).ok_or_else(|| {
            anyhow!(
                "Input error: missing prev_tx for txid: {}",
                tx_in.previous_output.txid
            )
        })?;
        let vout = tx_in.previous_output.vout as usize;
        ensure!(
            vout < prev_tx.output.len(),
            "Input error: prev_tx for txid: {} missing output with index: {}",
            tx_in.previous_output.txid,
            tx_in.previous_output.vout
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
