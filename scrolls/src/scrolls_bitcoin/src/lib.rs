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
    SignWithSchnorrArgs, VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId, VetKDPublicKeyArgs,
    ecdsa_public_key, raw_rand, sign_with_ecdsa, sign_with_schnorr, vetkd_derive_key,
    vetkd_public_key,
};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
    sync::{LazyLock, OnceLock},
    time::Duration,
};

const SCROLLS: &'static [u8; 7] = b"scrolls";
const SIGN: &'static [u8; 4] = b"sign";

/// Fixed input/context/domain separator passed to `vetkd_derive_key` when
/// bootstrapping the canister-specific secret prefix. Changing any of these
/// constants would derive a different prefix and orphan every previously
/// created address.
const VETKD_SECRET_PREFIX_INPUT: &[u8] = b"scrolls_bitcoin/derivation_prefix/v1";
const VETKD_SECRET_PREFIX_CONTEXT: &[u8] = b"scrolls_bitcoin/derivation_prefix";
const VETKD_SECRET_PREFIX_DOMAIN_SEP: &str = "scrolls_bitcoin/derivation_prefix";

/// Width of the canister-specific secret prefix kept in `SECRET_PREFIX`.
const SECRET_PREFIX_LEN: usize = 32;

/// Minimum cycles accepted by `deposit_cycles`. Once the canister is blackholed
/// it can never be topped up by its (now non-existent) controllers, so anybody
/// must be able to add cycles to keep it alive — but a minimum keeps the
/// endpoint from being spammed with dust.
const MIN_DEPOSIT_CYCLES: u128 = 1_000_000_000_000;

/// Canister ID of the `scrolls_bitcoin` canister for the Charms v14.
const V14_SCROLLS_BITCOIN_CANISTER_ID: &str = "lmbwh-3qaaa-aaaak-qunha-cai";

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

// In-memory cache of the canister-specific secret prefix derived via vetKD.
// Populated once per canister boot by the timer scheduled in `do_init`. The
// prefix is fully reproducible from `(canister_id, input, context)` via
// vetKD, so it's re-derived rather than persisted across upgrades.
// Write-once semantics, so `OnceLock` matches the use exactly.
static SECRET_PREFIX: OnceLock<[u8; SECRET_PREFIX_LEN]> = OnceLock::new();

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

    // Bootstrap the secret prefix asynchronously on a timer that fires as
    // soon as the canister becomes idle after init/post_upgrade. Lifecycle
    // hooks themselves cannot run inter-canister calls, but they can
    // schedule timers that do. The prefix is re-derived via vetKD on every
    // boot — it's deterministic per (canister_id, input, context), so we
    // intentionally don't persist it.
    schedule_secret_prefix_bootstrap(Duration::ZERO);
}

/// Schedule one attempt at `ensure_secret_prefix` after `delay`. On failure,
/// reschedule with exponential backoff (1s, 2s, 4s, …, capped at one hour)
/// until it succeeds. On success the chain stops because the cache
/// short-circuit at the top of `ensure_secret_prefix` makes any subsequent
/// invocation a no-op (and nothing else schedules a retry).
fn schedule_secret_prefix_bootstrap(delay: Duration) {
    ic_cdk_timers::set_timer(delay, async move {
        if let Err(e) = ensure_secret_prefix().await {
            let next = next_bootstrap_delay(delay);
            ic_cdk::println!(
                "scrolls_bitcoin: ensure_secret_prefix failed ({}); retrying in {}s",
                e,
                next.as_secs()
            );
            schedule_secret_prefix_bootstrap(next);
        }
    });
}

fn next_bootstrap_delay(prev: Duration) -> Duration {
    const FIRST_RETRY: Duration = Duration::from_secs(1);
    const MAX_RETRY: Duration = Duration::from_secs(3600);
    let next = if prev.is_zero() {
        FIRST_RETRY
    } else {
        prev.saturating_mul(2)
    };
    next.min(MAX_RETRY)
}

fn vetkd_key_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "key_1".to_string(),
    }
}

/// Populate `SECRET_PREFIX` (idempotent). Called by the timer scheduled in
/// [`do_init`] and retried with exponential backoff on failure until it
/// succeeds.
///
/// The decrypted vetKey returned by vetKD is the canonical threshold-derived
/// key for `(canister_id, input, context)` — it does **not** depend on the
/// transport keypair, which only wraps it in transit. So an ephemeral random
/// transport keypair is fine; decryption always recovers the same vetKey,
/// and the resulting prefix is reproducible by this canister on every boot
/// as long as its identity survives. No need to persist it.
async fn ensure_secret_prefix() -> anyhow::Result<()> {
    if SECRET_PREFIX.get().is_some() {
        return Ok(());
    }

    let seed = raw_rand()
        .await
        .map_err(|e| anyhow!("System error: raw_rand failed: {}", e))?;
    let tsk = TransportSecretKey::from_seed(seed)
        .map_err(|e| anyhow!("System error: building transport secret key: {}", e))?;

    let derive_result = vetkd_derive_key(&VetKDDeriveKeyArgs {
        input: VETKD_SECRET_PREFIX_INPUT.to_vec(),
        context: VETKD_SECRET_PREFIX_CONTEXT.to_vec(),
        transport_public_key: tsk.public_key(),
        key_id: vetkd_key_id(),
    })
    .await
    .map_err(|e| anyhow!("System error: vetkd_derive_key failed: {}", e))?;

    let pk_result = vetkd_public_key(&VetKDPublicKeyArgs {
        canister_id: None,
        context: VETKD_SECRET_PREFIX_CONTEXT.to_vec(),
        key_id: vetkd_key_id(),
    })
    .await
    .map_err(|e| anyhow!("System error: vetkd_public_key failed: {}", e))?;
    let derived_pk = DerivedPublicKey::deserialize(&pk_result.public_key)
        .map_err(|e| anyhow!("System error: parsing derived public key: {:?}", e))?;

    let encrypted = EncryptedVetKey::deserialize(&derive_result.encrypted_key)
        .map_err(|e| anyhow!("System error: parsing encrypted vetKey: {}", e))?;
    let vetkey = encrypted
        .decrypt_and_verify(&tsk, &derived_pk, VETKD_SECRET_PREFIX_INPUT)
        .map_err(|e| anyhow!("System error: decrypting vetKey: {}", e))?;

    let bytes = vetkey.derive_symmetric_key(VETKD_SECRET_PREFIX_DOMAIN_SEP, SECRET_PREFIX_LEN);
    let prefix: [u8; SECRET_PREFIX_LEN] = bytes
        .as_slice()
        .try_into()
        .context("System error: vetKey-derived symmetric key has unexpected length")?;

    let _ = SECRET_PREFIX.set(prefix);
    Ok(())
}

/// Fail-fast check for public entry points that need the secret prefix.
/// Returns an error if the one-time init timer has not finished yet, so
/// callers see a clear "try again shortly" message instead of a trap deep
/// inside `derivation_path_for_output`.
fn require_secret_prefix() -> anyhow::Result<()> {
    ensure!(
        SECRET_PREFIX.get().is_some(),
        "Service unavailable: secret prefix not initialized yet, retry shortly"
    );
    Ok(())
}

/// Read the cached secret prefix. Traps if [`require_secret_prefix`] was
/// not checked first.
fn cached_secret_prefix() -> [u8; SECRET_PREFIX_LEN] {
    *SECRET_PREFIX
        .get()
        .unwrap_or_else(|| ic_cdk::trap("System error: secret prefix not initialized"))
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

    let spell = committed_normalized_spell(&SPELL_VK, &tx, mock).map_err(|e| {
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

/// Result of [`addresses`]: the map from output index to its derived P2WPKH
/// `scriptPubKey` (hex-encoded raw script bytes), plus a BIP-340 Schnorr
/// signature over the CBOR-serialized map produced by the canister's chain
/// key under derivation path `[b"sign"]`. The signature is hex-encoded.
///
/// The `scriptPubKey` is what goes directly into a Bitcoin output's
/// `script_pubkey` field; it is the same byte string that ends up in
/// `spell.tx.coins[i].dest`. Unlike an address, it is network-independent —
/// P2WPKH scripts have identical bytes on `main` and `testnet4`.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct Addresses {
    pub script_pubkeys: BTreeMap<u32, String>,
    pub signature: String,
}

#[ic_cdk::update]
/// Returns the Scroll-controlled P2WPKH `scriptPubKey`s (hex-encoded) for the
/// given derivation anchor, together with a BIP-340 Schnorr signature over the
/// `(output_index -> scriptPubKey)` map produced by the canister's chain key
/// under derivation path `[b"sign"]`.
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
/// `out_is` is a list of output indexes (within the creating transaction) for
/// which `scriptPubKey`s should be generated. At most 256 indexes are accepted
/// per call.
///
/// No `network` argument is taken because a P2WPKH `scriptPubKey` is just
/// `OP_0 <20-byte-pubkey-hash>` — the same bytes on every Bitcoin network.
pub async fn addresses(tx_in_0: String, out_is: Vec<u32>) -> Result<Addresses, String> {
    addresses_impl(tx_in_0, out_is)
        .await
        .map_err(|e| e.to_string())
}

async fn addresses_impl(tx_in_0: String, out_is: Vec<u32>) -> anyhow::Result<Addresses> {
    ensure!(
        out_is.len() <= 256,
        "Input error: too many output indexes requested (max: 256)"
    );

    require_secret_prefix()?;

    let tx_in_0: UtxoId = tx_in_0
        .parse()
        .map_err(|e| anyhow!("Input error: invalid tx_in_0: {}", e))?;

    let mut script_pubkeys = BTreeMap::new();
    for out_i in out_is {
        let public_key = derive_public_key_for_output(&tx_in_0, out_i).await?;
        let spk = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash());
        script_pubkeys.insert(out_i, hex::encode(spk.as_bytes()));
    }

    let signature = sign_script_pubkeys(&script_pubkeys).await?;

    Ok(Addresses {
        script_pubkeys,
        signature,
    })
}

/// Sign the CBOR serialization of `script_pubkeys` (after SHA-256 hashing) with
/// the canister's BIP-340/secp256k1 Schnorr chain key under derivation path
/// `[b"sign"]`. Returns the hex-encoded signature.
async fn sign_script_pubkeys(script_pubkeys: &BTreeMap<u32, String>) -> anyhow::Result<String> {
    let message_bytes = util::write(script_pubkeys)
        .context("System error: serializing script_pubkeys for signing")?;
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

fn derivation_path_for_output(tx_in_0: &UtxoId, out_i: u32) -> Vec<Vec<u8>> {
    vec![
        cached_secret_prefix().to_vec(),
        SCROLLS.to_vec(),
        tx_in_0.to_bytes().to_vec(),
        out_i.to_le_bytes().to_vec(),
    ]
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
    /// Inputs spending Scrolls v14 UTXOs. When present and non-empty, signing
    /// of these inputs is delegated to the v14 `scrolls_bitcoin` canister
    /// identified by `V14_SCROLLS_BITCOIN_CANISTER_ID` before the remaining
    /// inputs listed in `sign_inputs` are signed locally.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    v14_sign_inputs: Option<Vec<V14SignInput>>,
}

/// One entry of [`SignRequest::v14_sign_inputs`]. Identifies an input that
/// needs to be signed by the v14 `scrolls_bitcoin` canister: `index` is the
/// input's position in the transaction, `nonce` is the v14 derivation nonce.
///
/// Wire-compatible with the v14 canister's `SignInput` (same field names,
/// same `nat64` types).
#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct V14SignInput {
    pub index: u64,
    pub nonce: u64,
}

/// Request body for the v14 canister's `sign` method. Mirrors the v14
/// `SignRequest` record exactly so it can be passed across an
/// inter-canister call.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct V14SignRequest {
    sign_inputs: Vec<V14SignInput>,
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
    require_secret_prefix()?;

    let network = check_network(&network_str)?;
    let SignRequest {
        sign_inputs,
        prev_txs,
        tx_to_sign,
        v14_sign_inputs,
    } = sign_request;

    let bitcoin_tx = parse_bitcoin_tx(&tx_to_sign)?;

    // If any inputs spend Scrolls v14 UTXOs, validate them against the parsed
    // tx (bounds + dedup + no overlap with `sign_inputs`) up front so any
    // malformed request fails before the inter-canister call, then delegate
    // their signing to the v14 `scrolls_bitcoin` canister. The returned hex
    // carries v14 witnesses already populated, so the
    // `check_existing_witnesses` invariant below sees those inputs as
    // already-signed.
    let (bitcoin_tx, tx_to_sign) = match v14_sign_inputs {
        Some(v14_inputs) if !v14_inputs.is_empty() => {
            check_v14_inputs(bitcoin_tx.input.len(), &sign_inputs, &v14_inputs)?;
            let new_hex =
                sign_with_v14_canister(&network_str, tx_to_sign, prev_txs.clone(), v14_inputs)
                    .await?;
            let new_tx = parse_bitcoin_tx(&new_hex)?;
            (new_tx, new_hex)
        }
        _ => (bitcoin_tx, tx_to_sign),
    };

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

/// Parse a hex-encoded Bitcoin transaction and assert it has at least one
/// input. Used twice in [`do_sign`]: once on the caller's `tx_to_sign`, and a
/// second time on the hex returned by the v14 canister after it signs its
/// inputs.
fn parse_bitcoin_tx(tx_hex: &str) -> anyhow::Result<Transaction> {
    let tx: Tx = BitcoinTx::from_hex(tx_hex)
        .map_err(|e| anyhow!("Input error: parsing tx: {}", e))?
        .into();
    let Tx::Bitcoin(BitcoinTx::Simple(bitcoin_tx)) = tx else {
        unreachable!()
    };
    // Prevents underflow in signable_inputs and gives a clear error early.
    ensure!(
        !bitcoin_tx.input.is_empty(),
        "Input error: transaction must have at least one input"
    );
    Ok(bitcoin_tx)
}

/// Validate `v14_sign_inputs` before any inter-canister call: each index must
/// fit in the transaction's input range, indices must be unique within
/// `v14_sign_inputs`, and none may also appear in `sign_inputs`. Catching all
/// three locally surfaces clear errors instead of opaque failures from the
/// v14 canister or a confusing "already has a signature" trip in
/// [`check_existing_witnesses`] after v14 has signed.
fn check_v14_inputs(
    input_count: usize,
    sign_inputs: &[u32],
    v14_sign_inputs: &[V14SignInput],
) -> anyhow::Result<()> {
    let local: HashSet<u64> = sign_inputs.iter().map(|&i| i as u64).collect();
    let mut seen: HashSet<u64> = HashSet::new();
    for v14_input in v14_sign_inputs {
        ensure!(
            v14_input.index < input_count as u64,
            "Input error: v14 input_index {} is out of range [0, {})",
            v14_input.index,
            input_count
        );
        ensure!(
            !local.contains(&v14_input.index),
            "Input error: input_index {} appears in both sign_inputs and v14_sign_inputs",
            v14_input.index
        );
        ensure!(
            seen.insert(v14_input.index),
            "Input error: duplicate v14 input_index: {}",
            v14_input.index
        );
    }
    Ok(())
}

/// Delegate signing of `v14_sign_inputs` to the v14 `scrolls_bitcoin` canister.
/// Returns the hex-encoded transaction with v14 input witnesses populated;
/// inputs not listed in `v14_sign_inputs` come back untouched and are signed
/// locally afterwards.
async fn sign_with_v14_canister(
    network_str: &str,
    tx_to_sign: String,
    prev_txs: Vec<String>,
    v14_sign_inputs: Vec<V14SignInput>,
) -> anyhow::Result<String> {
    let principal = Principal::from_text(V14_SCROLLS_BITCOIN_CANISTER_ID)
        .context("System error: parsing V14_SCROLLS_BITCOIN_CANISTER_ID")?;
    let req = V14SignRequest {
        sign_inputs: v14_sign_inputs,
        prev_txs,
        tx_to_sign,
    };
    let response = Call::unbounded_wait(principal, "sign")
        .with_args(&(network_str.to_string(), req))
        .await
        .map_err(|e| {
            anyhow!(
                "System error: inter-canister call to v14 sign failed: {}",
                e
            )
        })?;
    let (inner,): (Result<String, String>,) = response
        .candid_tuple()
        .map_err(|e| anyhow!("System error: decoding v14 sign response: {}", e))?;
    match inner {
        Ok(signed_hex) => Ok(signed_hex),
        Err(e) => bail!("Input error: v14 sign failed: {}", e),
    }
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
    sign_tx_sighash_with_path(derivation_path_for_output(tx_in_0, out_i), tx_sighash).await
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
    derive_public_key_with_path(derivation_path_for_output(tx_in_0, out_i)).await
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
