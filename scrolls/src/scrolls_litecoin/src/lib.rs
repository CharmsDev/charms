use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::{
    CompressedPublicKey, EcdsaSighashType, ScriptBuf, SegwitV0Sighash, Transaction, TxIn, Txid,
    WPubkeyHash, consensus::encode::deserialize_hex, ecdsa::Signature, hashes::Hash, secp256k1,
    sighash::SighashCache,
};
use candid::{CandidType, Principal};
use charms_data::{TxId, UtxoId, util};
use charms_lib::{
    CURRENT_VERSION, NormalizedSpell, SPELL_VK,
    bitcoin_tx::LitecoinTx,
    extract_and_verify_spell,
    tx::{Tx, UnsupportedSpellVersion, committed_normalized_spell},
};
use getrandom::register_custom_getrandom;
use ic_cdk::call::Call;
use ic_cdk_management_canister::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, HttpHeader, HttpMethod, HttpRequestArgs,
    HttpRequestResult, SchnorrAlgorithm, SchnorrKeyId, SignWithEcdsaArgs, SignWithSchnorrArgs,
    TransformArgs, VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId, VetKDPublicKeyArgs,
    ecdsa_public_key, http_request, raw_rand, sign_with_ecdsa, sign_with_schnorr,
    transform_context_from_query, vetkd_derive_key, vetkd_public_key,
};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{LazyLock, OnceLock},
    time::Duration,
};

const SCROLLS: &[u8; 7] = b"scrolls";
const SIGN: &[u8; 4] = b"sign";

const NETWORK_MAIN: &str = "main";
const NETWORK_TEST: &str = "test";
const HRP_MAIN: &str = "ltc";
const HRP_TEST: &str = "tltc";

/// Domain separator for this canister's vetKD prefix. Distinct from any other
/// scrolls canister so the source does not claim that canister's identity.
const VETKD_SECRET_PREFIX_INPUT: &[u8] = b"scrolls_litecoin/derivation_prefix/v1";
const VETKD_SECRET_PREFIX_CONTEXT: &[u8] = b"scrolls_litecoin/derivation_prefix";
const VETKD_SECRET_PREFIX_DOMAIN_SEP: &str = "scrolls_litecoin/derivation_prefix";

const SECRET_PREFIX_LEN: usize = 32;

/// Minimum cycles accepted by `deposit_cycles`.
const MIN_DEPOSIT_CYCLES: u128 = 1_000_000_000_000;

/// Canister id of a later scrolls_litecoin build. Empty unless the operator
/// sets `NEXT_SCROLLS_LITECOIN_CANISTER_ID` at compile time. Not an init argument.
const NEXT_SCROLLS_LITECOIN_CANISTER_ID: &str =
    match option_env!("NEXT_SCROLLS_LITECOIN_CANISTER_ID") {
        Some(id) => id,
        None => "",
    };

const LITECOINSPACE_MAINNET_BROADCAST_URL: &str = "https://litecoinspace.org/api/tx";
const LITECOINSPACE_TESTNET_BROADCAST_URL: &str = "https://litecoinspace.org/testnet/api/tx";

const MAX_BROADCAST_RESPONSE_BYTES: u64 = 1024;

/// litecoind `sendrawtransaction` code for a transaction already in a block.
const LITECOIND_TX_ALREADY_IN_CHAIN_RPC_CODE: i64 = -27;

pub type LitecoinAddresses = BTreeMap<String, String>;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub fee_address: LitecoinAddresses,
    pub fee_per_input: u64,
    pub fee_basis_points: u64,
    pub fixed_cost: u64,
}

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let config_bytes = include_bytes!("../config.yaml");
    serde_yaml::from_slice(config_bytes).expect("config.yaml")
});

static SECRET_PREFIX: OnceLock<[u8; SECRET_PREFIX_LEN]> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LitecoinNetwork {
    Main,
    Test,
}

impl LitecoinNetwork {
    fn label(self) -> &'static str {
        match self {
            Self::Main => NETWORK_MAIN,
            Self::Test => NETWORK_TEST,
        }
    }

    fn from_label(label: &str) -> anyhow::Result<Self> {
        match label {
            NETWORK_MAIN => Ok(Self::Main),
            NETWORK_TEST => Ok(Self::Test),
            _ => bail!("Input error: unsupported network: {label}"),
        }
    }
}

#[ic_cdk::init]
fn init() {
    do_init();
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    do_init();
}

fn do_init() {
    for (network, address) in &CONFIG.fee_address {
        litecoin_fee_script(network, address)
            .unwrap_or_else(|e| panic!("fee address for {network}: {e}"));
    }
    for network in [NETWORK_MAIN, NETWORK_TEST] {
        assert!(
            CONFIG.fee_address.contains_key(network),
            "fee address for {network} is required"
        );
    }
    schedule_secret_prefix_bootstrap(Duration::ZERO);
}

fn schedule_secret_prefix_bootstrap(delay: Duration) {
    ic_cdk_timers::set_timer(delay, async move {
        if let Err(e) = ensure_secret_prefix().await {
            let next = next_bootstrap_delay(delay);
            ic_cdk::println!(
                "scrolls_litecoin: ensure_secret_prefix failed ({e}); retrying in {}s",
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

async fn ensure_secret_prefix() -> anyhow::Result<()> {
    if SECRET_PREFIX.get().is_some() {
        return Ok(());
    }

    let seed = raw_rand()
        .await
        .map_err(|e| anyhow!("System error: raw_rand failed: {e}"))?;
    let tsk = TransportSecretKey::from_seed(seed)
        .map_err(|e| anyhow!("System error: building transport secret key: {e}"))?;

    let derive_result = vetkd_derive_key(&VetKDDeriveKeyArgs {
        input: VETKD_SECRET_PREFIX_INPUT.to_vec(),
        context: VETKD_SECRET_PREFIX_CONTEXT.to_vec(),
        transport_public_key: tsk.public_key(),
        key_id: vetkd_key_id(),
    })
    .await
    .map_err(|e| anyhow!("System error: vetkd_derive_key failed: {e}"))?;

    let pk_result = vetkd_public_key(&VetKDPublicKeyArgs {
        canister_id: None,
        context: VETKD_SECRET_PREFIX_CONTEXT.to_vec(),
        key_id: vetkd_key_id(),
    })
    .await
    .map_err(|e| anyhow!("System error: vetkd_public_key failed: {e}"))?;
    let derived_pk = DerivedPublicKey::deserialize(&pk_result.public_key)
        .map_err(|e| anyhow!("System error: parsing derived public key: {e:?}"))?;

    let encrypted = EncryptedVetKey::deserialize(&derive_result.encrypted_key)
        .map_err(|e| anyhow!("System error: parsing encrypted vetKey: {e}"))?;
    let vetkey = encrypted
        .decrypt_and_verify(&tsk, &derived_pk, VETKD_SECRET_PREFIX_INPUT)
        .map_err(|e| anyhow!("System error: decrypting vetKey: {e}"))?;

    let bytes = vetkey.derive_symmetric_key(VETKD_SECRET_PREFIX_DOMAIN_SEP, SECRET_PREFIX_LEN);
    let prefix: [u8; SECRET_PREFIX_LEN] = bytes
        .as_slice()
        .try_into()
        .context("System error: vetKey-derived symmetric key has unexpected length")?;

    let _ = SECRET_PREFIX.set(prefix);
    Ok(())
}

fn require_secret_prefix() -> anyhow::Result<()> {
    ensure!(
        SECRET_PREFIX.get().is_some(),
        "Service unavailable: secret prefix not initialized yet, retry shortly"
    );
    Ok(())
}

fn cached_secret_prefix() -> [u8; SECRET_PREFIX_LEN] {
    *SECRET_PREFIX
        .get()
        .unwrap_or_else(|| ic_cdk::trap("System error: secret prefix not initialized"))
}

#[ic_cdk::query]
pub fn config() -> Config {
    CONFIG.clone()
}

#[ic_cdk::query]
pub fn cycles_balance() -> u128 {
    ic_cdk::api::canister_cycle_balance()
}

fn insufficient_deposit(available: u128) -> Option<String> {
    if available < MIN_DEPOSIT_CYCLES {
        Some(format!(
            "Input error: insufficient cycles attached: provided {available}, minimum {MIN_DEPOSIT_CYCLES}"
        ))
    } else {
        None
    }
}

#[ic_cdk::update]
pub fn deposit_cycles() -> Result<u128, String> {
    let available = ic_cdk::api::msg_cycles_available();
    if let Some(err) = insufficient_deposit(available) {
        return Err(err);
    }
    let _ = ic_cdk::api::msg_cycles_accept(available);
    Ok(ic_cdk::api::canister_cycle_balance())
}

#[ic_cdk::update]
pub async fn verify_spell(tx: String, mock: bool) -> Result<String, String> {
    let spell = verify_spell_impl(tx, mock, None, Vec::new())
        .await
        .map_err(|e| e.to_string())?;
    spell_to_hex(spell)
}

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
    let parsed =
        LitecoinTx::from_hex(tx_hex).map_err(|e| anyhow!("Input error: parsing tx: {e}"))?;
    let tx = Tx::from(parsed);
    committed_normalized_spell(&SPELL_VK, &tx, mock).map_err(|e| {
        if e.is::<UnsupportedSpellVersion>() {
            e
        } else {
            anyhow!("Input error: extracting and verifying spell: {e}")
        }
    })
}

async fn delegate_to_next(
    tx: String,
    mock: bool,
    spell_version: u32,
    mut seen: Vec<String>,
) -> anyhow::Result<String> {
    let next_id = NEXT_SCROLLS_LITECOIN_CANISTER_ID;
    if next_id.is_empty() {
        bail!(
            "Input error: unsupported spell version {spell_version} (NEXT_SCROLLS_LITECOIN_CANISTER_ID not set)"
        );
    }

    let self_id = ic_cdk::api::canister_self().to_string();
    if next_id == self_id {
        bail!(
            "Input error: unsupported spell version {spell_version} (next canister ID points to self)"
        );
    }
    if seen.iter().any(|id| id == next_id) {
        bail!(
            "Input error: delegation cycle detected (next canister {next_id} already in chain {seen:?})"
        );
    }
    seen.push(self_id);

    let principal = Principal::from_text(next_id)
        .context("System error: parsing NEXT_SCROLLS_LITECOIN_CANISTER_ID")?;

    let response = Call::unbounded_wait(principal, "verify_spell_delegated")
        .with_args(&(tx, mock, spell_version, seen))
        .await
        .map_err(|e| anyhow!("System error: inter-canister call failed: {e}"))?;

    let (inner,): (Result<String, String>,) = response
        .candid_tuple()
        .map_err(|e| anyhow!("System error: decoding next canister response: {e}"))?;

    match inner {
        Ok(spell_hex) => Ok(spell_hex),
        Err(e) => bail!("Input error: next canister: {e}"),
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
        .map_err(|e| anyhow!("System error: decoding spell hex from next canister: {e}"))?;
    let spell: NormalizedSpell = util::read(spell_bytes.as_slice())
        .map_err(|e| anyhow!("System error: deserializing spell from next canister: {e}"))?;
    Ok(spell)
}

fn spell_to_hex(spell: NormalizedSpell) -> Result<String, String> {
    let spell_bytes =
        util::write(&spell).map_err(|e| format!("System error: serializing spell: {e}"))?;
    Ok(hex::encode(spell_bytes))
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct Addresses {
    pub script_pubkeys: BTreeMap<u32, String>,
    pub signature: String,
}

#[ic_cdk::update]
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
        .map_err(|e| anyhow!("Input error: invalid tx_in_0: {e}"))?;

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
        .map_err(|e| anyhow!("System error: signing addresses with Schnorr: {e}"))?;
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
    } = sign_request;

    let litecoin_tx = parse_litecoin_tx(&tx_to_sign)?;
    let signing = check_sign_inputs_indices(litecoin_tx.input.len(), &sign_inputs)?;
    check_existing_witnesses(&litecoin_tx, &signing)?;

    let prev_txs = txid_to_tx(&litecoin_tx, prev_txs)?;
    let spell = verify_spell_impl(tx_to_sign, true, None, Vec::new())
        .await
        .map_err(|e| anyhow!("Input error: extracting and verifying spell: {e}"))?;
    check_prev_txs_mock(&prev_txs, spell.mock)?;
    check_fee(network, &prev_txs, &litecoin_tx)?;

    let signed_tx = sign_tx(sign_inputs, &prev_txs, litecoin_tx).await?;
    submit_tx(network, &signed_tx).await?;

    Ok(SignAndSubmitResult {
        txid: signed_tx.compute_txid().to_string(),
        wtxid: signed_tx.compute_wtxid().to_string(),
    })
}

fn parse_litecoin_tx(tx_hex: &str) -> anyhow::Result<Transaction> {
    let tx = LitecoinTx::from_hex(tx_hex)
        .map_err(|e| anyhow!("Input error: parsing tx: {e}"))?
        .inner()
        .clone();
    ensure!(
        !tx.input.is_empty(),
        "Input error: transaction must have at least one input"
    );
    Ok(tx)
}

fn check_sign_inputs_indices(
    input_count: usize,
    sign_inputs: &[u32],
) -> anyhow::Result<HashSet<usize>> {
    let mut signing = HashSet::new();
    for &idx in sign_inputs {
        let idx_usize = idx as usize;
        ensure!(
            idx_usize < input_count,
            "Input error: input_index {idx} is out of range [0, {input_count})"
        );
        ensure!(
            signing.insert(idx_usize),
            "Input error: duplicate input_index: {idx}"
        );
    }
    Ok(signing)
}

fn check_existing_witnesses(tx: &Transaction, signing: &HashSet<usize>) -> anyhow::Result<()> {
    for (i, input) in tx.input.iter().enumerate() {
        let is_signed = !input.witness.is_empty() || !input.script_sig.is_empty();
        if signing.contains(&i) {
            ensure!(
                !is_signed,
                "Input error: input {i} already has a signature but is in sign_inputs"
            );
        } else {
            ensure!(
                is_signed,
                "Input error: input {i} has no signature and is not being signed"
            );
        }
    }
    Ok(())
}

fn litecoinspace_broadcast_url(network: LitecoinNetwork) -> &'static str {
    match network {
        LitecoinNetwork::Main => LITECOINSPACE_MAINNET_BROADCAST_URL,
        LitecoinNetwork::Test => LITECOINSPACE_TESTNET_BROADCAST_URL,
    }
}

async fn submit_tx(network: LitecoinNetwork, tx: &Transaction) -> anyhow::Result<()> {
    let url = litecoinspace_broadcast_url(network);
    let tx_hex = hex::encode(bitcoin::consensus::encode::serialize(tx));
    let txid = tx.compute_txid().to_string();

    let request = HttpRequestArgs {
        url: url.to_string(),
        max_response_bytes: Some(MAX_BROADCAST_RESPONSE_BYTES),
        method: HttpMethod::POST,
        headers: vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "text/plain".to_string(),
        }],
        body: Some(tx_hex.into_bytes()),
        transform: Some(transform_context_from_query(
            "transform_http".to_string(),
            txid.clone().into_bytes(),
        )),
        is_replicated: None,
    };

    let response = http_request(&request)
        .await
        .map_err(|e| anyhow!("System error: litecoinspace HTTP outcall failed: {e}"))?;

    let status: u16 = response
        .status
        .0
        .try_into()
        .map_err(|_| anyhow!("System error: invalid HTTP status from litecoinspace"))?;

    if status == 200 {
        ensure!(
            response_body_matches_txid(&response.body, &txid),
            "System error: litecoinspace returned unexpected txid in response body"
        );
        return Ok(());
    }

    let body = String::from_utf8_lossy(&response.body);
    bail!(
        "System error: litecoinspace returned HTTP {status}: {}",
        body.trim()
    );
}

#[ic_cdk::query]
fn transform_http(args: TransformArgs) -> HttpRequestResult {
    let TransformArgs { context, response } = args;
    let status: u16 = response.status.0.clone().try_into().unwrap_or(u16::MAX);

    if status == 200 {
        return HttpRequestResult {
            status: response.status,
            headers: vec![],
            body: response.body,
        };
    }

    let body = String::from_utf8_lossy(&response.body);
    if is_tx_already_in_chain_error(status, body.as_ref())
        && let Ok(txid) = std::str::from_utf8(&context)
    {
        return HttpRequestResult {
            status: candid::Nat::from(200u32),
            headers: vec![],
            body: txid.as_bytes().to_vec(),
        };
    }

    HttpRequestResult {
        status: response.status,
        headers: vec![],
        body: normalized_broadcast_error_body(status, body.as_ref()),
    }
}

fn response_body_matches_txid(body: &[u8], expected_txid: &str) -> bool {
    std::str::from_utf8(body)
        .map(|body| body.trim().eq_ignore_ascii_case(expected_txid))
        .unwrap_or(false)
}

fn litecoinspace_sendrawtransaction_rpc_code(body: &str) -> Option<i64> {
    let json_start = body.find('{')?;
    let value = serde_json::from_str::<serde_json::Value>(&body[json_start..]).ok()?;
    value.get("code")?.as_i64()
}

fn is_tx_already_in_chain_error(status: u16, body: &str) -> bool {
    status == 400
        && litecoinspace_sendrawtransaction_rpc_code(body)
            == Some(LITECOIND_TX_ALREADY_IN_CHAIN_RPC_CODE)
}

fn normalized_broadcast_error_body(status: u16, body: &str) -> Vec<u8> {
    if let Some(code) = litecoinspace_sendrawtransaction_rpc_code(body) {
        format!("rpc_code:{code}").into_bytes()
    } else {
        format!("http_status:{status}").into_bytes()
    }
}

fn check_network(network: &str) -> anyhow::Result<LitecoinNetwork> {
    let parsed = LitecoinNetwork::from_label(network)?;
    if !CONFIG.fee_address.contains_key(network) {
        bail!("Input error: unsupported network: {network}");
    }
    Ok(parsed)
}

fn check_prev_txs_mock(
    prev_txs: &BTreeMap<Txid, Transaction>,
    spell_mock: bool,
) -> anyhow::Result<()> {
    if !spell_mock {
        return Ok(());
    }
    for prev_tx in prev_txs.values() {
        let prev_tx = Tx::from(LitecoinTx::new(prev_tx.clone()));
        if extract_and_verify_spell(&prev_tx, false).is_ok() {
            bail!("Input error: mock=true but prev_tx contains a non-mock spell");
        }
    }
    Ok(())
}

fn check_fee(
    network: LitecoinNetwork,
    prev_txs: &BTreeMap<Txid, Transaction>,
    tx: &Transaction,
) -> anyhow::Result<()> {
    let expected_fee_script_pubkey = configured_fee_script_pubkey(network);
    let fee: u64 = tx
        .output
        .iter()
        .filter(|output| output.script_pubkey == expected_fee_script_pubkey)
        .map(|output| output.value.to_sat())
        .sum();
    let expected_fee = compute_expected_fee(signable_inputs(tx), prev_txs, tx);
    ensure!(fee >= expected_fee, "Input error: insufficient fee");
    Ok(())
}

fn compute_expected_fee(
    inputs_count: usize,
    prev_txs: &BTreeMap<Txid, Transaction>,
    tx: &Transaction,
) -> u64 {
    let input_sats: u64 = tx
        .input
        .iter()
        .map(|tx_in| {
            let out_point = tx_in.previous_output;
            prev_txs[&out_point.txid].output[out_point.vout as usize]
                .value
                .to_sat()
        })
        .sum();
    input_sats
        .saturating_mul(CONFIG.fee_basis_points)
        .saturating_div(10000)
        .saturating_add(CONFIG.fee_per_input.saturating_mul(inputs_count as u64))
        .saturating_add(CONFIG.fixed_cost)
}

fn signable_inputs(tx: &Transaction) -> usize {
    tx.input.len()
}

fn extract_coinbase_height(coinbase_input: &TxIn) -> Option<u32> {
    let push = coinbase_input
        .script_sig
        .instructions_minimal()
        .next()?
        .ok()?;
    let bitcoin::script::Instruction::PushBytes(bytes) = push else {
        return None;
    };
    let height = bitcoin::script::read_scriptint(bytes.as_bytes()).ok()?;
    u32::try_from(height).ok()
}

fn configured_fee_script_pubkey(network: LitecoinNetwork) -> ScriptBuf {
    litecoin_fee_script(network.label(), &CONFIG.fee_address[network.label()])
        .expect("fee address checked at init")
}

fn litecoin_fee_script(network: &str, address: &str) -> anyhow::Result<ScriptBuf> {
    let expected_hrp = match network {
        NETWORK_MAIN => HRP_MAIN,
        NETWORK_TEST => HRP_TEST,
        _ => bail!("Input error: unsupported network: {network}"),
    };
    let (hrp, version, program) = bech32::segwit::decode(address).map_err(|e| {
        anyhow!("Input error: fee address {address} is not a Litecoin segwit address: {e}")
    })?;
    ensure!(
        hrp == bech32::Hrp::parse(expected_hrp).expect("hrp"),
        "Input error: fee address HRP is not {expected_hrp}"
    );
    ensure!(
        version.to_u8() == 0 && program.len() == 20,
        "Input error: fee address is not P2WPKH"
    );
    let program: [u8; 20] = program.as_slice().try_into().expect("length checked");
    Ok(ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
        program,
    )))
}

async fn sign_tx(
    sign_inputs: Vec<u32>,
    prev_txs: &BTreeMap<Txid, Transaction>,
    mut tx: Transaction,
) -> anyhow::Result<Transaction> {
    for input_index in sign_inputs {
        let input_index_usize = input_index as usize;
        let out_point = tx
            .input
            .get(input_index_usize)
            .ok_or_else(|| anyhow!("Input error: invalid input_index: {input_index}"))?
            .previous_output;

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
                "Input error: prev_tx {} missing output with index: {out_i}",
                out_point.txid
            )
        })?;
        let expected_spk = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash());
        ensure!(
            tx_out.script_pubkey == expected_spk,
            "Input error: output script in prev_tx {} does not match the derived public key",
            out_point.txid
        );

        let tx_sighash = SighashCache::new(&tx)
            .p2wpkh_signature_hash(
                input_index_usize,
                &tx_out.script_pubkey,
                tx_out.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| anyhow!("System error: computing sighash: {e}"))?;
        let ecdsa_signature = sign_tx_sighash_for_output(&tx_in_0, out_i, &tx_sighash).await?;

        let witness = &mut tx.input[input_index_usize].witness;
        witness.push_ecdsa_signature(&ecdsa_signature);
        witness.push(&public_key.to_bytes());
    }
    Ok(tx)
}

async fn sign_tx_sighash_with_path(
    derivation_path: Vec<Vec<u8>>,
    tx_sighash: &SegwitV0Sighash,
) -> anyhow::Result<Signature> {
    let sign_result = sign_with_ecdsa(&SignWithEcdsaArgs {
        message_hash: tx_sighash.to_byte_array().to_vec(),
        derivation_path,
        key_id: key_id(),
    })
    .await
    .context("System error: signing valid tx")?;
    let signature = secp256k1::ecdsa::Signature::from_compact(&sign_result.signature)
        .context("System error: parsing signature")?;
    Ok(Signature {
        signature,
        sighash_type: EcdsaSighashType::All,
    })
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
    let result = ecdsa_public_key(&EcdsaPublicKeyArgs {
        canister_id: None,
        derivation_path,
        key_id: key_id(),
    })
    .await
    .map_err(|e| anyhow!("System error: getting ECDSA public key: {e}"))?;
    CompressedPublicKey::from_slice(&result.public_key)
        .map_err(|e| anyhow!("System error: parsing user public key: {e}"))
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
    let input_count = signable_inputs(tx);
    ensure!(
        prev_txs.len() <= input_count,
        "Input error: too many prev_txs (max: {input_count})"
    );

    let prev_txs: BTreeMap<Txid, Transaction> = prev_txs
        .into_iter()
        .map(|tx| {
            let tx: Transaction =
                deserialize_hex(&tx).map_err(|e| anyhow!("Input error: parsing prev_tx: {e}"))?;
            Ok((tx.compute_txid(), tx))
        })
        .collect::<anyhow::Result<_>>()?;
    for tx_in in &tx.input {
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

#[cfg(test)]
mod tests {
    use super::{
        CONFIG, HRP_MAIN, HRP_TEST, LITECOINSPACE_MAINNET_BROADCAST_URL,
        LITECOINSPACE_TESTNET_BROADCAST_URL, LitecoinNetwork, MIN_DEPOSIT_CYCLES, NETWORK_MAIN,
        NETWORK_TEST, NEXT_SCROLLS_LITECOIN_CANISTER_ID, VETKD_SECRET_PREFIX_CONTEXT,
        VETKD_SECRET_PREFIX_DOMAIN_SEP, VETKD_SECRET_PREFIX_INPUT, check_network, config,
        insufficient_deposit, is_tx_already_in_chain_error, litecoin_fee_script,
        litecoinspace_broadcast_url, verify_spell_locally,
    };
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash,
        Witness, absolute::LockTime, consensus::encode::serialize_hex, hashes::Hash,
        transaction::Version,
    };

    #[test]
    fn vetkd_domain_strings_are_litecoin() {
        assert_eq!(
            VETKD_SECRET_PREFIX_INPUT,
            b"scrolls_litecoin/derivation_prefix/v1"
        );
        assert_eq!(
            VETKD_SECRET_PREFIX_CONTEXT,
            b"scrolls_litecoin/derivation_prefix"
        );
        assert_eq!(
            VETKD_SECRET_PREFIX_DOMAIN_SEP,
            "scrolls_litecoin/derivation_prefix"
        );
        assert_ne!(
            VETKD_SECRET_PREFIX_INPUT,
            b"scrolls_bitcoin/derivation_prefix/v1"
        );
    }

    #[test]
    fn network_labels_are_main_and_test() {
        assert_eq!(check_network(NETWORK_MAIN).unwrap(), LitecoinNetwork::Main);
        assert_eq!(check_network(NETWORK_TEST).unwrap(), LitecoinNetwork::Test);
        for label in ["testnet4", "regtest", "mainnet", "bitcoin"] {
            let err = check_network(label).unwrap_err().to_string();
            assert!(err.contains("unsupported network"), "{label}: {err}");
        }
    }

    #[test]
    fn broadcast_urls_are_litecoinspace() {
        assert_eq!(
            litecoinspace_broadcast_url(LitecoinNetwork::Main),
            LITECOINSPACE_MAINNET_BROADCAST_URL
        );
        assert_eq!(
            litecoinspace_broadcast_url(LitecoinNetwork::Test),
            LITECOINSPACE_TESTNET_BROADCAST_URL
        );
        assert_eq!(
            LITECOINSPACE_MAINNET_BROADCAST_URL,
            "https://litecoinspace.org/api/tx"
        );
        assert_eq!(
            LITECOINSPACE_TESTNET_BROADCAST_URL,
            "https://litecoinspace.org/testnet/api/tx"
        );
        assert!(!LITECOINSPACE_MAINNET_BROADCAST_URL.contains("mempool.space"));
        assert!(!LITECOINSPACE_TESTNET_BROADCAST_URL.contains("mempool.space"));
    }

    #[test]
    fn fee_addresses_are_p2wpkh_for_main_and_test() {
        let keys: Vec<_> = CONFIG.fee_address.keys().cloned().collect();
        assert_eq!(
            keys,
            vec![NETWORK_MAIN.to_string(), NETWORK_TEST.to_string()]
        );
        let main = litecoin_fee_script(NETWORK_MAIN, &CONFIG.fee_address[NETWORK_MAIN]).unwrap();
        let test = litecoin_fee_script(NETWORK_TEST, &CONFIG.fee_address[NETWORK_TEST]).unwrap();
        assert_eq!(
            main.as_bytes(),
            &hex::decode("0014318d2dbf53a3f9c41b2e36683a3a8b8580e05516").unwrap()
        );
        assert_eq!(
            test.as_bytes(),
            &hex::decode("00141db4ded10fa155036bfb40717ea68022be899fbb").unwrap()
        );
        assert!(main.is_p2wpkh());
        assert!(test.is_p2wpkh());
        assert_ne!(main, test);
        assert!(
            litecoin_fee_script(NETWORK_MAIN, "bc1qxxxjm06n50uugxewxe5r5w5tskqwq4gkwrm0al")
                .is_err()
        );
        assert!(litecoin_fee_script(NETWORK_TEST, &CONFIG.fee_address[NETWORK_MAIN]).is_err());
        assert_eq!(HRP_MAIN, "ltc");
        assert_eq!(HRP_TEST, "tltc");
        let returned = config();
        assert_eq!(returned.fee_address, CONFIG.fee_address);
        assert_eq!(returned.fee_per_input, 64);
        assert_eq!(returned.fee_basis_points, 10);
        assert_eq!(returned.fixed_cost, 895);
    }

    #[test]
    fn deposit_minimum_is_one_trillion_cycles() {
        assert_eq!(MIN_DEPOSIT_CYCLES, 1_000_000_000_000);
        let rejected = insufficient_deposit(MIN_DEPOSIT_CYCLES - 1).unwrap();
        assert!(rejected.contains("1000000000000"), "{rejected}");
        assert!(insufficient_deposit(MIN_DEPOSIT_CYCLES).is_none());
    }

    #[test]
    fn next_canister_id_is_unset_in_this_build() {
        assert!(NEXT_SCROLLS_LITECOIN_CANISTER_ID.is_empty());
    }

    #[test]
    fn spell_check_uses_the_op_return_parser() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2u8; 20])),
            }],
        };
        let err = verify_spell_locally(&serialize_hex(&tx), true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("expected exactly one spell OP_RETURN output"),
            "{err}"
        );
        assert!(!err.contains("no control block"), "{err}");
    }

    #[test]
    fn detects_already_in_chain_rpc_error() {
        let body = r#"sendrawtransaction RPC error: {"code":-27,"message":"Transaction already in block chain"}"#;
        assert!(is_tx_already_in_chain_error(400, body));
    }

    #[test]
    fn rejects_already_in_mempool_rpc_error() {
        let body =
            r#"sendrawtransaction RPC error: {"code":-26,"message":"258: txn-already-in-mempool"}"#;
        assert!(!is_tx_already_in_chain_error(400, body));
    }

    #[test]
    fn rejects_unrelated_broadcast_errors() {
        let body = r#"sendrawtransaction RPC error: {"code":-22,"message":"TX decode failed. Make sure the tx has at least one input."}"#;
        assert!(!is_tx_already_in_chain_error(400, body));
        assert!(!is_tx_already_in_chain_error(500, body));
    }

    #[test]
    fn production_source_does_not_reuse_bitcoin_canister_identity() {
        let prod = include_str!("lib.rs").split("mod tests").next().unwrap();
        let yaml = include_str!("../config.yaml");
        let did = include_str!("../scrolls_litecoin.did");
        let combined = format!("{prod}\n{yaml}\n{did}");
        for needle in [
            "rpgc6-oqaaa-aaaak-qy3uq-cai",
            "lmbwh-3qaaa-aaaak-qunha-cai",
            "scrolls_bitcoin",
            "mempool.space",
            "sign_with_v14_canister",
            "testnet4",
            "BitcoinTx",
            "bc1q",
            "tb1q",
        ] {
            assert!(!combined.contains(needle), "{needle}");
        }
    }

    #[test]
    fn candid_file_matches_export() {
        let generated = super::__export_service();
        let committed = include_str!("../scrolls_litecoin.did");
        assert_eq!(generated.trim(), committed.trim());
    }
}

ic_cdk::export_candid!();

register_custom_getrandom!(custom_getrandom);
fn custom_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
