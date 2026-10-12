mod light;
mod stable;
mod trie;

#[cfg(test)]
mod consensus_fixture;

use candid::{CandidType, Deserialize};
use getrandom::register_custom_getrandom;
use ic_cdk_management_canister::{
    HttpMethod, HttpRequest, HttpRequestResult, SchnorrAlgorithm, SchnorrKeyId,
    SignWithSchnorrArgs, TransformArgs, cost_sign_with_schnorr, schnorr_public_key,
    sign_with_schnorr, transform_context_from_query,
};
use light::{
    Chain, Persisted, execution_block_hash, finality_payload, needs_period_update,
    period_of_finalized_header, stored_period, update_payloads, update_period_to_fetch,
};
use serde::Serialize;
use std::{cell::RefCell, time::Duration};
use trie::{ERC1967_SLOT, ExecProofs, StorageProof, mapping_key};

const MAX_RESPONSE_BYTES: u64 = 128 * 1024;
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

thread_local! {
    static STATE: RefCell<Persisted> = const {
        RefCell::new(Persisted {
            chain: Chain {
                beacon_api: String::new(),
                execution_api: String::new(),
                charms: [0; 20],
                implementation: [0; 20],
                proxy_code_hash: [0; 32],
                beam_source_slot: 0,
                ws_period_epochs: 1,
            },
            store: None,
            public_key: None,
            signatures: light::SignatureCache::empty(),
        })
    };
}

#[derive(CandidType, Deserialize, Clone)]
struct DeployConfig {
    beacon_api: String,
    execution_api: String,
    charms: Vec<u8>,
    implementation: Vec<u8>,
    proxy_code_hash: Vec<u8>,
    beam_source_slot: u64,
    ws_period_epochs: u64,
}

#[derive(CandidType, Deserialize, Clone)]
struct StorageProofArg {
    key: Vec<u8>,
    proof: Vec<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Clone)]
struct CertifyProofs {
    updates: Vec<Vec<u8>>,
    finality: Vec<u8>,
    account_proof: Vec<Vec<u8>>,
    storage_proofs: Vec<StorageProofArg>,
}

#[derive(CandidType, Serialize)]
struct FinalityStatus {
    finalized_slot: u64,
    finalized_epoch: u64,
    current_period: u64,
    implementation: Vec<u8>,
}

#[ic_cdk::init]
fn init(config: DeployConfig) {
    let chain = parse_config(config).unwrap_or_else(|e| ic_cdk::trap(&e));
    STATE.with(|state| state.borrow_mut().chain = chain);
    let state = snapshot();
    stable::save_all(&state, &mut stable::IcStable).unwrap_or_else(|e| ic_cdk::trap(&e));
    schedule_key(Duration::ZERO);
    schedule_daily();
}

#[ic_cdk::post_upgrade]
fn post_upgrade(config: Option<DeployConfig>) {
    let loaded = stable::load(&stable::IcStable).unwrap_or_else(|e| ic_cdk::trap(&e));
    let legacy = loaded.is_legacy();
    let mut persisted = loaded.into_persisted();
    let before = persisted.clone();
    if let Some(config) = config {
        persisted.chain = parse_config(config).unwrap_or_else(|e| ic_cdk::trap(&e));
    }
    align_signatures(&mut persisted);
    if legacy {
        stable::save_all(&persisted, &mut stable::IcStable).unwrap_or_else(|e| ic_cdk::trap(&e));
    } else {
        stable::flush(&before, &persisted, &mut stable::IcStable)
            .unwrap_or_else(|e| ic_cdk::trap(&e));
    }
    let missing_key = persisted.public_key.is_none();
    STATE.with(|state| *state.borrow_mut() = persisted);
    if missing_key {
        schedule_key(Duration::ZERO);
    }
    schedule_daily();
}

#[ic_cdk::update]
fn reset_checkpoint(bootstrap: Vec<u8>) -> Result<(), String> {
    require_controller()?;
    let now = ic_now_secs();
    let before = snapshot();
    let result = STATE.with(|state| {
        let state = &mut *state.borrow_mut();
        state.store = Some(light::reset_checkpoint(
            &bootstrap,
            now,
            state.chain.ws_period_epochs,
        )?);
        Ok(())
    });
    commit(&before);
    result
}

#[ic_cdk::update]
fn set_ws_period(epochs: u64) -> Result<(), String> {
    require_controller()?;
    if epochs == 0 {
        return Err("Input error: ws_period_epochs must be non-zero".into());
    }
    let before = snapshot();
    STATE.with(|state| state.borrow_mut().chain.ws_period_epochs = epochs);
    commit(&before);
    Ok(())
}

#[ic_cdk::query]
fn finality_public_key() -> Vec<u8> {
    STATE.with(|state| {
        state
            .borrow()
            .public_key
            .clone()
            .unwrap_or_else(|| ic_cdk::trap("finality public key is not available yet"))
    })
}

#[ic_cdk::query]
fn finality_status() -> FinalityStatus {
    STATE.with(|state| {
        let state = state.borrow();
        let (slot, period) = match &state.store {
            Some(store) => (store.finalized_header.beacon().slot, stored_period(store)),
            None => (0, 0),
        };
        FinalityStatus {
            finalized_slot: slot,
            finalized_epoch: slot / 32,
            current_period: period,
            implementation: state.chain.implementation.to_vec(),
        }
    })
}

#[ic_cdk::update]
async fn certify_final(
    eth_tx_id: Vec<u8>,
    proofs: Option<CertifyProofs>,
) -> Result<Vec<u8>, String> {
    let eth_tx_id: [u8; 32] = eth_tx_id
        .try_into()
        .map_err(|_| "Input error: eth_tx_id must be 32 bytes".to_string())?;
    if proofs
        .as_ref()
        .is_some_and(|proofs| proofs.updates.len() > 1)
    {
        return Err("Input error: at most one light client update".into());
    }
    admit_fetches(proofs.is_some())?;
    let supplied_update = proofs
        .as_ref()
        .and_then(|proofs| proofs.updates.first().cloned());
    let finality = match &proofs {
        Some(proofs) => proofs.finality.clone(),
        None => fetch_finality().await?,
    };
    let needs_update = STATE.with(|state| {
        let state = state.borrow();
        let store = state
            .store
            .as_ref()
            .ok_or_else(|| "Input error: checkpoint is not set".to_string())?;
        needs_period_update(store, &finality)
    })?;
    let update = if needs_update {
        match supplied_update {
            Some(update) => Some(update),
            None if proofs.is_none() => Some(fetch_update().await?),
            None => None,
        }
    } else {
        supplied_update
    };
    let exec = match proofs {
        Some(proofs) => exec_from_args(&eth_tx_id, proofs)?,
        None => {
            let block = execution_block_hash(&finality)?;
            fetch_execution_proof(&eth_tx_id, block).await?
        }
    };
    let before = snapshot();
    let message = STATE.with(|state| {
        let now = ic_now_secs();
        let state = &mut *state.borrow_mut();
        light::certify(
            &mut state.store,
            now,
            &state.chain,
            &eth_tx_id,
            update.as_deref(),
            &finality,
            &exec,
        )
    });
    commit(&before);
    issue_signature(eth_tx_id, message?).await
}

#[ic_cdk::query]
fn transform_http(args: TransformArgs) -> HttpRequestResult {
    HttpRequestResult {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}

fn exec_from_args(eth_tx_id: &[u8; 32], proofs: CertifyProofs) -> Result<ExecProofs, String> {
    let chain = STATE.with(|state| state.borrow().chain.clone());
    let beam_key = mapping_key(eth_tx_id, chain.beam_source_slot);
    let mut storage_proofs = Vec::new();
    for proof in proofs.storage_proofs {
        let key: [u8; 32] = proof
            .key
            .try_into()
            .map_err(|_| "Input error: storage proof key must be 32 bytes".to_string())?;
        if key != beam_key && key != ERC1967_SLOT {
            return Err("Input error: storage proof key".into());
        }
        storage_proofs.push(StorageProof {
            key,
            proof: proof.proof,
        });
    }
    Ok(ExecProofs {
        account_proof: proofs.account_proof,
        storage_proofs,
    })
}

fn parse_config(config: DeployConfig) -> Result<Chain, String> {
    check_url(&config.beacon_api, "beacon_api")?;
    check_url(&config.execution_api, "execution_api")?;
    if config.ws_period_epochs == 0 {
        return Err("Input error: ws_period_epochs must be non-zero".into());
    }
    Ok(Chain {
        beacon_api: config.beacon_api.trim_end_matches('/').to_string(),
        execution_api: config.execution_api.trim_end_matches('/').to_string(),
        charms: fixed::<20>(config.charms, "charms")?,
        implementation: fixed::<20>(config.implementation, "implementation")?,
        proxy_code_hash: fixed::<32>(config.proxy_code_hash, "proxy_code_hash")?,
        beam_source_slot: config.beam_source_slot,
        ws_period_epochs: config.ws_period_epochs,
    })
}

fn fixed<const N: usize>(bytes: Vec<u8>, name: &str) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("Input error: {name} has the wrong length"))
}

fn check_url(url: &str, name: &str) -> Result<(), String> {
    if url.starts_with("https://") && !url.contains('@') && !url.contains(char::is_whitespace) {
        Ok(())
    } else {
        Err(format!("Input error: {name} must be an https URL"))
    }
}

fn require_controller() -> Result<(), String> {
    if ic_cdk::api::is_controller(&ic_cdk::api::msg_caller()) {
        Ok(())
    } else {
        Err("Input error: caller is not the controller".into())
    }
}

fn ic_now_secs() -> u64 {
    ic_cdk::api::time() / 1_000_000_000
}

fn schedule_daily() {
    ic_cdk_timers::set_timer_interval(DAY, || async {
        if let Err(e) = tick().await {
            ic_cdk::println!("light client tick failed: {e}");
        }
    });
}

fn schedule_key(delay: Duration) {
    ic_cdk_timers::set_timer(delay, async move {
        match fetch_public_key().await {
            Ok(key) => {
                let before = snapshot();
                STATE.with(|state| state.borrow_mut().public_key = Some(key));
                commit(&before);
            }
            Err(e) => {
                ic_cdk::println!("finality public key fetch failed: {e}");
                let next = if delay.is_zero() {
                    Duration::from_secs(1)
                } else {
                    delay.saturating_mul(2).min(Duration::from_secs(3600))
                };
                schedule_key(next);
            }
        }
    });
}

async fn tick() -> Result<(), String> {
    let period = STATE.with(|state| {
        let state = state.borrow();
        let store = state.store.as_ref()?;
        let now = ic_now_secs();
        if light::outside_weak_subjectivity(
            store.finalized_header.beacon().slot,
            now,
            state.chain.ws_period_epochs,
        ) {
            return None;
        }
        Some(update_period_to_fetch(store))
    });
    let Some(period) = period else {
        return Ok(());
    };
    let body = match http_get(&updates_url(period), "application/octet-stream").await {
        Ok(body) => body,
        Err(error) if error.contains("HTTP 404") => return Ok(()),
        Err(error) => return Err(error),
    };
    let payloads = update_payloads(&body)?;
    let Some(payload) = payloads
        .iter()
        .find(|payload| period_of_finalized_header(payload).ok() == Some(period))
    else {
        return Ok(());
    };
    let now = ic_now_secs();
    let before = snapshot();
    let applied = STATE.with(|state| {
        let state = &mut *state.borrow_mut();
        let Some(store) = state.store.as_mut() else {
            return Ok(());
        };
        light::apply_period_update(store, payload, now, state.chain.ws_period_epochs)
    });
    commit(&before);
    applied
}

async fn fetch_update() -> Result<Vec<u8>, String> {
    let period = STATE.with(|state| -> Result<u64, String> {
        let state = state.borrow();
        let store = state
            .store
            .as_ref()
            .ok_or_else(|| "Input error: checkpoint is not set".to_string())?;
        Ok(update_period_to_fetch(store))
    })?;
    let body = http_get(&updates_url(period), "application/octet-stream").await?;
    let payloads = update_payloads(&body)?;
    payloads
        .into_iter()
        .find(|payload| period_of_finalized_header(payload).ok() == Some(period))
        .ok_or_else(|| "System error: beacon API returned no update for the stored period".into())
}

async fn fetch_finality() -> Result<Vec<u8>, String> {
    let body = http_get(&finality_url(), "application/octet-stream").await?;
    finality_payload(&body)
}

async fn fetch_execution_proof(
    eth_tx_id: &[u8; 32],
    block_hash: alloy::primitives::B256,
) -> Result<ExecProofs, String> {
    let (url, charms, slot) = STATE.with(|state| {
        let chain = &state.borrow().chain;
        (
            chain.execution_api.clone(),
            chain.charms,
            chain.beam_source_slot,
        )
    });
    let beam_key = mapping_key(eth_tx_id, slot);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getProof",
        "params": [
            format!("0x{}", hex::encode(charms)),
            [format!("0x{}", hex::encode(beam_key)), format!("0x{}", hex::encode(ERC1967_SLOT))],
            format!("0x{}", hex::encode(block_hash.as_slice())),
        ],
    })
    .to_string()
    .into_bytes();
    let response = http_post(&url, &body).await?;
    parse_eth_proof(&response, beam_key)
}

fn parse_eth_proof(body: &[u8], beam_key: [u8; 32]) -> Result<ExecProofs, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("System error: eth_getProof: {e}"))?;
    if let Some(error) = value.get("error") {
        return Err(format!("System error: eth_getProof: {error}"));
    }
    let result = value
        .get("result")
        .ok_or_else(|| "System error: eth_getProof has no result".to_string())?;
    let account_proof = hex_list(result.get("accountProof"))?;
    let storage = result
        .get("storageProof")
        .and_then(|proof| proof.as_array())
        .ok_or_else(|| "System error: eth_getProof has no storageProof".to_string())?;
    let mut storage_proofs = Vec::new();
    for proof in storage {
        let key = decode_word(proof.get("key").and_then(|key| key.as_str()).unwrap_or(""))?;
        let nodes = hex_list(proof.get("proof"))?;
        if key != beam_key && key != ERC1967_SLOT {
            return Err("System error: eth_getProof returned an unexpected key".into());
        }
        storage_proofs.push(StorageProof { key, proof: nodes });
    }
    Ok(ExecProofs {
        account_proof,
        storage_proofs,
    })
}

fn hex_list(value: Option<&serde_json::Value>) -> Result<Vec<Vec<u8>>, String> {
    let list = value
        .and_then(|value| value.as_array())
        .ok_or_else(|| "System error: proof list".to_string())?;
    list.iter()
        .map(|item| {
            let text = item
                .as_str()
                .ok_or_else(|| "System error: proof node".to_string())?;
            decode_hex(text)
        })
        .collect()
}

fn decode_word(text: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(text)?;
    if bytes.len() > 32 {
        return Err("System error: storage key".into());
    }
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.len().is_multiple_of(2) {
        return Err("System error: odd hex length".into());
    }
    hex::decode(text).map_err(|e| format!("System error: hex: {e}"))
}

fn updates_url(period: u64) -> String {
    let base = STATE.with(|state| state.borrow().chain.beacon_api.clone());
    format!("{base}/eth/v1/beacon/light_client/updates?start_period={period}&count=1")
}

fn finality_url() -> String {
    let base = STATE.with(|state| state.borrow().chain.beacon_api.clone());
    format!("{base}/eth/v1/beacon/light_client/finality_update")
}

fn admit_fetches(proofs_supplied: bool) -> Result<(), String> {
    let (set, fresh) = checkpoint_flags();
    let (available, quote) = if proofs_supplied || !set || !fresh {
        (0, 0)
    } else {
        (ic_cdk::api::msg_cycles_available(), fetch_quote())
    };
    let Some(cycles) = light::admit_public_fetch(set, fresh, proofs_supplied, available, quote)?
    else {
        return Ok(());
    };
    let accepted = ic_cdk::api::msg_cycles_accept(cycles);
    if accepted < cycles {
        return Err("Input error: could not accept cycles for proof fetches".into());
    }
    Ok(())
}

fn checkpoint_flags() -> (bool, bool) {
    STATE.with(|state| {
        let state = state.borrow();
        let Some(store) = state.store.as_ref() else {
            return (false, false);
        };
        let fresh = !light::outside_weak_subjectivity(
            store.finalized_header.beacon().slot,
            ic_now_secs(),
            state.chain.ws_period_epochs,
        );
        (true, fresh)
    })
}

fn fetch_quote() -> u128 {
    let finality = http_get_request(&finality_url(), "application/octet-stream").get_cost();
    let update = http_get_request(&updates_url(u64::MAX), "application/octet-stream").get_cost();
    let url = STATE.with(|state| state.borrow().chain.execution_api.clone());
    let execution = http_post_request(&url, &execution_quote_body()).get_cost();
    finality.saturating_add(update).saturating_add(execution)
}

fn execution_quote_body() -> Vec<u8> {
    let charms = [0xffu8; 20];
    let beam_key = [0xffu8; 32];
    let block = [0xffu8; 32];
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getProof",
        "params": [
            format!("0x{}", hex::encode(charms)),
            [
                format!("0x{}", hex::encode(beam_key)),
                format!("0x{}", hex::encode(ERC1967_SLOT)),
            ],
            format!("0x{}", hex::encode(block)),
        ],
    })
    .to_string()
    .into_bytes()
}

fn http_get_request(url: &str, accept: &str) -> HttpRequest {
    HttpRequest::new(url)
        .with_method(HttpMethod::GET)
        .with_header("Accept", accept)
        .with_max_response_bytes(MAX_RESPONSE_BYTES)
        .with_transform(transform_context_from_query(
            "transform_http".into(),
            vec![],
        ))
}

fn http_post_request(url: &str, body: &[u8]) -> HttpRequest {
    HttpRequest::new(url)
        .with_method(HttpMethod::POST)
        .with_header("Content-Type", "application/json")
        .with_body(body.to_vec())
        .with_max_response_bytes(MAX_RESPONSE_BYTES)
        .with_transform(transform_context_from_query(
            "transform_http".into(),
            vec![],
        ))
}

async fn http_get(url: &str, accept: &str) -> Result<Vec<u8>, String> {
    let response = http_get_request(url, accept)
        .send()
        .await
        .map_err(|e| format!("System error: HTTP outcall failed: {e}"))?;
    http_ok(response)
}

async fn http_post(url: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let response = http_post_request(url, body)
        .send()
        .await
        .map_err(|e| format!("System error: HTTP outcall failed: {e}"))?;
    http_ok(response)
}

fn http_ok(response: HttpRequestResult) -> Result<Vec<u8>, String> {
    let status: u16 = response
        .status
        .0
        .try_into()
        .map_err(|_| "System error: HTTP status".to_string())?;
    if status == 200 {
        Ok(response.body)
    } else {
        let body = String::from_utf8_lossy(&response.body);
        let body = body.chars().take(200).collect::<String>();
        Err(format!("System error: HTTP {status}: {body}"))
    }
}

async fn fetch_public_key() -> Result<Vec<u8>, String> {
    let args = ic_cdk_management_canister::SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: derivation_path(),
        key_id: key_id(),
    };
    let result = schnorr_public_key(&args)
        .await
        .map_err(|e| format!("System error: Schnorr public key: {e}"))?;
    Ok(result.public_key)
}

async fn issue_signature(eth_tx_id: [u8; 32], message: [u8; 32]) -> Result<Vec<u8>, String> {
    let header = STATE
        .with(|state| {
            state
                .borrow()
                .store
                .as_ref()
                .map(light::finalized_beacon_root)
        })
        .ok_or_else(|| "Input error: checkpoint is not set".to_string())?;
    if let Some(signature) = STATE.with(|state| state.borrow().signatures.get(&eth_tx_id, &header))
    {
        return Ok(signature);
    }
    let quote = signature_quote(&message)?;
    let cycles = light::admit_signature(ic_cdk::api::msg_cycles_available(), quote)?;
    let accepted = ic_cdk::api::msg_cycles_accept(cycles);
    if accepted < cycles {
        return Err("Input error: could not accept cycles for signing".into());
    }
    let signature = sign_message(&message).await?;
    let before = snapshot();
    STATE.with(|state| {
        let state = &mut *state.borrow_mut();
        match state.store.as_ref().map(light::finalized_beacon_root) {
            Some(current) => {
                state
                    .signatures
                    .remember(&current, &header, eth_tx_id, signature.clone());
            }
            None => state.signatures.retain_current(None),
        }
    });
    commit(&before);
    Ok(signature)
}

fn align_signatures(state: &mut Persisted) {
    let header = state.store.as_ref().map(light::finalized_beacon_root);
    state.signatures.retain_current(header);
}

fn snapshot() -> Persisted {
    STATE.with(|state| state.borrow().clone())
}

fn commit(before: &Persisted) {
    STATE.with(|state| {
        let state = &mut *state.borrow_mut();
        align_signatures(state);
        stable::flush(before, state, &mut stable::IcStable).unwrap_or_else(|e| ic_cdk::trap(&e));
    });
}

fn signature_quote(message: &[u8; 32]) -> Result<u128, String> {
    cost_sign_with_schnorr(&schnorr_args(message))
        .map_err(|e| format!("System error: signature cost: {e}"))
}

async fn sign_message(message: &[u8; 32]) -> Result<Vec<u8>, String> {
    let result = sign_with_schnorr(&schnorr_args(message))
        .await
        .map_err(|e| format!("System error: signing: {e}"))?;
    if result.signature.len() != 64 {
        return Err("System error: signature length".into());
    }
    Ok(result.signature)
}

fn schnorr_args(message: &[u8; 32]) -> SignWithSchnorrArgs {
    SignWithSchnorrArgs {
        message: message.to_vec(),
        derivation_path: derivation_path(),
        key_id: key_id(),
        aux: None,
    }
}

fn derivation_path() -> Vec<Vec<u8>> {
    vec![
        b"scrolls".to_vec(),
        b"ethereum".to_vec(),
        b"finality".to_vec(),
    ]
}

fn key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: "key_1".into(),
    }
}

register_custom_getrandom!(custom_getrandom);

fn custom_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

ic_cdk::export_candid!();

#[cfg(test)]
mod candid_export {
    #[test]
    fn did_file_matches_the_service() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/scrolls_ethereum.did");
        let on_disk = std::fs::read_to_string(path).unwrap();
        assert_eq!(on_disk, super::__export_service());
    }

    #[test]
    fn upgrade_hook_is_absent() {
        let src = include_str!("lib.rs");
        let hook = ["pre", "_upgrade"].concat();
        assert!(!src.contains(&hook), "upgrade hook is still present");
    }
}
