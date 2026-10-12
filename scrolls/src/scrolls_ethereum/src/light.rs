use alloy::primitives::{B256, U256, b256, fixed_bytes};
use helios_consensus_core::{
    apply_bootstrap, apply_finality_update, apply_update, calc_sync_period,
    consensus_spec::{ConsensusSpec, MainnetConsensusSpec},
    get_bits,
    types::{
        Bootstrap, BootstrapElectra, FinalityUpdate, FinalityUpdateElectra, Fork, Forks,
        LightClientStore, Update, UpdateElectra,
    },
    verify_bootstrap, verify_finality_update, verify_update,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use ssz::Decode;
use std::collections::BTreeMap;
use tree_hash::TreeHash;

use crate::trie::{ExecProofs, check_storage};

pub const GENESIS_TIME: u64 = 1_606_824_023;
pub const CHAIN_ID: u64 = 1;
const GENESIS_ROOT: B256 =
    b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
const DOMAIN: &[u8] = b"charms/ethereum/finality/v1";

pub type Store = LightClientStore<MainnetConsensusSpec>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chain {
    pub beacon_api: String,
    pub execution_api: String,
    pub charms: [u8; 20],
    pub implementation: [u8; 20],
    pub proxy_code_hash: [u8; 32],
    pub beam_source_slot: u64,
    pub ws_period_epochs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureRecord {
    pub eth_tx_id: [u8; 32],
    pub header: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureCache {
    header: Option<[u8; 32]>,
    by_tx: BTreeMap<[u8; 32], Vec<u8>>,
    pending: Vec<SignatureRecord>,
}

impl SignatureCache {
    pub const fn empty() -> Self {
        Self {
            header: None,
            by_tx: BTreeMap::new(),
            pending: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_tx.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.by_tx.is_empty() && self.pending.is_empty()
    }

    pub fn get(&self, eth_tx_id: &[u8; 32], header: &[u8; 32]) -> Option<Vec<u8>> {
        if self.header != Some(*header) {
            return None;
        }
        self.by_tx.get(eth_tx_id).cloned()
    }

    pub fn retain_current(&mut self, header: Option<[u8; 32]>) {
        let Some(header) = header else {
            *self = Self::empty();
            return;
        };
        if self.header != Some(header) {
            self.by_tx.clear();
            self.header = Some(header);
        }
        for record in self.pending.drain(..) {
            if record.header == header {
                self.by_tx.insert(record.eth_tx_id, record.signature);
            }
        }
    }

    pub fn remember(
        &mut self,
        current: &[u8; 32],
        signed_header: &[u8; 32],
        eth_tx_id: [u8; 32],
        signature: Vec<u8>,
    ) {
        self.retain_current(Some(*current));
        if signed_header == current {
            self.by_tx.insert(eth_tx_id, signature);
        }
    }

    fn from_records(records: Vec<SignatureRecord>) -> Self {
        let Some(first) = records.first() else {
            return Self::empty();
        };
        let header = first.header;
        if records.iter().all(|record| record.header == header) {
            let mut by_tx = BTreeMap::new();
            for record in records {
                by_tx.insert(record.eth_tx_id, record.signature);
            }
            return Self {
                header: Some(header),
                by_tx,
                pending: Vec::new(),
            };
        }
        Self {
            header: None,
            by_tx: BTreeMap::new(),
            pending: records,
        }
    }
}

impl Default for SignatureCache {
    fn default() -> Self {
        Self::empty()
    }
}

impl Serialize for SignatureCache {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut records = Vec::new();
        if let Some(header) = self.header {
            records.extend(
                self.by_tx
                    .iter()
                    .map(|(eth_tx_id, signature)| SignatureRecord {
                        eth_tx_id: *eth_tx_id,
                        header,
                        signature: signature.clone(),
                    }),
            );
        }
        records.extend(self.pending.iter().cloned());
        records.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignatureCache {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_records(Vec::<SignatureRecord>::deserialize(
            deserializer,
        )?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Persisted {
    pub chain: Chain,
    pub store: Option<Store>,
    pub public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub signatures: SignatureCache,
}

pub fn current_slot(now_secs: u64) -> u64 {
    now_secs.saturating_sub(GENESIS_TIME) / 12
}

pub fn participation_reaches_quorum(bits: u64, committee: u64) -> bool {
    bits * 3 >= committee * 2
}

pub fn outside_weak_subjectivity(
    finalized_slot: u64,
    now_secs: u64,
    ws_period_epochs: u64,
) -> bool {
    let finalized_epoch = finalized_slot / MainnetConsensusSpec::slots_per_epoch();
    let current_epoch = current_slot(now_secs) / MainnetConsensusSpec::slots_per_epoch();
    current_epoch > finalized_epoch.saturating_add(ws_period_epochs)
}

pub fn admit_public_fetch(
    checkpoint_is_set: bool,
    within_weak_subjectivity: bool,
    proofs_supplied: bool,
    cycles_available: u128,
    quote_cycles: u128,
) -> Result<Option<u128>, String> {
    if !checkpoint_is_set {
        return Err("Input error: checkpoint is not set".into());
    }
    if !within_weak_subjectivity {
        return Err("Input error: checkpoint is outside the weak subjectivity window".into());
    }
    if proofs_supplied {
        return Ok(None);
    }
    if quote_cycles == 0 || cycles_available < quote_cycles {
        return Err(format!(
            "Input error: fetching proofs requires {quote_cycles} cycles, attached {cycles_available}"
        ));
    }
    Ok(Some(quote_cycles))
}

pub fn finalized_beacon_root(store: &Store) -> [u8; 32] {
    store.finalized_header.beacon().tree_hash_root().0
}

pub fn admit_signature(cycles_available: u128, quote_cycles: u128) -> Result<u128, String> {
    if quote_cycles == 0 || cycles_available < quote_cycles {
        return Err(format!(
            "Input error: signing requires {quote_cycles} cycles, attached {cycles_available}"
        ));
    }
    Ok(quote_cycles)
}

pub fn finality_message(charms: &[u8; 20], eth_tx_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(U256::from(CHAIN_ID).to_be_bytes::<32>());
    hasher.update(charms);
    hasher.update(eth_tx_id);
    hasher.finalize().into()
}

pub fn reset_checkpoint(
    bytes: &[u8],
    now_secs: u64,
    ws_period_epochs: u64,
) -> Result<Store, String> {
    let bootstrap = decode_bootstrap(bytes)?;
    let root = bootstrap.header().beacon().tree_hash_root();
    verify_bootstrap(&bootstrap, root, &mainnet_forks())
        .map_err(|e| format!("Input error: bootstrap: {e}"))?;
    let slot = bootstrap.header().beacon().slot;
    if outside_weak_subjectivity(slot, now_secs, ws_period_epochs) {
        return Err("Input error: bootstrap is outside the weak subjectivity window".into());
    }
    let mut store = Store::default();
    apply_bootstrap(&mut store, &bootstrap);
    Ok(store)
}

pub fn stored_period(store: &Store) -> u64 {
    calc_sync_period::<MainnetConsensusSpec>(store.finalized_header.beacon().slot)
}

pub fn update_period_to_fetch(store: &Store) -> u64 {
    let stored = stored_period(store);
    if store.next_sync_committee.is_none() {
        stored
    } else {
        stored + 1
    }
}

pub fn period_of_finalized_header(update: &[u8]) -> Result<u64, String> {
    let update = decode_update(update)?;
    Ok(calc_sync_period::<MainnetConsensusSpec>(
        update.finalized_header().beacon().slot,
    ))
}

pub fn certify(
    store: &mut Option<Store>,
    now_secs: u64,
    chain: &Chain,
    eth_tx_id: &[u8; 32],
    update: Option<&[u8]>,
    finality: &[u8],
    proofs: &ExecProofs,
) -> Result<[u8; 32], String> {
    let store = store
        .as_mut()
        .ok_or_else(|| "Input error: checkpoint is not set".to_string())?;
    reject_if_stale(store, now_secs, chain.ws_period_epochs)?;
    let finality_update = decode_finality(finality)?;
    let fin_root = finality_update.finalized_header().beacon().tree_hash_root();
    if fin_root != store.finalized_header.beacon().tree_hash_root() {
        let signature_slot = *finality_update.signature_slot();
        if !period_covered(store, signature_slot) {
            let update = update.ok_or_else(|| {
                "Input error: stored committee cannot verify this finality update".to_string()
            })?;
            apply_period_update(store, update, now_secs, chain.ws_period_epochs)?;
        }
        if fin_root != store.finalized_header.beacon().tree_hash_root() {
            reject_if_stale(store, now_secs, chain.ws_period_epochs)?;
            quorum(finality_update.sync_aggregate())?;
            verify_finality_update(
                &finality_update,
                current_slot(now_secs),
                store,
                GENESIS_ROOT,
                &mainnet_forks(),
            )
            .map_err(|e| format!("Input error: finality update: {e}"))?;
            apply_finality_update(store, &finality_update);
            if fin_root != store.finalized_header.beacon().tree_hash_root() {
                return Err(
                    "Input error: finality update did not advance the finalized header".into(),
                );
            }
        }
    }

    let execution = store
        .finalized_header
        .execution()
        .map_err(|_| "Input error: finalized header has no execution payload".to_string())?;
    check_storage(
        *execution.state_root(),
        *execution.block_number(),
        chain,
        eth_tx_id,
        proofs,
    )?;
    Ok(finality_message(&chain.charms, eth_tx_id))
}

pub fn apply_period_update(
    store: &mut Store,
    bytes: &[u8],
    now_secs: u64,
    ws_period_epochs: u64,
) -> Result<(), String> {
    reject_if_stale(store, now_secs, ws_period_epochs)?;
    let update = decode_update(bytes)?;
    quorum(update.sync_aggregate())?;
    verify_update(
        &update,
        current_slot(now_secs),
        store,
        GENESIS_ROOT,
        &mainnet_forks(),
    )
    .map_err(|e| format!("Input error: light client update: {e}"))?;
    apply_update(store, &update);
    Ok(())
}

pub fn needs_period_update(store: &Store, finality: &[u8]) -> Result<bool, String> {
    let update = decode_finality(finality)?;
    if update.finalized_header().beacon().tree_hash_root()
        == store.finalized_header.beacon().tree_hash_root()
    {
        return Ok(false);
    }
    Ok(!period_covered(store, *update.signature_slot()))
}

pub fn execution_block_hash(finality: &[u8]) -> Result<B256, String> {
    let update = decode_finality(finality)?;
    let execution = update
        .finalized_header()
        .execution()
        .map_err(|_| "Input error: finality update has no execution payload".to_string())?;
    Ok(*execution.block_hash())
}

pub fn update_payloads(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if decode_update(bytes).is_ok() {
        return Ok(vec![bytes.to_vec()]);
    }
    let payloads = parse_update_chunks(bytes)?;
    if payloads.is_empty() {
        return Err("Input error: no light client update".into());
    }
    for payload in &payloads {
        decode_update(payload)?;
    }
    Ok(payloads)
}

pub fn finality_payload(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if decode_finality(bytes).is_ok() {
        return Ok(bytes.to_vec());
    }
    let payloads = parse_update_chunks(bytes)?;
    if payloads.len() != 1 {
        return Err("Input error: finality update".into());
    }
    decode_finality(&payloads[0])?;
    Ok(payloads[0].clone())
}

/// Beacon API octet-stream updates are a sequence of response chunks:
/// little-endian length, 4-byte fork digest, then the SSZ payload.
pub fn parse_update_chunks(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut pos = 0usize;
    let mut payloads = Vec::new();
    if bytes.is_empty() {
        return Ok(payloads);
    }
    while pos < bytes.len() {
        if bytes.len() - pos < 8 {
            return Err("Input error: truncated light client update chunk".into());
        }
        let chunk_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().expect("8")) as usize;
        pos += 8;
        if chunk_len < 4 || bytes.len() - pos < chunk_len {
            return Err("Input error: light client update chunk length".into());
        }
        payloads.push(bytes[pos + 4..pos + chunk_len].to_vec());
        pos += chunk_len;
    }
    Ok(payloads)
}

fn reject_if_stale(store: &Store, now_secs: u64, ws_period_epochs: u64) -> Result<(), String> {
    if outside_weak_subjectivity(
        store.finalized_header.beacon().slot,
        now_secs,
        ws_period_epochs,
    ) {
        Err("Input error: checkpoint is outside the weak subjectivity window".into())
    } else {
        Ok(())
    }
}

fn period_covered(store: &Store, signature_slot: u64) -> bool {
    let store_period =
        calc_sync_period::<MainnetConsensusSpec>(store.finalized_header.beacon().slot);
    let signature_period = calc_sync_period::<MainnetConsensusSpec>(signature_slot);
    if store.next_sync_committee.is_some() {
        signature_period == store_period || signature_period == store_period + 1
    } else {
        signature_period == store_period
    }
}

fn quorum<S: ConsensusSpec>(
    aggregate: &helios_consensus_core::types::SyncAggregate<S>,
) -> Result<(), String> {
    let bits = get_bits::<S>(&aggregate.sync_committee_bits);
    let size = S::sync_committee_size();
    if participation_reaches_quorum(bits, size) {
        Ok(())
    } else {
        Err(format!(
            "Input error: sync committee participation {bits} of {size}"
        ))
    }
}

fn decode_update(bytes: &[u8]) -> Result<Update<MainnetConsensusSpec>, String> {
    let inner = UpdateElectra::<MainnetConsensusSpec>::from_ssz_bytes(bytes)
        .map_err(|e| format!("Input error: light client update: {e:?}"))?;
    Ok(Update::Electra(inner))
}

fn decode_finality(bytes: &[u8]) -> Result<FinalityUpdate<MainnetConsensusSpec>, String> {
    let inner = FinalityUpdateElectra::<MainnetConsensusSpec>::from_ssz_bytes(bytes)
        .map_err(|e| format!("Input error: finality update: {e:?}"))?;
    Ok(FinalityUpdate::Electra(inner))
}

fn decode_bootstrap(bytes: &[u8]) -> Result<Bootstrap<MainnetConsensusSpec>, String> {
    let inner = BootstrapElectra::<MainnetConsensusSpec>::from_ssz_bytes(bytes)
        .map_err(|e| format!("Input error: bootstrap: {e:?}"))?;
    Ok(Bootstrap::Electra(inner))
}

fn mainnet_forks() -> Forks {
    Forks {
        genesis: Fork {
            epoch: 0,
            fork_version: fixed_bytes!("00000000"),
        },
        altair: Fork {
            epoch: 74_240,
            fork_version: fixed_bytes!("01000000"),
        },
        bellatrix: Fork {
            epoch: 144_896,
            fork_version: fixed_bytes!("02000000"),
        },
        capella: Fork {
            epoch: 194_048,
            fork_version: fixed_bytes!("03000000"),
        },
        deneb: Fork {
            epoch: 269_568,
            fork_version: fixed_bytes!("04000000"),
        },
        electra: Fork {
            epoch: 364_032,
            fork_version: fixed_bytes!("05000000"),
        },
        fulu: Fork {
            epoch: 411_392,
            fork_version: fixed_bytes!("06000000"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_is_the_domain_hash() {
        let expected =
            hex::decode("f135357a203055459dfaf7ca289af532e3e48e5797907eb32819090e49baf794")
                .unwrap();
        let message = finality_message(&[0x11; 20], &[0x22; 32]);
        assert_eq!(message.to_vec(), expected);
    }

    #[test]
    fn quorum_boundary_is_342_of_512() {
        assert!(!participation_reaches_quorum(341, 512));
        assert!(participation_reaches_quorum(342, 512));
        assert!(participation_reaches_quorum(512, 512));
    }

    #[test]
    fn weak_subjectivity_rejects_the_next_epoch() {
        let finalized_slot = 100 * 32;
        let ws = 10;
        let inside = GENESIS_TIME + (110 * 32) * 12;
        let past = GENESIS_TIME + (111 * 32) * 12;
        assert!(!outside_weak_subjectivity(finalized_slot, inside, ws));
        assert!(outside_weak_subjectivity(finalized_slot, past, ws));
    }

    #[test]
    fn slot_zero_is_genesis() {
        assert_eq!(current_slot(GENESIS_TIME), 0);
        assert_eq!(current_slot(GENESIS_TIME + 12), 1);
        assert_eq!(current_slot(GENESIS_TIME + 11), 0);
    }

    #[test]
    fn garbage_bootstrap_is_rejected() {
        let err = reset_checkpoint(&[0, 1, 2, 3], GENESIS_TIME, 3532).unwrap_err();
        assert!(err.starts_with("Input error: bootstrap:"), "{err}");
    }

    #[test]
    fn one_chunk_round_trips_its_payload() {
        let payload = b"electra-update".to_vec();
        let mut bytes = Vec::new();
        let chunk_len = (4 + payload.len()) as u64;
        bytes.extend_from_slice(&chunk_len.to_le_bytes());
        bytes.extend_from_slice(&[9, 9, 9, 9]);
        bytes.extend_from_slice(&payload);
        let parsed = parse_update_chunks(&bytes).unwrap();
        assert_eq!(parsed, vec![payload]);
    }

    #[test]
    fn truncated_chunk_is_rejected() {
        let err = parse_update_chunks(&[4, 0, 0, 0, 0, 0, 0, 0, 1, 2]).unwrap_err();
        assert_eq!(err, "Input error: light client update chunk length");
    }

    #[test]
    fn public_fetch_requires_a_ready_checkpoint_and_cycles() {
        let unset = admit_public_fetch(false, true, false, 50, 10).unwrap_err();
        assert_eq!(unset, "Input error: checkpoint is not set");
        let stale = admit_public_fetch(true, false, true, 50, 10).unwrap_err();
        assert_eq!(
            stale,
            "Input error: checkpoint is outside the weak subjectivity window"
        );
        let short = admit_public_fetch(true, true, false, 9, 10).unwrap_err();
        assert_eq!(
            short,
            "Input error: fetching proofs requires 10 cycles, attached 9"
        );
        assert_eq!(
            admit_public_fetch(true, true, false, 10, 10).unwrap(),
            Some(10)
        );
        assert_eq!(admit_public_fetch(true, true, true, 0, 0).unwrap(), None);
    }

    #[test]
    fn signature_cache_keeps_only_the_current_header() {
        let mut cache = SignatureCache::empty();
        let old = [2u8; 32];
        let new = [3u8; 32];
        cache.remember(&old, &old, [1; 32], vec![9; 64]);
        cache.remember(&old, &old, [4; 32], vec![8; 64]);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&[1; 32], &old).unwrap(), vec![9; 64]);

        cache.remember(&new, &old, [1; 32], vec![7; 64]);
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&[1; 32], &old).is_none());
        assert!(cache.get(&[4; 32], &old).is_none());
        assert!(cache.get(&[1; 32], &new).is_none());

        cache.remember(&new, &new, [1; 32], vec![6; 64]);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&[1; 32], &new).unwrap(), vec![6; 64]);
        assert!(cache.get(&[4; 32], &new).is_none());
    }

    #[test]
    fn signing_requires_cycles_on_a_cache_miss() {
        let short = admit_signature(25, 26).unwrap_err();
        assert_eq!(
            short,
            "Input error: signing requires 26 cycles, attached 25"
        );
        assert_eq!(admit_signature(26, 26).unwrap(), 26);
        let free = admit_signature(26, 0).unwrap_err();
        assert_eq!(free, "Input error: signing requires 0 cycles, attached 26");
    }

    #[test]
    fn store_json_keeps_the_finalized_slot() {
        let mut store = Store::default();
        store.finalized_header.beacon_mut().slot = 99;
        let persisted = Persisted {
            chain: Chain {
                beacon_api: "https://beacon.example".into(),
                execution_api: "https://execution.example".into(),
                charms: [1; 20],
                implementation: [2; 20],
                proxy_code_hash: [3; 32],
                beam_source_slot: 7,
                ws_period_epochs: 3532,
            },
            store: Some(store),
            public_key: Some(vec![4; 32]),
            signatures: {
                let mut cache = SignatureCache::empty();
                cache.remember(&[6; 32], &[6; 32], [5; 32], vec![7; 64]);
                cache
            },
        };
        let bytes = serde_json::to_vec(&persisted).unwrap();
        let back: Persisted = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.store.unwrap().finalized_header.beacon().slot, 99);
        assert_eq!(back.public_key.unwrap(), vec![4; 32]);
        assert_eq!(back.chain.beam_source_slot, 7);
        assert_eq!(back.signatures, persisted.signatures);
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value.as_object_mut().unwrap().remove("signatures");
        let older: Persisted = serde_json::from_value(value).unwrap();
        assert!(older.signatures.is_empty());

        let legacy = vec![
            SignatureRecord {
                eth_tx_id: [5; 32],
                header: [6; 32],
                signature: vec![7; 64],
            },
            SignatureRecord {
                eth_tx_id: [8; 32],
                header: [9; 32],
                signature: vec![1; 64],
            },
        ];
        let mut loaded: SignatureCache =
            serde_json::from_slice(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(loaded.len(), 0);
        loaded.retain_current(Some([6; 32]));
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&[5; 32], &[6; 32]).unwrap(), vec![7; 64]);
        let kept: Vec<SignatureRecord> =
            serde_json::from_slice(&serde_json::to_vec(&loaded).unwrap()).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].header, [6; 32]);
        assert_eq!(kept[0].eth_tx_id, [5; 32]);
    }
}
