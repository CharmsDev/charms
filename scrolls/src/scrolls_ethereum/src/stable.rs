use serde::{Deserialize, Serialize};

use crate::light::{Chain, CurrentSignatures, Persisted, SignatureCache, Store, StoredSignature};

const MAGIC: [u8; 4] = *b"SCE1";
const VERSION: u32 = 1;
const HEAD: u64 = 24;
const DATA_START: u64 = 8 + 10 * HEAD;
const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy)]
enum Slot {
    Chain = 0,
    PublicKey = 1,
    StoreFlag = 2,
    FinalizedHeader = 3,
    OptimisticHeader = 4,
    CurrentCommittee = 5,
    NextCommittee = 6,
    Participants = 7,
    BestUpdate = 8,
    Signatures = 9,
}

impl Slot {
    const ALL: [Slot; 10] = [
        Slot::Chain,
        Slot::PublicKey,
        Slot::StoreFlag,
        Slot::FinalizedHeader,
        Slot::OptimisticHeader,
        Slot::CurrentCommittee,
        Slot::NextCommittee,
        Slot::Participants,
        Slot::BestUpdate,
        Slot::Signatures,
    ];

    fn index(self) -> u64 {
        self as u64
    }
}

struct SlotHead {
    offset: u64,
    len: u64,
    cap: u64,
}

impl SlotHead {
    fn empty() -> Self {
        Self {
            offset: 0,
            len: 0,
            cap: 0,
        }
    }
}

pub(crate) trait Memory {
    fn byte_size(&self) -> u64;
    fn read(&self, offset: u64, dst: &mut [u8]);
    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), String>;
}

pub(crate) struct IcStable;

impl Memory for IcStable {
    fn byte_size(&self) -> u64 {
        ic_cdk::stable::stable_size() * 65_536
    }

    fn read(&self, offset: u64, dst: &mut [u8]) {
        ic_cdk::stable::stable_read(offset, dst);
    }

    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), String> {
        let end = offset + src.len() as u64;
        let have = self.byte_size();
        if have < end {
            let pages = (end - have).div_ceil(65_536);
            ic_cdk::stable::stable_grow(pages).map_err(|e| e.to_string())?;
        }
        ic_cdk::stable::stable_write(offset, src);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) struct VecMemory {
    bytes: Vec<u8>,
    pub written: u64,
}

#[cfg(test)]
impl VecMemory {
    pub(crate) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            written: 0,
        }
    }
}

#[cfg(test)]
impl Memory for VecMemory {
    fn byte_size(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read(&self, offset: u64, dst: &mut [u8]) {
        let start = offset as usize;
        for (index, byte) in dst.iter_mut().enumerate() {
            *byte = self.bytes.get(start + index).copied().unwrap_or(0);
        }
    }

    fn write(&mut self, offset: u64, src: &[u8]) -> Result<(), String> {
        let start = offset as usize;
        let end = start + src.len();
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
        }
        self.bytes[start..end].copy_from_slice(src);
        self.written += src.len() as u64;
        Ok(())
    }
}

pub(crate) enum Loaded {
    Records(Persisted),
    Legacy(Persisted),
}

impl Loaded {
    pub(crate) fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }

    pub(crate) fn into_persisted(self) -> Persisted {
        match self {
            Self::Records(state) | Self::Legacy(state) => state,
        }
    }
}

pub(crate) fn load(mem: &impl Memory) -> Result<Loaded, String> {
    if mem.byte_size() < 8 {
        return Err("stable memory is empty".into());
    }
    let mut magic = [0u8; 4];
    mem.read(0, &mut magic);
    if magic == MAGIC {
        let mut version = [0u8; 4];
        mem.read(4, &mut version);
        if u32::from_le_bytes(version) != VERSION {
            return Err("stable memory version".into());
        }
        return Ok(Loaded::Records(load_records(mem)?));
    }
    Ok(Loaded::Legacy(load_legacy(mem)?))
}

pub(crate) fn save_all(state: &Persisted, mem: &mut impl Memory) -> Result<(), String> {
    format_directory(mem)?;
    write_chain(&state.chain, mem)?;
    write_key(state.public_key.as_deref(), mem)?;
    write_store(state.store.as_ref(), mem)?;
    write_signatures(&state.signatures, mem)?;
    Ok(())
}

pub(crate) fn flush(
    before: &Persisted,
    after: &Persisted,
    mem: &mut impl Memory,
) -> Result<(), String> {
    if mem.byte_size() < 8 {
        return save_all(after, mem);
    }
    let mut magic = [0u8; 4];
    mem.read(0, &mut magic);
    if magic != MAGIC {
        return save_all(after, mem);
    }
    if before.chain != after.chain {
        write_chain(&after.chain, mem)?;
    }
    if before.public_key != after.public_key {
        write_key(after.public_key.as_deref(), mem)?;
    }
    flush_store(before.store.as_ref(), after.store.as_ref(), mem)?;
    let before_sigs = encode_signatures(&before.signatures)?;
    let after_sigs = encode_signatures(&after.signatures)?;
    if before_sigs != after_sigs {
        write_slot(mem, Slot::Signatures, &after_sigs)?;
    }
    Ok(())
}

fn load_records(mem: &impl Memory) -> Result<Persisted, String> {
    let chain = from_json(&read_slot(mem, Slot::Chain)?)?;
    let public_key = {
        let bytes = read_slot(mem, Slot::PublicKey)?;
        if bytes.is_empty() { None } else { Some(bytes) }
    };
    let store = if read_slot(mem, Slot::StoreFlag)?.as_slice() == [1] {
        Some(load_store(mem)?)
    } else {
        None
    };
    let signatures = decode_signatures(&read_slot(mem, Slot::Signatures)?)?;
    Ok(Persisted {
        chain,
        store,
        public_key,
        signatures,
    })
}

fn load_store(mem: &impl Memory) -> Result<Store, String> {
    let participants = read_slot(mem, Slot::Participants)?;
    if participants.len() != 16 {
        return Err("participant record length".into());
    }
    let previous = u64::from_le_bytes(words(&participants[..8])?);
    let current = u64::from_le_bytes(words(&participants[8..])?);
    let next = optional_json(mem, Slot::NextCommittee)?;
    let best = optional_json(mem, Slot::BestUpdate)?;
    Ok(Store {
        finalized_header: from_json(&read_slot(mem, Slot::FinalizedHeader)?)?,
        current_sync_committee: from_json(&read_slot(mem, Slot::CurrentCommittee)?)?,
        next_sync_committee: next,
        optimistic_header: from_json(&read_slot(mem, Slot::OptimisticHeader)?)?,
        previous_max_active_participants: previous,
        current_max_active_participants: current,
        best_valid_update: best,
    })
}

fn load_legacy(mem: &impl Memory) -> Result<Persisted, String> {
    let mut len_bytes = [0u8; 8];
    mem.read(0, &mut len_bytes);
    let len = u64::from_le_bytes(len_bytes);
    let Some(end) = len.checked_add(8) else {
        return Err("stable memory is not a scrolls_ethereum record".into());
    };
    if len == 0 || end > mem.byte_size() {
        return Err("stable memory is not a scrolls_ethereum record".into());
    }
    let bytes = read_at(mem, 8, len)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("stable record: {e}"))
}

fn flush_store(
    before: Option<&Store>,
    after: Option<&Store>,
    mem: &mut impl Memory,
) -> Result<(), String> {
    match (before, after) {
        (None, None) => Ok(()),
        (_, None) => write_slot(mem, Slot::StoreFlag, &[0]),
        (None, Some(after)) => write_store(Some(after), mem),
        (Some(before), Some(after)) => {
            if before.finalized_header != after.finalized_header {
                write_json_slot(mem, Slot::FinalizedHeader, &after.finalized_header)?;
            }
            if before.optimistic_header != after.optimistic_header {
                write_json_slot(mem, Slot::OptimisticHeader, &after.optimistic_header)?;
            }
            if before.current_sync_committee != after.current_sync_committee {
                write_json_slot(mem, Slot::CurrentCommittee, &after.current_sync_committee)?;
            }
            if before.next_sync_committee != after.next_sync_committee {
                write_optional_json(mem, Slot::NextCommittee, &after.next_sync_committee)?;
            }
            if before.previous_max_active_participants != after.previous_max_active_participants
                || before.current_max_active_participants != after.current_max_active_participants
            {
                write_slot(mem, Slot::Participants, &participant_bytes(after))?;
            }
            if best_changed(before, after)? {
                write_optional_json(mem, Slot::BestUpdate, &after.best_valid_update)?;
            }
            Ok(())
        }
    }
}

fn write_store(store: Option<&Store>, mem: &mut impl Memory) -> Result<(), String> {
    let Some(store) = store else {
        return write_slot(mem, Slot::StoreFlag, &[0]);
    };
    write_slot(mem, Slot::StoreFlag, &[1])?;
    write_json_slot(mem, Slot::FinalizedHeader, &store.finalized_header)?;
    write_json_slot(mem, Slot::OptimisticHeader, &store.optimistic_header)?;
    write_json_slot(mem, Slot::CurrentCommittee, &store.current_sync_committee)?;
    write_optional_json(mem, Slot::NextCommittee, &store.next_sync_committee)?;
    write_slot(mem, Slot::Participants, &participant_bytes(store))?;
    write_optional_json(mem, Slot::BestUpdate, &store.best_valid_update)?;
    Ok(())
}

fn write_chain(chain: &Chain, mem: &mut impl Memory) -> Result<(), String> {
    write_json_slot(mem, Slot::Chain, chain)
}

fn write_key(key: Option<&[u8]>, mem: &mut impl Memory) -> Result<(), String> {
    write_slot(mem, Slot::PublicKey, key.unwrap_or_default())
}

fn write_signatures(cache: &SignatureCache, mem: &mut impl Memory) -> Result<(), String> {
    write_slot(mem, Slot::Signatures, &encode_signatures(cache)?)
}

fn best_changed(before: &Store, after: &Store) -> Result<bool, String> {
    match (&before.best_valid_update, &after.best_valid_update) {
        (None, None) => Ok(false),
        (Some(left), Some(right)) => Ok(to_json(left)? != to_json(right)?),
        _ => Ok(true),
    }
}

fn participant_bytes(store: &Store) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&store.previous_max_active_participants.to_le_bytes());
    bytes[8..].copy_from_slice(&store.current_max_active_participants.to_le_bytes());
    bytes
}

fn write_optional_json<T: Serialize>(
    mem: &mut impl Memory,
    slot: Slot,
    value: &Option<T>,
) -> Result<(), String> {
    match value {
        Some(value) => write_json_slot(mem, slot, value),
        None => write_slot(mem, slot, &[]),
    }
}

fn write_json_slot<T: Serialize>(
    mem: &mut impl Memory,
    slot: Slot,
    value: &T,
) -> Result<(), String> {
    write_slot(mem, slot, &to_json(value)?)
}

fn optional_json<T: for<'de> Deserialize<'de>>(
    mem: &impl Memory,
    slot: Slot,
) -> Result<Option<T>, String> {
    let bytes = read_slot(mem, slot)?;
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(from_json(&bytes)?))
    }
}

fn encode_signatures(cache: &SignatureCache) -> Result<Vec<u8>, String> {
    let Some(exported) = cache.export_current() else {
        return Ok(Vec::new());
    };
    let count =
        u32::try_from(exported.entries.len()).map_err(|_| "signature cache is too large")?;
    let mut bytes = Vec::with_capacity(36 + exported.entries.len() * 96);
    bytes.extend(exported.header);
    bytes.extend(count.to_le_bytes());
    for entry in exported.entries {
        if entry.signature.len() != SIGNATURE_LEN {
            return Err("signature length".into());
        }
        bytes.extend(entry.eth_tx_id);
        bytes.extend(entry.signature);
    }
    Ok(bytes)
}

fn decode_signatures(bytes: &[u8]) -> Result<SignatureCache, String> {
    if bytes.is_empty() {
        return Ok(SignatureCache::empty());
    }
    if bytes.len() < 36 {
        return Err("signature record is short".into());
    }
    let header: [u8; 32] = words(&bytes[..32])?;
    let count = u32::from_le_bytes(words(&bytes[32..36])?) as usize;
    let rest = &bytes[36..];
    if rest.len() != count * 96 {
        return Err("signature record length".into());
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * 96;
        entries.push(StoredSignature {
            eth_tx_id: words(&rest[start..start + 32])?,
            signature: rest[start + 32..start + 96].to_vec(),
        });
    }
    Ok(SignatureCache::import_current(Some(CurrentSignatures {
        header,
        entries,
    })))
}

fn format_directory(mem: &mut impl Memory) -> Result<(), String> {
    mem.write(0, &MAGIC)?;
    mem.write(4, &VERSION.to_le_bytes())?;
    mem.write(8, &vec![0u8; (DATA_START - 8) as usize])?;
    Ok(())
}

fn write_slot(mem: &mut impl Memory, slot: Slot, bytes: &[u8]) -> Result<(), String> {
    let head = read_head(mem, slot)?;
    if head.len as usize == bytes.len() && payload_matches(mem, &head, bytes)? {
        return Ok(());
    }
    if head.offset != 0 && bytes.len() as u64 <= head.cap {
        write_in_place(mem, &head, bytes)?;
        return write_head(
            mem,
            slot,
            SlotHead {
                offset: head.offset,
                len: bytes.len() as u64,
                cap: head.cap,
            },
        );
    }
    let end = data_end(mem)?;
    if head.offset != 0 && head.cap > 0 && head.offset.saturating_add(head.cap) == end {
        return place(mem, slot, head.offset, bytes);
    }
    if head.offset != 0 && head.cap > 0 {
        mem.write(head.offset, &vec![0u8; head.cap as usize])?;
    }
    let offset = if bytes.is_empty() { 0 } else { end };
    place(mem, slot, offset, bytes)
}

fn place(mem: &mut impl Memory, slot: Slot, offset: u64, bytes: &[u8]) -> Result<(), String> {
    if offset != 0 && !bytes.is_empty() {
        mem.write(offset, bytes)?;
    }
    write_head(
        mem,
        slot,
        SlotHead {
            offset,
            len: bytes.len() as u64,
            cap: bytes.len() as u64,
        },
    )
}

fn write_in_place(mem: &mut impl Memory, head: &SlotHead, bytes: &[u8]) -> Result<(), String> {
    if !bytes.is_empty() {
        mem.write(head.offset, bytes)?;
    }
    if (bytes.len() as u64) < head.len {
        let zeros = vec![0u8; head.len as usize - bytes.len()];
        mem.write(head.offset + bytes.len() as u64, &zeros)?;
    }
    Ok(())
}

fn payload_matches(mem: &impl Memory, head: &SlotHead, bytes: &[u8]) -> Result<bool, String> {
    if head.len as usize != bytes.len() {
        return Ok(false);
    }
    if bytes.is_empty() {
        return Ok(true);
    }
    if head.offset == 0 {
        return Ok(false);
    }
    Ok(read_at(mem, head.offset, head.len)? == bytes)
}

fn write_head(mem: &mut impl Memory, slot: Slot, head: SlotHead) -> Result<(), String> {
    let mut bytes = [0u8; 24];
    bytes[..8].copy_from_slice(&head.offset.to_le_bytes());
    bytes[8..16].copy_from_slice(&head.len.to_le_bytes());
    bytes[16..].copy_from_slice(&head.cap.to_le_bytes());
    mem.write(8 + slot.index() * HEAD, &bytes)
}

fn read_head(mem: &impl Memory, slot: Slot) -> Result<SlotHead, String> {
    let at = 8 + slot.index() * HEAD;
    if mem.byte_size() < at + HEAD {
        return Ok(SlotHead::empty());
    }
    let bytes = read_at(mem, at, HEAD)?;
    Ok(SlotHead {
        offset: u64::from_le_bytes(words(&bytes[..8])?),
        len: u64::from_le_bytes(words(&bytes[8..16])?),
        cap: u64::from_le_bytes(words(&bytes[16..])?),
    })
}

fn read_slot(mem: &impl Memory, slot: Slot) -> Result<Vec<u8>, String> {
    let head = read_head(mem, slot)?;
    if head.len == 0 {
        return Ok(Vec::new());
    }
    read_at(mem, head.offset, head.len)
}

fn data_end(mem: &impl Memory) -> Result<u64, String> {
    let mut end = DATA_START;
    for slot in Slot::ALL {
        let head = read_head(mem, slot)?;
        if head.offset != 0 {
            end = end.max(head.offset.saturating_add(head.cap));
        }
    }
    Ok(end)
}

fn read_at(mem: &impl Memory, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let end = offset.saturating_add(len);
    if offset.saturating_add(len) < offset || end > mem.byte_size() {
        return Err("stable record is out of range".into());
    }
    let mut bytes = vec![0u8; len as usize];
    mem.read(offset, &mut bytes);
    Ok(bytes)
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| format!("stable record: {e}"))
}

fn from_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("stable record: {e}"))
}

fn words<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| "stable record length".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::light::finalized_beacon_root;

    fn chain() -> Chain {
        Chain {
            beacon_api: "https://beacon.example".into(),
            execution_api: "https://execution.example".into(),
            charms: [1; 20],
            implementation: [2; 20],
            proxy_code_hash: [3; 32],
            beam_source_slot: 7,
            ws_period_epochs: 3532,
        }
    }

    fn sample() -> Persisted {
        let mut store = Store::default();
        let header = crate::consensus_fixture::electra_light_header(99);
        store.finalized_header = header.clone();
        store.optimistic_header = header;
        store.next_sync_committee = Some(store.current_sync_committee.clone());
        let header = finalized_beacon_root(&store);
        let mut signatures = SignatureCache::empty();
        signatures.remember(&header, &header, [5; 32], vec![7; 64]);
        Persisted {
            chain: chain(),
            store: Some(store),
            public_key: Some(vec![4; 32]),
            signatures,
        }
    }

    fn bare(public_key: Option<Vec<u8>>) -> Persisted {
        Persisted {
            chain: chain(),
            store: None,
            public_key,
            signatures: SignatureCache::empty(),
        }
    }

    fn snapshot_len(state: &Persisted) -> u64 {
        8 + serde_json::to_vec(state).unwrap().len() as u64
    }

    #[test]
    fn upgrade_restores_checkpoint_and_current_header_signatures() {
        let state = sample();
        let header = finalized_beacon_root(state.store.as_ref().unwrap());
        let mut memory = VecMemory::new();
        save_all(&state, &mut memory).unwrap();
        let loaded = load(&memory).unwrap();
        assert!(!loaded.is_legacy());
        let loaded = loaded.into_persisted();
        let store = loaded.store.unwrap();
        assert_eq!(store.finalized_header.beacon().slot, 99);
        assert!(store.next_sync_committee.is_some());
        assert_eq!(loaded.public_key.unwrap(), vec![4; 32]);
        assert_eq!(loaded.chain.ws_period_epochs, 3532);
        assert_eq!(
            loaded.signatures.get(&[5; 32], &header).unwrap(),
            vec![7; 64]
        );
        assert!(loaded.signatures.get(&[9; 32], &header).is_none());
    }

    #[test]
    fn late_signature_for_a_retired_header_is_not_in_stable_memory() {
        let mut state = sample();
        let old = finalized_beacon_root(state.store.as_ref().unwrap());
        let mut memory = VecMemory::new();
        save_all(&state, &mut memory).unwrap();

        let before = state.clone();
        let store = state.store.as_mut().unwrap();
        store.finalized_header.beacon_mut().slot = 98;
        let current = finalized_beacon_root(store);
        state
            .signatures
            .remember(&current, &old, [5; 32], vec![1; 64]);
        flush(&before, &state, &mut memory).unwrap();

        let loaded = load(&memory).unwrap().into_persisted();
        let store = loaded.store.unwrap();
        assert_eq!(store.finalized_header.beacon().slot, 98);
        assert!(loaded.signatures.get(&[5; 32], &old).is_none());
        assert!(loaded.signatures.get(&[5; 32], &current).is_none());
        assert!(loaded.signatures.is_empty());
        let raw = read_slot(&memory, Slot::Signatures).unwrap();
        assert!(raw.is_empty());
    }

    fn written(memory: &mut VecMemory, before: &Persisted, after: &Persisted) -> u64 {
        memory.written = 0;
        flush(before, after, memory).unwrap();
        memory.written
    }

    #[test]
    fn certify_writes_changed_records_not_the_snapshot() {
        let snapshot = snapshot_len(&sample());
        let mut quiet = sample();
        quiet.signatures = SignatureCache::empty();
        quiet.store.as_mut().unwrap().next_sync_committee = None;
        let mut memory = VecMemory::new();
        save_all(&quiet, &mut memory).unwrap();
        let current_committee = read_slot(&memory, Slot::CurrentCommittee).unwrap();

        assert_eq!(written(&mut memory, &quiet, &quiet), 0);

        let mut header_only = quiet.clone();
        header_only
            .store
            .as_mut()
            .unwrap()
            .finalized_header
            .beacon_mut()
            .slot = 98;
        let header_bytes = written(&mut memory, &quiet, &header_only);
        let loaded = load(&memory).unwrap().into_persisted();
        assert_eq!(
            loaded
                .store
                .as_ref()
                .unwrap()
                .finalized_header
                .beacon()
                .slot,
            98
        );
        assert!(loaded.signatures.is_empty());

        let mut optimistic_only = header_only.clone();
        let store = optimistic_only.store.as_mut().unwrap();
        store.optimistic_header = store.finalized_header.clone();
        let optimistic_bytes = written(&mut memory, &header_only, &optimistic_only);

        let mut advanced = optimistic_only.clone();
        advanced
            .store
            .as_mut()
            .unwrap()
            .current_max_active_participants = 342;
        let participant_bytes = written(&mut memory, &optimistic_only, &advanced);
        let finality_bytes = header_bytes + optimistic_bytes + participant_bytes;
        assert_eq!(
            read_slot(&memory, Slot::CurrentCommittee).unwrap(),
            current_committee
        );
        assert!(read_slot(&memory, Slot::NextCommittee).unwrap().is_empty());

        let mut rotated = advanced.clone();
        let store = rotated.store.as_mut().unwrap();
        store.next_sync_committee = Some(store.current_sync_committee.clone());
        let rotation_bytes = written(&mut memory, &advanced, &rotated);
        assert_eq!(
            read_slot(&memory, Slot::CurrentCommittee).unwrap(),
            current_committee
        );
        let loaded = load(&memory).unwrap().into_persisted();
        assert!(loaded.store.unwrap().next_sync_committee.is_some());

        let mut signed_memory = VecMemory::new();
        save_all(&quiet, &mut signed_memory).unwrap();
        let mut signed = quiet.clone();
        let header = finalized_beacon_root(signed.store.as_ref().unwrap());
        signed
            .signatures
            .remember(&header, &header, [8; 32], vec![6; 64]);
        let signature_bytes = written(&mut signed_memory, &quiet, &signed);
        let loaded = load(&signed_memory).unwrap().into_persisted();
        assert_eq!(loaded.signatures.get(&[8; 32], &header).unwrap(), vec![6; 64]);

        assert_eq!(
            (
                snapshot,
                signature_bytes,
                header_bytes,
                optimistic_bytes,
                participant_bytes,
                finality_bytes,
                rotation_bytes,
            ),
            (108_542, 156, 1_959, 1_959, 40, 3_958, 51_869)
        );

        let mut retired = signed.clone();
        let store = retired.store.as_mut().unwrap();
        store.finalized_header.beacon_mut().slot = 98;
        let current = finalized_beacon_root(store);
        retired.signatures.retain_current(Some(current));
        written(&mut signed_memory, &signed, &retired);
        let loaded = load(&signed_memory).unwrap().into_persisted();
        assert_eq!(loaded.store.unwrap().finalized_header.beacon().slot, 98);
        assert!(loaded.signatures.is_empty());
        assert!(read_slot(&signed_memory, Slot::Signatures).unwrap().is_empty());
    }

    #[test]
    fn legacy_json_blob_loads_once() {
        let state = sample();
        let bytes = serde_json::to_vec(&state).unwrap();
        let mut prefixed = (bytes.len() as u64).to_le_bytes().to_vec();
        prefixed.extend(bytes);
        let mut memory = VecMemory::new();
        memory.write(0, &prefixed).unwrap();
        let loaded = load(&memory).unwrap();
        assert!(loaded.is_legacy());
        let loaded = loaded.into_persisted();
        assert_eq!(
            loaded
                .store
                .as_ref()
                .unwrap()
                .finalized_header
                .beacon()
                .slot,
            99
        );
        save_all(&loaded, &mut memory).unwrap();
        let again = load(&memory).unwrap();
        assert!(!again.is_legacy());
        assert_eq!(
            again
                .into_persisted()
                .store
                .unwrap()
                .finalized_header
                .beacon()
                .slot,
            99
        );
    }

    #[test]
    fn signature_growth_keeps_stable_memory_with_the_live_record() {
        let mut memory = VecMemory::new();
        save_all(&bare(None), &mut memory).unwrap();
        let base = memory.byte_size();
        let header = [4u8; 32];
        let mut cache = SignatureCache::empty();
        for i in 0..1_000u32 {
            let mut tx = [0u8; 32];
            tx[..4].copy_from_slice(&i.to_le_bytes());
            cache.remember(&header, &header, tx, vec![9; 64]);
            write_signatures(&cache, &mut memory).unwrap();
        }
        let live = encode_signatures(&cache).unwrap().len() as u64;
        assert_eq!(memory.byte_size(), base + live);
        let loaded = load(&memory).unwrap().into_persisted();
        assert_eq!(loaded.signatures.len(), 1_000);
        let mut first = [0u8; 32];
        first[..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(loaded.signatures.get(&first, &header).unwrap(), vec![9; 64]);
    }

    #[test]
    fn record_before_the_tail_moves_once_then_grows_in_place() {
        let header = [4u8; 32];
        let mut cache = SignatureCache::empty();
        cache.remember(&header, &header, [1; 32], vec![2; 64]);
        let mut state = bare(Some(vec![1]));
        state.signatures = cache;
        let mut memory = VecMemory::new();
        save_all(&state, &mut memory).unwrap();
        let base = memory.byte_size();
        let signature = read_slot(&memory, Slot::Signatures).unwrap();
        for len in 2..=40 {
            write_key(Some(&vec![3; len]), &mut memory).unwrap();
        }
        assert_eq!(memory.byte_size(), base + 40);
        assert_eq!(read_slot(&memory, Slot::PublicKey).unwrap().len(), 40);
        assert_eq!(read_slot(&memory, Slot::Signatures).unwrap(), signature);
    }

    #[test]
    fn legacy_snapshot_over_two_mib_migrates() {
        let header = [6u8; 32];
        let mut signatures = SignatureCache::empty();
        for i in 0..10_000u32 {
            let mut tx = [0u8; 32];
            tx[..4].copy_from_slice(&i.to_le_bytes());
            signatures.remember(&header, &header, tx, vec![7; 64]);
        }
        let mut state = bare(Some(vec![4; 32]));
        state.signatures = signatures;
        let mut bytes = serde_json::to_vec(&state).unwrap();
        if bytes.len() < 3_569_549 {
            let pad = 3_569_549 - bytes.len();
            state.chain.beacon_api.push_str(&"a".repeat(pad));
            bytes = serde_json::to_vec(&state).unwrap();
        }
        assert_eq!(bytes.len(), 3_569_549);
        let mut prefixed = (bytes.len() as u64).to_le_bytes().to_vec();
        prefixed.extend(bytes);
        let mut memory = VecMemory::new();
        memory.write(0, &prefixed).unwrap();
        let loaded = load(&memory).unwrap();
        assert!(loaded.is_legacy());
        let loaded = loaded.into_persisted();
        assert_eq!(loaded.signatures.len(), 10_000);
        let mut first = [0u8; 32];
        first[..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(loaded.signatures.get(&first, &header).unwrap(), vec![7; 64]);
        save_all(&loaded, &mut memory).unwrap();
        let again = load(&memory).unwrap();
        assert!(!again.is_legacy());
        assert_eq!(again.into_persisted().signatures.len(), 10_000);
    }
}
