use alloy::primitives::{Address, B256, U256, b256};
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
};
use helios_consensus_core::{
    consensus_spec::MainnetConsensusSpec,
    types::{
        BeaconBlockHeader, ExecutionPayloadHeader, ExecutionPayloadHeaderElectra, LogsBloom,
        SyncAggregate, SyncCommittee,
        bls::{PublicKey, Signature},
        bytes::ByteList,
    },
};
use sha2::{Digest, Sha256};
use sha2_v9::Sha256 as Sha256v9;
use ssz::{Decode, Encode};
use ssz_types::{BitVector, FixedVector, typenum, typenum::Unsigned};
use tree_hash::TreeHash;

use crate::{light, trie::fixture_exec_proofs};

const GENESIS_ROOT: B256 =
    b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
const FULU_START_SLOT: u64 = 13_164_544;
const PERIOD_SLOTS: u64 = 8_192;
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

type Committee = SyncCommittee<MainnetConsensusSpec>;
type Aggregate = SyncAggregate<MainnetConsensusSpec>;

#[test]
fn electra_update_verifies_a_signature_and_rotates_committees() {
    let chain = chain();
    let committee_a = committee(1);
    let committee_b = committee(2);
    let committee_c = committee(3);
    let dummy = execution_payload(B256::ZERO, 1, B256::ZERO);
    let (bootstrap_root, current_branch) = committee_root(&committee_a, 22);
    let (bootstrap_header, bootstrap_bytes) = light_header(FULU_START_SLOT, bootstrap_root, &dummy);
    let bootstrap = encode_bootstrap(&bootstrap_bytes, &committee_a, &current_branch);
    let mut store =
        light::reset_checkpoint(&bootstrap, at(FULU_START_SLOT), chain.ws_period_epochs).unwrap();
    assert_eq!(
        store.current_sync_committee.aggregate_pubkey,
        committee_a.aggregate_pubkey
    );
    assert!(store.next_sync_committee.is_none());
    let before_rotation = store.clone();

    let same_period = PeriodUpdate {
        next: &committee_b,
        previous_beacon: &bootstrap_header,
        previous_header: &bootstrap_bytes,
        finalized_slot: FULU_START_SLOT,
        attested_slot: FULU_START_SLOT + 1,
        signature_slot: FULU_START_SLOT + 2,
        execution: &dummy,
        sk: 1,
        flip_signature: false,
        flip_branch: false,
    };
    light::apply_period_update(
        &mut store,
        &period_update(same_period),
        at(FULU_START_SLOT + 2),
        chain.ws_period_epochs,
    )
    .unwrap();
    assert_eq!(
        store.current_sync_committee.aggregate_pubkey,
        committee_a.aggregate_pubkey
    );
    assert_eq!(
        store.next_sync_committee.as_ref().unwrap().aggregate_pubkey,
        committee_b.aggregate_pubkey
    );

    let next_finalized = FULU_START_SLOT + PERIOD_SLOTS;
    let next_period = period_update(PeriodUpdate {
        next: &committee_c,
        finalized_slot: next_finalized,
        attested_slot: next_finalized + 1,
        signature_slot: next_finalized + 2,
        sk: 2,
        ..same_period
    });
    light::apply_period_update(
        &mut store,
        &next_period,
        at(next_finalized + 2),
        chain.ws_period_epochs,
    )
    .unwrap();
    assert_eq!(
        store.current_sync_committee.aggregate_pubkey,
        committee_b.aggregate_pubkey
    );
    assert_eq!(
        store.next_sync_committee.as_ref().unwrap().aggregate_pubkey,
        committee_c.aggregate_pubkey
    );
    assert_eq!(store.finalized_header.beacon().slot, next_finalized);

    let eth_tx_id = [0x22u8; 32];
    let (state_root, proofs) = fixture_exec_proofs(&chain, &eth_tx_id, 100);
    let fin_slot = next_finalized + 32;
    let attested_slot = fin_slot + 1;
    let signature_slot = fin_slot + 2;
    let execution = execution_payload(state_root, 150, B256::from([0xab; 32]));
    let (fin_beacon, fin_bytes) = light_header(fin_slot, B256::ZERO, &execution);
    let (state_root, finality_branch) = finality_root(&fin_beacon);
    let (attested, attested_bytes) = light_header(attested_slot, state_root, &dummy);
    let aggregate = aggregate_for(&attested, signature_slot, 2);
    let finality = encode_finality(
        &attested_bytes,
        &fin_bytes,
        &finality_branch,
        &aggregate,
        signature_slot,
    );
    let message = light::certify(
        &mut Some(store),
        at(signature_slot),
        &chain,
        &eth_tx_id,
        None,
        &finality,
        &proofs,
    )
    .unwrap();
    assert_eq!(message, light::finality_message(&chain.charms, &eth_tx_id));

    let bad_signature = period_update(PeriodUpdate {
        flip_signature: true,
        ..same_period
    });
    let err = light::apply_period_update(
        &mut before_rotation.clone(),
        &bad_signature,
        at(FULU_START_SLOT + 2),
        chain.ws_period_epochs,
    )
    .unwrap_err();
    assert!(err.contains("invalid sync committee signature"), "{err}");

    let bad_branch = period_update(PeriodUpdate {
        flip_branch: true,
        ..same_period
    });
    let err = light::apply_period_update(
        &mut before_rotation.clone(),
        &bad_branch,
        at(FULU_START_SLOT + 2),
        chain.ws_period_epochs,
    )
    .unwrap_err();
    assert!(err.contains("invalid next sync committee proof"), "{err}");
}

pub(crate) fn electra_light_header(slot: u64) -> helios_consensus_core::types::LightClientHeader {
    use helios_consensus_core::types::LightClientHeader;

    let execution = execution_payload(B256::from([2u8; 32]), slot, B256::from([3u8; 32]));
    let (_, bytes) = light_header(slot, B256::from([4u8; 32]), &execution);
    LightClientHeader::from_ssz_bytes(&bytes).expect("light client header")
}

#[test]
fn electra_header_json_is_much_smaller_than_one_committee() {
    let header_json = serde_json::to_vec(&electra_light_header(99)).unwrap().len();
    let committee_json = serde_json::to_vec(&committee(1)).unwrap().len();
    assert_eq!((header_json, committee_json), (1_935, 51_845));
}

#[derive(Clone, Copy)]
struct PeriodUpdate<'a> {
    next: &'a Committee,
    previous_beacon: &'a BeaconBlockHeader,
    previous_header: &'a [u8],
    finalized_slot: u64,
    attested_slot: u64,
    signature_slot: u64,
    execution: &'a [u8],
    sk: u64,
    flip_signature: bool,
    flip_branch: bool,
}

fn period_update(update: PeriodUpdate<'_>) -> Vec<u8> {
    let (finalized_beacon, finalized_bytes) =
        if update.finalized_slot == update.previous_beacon.slot {
            (
                update.previous_beacon.clone(),
                update.previous_header.to_vec(),
            )
        } else {
            light_header(update.finalized_slot, B256::ZERO, update.execution)
        };
    let (state_root, finality_branch, mut next_branch) =
        committee_and_finality(update.next, &finalized_beacon);
    if update.flip_branch {
        next_branch[0] = B256::from([0xff; 32]);
    }
    let (attested, attested_bytes) =
        light_header(update.attested_slot, state_root, update.execution);
    let mut aggregate = aggregate_for(&attested, update.signature_slot, update.sk);
    if update.flip_signature {
        let mut bytes = aggregate.sync_committee_signature.as_ssz_bytes();
        bytes[0] ^= 0xff;
        aggregate.sync_committee_signature = Signature::from_ssz_bytes(&bytes).unwrap();
    }
    encode_update(
        &attested_bytes,
        update.next,
        &next_branch,
        &finalized_bytes,
        &finality_branch,
        &aggregate,
        update.signature_slot,
    )
}

fn chain() -> light::Chain {
    light::Chain {
        beacon_api: "https://beacon.example".into(),
        execution_api: "https://execution.example".into(),
        charms: [0x11; 20],
        implementation: [0x33; 20],
        proxy_code_hash: [0x44; 32],
        beam_source_slot: 7,
        ws_period_epochs: 3532,
    }
}

fn at(slot: u64) -> u64 {
    light::GENESIS_TIME + slot * 12
}

fn committee(sk: u64) -> Committee {
    let pubkey = pubkey(sk);
    Committee {
        pubkeys: FixedVector::new(vec![pubkey; 512]).unwrap(),
        aggregate_pubkey: pubkey_multiple(sk, 512),
    }
}

fn pubkey(sk: u64) -> PublicKey {
    pubkey_multiple(sk, 1)
}

fn pubkey_multiple(sk: u64, copies: u64) -> PublicKey {
    let point = G1Projective::generator() * (Scalar::from(sk) * Scalar::from(copies));
    PublicKey::from_ssz_bytes(&G1Affine::from(point).to_compressed()).unwrap()
}

fn aggregate_for(header: &BeaconBlockHeader, signature_slot: u64, sk: u64) -> Aggregate {
    Aggregate {
        sync_committee_bits: quorum_bits(),
        sync_committee_signature: sign(header, signature_slot, sk),
    }
}

fn quorum_bits() -> BitVector<typenum::U512> {
    let mut bits = BitVector::<typenum::U512>::default();
    for i in 0..342 {
        bits.set(i, true).unwrap();
    }
    bits
}

fn sign(header: &BeaconBlockHeader, signature_slot: u64, sk: u64) -> Signature {
    let root = signing_root(header.tree_hash_root(), signature_slot);
    let message =
        <G2Projective as HashToCurve<ExpandMsgXmd<Sha256v9>>>::hash_to_curve(root.as_slice(), DST);
    let sig = G2Affine::from(message * (Scalar::from(342u64) * Scalar::from(sk)));
    Signature::from_ssz_bytes(&sig.to_compressed()).unwrap()
}

fn signing_root(header_root: B256, signature_slot: u64) -> B256 {
    assert!(signature_slot > FULU_START_SLOT);
    let mut version = [0u8; 32];
    version[..4].copy_from_slice(&[6, 0, 0, 0]);
    let fork_data = sha256_pair(B256::from(version), GENESIS_ROOT);
    let mut domain = [0u8; 32];
    domain[0] = 7;
    domain[4..].copy_from_slice(&fork_data[..28]);
    sha256_pair(header_root, B256::from(domain))
}

fn execution_payload(state_root: B256, block_number: u64, block_hash: B256) -> Vec<u8> {
    ExecutionPayloadHeaderElectra {
        parent_hash: B256::ZERO,
        fee_recipient: Address::ZERO,
        state_root,
        receipts_root: B256::ZERO,
        logs_bloom: LogsBloom::default(),
        prev_randao: B256::ZERO,
        block_number,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: ByteList::default(),
        base_fee_per_gas: U256::ZERO,
        block_hash,
        transactions_root: B256::ZERO,
        withdrawals_root: B256::ZERO,
        blob_gas_used: 0,
        excess_blob_gas: 0,
    }
    .as_ssz_bytes()
}

fn execution_root(bytes: &[u8]) -> B256 {
    ExecutionPayloadHeader::from_ssz_bytes(bytes)
        .expect("execution payload")
        .tree_hash_root()
}

fn light_header(slot: u64, state_root: B256, execution: &[u8]) -> (BeaconBlockHeader, Vec<u8>) {
    let branch = vec![B256::ZERO; 4];
    let body_root = fold(execution_root(execution), 9, &branch);
    let beacon = BeaconBlockHeader {
        slot,
        proposer_index: 0,
        parent_root: B256::ZERO,
        state_root,
        body_root,
    };
    let bytes = pack(&[
        Part::Fixed(beacon.as_ssz_bytes()),
        Part::Variable(execution.to_vec()),
        Part::Fixed(words::<typenum::U4>(&branch).as_ssz_bytes()),
    ]);
    (beacon, bytes)
}

fn committee_root(committee: &Committee, index: usize) -> (B256, Vec<B256>) {
    let branch = vec![B256::ZERO; 6];
    let root = fold(committee.tree_hash_root(), index, &branch);
    (root, branch)
}

fn finality_root(beacon: &BeaconBlockHeader) -> (B256, Vec<B256>) {
    let mut branch = vec![B256::ZERO; 7];
    // An all-zero branch is treated as absent, so the proof keeps one sibling.
    branch[0] = B256::from([1u8; 32]);
    let root = fold(beacon.tree_hash_root(), 41, &branch);
    (root, branch)
}

fn committee_and_finality(
    committee: &Committee,
    finalized: &BeaconBlockHeader,
) -> (B256, Vec<B256>, Vec<B256>) {
    let committee_leaf = committee.tree_hash_root();
    let committee_parent = sha256_pair(B256::ZERO, committee_leaf);
    let mut node = finalized.tree_hash_root();
    node = sha256_pair(B256::ZERO, node);
    node = sha256_pair(node, B256::ZERO);
    let finality_branch = vec![
        B256::ZERO,
        B256::ZERO,
        committee_parent,
        B256::ZERO,
        B256::ZERO,
        B256::ZERO,
        B256::ZERO,
    ];
    let next_branch = vec![
        B256::ZERO,
        node,
        B256::ZERO,
        B256::ZERO,
        B256::ZERO,
        B256::ZERO,
    ];
    let state_root = fold(finalized.tree_hash_root(), 41, &finality_branch);
    assert_eq!(state_root, fold(committee_leaf, 23, &next_branch));
    (state_root, finality_branch, next_branch)
}

fn fold(leaf: B256, index: usize, branch: &[B256]) -> B256 {
    let mut derived = leaf;
    let mut hasher = Sha256::new();
    for (i, node) in branch.iter().enumerate() {
        if (index / 2usize.pow(i as u32)).is_multiple_of(2) {
            hasher.update(derived);
            hasher.update(node);
        } else {
            hasher.update(node);
            hasher.update(derived);
        }
        derived = B256::from_slice(hasher.finalize_reset().as_slice());
    }
    derived
}

fn sha256_pair(left: B256, right: B256) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    B256::from_slice(&hasher.finalize())
}

fn encode_bootstrap(header: &[u8], committee: &Committee, branch: &[B256]) -> Vec<u8> {
    pack(&[
        Part::Variable(header.to_vec()),
        Part::Fixed(committee.as_ssz_bytes()),
        Part::Fixed(words::<typenum::U6>(branch).as_ssz_bytes()),
    ])
}

fn encode_update(
    attested: &[u8],
    next: &Committee,
    next_branch: &[B256],
    finalized: &[u8],
    finality_branch: &[B256],
    aggregate: &Aggregate,
    signature_slot: u64,
) -> Vec<u8> {
    pack(&[
        Part::Variable(attested.to_vec()),
        Part::Fixed(next.as_ssz_bytes()),
        Part::Fixed(words::<typenum::U6>(next_branch).as_ssz_bytes()),
        Part::Variable(finalized.to_vec()),
        Part::Fixed(words::<typenum::U7>(finality_branch).as_ssz_bytes()),
        Part::Fixed(aggregate.as_ssz_bytes()),
        Part::Fixed(signature_slot.to_le_bytes().to_vec()),
    ])
}

fn encode_finality(
    attested: &[u8],
    finalized: &[u8],
    finality_branch: &[B256],
    aggregate: &Aggregate,
    signature_slot: u64,
) -> Vec<u8> {
    pack(&[
        Part::Variable(attested.to_vec()),
        Part::Variable(finalized.to_vec()),
        Part::Fixed(words::<typenum::U7>(finality_branch).as_ssz_bytes()),
        Part::Fixed(aggregate.as_ssz_bytes()),
        Part::Fixed(signature_slot.to_le_bytes().to_vec()),
    ])
}

fn words<N: Unsigned>(branch: &[B256]) -> FixedVector<B256, N> {
    FixedVector::new(branch.to_vec()).unwrap()
}

enum Part {
    Fixed(Vec<u8>),
    Variable(Vec<u8>),
}

fn pack(parts: &[Part]) -> Vec<u8> {
    let fixed_len: usize = parts
        .iter()
        .map(|part| match part {
            Part::Fixed(bytes) => bytes.len(),
            Part::Variable(_) => 4,
        })
        .sum();
    let mut head = Vec::<u8>::new();
    let mut tail = Vec::<u8>::new();
    let mut offset = fixed_len;
    for part in parts {
        match part {
            Part::Fixed(bytes) => head.extend(bytes),
            Part::Variable(bytes) => {
                head.extend_from_slice(&(offset as u32).to_le_bytes());
                offset += bytes.len();
                tail.extend(bytes);
            }
        }
    }
    head.extend(tail);
    head
}
