use alloy::{
    consensus::TrieAccount,
    primitives::{B256, Bytes, U256, keccak256},
};
#[cfg(test)]
use alloy_rlp::Encodable;
use alloy_rlp::{Decodable, Header};
#[cfg(test)]
use alloy_trie::{HashBuilder, proof::ProofRetainer};
use alloy_trie::{Nibbles, proof::verify_proof};

use crate::light::Chain;

pub const ERC1967_SLOT: [u8; 32] = [
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
    0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
];

/// EIP-1186 logical key of `mapping(bytes32 => uint256)` at `slot`.
pub fn mapping_key(key: &[u8; 32], slot: u64) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(key);
    preimage[32..].copy_from_slice(&U256::from(slot).to_be_bytes::<32>());
    keccak256(preimage).0
}

pub struct StorageProof {
    pub key: [u8; 32],
    pub proof: Vec<Vec<u8>>,
}

pub struct ExecProofs {
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proofs: Vec<StorageProof>,
}

pub fn check_storage(
    state_root: B256,
    block_number: u64,
    chain: &Chain,
    eth_tx_id: &[u8; 32],
    proofs: &ExecProofs,
) -> Result<(), String> {
    let account_path = keccak256(chain.charms);
    let account_bytes = proved_value(state_root, account_path, &proofs.account_proof)?
        .ok_or_else(|| "Input error: Charms account is absent".to_string())?;
    let mut account_buf = account_bytes.as_slice();
    let account = TrieAccount::decode(&mut account_buf)
        .map_err(|e| format!("Input error: Charms account: {e}"))?;
    if !account_buf.is_empty() {
        return Err("Input error: Charms account has trailing bytes".into());
    }
    if account.code_hash != B256::from(chain.proxy_code_hash) {
        return Err("Input error: Charms code hash".into());
    }

    let beam_key = mapping_key(eth_tx_id, chain.beam_source_slot);
    let beam = take_proof(&proofs.storage_proofs, &beam_key, "beamSourceAt")?;
    let implementation = take_proof(&proofs.storage_proofs, &ERC1967_SLOT, "implementation")?;
    if proofs.storage_proofs.len() != 2 {
        return Err("Input error: expected beamSourceAt and implementation proofs".into());
    }

    let beam_value = open_uint(account.storage_root, beam_key, &beam.proof)?;
    if beam_value == U256::ZERO || beam_value > U256::from(block_number) {
        return Err("Input error: beamSourceAt is outside the finalized block".into());
    }

    let code = open_uint(account.storage_root, ERC1967_SLOT, &implementation.proof)?;
    let expected = U256::from_be_slice(&chain.implementation);
    if code != expected {
        return Err("Input error: implementation slot".into());
    }
    Ok(())
}

fn take_proof<'a>(
    proofs: &'a [StorageProof],
    key: &[u8; 32],
    name: &str,
) -> Result<&'a StorageProof, String> {
    let mut found = None;
    for proof in proofs {
        if proof.key == *key {
            if found.is_some() {
                return Err(format!("Input error: duplicate {name} proof"));
            }
            found = Some(proof);
        }
    }
    found.ok_or_else(|| format!("Input error: missing {name} proof"))
}

fn open_uint(root: B256, logical_key: [u8; 32], proof: &[Vec<u8>]) -> Result<U256, String> {
    let path = keccak256(logical_key);
    let value = proved_value(root, path, proof)?
        .ok_or_else(|| "Input error: storage slot is absent".to_string())?;
    decode_uint(&value)
}

fn decode_uint(rlp_value: &[u8]) -> Result<U256, String> {
    let bytes = rlp_string(rlp_value)?;
    if bytes.len() > 32 {
        return Err("Input error: storage value is wider than 32 bytes".into());
    }
    Ok(U256::from_be_slice(&bytes))
}

fn proved_value(root: B256, trie_path: B256, nodes: &[Vec<u8>]) -> Result<Option<Vec<u8>>, String> {
    if nodes.is_empty() {
        return Err("Input error: empty trie proof".into());
    }
    let nibbles = Nibbles::unpack(trie_path);
    let encoded: Vec<Bytes> = nodes
        .iter()
        .map(|node| Bytes::copy_from_slice(node))
        .collect();
    if verify_proof(root, nibbles, None, encoded.iter()).is_ok() {
        return Ok(None);
    }
    let value = terminal_value(nodes.last().expect("non-empty"))?;
    verify_proof(root, nibbles, Some(value.clone()), encoded.iter())
        .map_err(|e| format!("Input error: trie proof: {e}"))?;
    Ok(Some(value))
}

fn terminal_value(node: &[u8]) -> Result<Vec<u8>, String> {
    let items = rlp_items(node)?;
    let value = if items.len() == 2 {
        let path = decode_bytes(items[0])?;
        let flag = path.first().copied().unwrap_or(0) >> 4;
        if flag < 2 {
            return Err("Input error: trie proof ends on an extension".into());
        }
        items[1]
    } else if items.len() == 17 {
        items[16]
    } else {
        return Err("Input error: trie node".into());
    };
    decode_bytes(value)
}

fn decode_bytes(item: &[u8]) -> Result<Vec<u8>, String> {
    rlp_string(item)
}

fn rlp_string(item: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = item;
    let bytes = Bytes::decode(&mut buf).map_err(|e| format!("Input error: rlp: {e}"))?;
    if !buf.is_empty() {
        return Err("Input error: rlp has trailing bytes".into());
    }
    Ok(bytes.to_vec())
}

fn rlp_items(node: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut rest = node;
    let header = Header::decode(&mut rest).map_err(|e| format!("Input error: rlp: {e}"))?;
    let mut pos = node.len() - rest.len();
    if !header.list {
        return Err("Input error: trie node is not a list".into());
    }
    let end = pos + header.payload_length;
    if end != node.len() {
        return Err("Input error: trie node length".into());
    }
    let mut items = Vec::new();
    while pos < end {
        let before = node.len() - pos;
        let mut item_rest = &node[pos..];
        let item_header =
            Header::decode(&mut item_rest).map_err(|e| format!("Input error: rlp: {e}"))?;
        let header_len = before - item_rest.len();
        let total = header_len + item_header.payload_length;
        if pos + total > end {
            return Err("Input error: truncated trie node".into());
        }
        items.push(&node[pos..pos + total]);
        pos += total;
    }
    Ok(items)
}

#[cfg(test)]
const EVEN_LEAF_HEX_PREFIX: u8 = 0x20;

#[cfg(test)]
fn leaf_proof(key: &[u8; 32], value: &[u8]) -> (B256, Vec<Vec<u8>>) {
    let mut path = Vec::with_capacity(33);
    path.push(EVEN_LEAF_HEX_PREFIX);
    path.extend_from_slice(key);
    let node = rlp_pair(&path, value);
    let root = keccak256(&node);
    (root, vec![node])
}

#[cfg(test)]
fn rlp_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    left.encode(&mut payload);
    right.encode(&mut payload);
    let mut out = Vec::new();
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend(payload);
    out
}

#[cfg(test)]
fn rlp_uint(word: &[u8]) -> Vec<u8> {
    let start = word
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(word.len());
    alloy_rlp::encode(&word[start..])
}

#[cfg(test)]
fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

#[cfg(test)]
pub(crate) fn fixture_exec_proofs(
    chain: &Chain,
    eth_tx_id: &[u8; 32],
    beam_block: u64,
) -> (B256, ExecProofs) {
    let beam_key = mapping_key(eth_tx_id, chain.beam_source_slot);
    let beam_path = Nibbles::unpack(keccak256(beam_key));
    let impl_path = Nibbles::unpack(keccak256(ERC1967_SLOT));
    let beam_value = rlp_uint(&U256::from(beam_block).to_be_bytes::<32>());
    let impl_value = rlp_uint(&address_word(&chain.implementation));
    let mut leaves = [(beam_path, beam_value), (impl_path, impl_value)];
    if leaves[0].0 > leaves[1].0 {
        leaves.swap(0, 1);
    }
    let retainer = ProofRetainer::new(vec![leaves[0].0, leaves[1].0]);
    let mut builder = HashBuilder::default().with_proof_retainer(retainer);
    for (path, value) in &leaves {
        builder.add_leaf(*path, value);
    }
    let storage_root = builder.root();
    let nodes = builder.take_proof_nodes();
    let account = TrieAccount {
        nonce: 1,
        balance: U256::ZERO,
        storage_root,
        code_hash: B256::from(chain.proxy_code_hash),
    };
    let (state_root, account_proof) =
        leaf_proof(&keccak256(chain.charms).0, &alloy_rlp::encode(account));
    let proofs = ExecProofs {
        account_proof,
        storage_proofs: vec![
            StorageProof {
                key: beam_key,
                proof: nodes
                    .matching_nodes_sorted(&beam_path)
                    .into_iter()
                    .map(|(_, node)| node.to_vec())
                    .collect(),
            },
            StorageProof {
                key: ERC1967_SLOT,
                proof: nodes
                    .matching_nodes_sorted(&impl_path)
                    .into_iter()
                    .map(|(_, node)| node.to_vec())
                    .collect(),
            },
        ],
    };
    (state_root, proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::light::Chain;

    fn chain() -> Chain {
        Chain {
            beacon_api: "https://beacon.example".into(),
            execution_api: "https://execution.example".into(),
            charms: [0x11; 20],
            implementation: [0x33; 20],
            proxy_code_hash: [0x44; 32],
            beam_source_slot: 7,
            ws_period_epochs: 3532,
        }
    }

    #[test]
    fn mapping_key_matches_abi_encode() {
        let key = [0x22u8; 32];
        let expected =
            hex::decode("d021e0273609215fbe9720ddae80f325b03c937180c328e9f83abc01aa745b5a")
                .unwrap();
        assert_eq!(mapping_key(&key, 7).to_vec(), expected);
    }

    #[test]
    fn erc1967_slot_is_one_below_the_implementation_hash() {
        let hash = keccak256(b"eip1967.proxy.implementation");
        let slot = U256::from_be_bytes(hash.0) - U256::from(1);
        assert_eq!(slot.to_be_bytes::<32>(), ERC1967_SLOT);
    }

    #[test]
    fn storage_proof_accepts_a_finalized_beam() {
        let chain = chain();
        let eth_tx_id = [0x22u8; 32];
        let (state_root, proofs) = fixture_exec_proofs(&chain, &eth_tx_id, 100);
        check_storage(state_root, 150, &chain, &eth_tx_id, &proofs).unwrap();
    }

    #[test]
    fn storage_proof_rejects_a_beam_after_the_finalized_block() {
        let chain = chain();
        let eth_tx_id = [0x22u8; 32];
        let (state_root, proofs) = fixture_exec_proofs(&chain, &eth_tx_id, 200);
        let err = check_storage(state_root, 150, &chain, &eth_tx_id, &proofs).unwrap_err();
        assert_eq!(
            err,
            "Input error: beamSourceAt is outside the finalized block"
        );
    }
}
