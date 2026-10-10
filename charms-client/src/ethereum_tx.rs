use crate::{CURRENT_VERSION, NormalizedSpell, tx::EnchantedTx, utxo_id_hash_with_nonce};
use anyhow::{Context, ensure};
use charms_data::{NativeOutput, TxId, UtxoId, util};
use serde::Serialize;
use serde_with::{IfIsHumanReadable, hex::Hex, serde_as};
use sha3::{Digest, Keccak256};
use std::borrow::Cow;
use std::collections::BTreeMap;

pub const ENVELOPE_PREFIX: &[u8] = b"CHET";

const MAX_OUTPUTS: usize = 64;

pub const TRANSACT_SIGNATURE: &str = "transact((uint32,(uint32,bytes32,bytes32)[],bytes[],(bytes32,uint32,bytes32)[],((bytes32,uint32),(uint32,uint64,bytes)[],(bytes32,uint32,bytes32)[])[],(bytes32,uint32)[],(address,(uint32,uint64,bytes)[])[],(uint32,bytes32)[],uint32[]),bytes32,bytes,bytes[])";

/// One Ethereum Charms record. The id is `keccak256` of the CHIP-0020 preimage, not the
/// Ethereum transaction hash. `anchor` is set only when `ins` is empty. `caller` and `salt`
/// are not part of the id. `proof` is empty on the native path and is not part of the id.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct EthereumTx {
    pub chain_id: u64,
    #[serde_as(as = "IfIsHumanReadable<Hex>")]
    pub charms: [u8; 20],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<IfIsHumanReadable<Hex>>")]
    pub anchor: Option<[u8; 32]>,
    #[serde_as(as = "IfIsHumanReadable<Hex>")]
    pub spell: Vec<u8>,
    #[serde_as(as = "IfIsHumanReadable<Hex>")]
    pub proof: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<IfIsHumanReadable<Hex>>")]
    pub caller: Option<[u8; 20]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<IfIsHumanReadable<Hex>>")]
    pub salt: Option<[u8; 32]>,
}

pub struct PlaceholderRequest {
    pub chain_id: u64,
    pub charms: [u8; 20],
    pub caller: [u8; 20],
    pub salt: [u8; 32],
    pub nonce: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EthCall {
    pub from: String,
    pub to: String,
    pub data: String,
    pub value: String,
}

#[derive(Debug)]
pub struct PlaceholderPlan {
    pub record: EthereumTx,
    pub tx_id: String,
    pub utxo_ids: Vec<String>,
    pub beamed_outs: BTreeMap<String, String>,
    pub nonce: Option<u64>,
    pub call: EthCall,
}

impl EthereumTx {
    pub fn eth_tx_id(&self) -> [u8; 32] {
        eth_tx_id(
            self.chain_id,
            &self.charms,
            self.anchor,
            self.spell_in_id().as_ref(),
        )
    }

    fn spell_in_id(&self) -> Cow<'_, [u8]> {
        let Ok(mut spell) = self.decode() else {
            return Cow::Borrowed(&self.spell);
        };
        let Some(beams) = &spell.tx.beamed_outs else {
            return Cow::Borrowed(&self.spell);
        };
        let Some(coins) = &spell.tx.coins else {
            return Cow::Borrowed(&self.spell);
        };
        let source_hashes = !beams.is_empty()
            && beams.keys().all(|index| {
                coins
                    .get(*index as usize)
                    .is_some_and(|coin| coin.dest.iter().any(|byte| *byte != 0))
            });
        if !source_hashes {
            return Cow::Borrowed(&self.spell);
        }
        spell.tx.beamed_outs = None;
        Cow::Owned(util::write(&spell).expect("spell CBOR"))
    }

    pub fn decode(&self) -> anyhow::Result<NormalizedSpell> {
        util::read(self.spell.as_slice()).context("ethereum spell CBOR")
    }
}

impl EnchantedTx for EthereumTx {
    fn extract_and_verify_spell(
        &self,
        _spell_vk: &[u8; 32],
        mock: bool,
    ) -> anyhow::Result<NormalizedSpell> {
        ensure!(
            self.anchor.is_some(),
            "ethereum placeholder is missing an anchor"
        );
        ensure!(
            self.proof.is_empty(),
            "ethereum placeholder proof must be empty"
        );
        let mut spell = self.decode()?;
        if !mock {
            ensure!(!spell.mock, "spell is a mock, but we are not in mock mode");
        }
        let beams = spell.tx.beamed_outs.take();
        let (mut committed, _) = committed_placeholder(&spell)?;
        if let Some(beams) = beams {
            ensure!(
                beams.keys().copied().eq(0..committed.tx.outs.len() as u32),
                "beamed_outs must name every placeholder output"
            );
            committed.tx.beamed_outs = Some(beams);
        }
        let canonical = util::write(&committed)?;
        ensure!(
            self.spell == canonical,
            "ethereum spell CBOR is not the committed placeholder"
        );
        Ok(committed)
    }

    fn virtual_spell(
        &self,
        spell_vk: &[u8; 32],
        next_spell: &NormalizedSpell,
    ) -> anyhow::Result<NormalizedSpell> {
        self.extract_and_verify_spell(spell_vk, next_spell.mock)
    }

    fn tx_outs_len(&self) -> usize {
        self.decode().map(|spell| spell.tx.outs.len()).unwrap_or(0)
    }

    fn tx_id(&self) -> TxId {
        let mut raw = self.eth_tx_id();
        raw.reverse();
        TxId(raw)
    }

    fn hex(&self) -> String {
        hex::encode(envelope_bytes(self))
    }

    fn spell_ins(&self) -> Vec<UtxoId> {
        self.decode()
            .ok()
            .and_then(|spell| spell.tx.ins)
            .unwrap_or_default()
    }

    fn all_coin_outs(&self, _spell: &NormalizedSpell) -> anyhow::Result<Vec<NativeOutput>> {
        self.decode()?
            .tx
            .coins
            .context("ethereum spell is missing coins")
    }

    fn proven_final(&self) -> bool {
        false
    }
}

/// `CHET` plus CBOR of the record.
pub fn from_envelope_hex(hex_str: &str) -> anyhow::Result<Option<EthereumTx>> {
    let Ok(bytes) = hex::decode(hex_str) else {
        return Ok(None);
    };
    if bytes.len() < ENVELOPE_PREFIX.len() || &bytes[..ENVELOPE_PREFIX.len()] != ENVELOPE_PREFIX {
        return Ok(None);
    }
    let tx = util::read(&bytes[ENVELOPE_PREFIX.len()..]).context("invalid CHET envelope")?;
    Ok(Some(tx))
}

fn envelope_bytes(tx: &EthereumTx) -> Vec<u8> {
    let mut bytes = ENVELOPE_PREFIX.to_vec();
    bytes.extend(util::write(tx).expect("EthereumTx CBOR"));
    bytes
}

/// `keccak256(abi.encode(caller, salt))`.
pub fn placeholder_anchor(caller: [u8; 20], salt: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(&caller);
    preimage[32..].copy_from_slice(&salt);
    Keccak256::digest(preimage).into()
}

/// `ethTxId = keccak256("charms/ethereum/tx/v1" ‖ chainid as uint256 ‖ proxy ‖ anchor ‖ spellCbor)`.
pub fn eth_tx_id(
    chain_id: u64,
    charms: &[u8; 20],
    anchor: Option<[u8; 32]>,
    spell_cbor: &[u8],
) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"charms/ethereum/tx/v1");
    let mut chain = [0u8; 32];
    chain[24..].copy_from_slice(&chain_id.to_be_bytes());
    hasher.update(chain);
    hasher.update(charms);
    hasher.update(anchor.unwrap_or([0u8; 32]));
    hasher.update(spell_cbor);
    hasher.finalize().into()
}

pub fn plan_placeholder(
    spell: &NormalizedSpell,
    request: &PlaceholderRequest,
) -> anyhow::Result<PlaceholderPlan> {
    let (executed, owners) = committed_placeholder(spell)?;
    let anchor = placeholder_anchor(request.caller, request.salt);
    let record = EthereumTx {
        chain_id: request.chain_id,
        charms: request.charms,
        anchor: Some(anchor),
        spell: util::write(&executed)?,
        proof: Vec::new(),
        caller: Some(request.caller),
        salt: Some(request.salt),
    };
    let tx_id = record.tx_id();
    let mut utxo_ids = Vec::with_capacity(owners.len());
    let mut beamed_outs = BTreeMap::new();
    let mut beams = BTreeMap::new();
    for (index, _) in owners.iter().enumerate() {
        let utxo_id = UtxoId(tx_id, index as u32);
        let hash = utxo_id_hash_with_nonce(&utxo_id, request.nonce);
        beamed_outs.insert(index.to_string(), hex::encode(hash.0));
        beams.insert(index as u32, hash);
        utxo_ids.push(utxo_id.to_string());
    }
    let mut recorded = executed;
    if request.nonce.is_some() {
        recorded.tx.beamed_outs = Some(beams);
    }
    let record = EthereumTx {
        spell: util::write(&recorded)?,
        ..record
    };
    let data = transact_calldata(recorded.version, &owners, request.salt);
    Ok(PlaceholderPlan {
        tx_id: tx_id.to_string(),
        utxo_ids,
        beamed_outs,
        nonce: request.nonce,
        call: EthCall {
            from: format!("0x{}", hex::encode(request.caller)),
            to: format!("0x{}", hex::encode(request.charms)),
            data: format!("0x{}", hex::encode(data)),
            value: "0".to_string(),
        },
        record,
    })
}

fn committed_placeholder(
    spell: &NormalizedSpell,
) -> anyhow::Result<(NormalizedSpell, Vec<[u8; 20]>)> {
    ensure!(
        spell.version == CURRENT_VERSION,
        "placeholder spell version must be {CURRENT_VERSION}"
    );
    ensure!(!spell.mock, "a placeholder is not a mock spell");
    ensure!(
        spell.app_public_inputs.is_empty(),
        "a placeholder has no apps"
    );
    ensure!(
        spell.versioned_apps.is_empty(),
        "a placeholder has no versioned apps"
    );
    ensure!(
        spell.tx.ins.as_ref().is_none_or(|ins| ins.is_empty()),
        "a placeholder has no inputs"
    );
    ensure!(
        spell.tx.refs.as_ref().is_none_or(|refs| refs.is_empty()),
        "a placeholder has no reference inputs"
    );
    ensure!(
        spell
            .tx
            .beamed_outs
            .as_ref()
            .is_none_or(|outs| outs.is_empty()),
        "a placeholder has no beamed outputs"
    );
    ensure!(
        spell
            .tx
            .scrolls
            .as_ref()
            .is_none_or(|scrolls| scrolls.is_empty()),
        "a placeholder has no scroll outputs"
    );
    ensure!(
        !spell.tx.outs.is_empty(),
        "a placeholder needs at least one output"
    );
    ensure!(
        spell.tx.outs.len() <= MAX_OUTPUTS,
        "a placeholder has at most {MAX_OUTPUTS} outputs"
    );
    for (index, charms) in spell.tx.outs.iter().enumerate() {
        ensure!(
            charms.is_empty(),
            "output {index} must carry an empty charm set"
        );
    }
    let coins = spell
        .tx
        .coins
        .as_ref()
        .context("coins must list each output owner in dest")?;
    ensure!(
        coins.len() == spell.tx.outs.len(),
        "coins length ({}) must match outs length ({})",
        coins.len(),
        spell.tx.outs.len()
    );
    let mut owners = Vec::with_capacity(coins.len());
    for (index, coin) in coins.iter().enumerate() {
        ensure!(coin.amount == 0, "coins[{index}].amount must be 0");
        ensure!(
            coin.content.is_none(),
            "coins[{index}].content must be empty"
        );
        ensure!(
            coin.dest.len() == 20,
            "coins[{index}].dest must be a 20-byte address"
        );
        let mut owner = [0u8; 20];
        owner.copy_from_slice(&coin.dest);
        ensure!(
            owner != [0u8; 20],
            "coins[{index}].dest must not be the zero address"
        );
        owners.push(owner);
    }

    let mut committed = spell.clone();
    committed.tx.ins = Some(Vec::new());
    committed.tx.refs = None;
    committed.tx.beamed_outs = None;
    committed.tx.scrolls = None;
    Ok((committed, owners))
}

/// ABI encoding of `transact(spell, salt, "", [])` for a placeholder with empty charm outputs.
pub fn transact_calldata(version: u32, owners: &[[u8; 20]], salt: [u8; 32]) -> Vec<u8> {
    let spell = encode_spell(version, owners);
    let proof = encode_bytes(&[]);
    let signatures = word(0);
    let spell_off = 4 * 32;
    let proof_off = spell_off + spell.len();
    let signatures_off = proof_off + proof.len();

    let mut data = Vec::with_capacity(4 + signatures_off + 32);
    data.extend(selector(TRANSACT_SIGNATURE));
    data.extend(word(spell_off as u64));
    data.extend(salt);
    data.extend(word(proof_off as u64));
    data.extend(word(signatures_off as u64));
    data.extend(spell);
    data.extend(proof);
    data.extend(signatures);
    data
}

fn encode_spell(version: u32, owners: &[[u8; 20]]) -> Vec<u8> {
    let tails = [
        word(0).to_vec(),
        word(0).to_vec(),
        word(0).to_vec(),
        word(0).to_vec(),
        word(0).to_vec(),
        encode_outputs(owners),
        word(0).to_vec(),
        word(0).to_vec(),
    ];
    let mut offset = 9 * 32;
    let mut encoded = word(version as u64).to_vec();
    let mut body: Vec<u8> = Vec::new();
    for tail in &tails {
        encoded.extend(word(offset as u64));
        offset += tail.len();
        body.extend(tail);
    }
    encoded.extend(body);
    encoded
}

fn encode_outputs(owners: &[[u8; 20]]) -> Vec<u8> {
    let output_len = 96;
    let heads = owners.len() * 32;
    let mut encoded = word(owners.len() as u64).to_vec();
    for index in 0..owners.len() {
        encoded.extend(word((heads + index * output_len) as u64));
    }
    for owner in owners {
        encoded.extend(address_word(*owner));
        encoded.extend(word(64));
        encoded.extend(word(0));
    }
    encoded
}

fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = word(bytes.len() as u64).to_vec();
    encoded.extend(bytes);
    let pad = (32 - (bytes.len() % 32)) % 32;
    encoded.extend(std::iter::repeat_n(0, pad));
    encoded
}

fn selector(signature: &str) -> [u8; 4] {
    let digest = Keccak256::digest(signature.as_bytes());
    digest[..4].try_into().expect("keccak prefix")
}

fn word(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn address_word(addr: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&addr);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{Chain, EnchantedTx, Tx};
    use std::str::FromStr;

    const CBOR: &str = "a36776657273696f6e0f627478a363696e7380646f75747381a065636f696e7381a266616d6f756e74006464657374940102030405060708090a0b0c0d0e0f1011121314716170705f7075626c69635f696e70757473a0";
    const TX_ID: &str = "fe12fb10d8317475b864e2393961d5aa2af56d0923de9c79ac8bc0eb02f3e7a7";
    const BEAM: &str = "adcaddcc66a2d1719f8a3145e458023be9f5fb8c466fdceae2a03e31b0015d5c";
    const BEAM_NONCE_1: &str = "9cc13c1cf309dfd6cc3fd38f3e14b3b7f1e971f5842a686591dc352b0accdd1a";
    const CALL: &str = "0x27485a930000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000000f000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000260000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000102030405060708090a0b0c0d0e0f1011121314000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    fn request(nonce: Option<u64>) -> PlaceholderRequest {
        let mut salt = [0u8; 32];
        salt[31] = 7;
        PlaceholderRequest {
            chain_id: 1,
            charms: [0x33; 20],
            caller: [0x11; 20],
            salt,
            nonce,
        }
    }

    fn spell(outs: u32) -> NormalizedSpell {
        let mut coins = String::new();
        let mut outputs = String::new();
        for index in 0..outs {
            outputs.push_str("    - {}\n");
            let dest = if index == 0 {
                "0102030405060708090a0b0c0d0e0f1011121314"
            } else {
                "2222222222222222222222222222222222222222"
            };
            coins.push_str(&format!("    - amount: 0\n      dest: \"{dest}\"\n"));
        }
        let yaml = format!(
            "version: 15\ntx:\n  outs:\n{outputs}  coins:\n{coins}app_public_inputs: {{}}\n"
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn placeholder_names_the_beam_target() {
        let plan = plan_placeholder(&spell(1), &request(None)).unwrap();
        assert_eq!(hex::encode(&plan.record.spell), CBOR);
        assert_eq!(plan.tx_id, TX_ID);
        assert_eq!(plan.utxo_ids, vec![format!("{TX_ID}:0")]);
        assert_eq!(plan.beamed_outs["0"], BEAM);
        assert_eq!(plan.call.data, CALL);
        assert_eq!(plan.call.from, "0x1111111111111111111111111111111111111111");
        assert_eq!(plan.call.to, "0x3333333333333333333333333333333333333333");
        assert_eq!(plan.call.value, "0");
        assert_eq!(plan.record.caller, Some(request(None).caller));
        assert_eq!(plan.record.salt, Some(request(None).salt));
        assert_eq!(
            plan.record.anchor,
            Some(placeholder_anchor(request(None).caller, request(None).salt))
        );
        assert!(plan.record.proof.is_empty());
        assert!(!plan.record.proven_final());

        let tx = Tx::Ethereum(plan.record.clone());
        assert_eq!(tx.tx_id().to_string(), TX_ID);
        assert_eq!(from_envelope_hex(&tx.hex()).unwrap().unwrap(), plan.record);
        assert_eq!(
            UtxoId::from_str(&plan.utxo_ids[0]).unwrap().to_string(),
            format!("{TX_ID}:0")
        );
        assert_eq!(Chain::from_str("ethereum").unwrap(), Chain::Ethereum);
    }

    #[test]
    fn the_saved_call_names_its_caller() {
        let plan = plan_placeholder(&spell(1), &request(None)).unwrap();
        let mut other = request(None);
        other.caller = [0x22; 20];
        let other_plan = plan_placeholder(&spell(1), &other).unwrap();
        assert_eq!(plan.call.from, "0x1111111111111111111111111111111111111111");
        assert_eq!(
            other_plan.call.from,
            "0x2222222222222222222222222222222222222222"
        );
        assert_ne!(plan.tx_id, other_plan.tx_id);
        assert_ne!(plan.beamed_outs["0"], other_plan.beamed_outs["0"]);
        assert_eq!(plan.call.data, other_plan.call.data);
    }

    #[test]
    fn nonce_is_written_into_the_spell() {
        let plan = plan_placeholder(&spell(1), &request(Some(1))).unwrap();
        assert_eq!(plan.tx_id, TX_ID);
        assert_eq!(plan.record.tx_id().to_string(), TX_ID);
        assert_eq!(plan.beamed_outs["0"], BEAM_NONCE_1);
        assert_ne!(plan.beamed_outs["0"], BEAM);
        assert_ne!(hex::encode(&plan.record.spell), CBOR);
        assert_eq!(plan.call.data, CALL);
        let decoded = plan.record.decode().unwrap();
        let beams = decoded.tx.beamed_outs.unwrap();
        assert_eq!(hex::encode(beams[&0].0), BEAM_NONCE_1);
        let shown = plan
            .record
            .extract_and_verify_spell(&[0u8; 32], false)
            .unwrap();
        assert_eq!(
            hex::encode(shown.tx.beamed_outs.unwrap()[&0].0),
            BEAM_NONCE_1
        );
    }

    #[test]
    fn two_empty_outputs_keep_their_indexes() {
        let plan = plan_placeholder(&spell(2), &request(None)).unwrap();
        assert_eq!(
            plan.tx_id,
            "1568b0106469209c7aa1b6c36bf9d7613e3843811128524d0887e1ae51bf7150"
        );
        assert_eq!(
            plan.beamed_outs["0"],
            "0ba3f5eb7e9c415c9cb1b90fe8d0670430216d023b4ebd6144a6a467ebd12d15"
        );
        assert_eq!(
            plan.beamed_outs["1"],
            "f93d8a3539d71ea1acb14c49adde0b1486382ae1fcc9956bb6840e1c371919b5"
        );
        assert_eq!(
            plan.utxo_ids[1],
            "1568b0106469209c7aa1b6c36bf9d7613e3843811128524d0887e1ae51bf7150:1"
        );
        assert_eq!(
            hex::encode(&plan.record.spell),
            "a36776657273696f6e0f627478a363696e7380646f75747382a0a065636f696e7382a266616d6f756e74006464657374940102030405060708090a0b0c0d0e0f1011121314a266616d6f756e740064646573749418221822182218221822182218221822182218221822182218221822182218221822182218221822716170705f7075626c69635f696e70757473a0"
        );
    }

    #[test]
    fn a_charm_on_the_output_is_not_a_placeholder() {
        let yaml = r#"
version: 15
tx:
  outs:
    - 0: 1
  coins:
    - amount: 0
      dest: "0102030405060708090a0b0c0d0e0f1011121314"
app_public_inputs: {}
"#;
        let spell: NormalizedSpell = serde_yaml::from_str(yaml).unwrap();
        let err = plan_placeholder(&spell, &request(None)).unwrap_err();
        assert_eq!(err.to_string(), "output 0 must carry an empty charm set");
    }

    #[test]
    fn a_charm_envelope_is_not_accepted() {
        let yaml = r#"
version: 15
tx:
  ins:
    - fe12fb10d8317475b864e2393961d5aa2af56d0923de9c79ac8bc0eb02f3e7a7:0
  outs:
    - 0: 1
  coins:
    - amount: 0
      dest: "0102030405060708090a0b0c0d0e0f1011121314"
app_public_inputs: {}
"#;
        let carried: NormalizedSpell = serde_yaml::from_str(yaml).unwrap();
        let record = EthereumTx {
            chain_id: 1,
            charms: [0x33; 20],
            anchor: Some([7u8; 32]),
            spell: util::write(&carried).unwrap(),
            proof: Vec::new(),
            caller: None,
            salt: None,
        };
        let err = record
            .extract_and_verify_spell(&[0u8; 32], false)
            .unwrap_err();
        assert_eq!(err.to_string(), "a placeholder has no inputs");

        let mut charm_only = spell(1);
        charm_only.tx.outs[0].insert(0, charms_data::Data::from(&1u64));
        charm_only.tx.ins = Some(Vec::new());
        let record = EthereumTx {
            chain_id: 1,
            charms: [0x33; 20],
            anchor: Some([7u8; 32]),
            spell: util::write(&charm_only).unwrap(),
            proof: Vec::new(),
            caller: None,
            salt: None,
        };
        let err = record
            .extract_and_verify_spell(&[0u8; 32], false)
            .unwrap_err();
        assert_eq!(err.to_string(), "output 0 must carry an empty charm set");
    }

    #[test]
    fn a_placeholder_envelope_must_be_canonical() {
        let plan = plan_placeholder(&spell(1), &request(None)).unwrap();
        plan.record
            .extract_and_verify_spell(&[0u8; 32], false)
            .unwrap();

        let mut proved = plan.record.clone();
        proved.proof = vec![1];
        let err = proved
            .extract_and_verify_spell(&[0u8; 32], false)
            .unwrap_err();
        assert_eq!(err.to_string(), "ethereum placeholder proof must be empty");

        let mut unanchored = plan.record.clone();
        unanchored.anchor = None;
        let err = unanchored
            .extract_and_verify_spell(&[0u8; 32], false)
            .unwrap_err();
        assert_eq!(err.to_string(), "ethereum placeholder is missing an anchor");

        let mut loose = spell(1);
        loose.tx.refs = Some(Vec::new());
        let mut record = plan.record.clone();
        record.spell = util::write(&loose).unwrap();
        let err = record
            .extract_and_verify_spell(&[0u8; 32], false)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "ethereum spell CBOR is not the committed placeholder"
        );
    }

    #[test]
    fn sixty_four_outputs_are_the_contract_limit() {
        plan_placeholder(&spell(64), &request(None)).unwrap();
        let err = plan_placeholder(&spell(65), &request(None)).unwrap_err();
        assert_eq!(err.to_string(), "a placeholder has at most 64 outputs");
    }

    #[test]
    fn a_zero_owner_is_not_a_placeholder() {
        let yaml = r#"
version: 15
tx:
  outs:
    - {}
  coins:
    - amount: 0
      dest: "0000000000000000000000000000000000000000"
app_public_inputs: {}
"#;
        let spell: NormalizedSpell = serde_yaml::from_str(yaml).unwrap();
        let err = plan_placeholder(&spell, &request(None)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "coins[0].dest must not be the zero address"
        );
    }
}
