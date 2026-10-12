use crate::{
    CURRENT_VERSION, NormalizedCharms, NormalizedSpell, V15,
    tx::{self, EnchantedTx, Tx},
    utxo_id_hash_with_nonce,
};
use anyhow::{Context, ensure};
use charms_data::{App, NativeOutput, TOKEN, TxId, UtxoId, util};
use serde::Serialize;
use serde_with::{IfIsHumanReadable, hex::Hex, serde_as};
use sha3::{Digest, Keccak256};
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
        eth_tx_id(self.chain_id, &self.charms, self.anchor, &self.spell)
    }

    pub fn decode(&self) -> anyhow::Result<NormalizedSpell> {
        util::read(self.spell.as_slice()).context("ethereum spell CBOR")
    }

    fn accept_placeholder(&self, committed: NormalizedSpell) -> anyhow::Result<NormalizedSpell> {
        ensure!(
            self.anchor.is_some(),
            "ethereum placeholder is missing an anchor"
        );
        ensure!(
            self.proof.is_empty(),
            "ethereum placeholder proof must be empty"
        );
        let canonical = util::write(&committed)?;
        ensure!(
            self.spell == canonical,
            "ethereum spell CBOR is not the committed placeholder"
        );
        Ok(committed)
    }

    fn verify_proved_spell(
        &self,
        spell: &NormalizedSpell,
        spell_vk: &[u8; 32],
    ) -> anyhow::Result<NormalizedSpell> {
        // The proof does not cover the anchor. `transact` writes 32 zero
        // bytes when the spell spends an input, so any other anchor names
        // an output id the contract never creates.
        ensure!(
            self.anchor.unwrap_or([0u8; 32]) == [0u8; 32],
            "a proved ethereum spell's anchor must be zero"
        );
        let ins = spell
            .tx
            .ins
            .as_ref()
            .context("ethereum spell is missing inputs")?;
        ensure!(!ins.is_empty(), "a proved ethereum spell spends an input");
        ensure_ethereum_output_coins(spell)?;
        let canonical = util::write(spell)?;
        ensure!(
            self.spell == canonical,
            "ethereum spell CBOR is not canonical"
        );
        let vk = tx::spell_vk(spell.version, spell_vk, spell.mock)?;
        let public_values = tx::to_serialized_pv(spell.version, vk, spell);
        tx::verify_snark_proof(&self.proof, &public_values, vk, spell.version, spell.mock)?;
        Ok(spell.clone())
    }
}

impl EnchantedTx for EthereumTx {
    fn extract_and_verify_spell(
        &self,
        spell_vk: &[u8; 32],
        mock: bool,
    ) -> anyhow::Result<NormalizedSpell> {
        let spell = self.decode()?;
        if !mock {
            ensure!(!spell.mock, "spell is a mock, but we are not in mock mode");
        }
        match committed_placeholder(&spell) {
            Ok((committed, _)) => self.accept_placeholder(committed),
            Err(err) if self.proof.is_empty() => Err(err),
            Err(_) => self.verify_proved_spell(&spell, spell_vk),
        }
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

/// Output coins of a spell whose transaction is `Tx::Ethereum`.
///
/// The record reader rejects any other shape, so the prover must too.
pub fn ensure_ethereum_output_coins(spell: &NormalizedSpell) -> anyhow::Result<()> {
    let coins = spell
        .tx
        .coins
        .as_ref()
        .context("ethereum spell is missing coins")?;
    ensure!(
        coins.len() == spell.tx.outs.len(),
        "coins length ({}) must match outs length ({})",
        coins.len(),
        spell.tx.outs.len()
    );
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
    }
    Ok(())
}

pub fn is_placeholder(spell: &NormalizedSpell) -> bool {
    committed_placeholder(spell).is_ok()
}

/// Chain id and Charms contract of the record that created `spell.tx.ins[0]`.
pub fn hosting_chain(spell: &NormalizedSpell, prev_txs: &[Tx]) -> anyhow::Result<(u64, [u8; 20])> {
    let first = spell
        .tx
        .ins
        .as_ref()
        .and_then(|ins| ins.first())
        .context("a proved ethereum spell spends an input")?;
    let host = prev_txs
        .iter()
        .find_map(|tx| match tx {
            Tx::Ethereum(record) if record.tx_id() == first.0 => Some(record),
            _ => None,
        })
        .context("prev_txs must include the Ethereum record that created the spent input")?;
    Ok((host.chain_id, host.charms))
}

pub fn record_with_proof(
    spell: &NormalizedSpell,
    proof: Vec<u8>,
    chain_id: u64,
    charms: [u8; 20],
) -> anyhow::Result<EthereumTx> {
    Ok(EthereumTx {
        chain_id,
        charms,
        anchor: None,
        spell: util::write(spell)?,
        proof,
        caller: None,
        salt: None,
    })
}

pub fn plan_placeholder(
    spell: &NormalizedSpell,
    request: &PlaceholderRequest,
) -> anyhow::Result<PlaceholderPlan> {
    let (committed, owners) = committed_placeholder(spell)?;
    let spell_cbor = util::write(&committed)?;
    let anchor = placeholder_anchor(request.caller, request.salt);
    let record = EthereumTx {
        chain_id: request.chain_id,
        charms: request.charms,
        anchor: Some(anchor),
        spell: spell_cbor,
        proof: Vec::new(),
        caller: Some(request.caller),
        salt: Some(request.salt),
    };
    let tx_id = record.tx_id();
    let mut utxo_ids = Vec::with_capacity(owners.len());
    let mut beamed_outs = BTreeMap::new();
    for (index, _) in owners.iter().enumerate() {
        let utxo_id = UtxoId(tx_id, index as u32);
        let hash = utxo_id_hash_with_nonce(&utxo_id, request.nonce);
        beamed_outs.insert(index.to_string(), hex::encode(hash.0));
        utxo_ids.push(utxo_id.to_string());
    }
    let call = transact_call(&record)?;
    Ok(PlaceholderPlan {
        tx_id: tx_id.to_string(),
        utxo_ids,
        beamed_outs,
        nonce: request.nonce,
        call,
        record,
    })
}

/// `transact` calldata for `record`: a placeholder sent by its caller with its salt, or a
/// proved spell sent by its first output owner with a zero salt.
pub fn transact_call(record: &EthereumTx) -> anyhow::Result<EthCall> {
    let (spell, from, salt) = if record.proof.is_empty() {
        placeholder_sender(record)?
    } else {
        proved_sender(record)?
    };
    let data = transact_calldata(&spell, salt, &record.proof)?;
    Ok(EthCall {
        from: format!("0x{}", hex::encode(from)),
        to: format!("0x{}", hex::encode(record.charms)),
        data: format!("0x{}", hex::encode(data)),
        value: "0".to_string(),
    })
}

fn placeholder_sender(
    record: &EthereumTx,
) -> anyhow::Result<(NormalizedSpell, [u8; 20], [u8; 32])> {
    let spell = record.extract_and_verify_spell(&[0u8; 32], false)?;
    let caller = record
        .caller
        .context("ethereum placeholder is missing a caller")?;
    let salt = record
        .salt
        .context("ethereum placeholder is missing a salt")?;
    ensure!(
        record.anchor == Some(placeholder_anchor(caller, salt)),
        "ethereum placeholder anchor does not match the caller and salt"
    );
    Ok((spell, caller, salt))
}

fn proved_sender(record: &EthereumTx) -> anyhow::Result<(NormalizedSpell, [u8; 20], [u8; 32])> {
    ensure!(
        record.anchor.unwrap_or([0u8; 32]) == [0u8; 32],
        "a proved ethereum spell's anchor must be zero"
    );
    ensure!(
        record.caller.is_none() && record.salt.is_none(),
        "a proved ethereum record has no caller or salt"
    );
    let spell = record.decode()?;
    ensure!(
        spell.tx.ins.as_ref().is_some_and(|ins| !ins.is_empty()),
        "a proved ethereum spell spends an input"
    );
    ensure_ethereum_output_coins(&spell)?;
    let beamed = spell.tx.beamed_outs.as_ref();
    for (index, coin) in spell.tx.coins.iter().flatten().enumerate() {
        ensure!(
            beamed.is_some_and(|outs| outs.contains_key(&(index as u32)))
                == (coin.dest.as_slice() == [0u8; 20]),
            "coins[{index}].dest must be the zero address exactly when output {index} is beamed"
        );
    }
    let owner = spell
        .tx
        .coins
        .iter()
        .flatten()
        .find(|coin| coin.dest.as_slice() != [0u8; 20])
        .context("a proved ethereum spell needs an output owner to send it")?;
    let from = owner.dest.as_slice().try_into()?;
    Ok((spell, from, [0u8; 32]))
}

fn committed_placeholder(
    spell: &NormalizedSpell,
) -> anyhow::Result<(NormalizedSpell, Vec<[u8; 20]>)> {
    // A version-15 empty UTXO keeps the bytes it was committed with.
    // Rewriting the version would change the transaction id.
    ensure!(
        spell.version == V15 || spell.version == CURRENT_VERSION,
        "placeholder spell version must be {V15} or {CURRENT_VERSION}"
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

enum Abi {
    Static(Vec<u8>),
    Dynamic(Vec<u8>),
}

/// ABI encoding of `transact(spell, salt, proof, [])`.
pub fn transact_calldata(
    spell: &NormalizedSpell,
    salt: [u8; 32],
    proof: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut data = selector(TRANSACT_SIGNATURE).to_vec();
    data.extend(tuple(vec![
        encode_spell(spell)?,
        Abi::Static(salt.to_vec()),
        Abi::Dynamic(encode_bytes(proof)),
        array(Vec::new()),
    ]));
    Ok(data)
}

fn encode_spell(spell: &NormalizedSpell) -> anyhow::Result<Abi> {
    let tx = &spell.tx;
    let apps: Vec<&App> = spell.app_public_inputs.keys().collect();
    let app_heads = apps
        .iter()
        .map(|app| {
            words(&[
                word(u64::from(u32::from(app.tag))),
                app.identity.0,
                app.vk.0,
            ])
        })
        .collect();
    let public_inputs = spell
        .app_public_inputs
        .values()
        .map(|input| Abi::Dynamic(encode_bytes(&input.bytes())))
        .collect();
    let pins = spell
        .versioned_apps
        .iter()
        .map(|(vk, pin)| words(&[vk.0, word(pin.version.into()), pin.wasm_hash.0]))
        .collect();
    let ins = tx
        .ins
        .iter()
        .flatten()
        .map(|utxo| {
            let opening = vec![utxo_ref(utxo), array(Vec::new()), array(Vec::new())];
            Abi::Dynamic(tuple(opening))
        })
        .collect();
    let refs = tx.refs.iter().flatten().map(utxo_ref).collect();
    let outs = tx
        .outs
        .iter()
        .zip(tx.coins.iter().flatten())
        .map(|(charms, coin)| {
            let owner = coin.dest.as_slice().try_into()?;
            let output = vec![
                Abi::Static(address_word(owner).to_vec()),
                encode_charms(&apps, charms)?,
            ];
            Ok(Abi::Dynamic(tuple(output)))
        })
        .collect::<anyhow::Result<_>>()?;
    let beamed_outs = tx
        .beamed_outs
        .iter()
        .flatten()
        .map(|(index, dest_hash)| words(&[word((*index).into()), dest_hash.0]))
        .collect();
    let scrolls = tx
        .scrolls
        .iter()
        .flatten()
        .map(|index| words(&[word((*index).into())]))
        .collect();
    Ok(Abi::Dynamic(tuple(vec![
        words(&[word(spell.version.into())]),
        array(app_heads),
        array(public_inputs),
        array(pins),
        array(ins),
        array(refs),
        array(outs),
        array(beamed_outs),
        array(scrolls),
    ])))
}

fn encode_charms(apps: &[&App], charms: &NormalizedCharms) -> anyhow::Result<Abi> {
    let charms = charms
        .iter()
        .map(|(&index, data)| {
            let app = apps
                .get(index as usize)
                .with_context(|| format!("charm app index {index} has no app"))?;
            let (amount, bytes) = match app.tag {
                TOKEN => (
                    data.value::<u64>().context("a token charm must be a u64")?,
                    Vec::new(),
                ),
                _ => (0, data.bytes()),
            };
            let charm = vec![
                words(&[word(index.into()), word(amount)]),
                Abi::Dynamic(encode_bytes(&bytes)),
            ];
            Ok(Abi::Dynamic(tuple(charm)))
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(array(charms))
}

/// `UtxoRef.txId` is in keccak byte order, the reverse of `TxId`.
fn utxo_ref(utxo: &UtxoId) -> Abi {
    let mut tx_id = utxo.0.0;
    tx_id.reverse();
    words(&[tx_id, word(utxo.1.into())])
}

fn tuple(fields: Vec<Abi>) -> Vec<u8> {
    let heads: usize = fields
        .iter()
        .map(|field| match field {
            Abi::Static(bytes) => bytes.len(),
            Abi::Dynamic(_) => 32,
        })
        .sum();
    let mut head = Vec::with_capacity(heads);
    let mut tail = Vec::new();
    for field in fields {
        match field {
            Abi::Static(bytes) => head.extend(bytes),
            Abi::Dynamic(bytes) => {
                head.extend(word((heads + tail.len()) as u64));
                tail.extend(bytes);
            }
        }
    }
    head.extend(tail);
    head
}

fn array(items: Vec<Abi>) -> Abi {
    let mut encoded = word(items.len() as u64).to_vec();
    encoded.extend(tuple(items));
    Abi::Dynamic(encoded)
}

fn words(words: &[[u8; 32]]) -> Abi {
    Abi::Static(words.concat())
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
    use crate::{NormalizedCharms, V14, is_correct};
    use ark_bls12_381::Bls12_381;
    use ark_ff::Field;
    use ark_ff::ToConstraintField;
    use ark_groth16::{Groth16, ProvingKey};
    use ark_relations::{
        gr1cs::{self, ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
        lc,
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_snark::SNARK;
    use ark_std::rand::{SeedableRng, rngs::StdRng};
    use charms_data::{B32, Data, NFT, NativeOutput, UtxoId, VersionedApp};
    use sha2::{Digest, Sha256};
    use std::str::FromStr;

    const CBOR: &str = "a36776657273696f6e10627478a363696e7380646f75747381a065636f696e7381a266616d6f756e74006464657374940102030405060708090a0b0c0d0e0f1011121314716170705f7075626c69635f696e70757473a0";
    const TX_ID: &str = "8cb5ef4b8fd977bd570fbe98db1eaed4f1bb223086ab3e8d0b1b6e892abe2b5d";
    const BEAM: &str = "07703e3d628141aaae43f70cafe8eaa764b9da77b076817be1c847e472665718";
    const BEAM_NONCE_1: &str = "c203c462cba325170ab8eb66e6b350d3a84bb4acf1545f680f471fa4278de2d7";
    const CALL: &str = "0x27485a9300000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000007000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000260000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000102030405060708090a0b0c0d0e0f1011121314000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

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
            "version: 16\ntx:\n  outs:\n{outputs}  coins:\n{coins}app_public_inputs: {{}}\n"
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn the_printed_record_encodes_transact() {
        let plan = plan_placeholder(&spell(1), &request(None)).unwrap();
        let spell = plan.record.decode().unwrap();
        assert!(spell.tx.beamed_outs.is_none());
        let json = serde_json::to_string(&Tx::Ethereum(plan.record)).unwrap();
        let Tx::Ethereum(parsed) = serde_json::from_str::<Tx>(&json).unwrap() else {
            panic!("ethereum record");
        };
        let call = transact_call(&parsed).unwrap();
        assert_eq!(call.data, CALL);
        assert_eq!(call.from, "0x1111111111111111111111111111111111111111");
        assert_eq!(call.to, "0x3333333333333333333333333333333333333333");
        assert_eq!(call.value, "0");
        assert!(!call.data.contains(BEAM));
    }

    #[test]
    fn a_record_without_its_caller_is_not_signable() {
        let mut plan = plan_placeholder(&spell(1), &request(None)).unwrap();
        plan.record.caller = None;
        let err = transact_call(&plan.record).unwrap_err();
        assert_eq!(err.to_string(), "ethereum placeholder is missing a caller");
    }

    #[test]
    fn a_record_without_its_salt_is_not_signable() {
        let mut plan = plan_placeholder(&spell(1), &request(None)).unwrap();
        plan.record.salt = None;
        let err = transact_call(&plan.record).unwrap_err();
        assert_eq!(err.to_string(), "ethereum placeholder is missing a salt");
    }

    #[test]
    fn a_changed_caller_does_not_encode_transact() {
        let mut plan = plan_placeholder(&spell(1), &request(None)).unwrap();
        plan.record.caller = Some([0x22; 20]);
        let err = transact_call(&plan.record).unwrap_err();
        assert_eq!(
            err.to_string(),
            "ethereum placeholder anchor does not match the caller and salt"
        );
    }

    #[test]
    fn a_changed_salt_does_not_encode_transact() {
        let mut plan = plan_placeholder(&spell(1), &request(None)).unwrap();
        let mut salt = plan.record.salt.unwrap();
        salt[31] = salt[31].wrapping_add(1);
        plan.record.salt = Some(salt);
        let err = transact_call(&plan.record).unwrap_err();
        assert_eq!(
            err.to_string(),
            "ethereum placeholder anchor does not match the caller and salt"
        );
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
        let parsed = from_envelope_hex(&tx.hex()).unwrap().unwrap();
        assert_eq!(parsed, plan.record);
        assert_eq!(transact_call(&parsed).unwrap().data, CALL);
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
    fn nonce_changes_only_the_beam_hash() {
        let plan = plan_placeholder(&spell(1), &request(Some(1))).unwrap();
        assert_eq!(plan.tx_id, TX_ID);
        assert_eq!(plan.beamed_outs["0"], BEAM_NONCE_1);
        assert_ne!(plan.beamed_outs["0"], BEAM);
    }

    #[test]
    fn two_empty_outputs_keep_their_indexes() {
        let plan = plan_placeholder(&spell(2), &request(None)).unwrap();
        assert_eq!(
            plan.tx_id,
            "4736b5c20eb90bbfb63815d4864551dcc71c7988983aabc244c498eddda6cce7"
        );
        assert_eq!(
            plan.beamed_outs["0"],
            "872a4fefe34ec766f5d02b94fbc95c52f7eae8130f40f549408c644e40bf46f3"
        );
        assert_eq!(
            plan.beamed_outs["1"],
            "e014ac9cae206f740ed6ef90179b42d5e399b7227b646d90099fe6738b2ddd73"
        );
        assert_eq!(
            plan.utxo_ids[1],
            "4736b5c20eb90bbfb63815d4864551dcc71c7988983aabc244c498eddda6cce7:1"
        );
        assert_eq!(
            hex::encode(&plan.record.spell),
            "a36776657273696f6e10627478a363696e7380646f75747382a0a065636f696e7382a266616d6f756e74006464657374940102030405060708090a0b0c0d0e0f1011121314a266616d6f756e740064646573749418221822182218221822182218221822182218221822182218221822182218221822182218221822716170705f7075626c69635f696e70757473a0"
        );
    }

    #[test]
    fn a_charm_on_the_output_is_not_a_placeholder() {
        let yaml = r#"
version: 16
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
version: 16
tx:
  ins:
    - 8cb5ef4b8fd977bd570fbe98db1eaed4f1bb223086ab3e8d0b1b6e892abe2b5d:0
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
version: 16
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

    fn claim_of(source: &EthereumTx, amount: u64, dest: Vec<u8>) -> NormalizedSpell {
        let mut claim = NormalizedSpell::default();
        claim.tx.ins = Some(vec![UtxoId(source.tx_id(), 0)]);
        claim.tx.outs = vec![NormalizedCharms::new()];
        claim.tx.coins = Some(vec![NativeOutput {
            amount,
            dest,
            content: None,
        }]);
        claim
    }

    fn token_claim(source: &EthereumTx) -> NormalizedSpell {
        let mut claim = claim_of(source, 0, vec![0x44; 20]);
        let token = App {
            tag: TOKEN,
            identity: B32([1; 32]),
            vk: B32([2; 32]),
        };
        claim.app_public_inputs.insert(token, Data::empty());
        claim.tx.outs[0].insert(0, Data::from(&1000u64));
        claim
    }

    #[test]
    fn a_proved_claim_encodes_transact_with_a_zero_salt() {
        let source = plan_placeholder(&spell(1), &request(None)).unwrap().record;
        let proof: Vec<u8> = (1..=100).collect();
        let claim = token_claim(&source);
        let record = record_with_proof(&claim, proof.clone(), 1, [0x33; 20]).unwrap();
        let call = transact_call(&record).unwrap();
        let data = hex::decode(&call.data[2..]).unwrap();
        assert_eq!(hex::encode(&data[..4]), "27485a93");
        assert_eq!(data[36..68], [0u8; 32]);
        assert!(call.data.contains(&hex::encode(&proof)));
        assert!(call.data.contains(&hex::encode(source.eth_tx_id())));
        assert_eq!(call.from, "0x4444444444444444444444444444444444444444");
        assert_eq!(call.to, "0x3333333333333333333333333333333333333333");
        assert_eq!(call.value, "0");

        let placeholder = plan_placeholder(&spell(1), &request(None)).unwrap().record;
        assert_eq!(transact_call(&placeholder).unwrap().data, CALL);
    }

    fn rich_claim() -> NormalizedSpell {
        let nft = App {
            tag: NFT,
            identity: B32([0x10; 32]),
            vk: B32([0x20; 32]),
        };
        let token = App {
            tag: TOKEN,
            identity: B32([0x30; 32]),
            vk: B32([0x40; 32]),
        };
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![UtxoId(TxId([0x51; 32]), 2)]);
        spell.tx.refs = Some(vec![UtxoId(TxId([0x61; 32]), 4)]);
        spell
            .app_public_inputs
            .insert(nft.clone(), Data::from(&7u64));
        spell.app_public_inputs.insert(token, Data::empty());
        spell.versioned_apps.insert(
            nft.vk,
            VersionedApp {
                version: 3,
                wasm_hash: B32([0x70; 32]),
            },
        );
        let mut both = NormalizedCharms::new();
        both.insert(0, Data::from(&9u64));
        both.insert(1, Data::from(&1000u64));
        let mut token_only = NormalizedCharms::new();
        token_only.insert(1, Data::from(&5u64));
        spell.tx.outs = vec![both, token_only, NormalizedCharms::new()];
        spell.tx.coins = Some(vec![
            NativeOutput {
                amount: 0,
                dest: vec![0x11; 20],
                content: None,
            },
            NativeOutput {
                amount: 0,
                dest: vec![0x22; 20],
                content: None,
            },
            NativeOutput {
                amount: 0,
                dest: vec![0; 20],
                content: None,
            },
        ]);
        spell.tx.beamed_outs = Some(BTreeMap::from([(2, B32([0x80; 32]))]));
        spell
    }

    #[test]
    fn a_rich_proved_call_matches_the_guest_spell() {
        let spell = rich_claim();
        let data = transact_calldata(&spell, [0u8; 32], &[0xab, 0xcd]).unwrap();
        let cbor = util::write(&spell).unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(data)),
            include_str!("../../ethereum/test/vectors/proved-claim-call.hex").trim()
        );
        assert_eq!(
            format!("0x{}", hex::encode(cbor)),
            include_str!("../../ethereum/test/vectors/proved-claim-cbor.hex").trim()
        );
    }

    #[test]
    fn a_proved_claim_the_contract_would_reject_is_not_encoded() {
        let source = plan_placeholder(&spell(1), &request(None)).unwrap().record;
        let claim = token_claim(&source);
        let mut record = record_with_proof(&claim, vec![1], 1, [0x33; 20]).unwrap();
        record.anchor = Some([0u8; 32]);
        transact_call(&record).expect("a zero anchor is the contract's anchor");

        record.anchor = Some([7u8; 32]);
        let err = transact_call(&record).unwrap_err();
        assert_eq!(
            err.to_string(),
            "a proved ethereum spell's anchor must be zero"
        );

        record.anchor = None;
        record.proof = Vec::new();
        let err = transact_call(&record).unwrap_err();
        assert_eq!(err.to_string(), "a placeholder has no apps");

        let mut beamed = claim.clone();
        beamed.tx.beamed_outs = Some(BTreeMap::from([(0, B32([5; 32]))]));
        let record = record_with_proof(&beamed, vec![1], 1, [0x33; 20]).unwrap();
        let err = transact_call(&record).unwrap_err();
        assert_eq!(
            err.to_string(),
            "coins[0].dest must be the zero address exactly when output 0 is beamed"
        );
    }

    #[test]
    fn a_v15_placeholder_still_extracts_and_can_be_spent() {
        let mut carried = spell(1);
        carried.version = V15;
        let plan = plan_placeholder(&carried, &request(None)).unwrap();
        let bytes = plan.record.spell.clone();
        let tx_id = plan.record.tx_id();
        let extracted = plan
            .record
            .extract_and_verify_spell(&[0; 32], false)
            .expect("v15 placeholder");
        assert_eq!(extracted.version, V15);
        assert_eq!(util::write(&extracted).unwrap(), bytes);
        assert_eq!(plan.record.spell, bytes);
        assert_eq!(plan.record.tx_id(), tx_id);

        let mut rewritten = extracted.clone();
        rewritten.version = CURRENT_VERSION;
        let mut rewritten_record = plan.record.clone();
        rewritten_record.spell = util::write(&rewritten).unwrap();
        assert_ne!(rewritten_record.spell, bytes);
        assert_ne!(rewritten_record.tx_id(), tx_id);

        let mut claim = NormalizedSpell::default();
        claim.tx.ins = Some(vec![UtxoId(tx_id, 0)]);
        claim.tx.outs = vec![NormalizedCharms::new()];
        claim.tx.coins = Some(vec![NativeOutput {
            amount: 0,
            dest: vec![1; 20],
            content: None,
        }]);
        assert_eq!(claim.version, CURRENT_VERSION);
        let ok = is_correct(
            &claim,
            &vec![Tx::Ethereum(plan.record)],
            None,
            &[0; 32],
            &BTreeMap::new(),
            None,
        )
        .expect("v16 spell spends the v15 placeholder");
        assert!(ok);
    }

    #[test]
    fn a_version_14_placeholder_is_rejected() {
        let mut carried = spell(1);
        carried.version = V14;
        let err = plan_placeholder(&carried, &request(None)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "placeholder spell version must be 15 or 16"
        );
    }

    #[test]
    fn a_nonzero_amount_is_rejected_for_an_ethereum_spell() {
        let source = plan_placeholder(&spell(1), &request(None)).unwrap().record;
        let claim = claim_of(&source, 1, vec![1; 20]);
        let err = is_correct(
            &claim,
            &vec![Tx::Ethereum(source)],
            None,
            &[0; 32],
            &BTreeMap::new(),
            None,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "coins[0].amount must be 0");
    }

    #[test]
    fn a_short_destination_is_rejected_for_an_ethereum_spell() {
        let source = plan_placeholder(&spell(1), &request(None)).unwrap().record;
        let claim = claim_of(&source, 0, vec![1; 19]);
        let err = is_correct(
            &claim,
            &vec![Tx::Ethereum(source)],
            None,
            &[0; 32],
            &BTreeMap::new(),
            None,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "coins[0].dest must be a 20-byte address");
    }

    fn proved_spell() -> NormalizedSpell {
        let mut spell = NormalizedSpell::default();
        spell.mock = true;
        spell.tx.ins = Some(vec![UtxoId(charms_data::TxId([9; 32]), 0)]);
        spell.tx.outs = vec![NormalizedCharms::new()];
        spell.tx.coins = Some(vec![NativeOutput {
            amount: 0,
            dest: vec![1; 20],
            content: None,
        }]);
        spell
    }

    fn mock_proof(spell: &NormalizedSpell) -> Vec<u8> {
        let vk = tx::spell_vk(spell.version, &[0; 32], true).unwrap();
        let public_values = tx::to_serialized_pv(spell.version, vk, spell);
        let field_elements = Sha256::digest(&public_values)
            .to_field_elements()
            .expect("public values hash");
        let pk = ProvingKey::<Bls12_381>::deserialize_compressed(MOCK_GROTH16_PK)
            .expect("mock groth16 proving key");
        let proof = Groth16::<Bls12_381>::prove(
            &pk,
            MintCircuit {
                a: Some(field_elements[0]),
            },
            &mut StdRng::seed_from_u64(1),
        )
        .expect("mock groth16 proof");
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    fn proved_record(spell: &NormalizedSpell, proof: Vec<u8>) -> EthereumTx {
        EthereumTx {
            chain_id: 1,
            charms: [0x33; 20],
            anchor: None,
            spell: util::write(spell).unwrap(),
            proof,
            caller: None,
            salt: None,
        }
    }

    #[test]
    fn a_valid_ethereum_proof_is_accepted() {
        let spell = proved_spell();
        let record = proved_record(&spell, mock_proof(&spell));
        let verified = record
            .extract_and_verify_spell(&[0; 32], true)
            .expect("valid proof");
        assert_eq!(verified, spell);

        let mut claim = NormalizedSpell::default();
        claim.mock = true;
        claim.tx.ins = Some(vec![UtxoId(record.tx_id(), 0)]);
        claim.tx.coins = Some(Vec::new());
        let ok = is_correct(
            &claim,
            &vec![Tx::Ethereum(record)],
            None,
            &[0; 32],
            &BTreeMap::new(),
            None,
        )
        .expect("claim checks the source proof");
        assert_eq!(ok, true);
    }

    #[test]
    fn a_proved_record_copies_the_host_and_verifies() {
        let source_spell = proved_spell();
        let source = proved_record(&source_spell, mock_proof(&source_spell));
        let mut claim = proved_spell();
        claim.tx.ins = Some(vec![UtxoId(source.tx_id(), 0)]);
        let (chain_id, charms) = hosting_chain(&claim, &[Tx::Ethereum(source.clone())]).unwrap();
        assert_eq!((chain_id, charms), (source.chain_id, source.charms));
        let record = record_with_proof(&claim, mock_proof(&claim), chain_id, charms).unwrap();
        let verified = record
            .extract_and_verify_spell(&[0; 32], true)
            .expect("proof of the committed spell");
        assert_eq!(verified, claim);
        assert!(is_placeholder(&spell(1)));
        assert!(!is_placeholder(&claim));
    }

    #[test]
    fn a_bad_ethereum_proof_is_rejected() {
        let spell = proved_spell();
        let proof = mock_proof(&spell);
        let mut other = spell.clone();
        other.tx.coins.as_mut().unwrap()[0].dest[0] ^= 1;
        let record = proved_record(&other, proof);
        let err = record
            .extract_and_verify_spell(&[0; 32], true)
            .expect_err("bad proof");
        assert_eq!(err.to_string(), "could not verify spell proof");

        let mut claim = NormalizedSpell::default();
        claim.mock = true;
        claim.tx.ins = Some(vec![UtxoId(record.tx_id(), 0)]);
        claim.tx.coins = Some(Vec::new());
        let err = is_correct(
            &claim,
            &vec![Tx::Ethereum(record)],
            None,
            &[0; 32],
            &BTreeMap::new(),
            None,
        )
        .expect_err("claim rejects the source proof");
        assert_eq!(err.to_string(), "could not verify spell proof");
    }

    fn claim_spending(records: &[EthereumTx]) -> NormalizedSpell {
        let mut claim = NormalizedSpell::default();
        claim.mock = true;
        claim.tx.ins = Some(
            records
                .iter()
                .map(|record| UtxoId(record.tx_id(), 0))
                .collect(),
        );
        claim.tx.coins = Some(Vec::new());
        claim
    }

    fn check_claim(records: Vec<EthereumTx>) -> anyhow::Result<bool> {
        let claim = claim_spending(&records);
        let prev_txs = records.into_iter().map(Tx::Ethereum).collect();
        is_correct(&claim, &prev_txs, None, &[0; 32], &BTreeMap::new(), None)
    }

    #[test]
    fn a_proved_spell_with_a_nonzero_anchor_is_rejected() {
        let spell = proved_spell();
        let mut record = proved_record(&spell, mock_proof(&spell));
        record.anchor = Some([0u8; 32]);
        record
            .extract_and_verify_spell(&[0; 32], true)
            .expect("a zero anchor is the contract's anchor");

        record.anchor = Some([7u8; 32]);
        let err = record
            .extract_and_verify_spell(&[0; 32], true)
            .expect_err("nonzero anchor");
        assert_eq!(
            err.to_string(),
            "a proved ethereum spell's anchor must be zero"
        );
        let err = check_claim(vec![record]).expect_err("claim of that output");
        assert_eq!(
            err.to_string(),
            "a proved ethereum spell's anchor must be zero"
        );
    }

    #[test]
    fn a_record_from_another_host_is_rejected() {
        let host_spell = proved_spell();
        let host = proved_record(&host_spell, mock_proof(&host_spell));
        let mut sibling_spell = proved_spell();
        sibling_spell.tx.coins.as_mut().unwrap()[0].dest[0] = 2;
        let sibling = proved_record(&sibling_spell, mock_proof(&sibling_spell));
        assert!(check_claim(vec![host.clone(), sibling.clone()]).expect("same host"));

        let mut other_chain = sibling.clone();
        other_chain.chain_id = host.chain_id + 1;
        let err = check_claim(vec![host.clone(), other_chain.clone()]).expect_err("other chain");
        assert_eq!(
            err.to_string(),
            format!(
                "Ethereum previous transaction {} is not on the same chain \
                 and contract as the hosting record",
                other_chain.tx_id()
            )
        );

        let mut other_contract = sibling;
        other_contract.charms[0] ^= 1;
        let err = check_claim(vec![host, other_contract.clone()]).expect_err("other contract");
        assert_eq!(
            err.to_string(),
            format!(
                "Ethereum previous transaction {} is not on the same chain \
                 and contract as the hosting record",
                other_contract.tx_id()
            )
        );
    }

    const MOCK_GROTH16_PK: &[u8] = include_bytes!("../../src/bin/mock-groth16-pk.bin");

    struct MintCircuit<F: Field> {
        a: Option<F>,
    }

    impl<F: Field> ConstraintSynthesizer<F> for MintCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> gr1cs::Result<()> {
            let missing = SynthesisError::AssignmentMissing;
            let a = cs.new_witness_variable(|| self.a.ok_or(missing))?;
            let c = cs.new_input_variable(|| self.a.ok_or(missing))?;
            cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + Variable::One, || lc!() + c)
        }
    }
}
