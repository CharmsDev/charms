//! Raw Ethereum transactions and the inverse of [`charms_client::ethereum_tx::transact_call`].
//!
//! A Charms `transact` carries the spell as an ABI struct. [`spell_from_transact_calldata`]
//! rebuilds the [`NormalizedSpell`] that struct was encoded from. An ERC-20 `transfer` or
//! `transferFrom` carries no spell. Those calls decode as [`empty_ethereum_spell`].
//!
//! Dynamic-array offsets in that struct are relative to the head after the length word.
//! [`alloy_sol_types::sol`] decodes that ABI. `ins` is always `Some`, including when the
//! array is empty, so the CBOR key survives.

use alloy_consensus::{
    SignableTransaction, Transaction, TxEip1559, TxEnvelope, transaction::RlpEcdsaDecodableTx,
};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, Result, anyhow, bail, ensure};
use charms_client::ethereum_tx::{self, EthereumTx};
use charms_client::{NormalizedCharms, NormalizedSpell, NormalizedTransaction};
use charms_data::{App, B32, Data, NativeOutput, TOKEN, TxId, UtxoId, VersionedApp};
use std::collections::{BTreeMap, BTreeSet};

sol! {
    struct CharmsApp {
        uint32 tag;
        bytes32 identity;
        bytes32 vk;
    }
    struct CharmsPin {
        bytes32 vk;
        uint32 version;
        bytes32 wasm_hash;
    }
    struct CharmsUtxo {
        bytes32 tx_id;
        uint32 index;
    }
    struct CharmsCharm {
        uint32 app_index;
        uint64 amount;
        bytes data;
    }
    struct CharmsInput {
        CharmsUtxo utxo;
        CharmsCharm[] charms;
        CharmsPin[] pins;
    }
    struct CharmsOutput {
        address owner;
        CharmsCharm[] charms;
    }
    struct CharmsBeam {
        uint32 index;
        bytes32 dest;
    }
    struct CharmsSpell {
        uint32 version;
        CharmsApp[] apps;
        bytes[] public_inputs;
        CharmsPin[] pins;
        CharmsInput[] inputs;
        CharmsUtxo[] refs;
        CharmsOutput[] outputs;
        CharmsBeam[] beamed_outs;
        uint32[] scrolls;
    }
    function transact(
        CharmsSpell spell,
        bytes32 salt,
        bytes proof,
        bytes[] signatures
    );
    function transfer(address to, uint256 amount);
    function transferFrom(address from, address to, uint256 amount);
}

const MAX_ABI_LEN: usize = 65_536;

/// Spell `show-spell` prints for an ERC-20 `transfer` or `transferFrom`.
///
/// The facade builds the real spell inside the contract. The calldata has none.
/// This is [`NormalizedSpell::default`]: protocol version 16, no inputs, no outputs,
/// and no apps.
pub fn empty_ethereum_spell() -> NormalizedSpell {
    NormalizedSpell::default()
}

/// Chain id, destination, and calldata of one Ethereum transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedEthereumCall {
    /// `None` for a legacy transaction signed without EIP-155.
    pub chain_id: Option<u64>,
    /// `None` when the transaction creates a contract.
    pub to: Option<[u8; 20]>,
    pub input: Vec<u8>,
}

/// Fee fields of an unsigned type-2 transaction. Amounts are wei.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eip1559Fee {
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
}

/// Unsigned type-2 transaction whose calldata is [`ethereum_tx::transact_call`] for `record`.
///
/// `to` is the record's Charms proxy. The value is 0 because `transact` is not payable.
/// The `signatures` array in the calldata stays empty, the same as
/// [`ethereum_tx::transact_call`] builds it today.
pub fn unsigned_transact_eip1559(record: &EthereumTx, fee: &Eip1559Fee) -> Result<Vec<u8>> {
    let call = ethereum_tx::transact_call(record)?;
    let input = hex::decode(strip_0x(call.data.trim())).context("transact calldata hex")?;
    let tx = TxEip1559 {
        chain_id: record.chain_id,
        nonce: fee.nonce,
        gas_limit: fee.gas_limit,
        max_fee_per_gas: fee.max_fee_per_gas,
        max_priority_fee_per_gas: fee.max_priority_fee_per_gas,
        to: TxKind::Call(Address::from(record.charms)),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::from(input),
    };
    let mut out = Vec::new();
    tx.encode_for_signing(&mut out);
    Ok(out)
}

/// Decode a signed transaction, or an unsigned type-2 transaction.
///
/// Unsigned EIP-1559 is `0x02` plus the RLP list header and the nine fields.
/// Signed legacy, type 1, and type 2 use the EIP-2718 envelope.
pub fn decode_ethereum_call(raw: &[u8]) -> Result<DecodedEthereumCall> {
    if raw.is_empty() {
        bail!("not an ethereum transaction");
    }
    if raw[0] == 0x02 {
        let mut payload = &raw[1..];
        if let Ok(tx) = TxEip1559::rlp_decode(&mut payload)
            && payload.is_empty()
        {
            return call_parts(Some(tx.chain_id), tx.to, &tx.input);
        }
    }
    let envelope =
        TxEnvelope::decode_2718_exact(raw).map_err(|_| anyhow!("not an ethereum transaction"))?;
    call_parts(envelope.chain_id(), envelope.kind(), envelope.input())
}

/// Spell carried by a raw transaction.
///
/// `transact` decodes the ABI spell. `transfer` and `transferFrom` return
/// [`empty_ethereum_spell`]. Anything else is an error. This does not panic.
pub fn spell_from_raw_transaction(raw: &[u8]) -> Result<NormalizedSpell> {
    let call = decode_ethereum_call(raw)?;
    if call.to.is_none() {
        bail!("transaction creates a contract and has no spell");
    }
    spell_from_input(&call.input)
}

/// Inverse of the `transact` calldata built by [`ethereum_tx::transact_call`].
pub fn spell_from_transact_calldata(calldata: &[u8]) -> Result<NormalizedSpell> {
    let (selector, _) = calldata.split_at_checked(4).context("calldata is short")?;
    ensure!(
        selector == transactCall::SELECTOR,
        "calldata is not a Charms transact call"
    );
    let call =
        transactCall::abi_decode(calldata).map_err(|err| anyhow!("transact arguments: {err}"))?;
    spell_from_abi(&call.spell)
}

fn spell_from_input(input: &[u8]) -> Result<NormalizedSpell> {
    let selector: [u8; 4] = input
        .get(..4)
        .context("transaction input has no function selector")?
        .try_into()
        .expect("four bytes");
    if selector == transactCall::SELECTOR {
        return spell_from_transact_calldata(input);
    }
    if selector == transferCall::SELECTOR || selector == transferFromCall::SELECTOR {
        return Ok(empty_ethereum_spell());
    }
    bail!("transaction input is not a Charms transact call or an ERC-20 transfer")
}

fn spell_from_abi(spell: &CharmsSpell) -> Result<NormalizedSpell> {
    bounded(spell.apps.len())?;
    bounded(spell.public_inputs.len())?;
    bounded(spell.pins.len())?;
    bounded(spell.inputs.len())?;
    bounded(spell.refs.len())?;
    bounded(spell.outputs.len())?;
    bounded(spell.beamed_outs.len())?;
    bounded(spell.scrolls.len())?;
    ensure!(
        spell.public_inputs.len() == spell.apps.len(),
        "public inputs do not match apps"
    );
    let mut app_public_inputs = BTreeMap::new();
    let mut apps = Vec::with_capacity(spell.apps.len());
    for (app, input) in spell.apps.iter().zip(&spell.public_inputs) {
        let decoded = decode_app(app)?;
        let data = cbor_data(input).context("public input is not one cbor value")?;
        ensure!(
            app_public_inputs.insert(decoded.clone(), data).is_none(),
            "duplicate app"
        );
        apps.push(decoded);
    }
    let mut versioned_apps = BTreeMap::new();
    for pin in &spell.pins {
        let vk = b32(pin.vk);
        let versioned = VersionedApp {
            version: pin.version,
            wasm_hash: b32(pin.wasm_hash),
        };
        ensure!(
            versioned_apps.insert(vk, versioned).is_none(),
            "duplicate versioned app"
        );
    }
    // Input openings are not part of the committed spell. Only the utxo is.
    let ins = spell
        .inputs
        .iter()
        .map(|input| read_utxo(&input.utxo))
        .collect();
    let refs: Vec<_> = spell.refs.iter().map(read_utxo).collect();
    let mut outs = Vec::with_capacity(spell.outputs.len());
    let mut coins = Vec::with_capacity(spell.outputs.len());
    for output in &spell.outputs {
        outs.push(decode_charms(&output.charms, &apps)?);
        coins.push(NativeOutput {
            amount: 0,
            dest: output.owner.into_array().to_vec(),
            content: None,
        });
    }
    let mut beamed_outs = BTreeMap::new();
    for beam in &spell.beamed_outs {
        ensure!(
            beamed_outs.insert(beam.index, b32(beam.dest)).is_none(),
            "duplicate beamed output {}",
            beam.index
        );
    }
    let mut scrolls = BTreeSet::new();
    for index in &spell.scrolls {
        ensure!(scrolls.insert(*index), "duplicate scroll {index}");
    }
    Ok(NormalizedSpell {
        version: spell.version,
        tx: NormalizedTransaction {
            ins: Some(ins),
            refs: some_if_not_empty(refs),
            outs,
            beamed_outs: some_if_not_empty_map(beamed_outs),
            coins: Some(coins),
            scrolls: some_if_not_empty_set(scrolls),
        },
        app_public_inputs,
        versioned_apps,
        mock: false,
    })
}

fn decode_app(app: &CharmsApp) -> Result<App> {
    let tag = char::from_u32(app.tag).context("app tag is not a unicode scalar")?;
    Ok(App {
        tag,
        identity: b32(app.identity),
        vk: b32(app.vk),
    })
}

fn decode_charms(charms: &[CharmsCharm], apps: &[App]) -> Result<NormalizedCharms> {
    bounded(charms.len())?;
    let mut out = NormalizedCharms::new();
    for charm in charms {
        let app = apps
            .get(charm.app_index as usize)
            .context("charm app index has no app")?;
        let raw = charm.data.as_ref();
        let data = if app.tag == TOKEN {
            ensure!(raw.is_empty(), "a token charm's data is empty");
            Data::from(&charm.amount)
        } else {
            ensure!(charm.amount == 0, "a non-token charm's amount is zero");
            cbor_data(raw).context("charm data is not one cbor value")?
        };
        ensure!(
            out.insert(charm.app_index, data).is_none(),
            "duplicate charm index {}",
            charm.app_index
        );
    }
    Ok(out)
}

fn read_utxo(utxo: &CharmsUtxo) -> UtxoId {
    // `UtxoRef.txId` is keccak byte order, the reverse of `TxId`.
    let mut tx_id = utxo.tx_id.0;
    tx_id.reverse();
    UtxoId(TxId(tx_id), utxo.index)
}

fn b32(word: alloy_primitives::B256) -> B32 {
    B32(word.0)
}

fn call_parts(chain_id: Option<u64>, to: TxKind, input: &Bytes) -> Result<DecodedEthereumCall> {
    Ok(DecodedEthereumCall {
        chain_id,
        to: match to {
            TxKind::Call(addr) => Some(addr.into_array()),
            TxKind::Create => None,
        },
        input: input.to_vec(),
    })
}

fn bounded(len: usize) -> Result<()> {
    ensure!(len <= MAX_ABI_LEN, "abi array is longer than {MAX_ABI_LEN}");
    Ok(())
}

fn cbor_data(bytes: &[u8]) -> Result<Data> {
    let data = Data::try_from_bytes(bytes)?;
    ensure!(data.bytes() == bytes, "cbor value is not the whole blob");
    Ok(data)
}

fn some_if_not_empty<T>(items: Vec<T>) -> Option<Vec<T>> {
    if items.is_empty() { None } else { Some(items) }
}

fn some_if_not_empty_map<K: Ord, V>(map: BTreeMap<K, V>) -> Option<BTreeMap<K, V>> {
    if map.is_empty() { None } else { Some(map) }
}

fn some_if_not_empty_set<T: Ord>(set: BTreeSet<T>) -> Option<BTreeSet<T>> {
    if set.is_empty() { None } else { Some(set) }
}

fn strip_0x(text: &str) -> &str {
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip2930, TxLegacy};
    use alloy_eips::eip2718::{Decodable2718, Encodable2718};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, keccak256};
    use alloy_rlp::Decodable;
    use alloy_sol_types::{SolCall, SolEvent};
    use charms_client::ethereum_tx::{self, EthereumTx};
    use charms_client::tx::{EnchantedTx, Tx};
    use charms_client::{NormalizedCharms, NormalizedSpell};
    use charms_data::{App, B32, Data, NFT, NativeOutput, TxId, UtxoId, VersionedApp, util};
    use std::collections::{BTreeMap, BTreeSet};

    mod event {
        alloy_sol_types::sol! {
            event Transaction(bytes32 indexed tx_id, bytes32 anchor, bytes spell);
        }
    }

    #[test]
    fn selectors_match_the_signatures() {
        assert_eq!(transactCall::SIGNATURE, ethereum_tx::TRANSACT_SIGNATURE);
        assert_eq!(transactCall::SELECTOR, selector(transactCall::SIGNATURE));
        assert_eq!(
            transferCall::SELECTOR,
            selector("transfer(address,uint256)")
        );
        assert_eq!(
            transferFromCall::SELECTOR,
            selector("transferFrom(address,address,uint256)")
        );
    }

    fn selector(signature: &str) -> [u8; 4] {
        let digest = keccak256(signature.as_bytes());
        digest.0[..4].try_into().unwrap()
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        hex::decode(strip_0x(text.trim())).unwrap()
    }

    fn assert_calldata_roundtrip(spell: &NormalizedSpell, proof: &[u8]) {
        let data = ethereum_tx::transact_calldata(spell, [7; 32], proof).unwrap();
        let decoded = spell_from_transact_calldata(&data).unwrap();
        assert_eq!(&decoded, spell);
        assert_eq!(util::write(&decoded).unwrap(), util::write(spell).unwrap());
    }

    #[test]
    fn transact_calldata_roundtrips_a_placeholder() {
        let yaml = "version: 16\ntx:\n  outs:\n    - {}\n  coins:\n    - amount: 0\n      dest: \"0102030405060708090a0b0c0d0e0f1011121314\"\napp_public_inputs: {}\n";
        let spell: NormalizedSpell = serde_yaml::from_str(yaml).unwrap();
        let mut salt = [0u8; 32];
        salt[31] = 7;
        let plan = ethereum_tx::plan_placeholder(
            &spell,
            &ethereum_tx::PlaceholderRequest {
                chain_id: 1,
                charms: [0x33; 20],
                caller: [0x11; 20],
                salt,
                nonce: None,
            },
        )
        .unwrap();
        let data = hex_bytes(&plan.call.data);
        let decoded = spell_from_transact_calldata(&data).unwrap();
        let committed = plan.record.decode().unwrap();
        assert_eq!(decoded, committed);
        assert_eq!(util::write(&decoded).unwrap(), plan.record.spell);
    }

    #[test]
    fn transact_calldata_roundtrips_a_spell_with_inputs_apps_and_a_proof() {
        let nft = App {
            tag: NFT,
            identity: B32([3; 32]),
            vk: B32([4; 32]),
        };
        let token = App {
            tag: TOKEN,
            identity: B32([9; 32]),
            vk: B32([8; 32]),
        };
        let mut tx_id = [0u8; 32];
        tx_id[0] = 0x01;
        tx_id[31] = 0x02;
        let mut ref_id = [0u8; 32];
        ref_id[0] = 0x0a;
        ref_id[31] = 0x0b;
        let mut spell = NormalizedSpell::default();
        spell.app_public_inputs.insert(nft, Data::from(&"glyph"));
        spell.app_public_inputs.insert(token, Data::empty());
        spell.versioned_apps.insert(
            B32([4; 32]),
            VersionedApp {
                version: 3,
                wasm_hash: B32([5; 32]),
            },
        );
        spell.tx.ins = Some(vec![UtxoId(TxId(tx_id), 2)]);
        spell.tx.refs = Some(vec![UtxoId(TxId(ref_id), 1)]);
        let mut out = NormalizedCharms::new();
        out.insert(0, Data::from(&"glyph"));
        out.insert(1, Data::from(&50u64));
        spell.tx.outs = vec![out, NormalizedCharms::new()];
        spell.tx.coins = Some(vec![
            NativeOutput {
                amount: 0,
                dest: vec![0xab; 20],
                content: None,
            },
            NativeOutput {
                amount: 0,
                dest: vec![0; 20],
                content: None,
            },
        ]);
        spell.tx.beamed_outs = Some(BTreeMap::from([(1, B32([0xee; 32]))]));
        spell.tx.scrolls = Some(BTreeSet::from([0]));
        assert_calldata_roundtrip(&spell, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn a_native_spell_roundtrips_without_its_input_openings() {
        let charms = [0x33; 20];
        let mut creator_spell = NormalizedSpell::default();
        creator_spell
            .app_public_inputs
            .insert(token_app(), Data::empty());
        creator_spell.tx.ins = Some(Vec::new());
        creator_spell.tx.outs = vec![token_output(8_000)];
        creator_spell.tx.coins = Some(vec![eth_coin([0x44; 20])]);
        let creator = EthereumTx {
            chain_id: 1,
            charms,
            anchor: Some([9; 32]),
            spell: util::write(&creator_spell).unwrap(),
            proof: Vec::new(),
            caller: None,
            salt: None,
            signature: None,
            input_sources: Vec::new(),
        };
        let mut spell = NormalizedSpell::default();
        spell.app_public_inputs.insert(token_app(), Data::empty());
        spell.tx.ins = Some(vec![UtxoId(creator.tx_id(), 0)]);
        spell.tx.outs = vec![token_output(8_000)];
        spell.tx.coins = Some(vec![eth_coin([0x55; 20])]);
        let plan = ethereum_tx::plan_native(&spell, &[Tx::Ethereum(creator)]).unwrap();
        let data = hex_bytes(&plan.call.data);
        let decoded = spell_from_transact_calldata(&data).unwrap();
        assert_eq!(decoded, spell);
        assert_eq!(util::write(&decoded).unwrap(), plan.record.spell);
    }

    fn token_app() -> App {
        App {
            tag: TOKEN,
            identity: B32([1; 32]),
            vk: B32([2; 32]),
        }
    }

    fn token_output(amount: u64) -> NormalizedCharms {
        let mut charms = NormalizedCharms::new();
        charms.insert(0, Data::from(&amount));
        charms
    }

    fn eth_coin(dest: [u8; 20]) -> NativeOutput {
        NativeOutput {
            amount: 0,
            dest: dest.to_vec(),
            content: None,
        }
    }

    #[test]
    fn an_unsigned_type_2_transaction_signs_and_shows_the_same_spell() {
        use alloy_primitives::b256;
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;

        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(Vec::new());
        spell.tx.outs = vec![NormalizedCharms::new()];
        spell.tx.coins = Some(vec![eth_coin([0x11; 20])]);
        let data = ethereum_tx::transact_calldata(&spell, [9; 32], &[]).unwrap();
        let fee = Eip1559Fee {
            nonce: 7,
            max_priority_fee_per_gas: 1_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 500_000,
        };
        let mut raw = Vec::new();
        TxEip1559 {
            chain_id: 1,
            nonce: fee.nonce,
            gas_limit: fee.gas_limit,
            max_fee_per_gas: fee.max_fee_per_gas,
            max_priority_fee_per_gas: fee.max_priority_fee_per_gas,
            to: TxKind::Call(Address::from([0x33; 20])),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from(data.clone()),
        }
        .encode_for_signing(&mut raw);
        assert_eq!(raw[0], 0x02);
        let plan = ethereum_tx::plan_placeholder(
            &spell,
            &ethereum_tx::PlaceholderRequest {
                chain_id: 1,
                charms: [0x33; 20],
                caller: [0x11; 20],
                salt: [9; 32],
                nonce: None,
            },
        )
        .unwrap();
        let produced = unsigned_transact_eip1559(&plan.record, &fee).unwrap();
        assert_eq!(
            spell_from_raw_transaction(&produced).unwrap(),
            plan.record.decode().unwrap()
        );

        let mut payload = &raw[1..];
        let decoded = TxEip1559::decode(&mut payload).expect("alloy decodes the unsigned tx");
        assert!(payload.is_empty());
        assert_eq!(decoded.chain_id, 1);
        assert_eq!(decoded.nonce, 7);
        assert_eq!(decoded.max_priority_fee_per_gas, 1_000_000);
        assert_eq!(decoded.max_fee_per_gas, 2_000_000_000);
        assert_eq!(decoded.gas_limit, 500_000);
        assert_eq!(decoded.to, TxKind::Call(Address::from([0x33; 20])));
        assert_eq!(decoded.value, U256::from(0));
        assert!(decoded.access_list.0.is_empty());
        assert_eq!(decoded.input, Bytes::from(data));
        let mut signing = Vec::new();
        decoded.encode_for_signing(&mut signing);
        assert_eq!(signing, raw);

        let signer = PrivateKeySigner::from_bytes(&b256!(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        ))
        .unwrap();
        let signature = signer.sign_hash_sync(&decoded.signature_hash()).unwrap();
        let envelope: TxEnvelope = decoded.into_signed(signature).into();
        let signed = envelope.encoded_2718();
        let again = TxEnvelope::decode_2718_exact(&signed).unwrap();
        assert_eq!(again.tx_hash(), envelope.tx_hash());

        let from_unsigned = spell_from_raw_transaction(&raw).unwrap();
        let from_signed = spell_from_raw_transaction(&signed).unwrap();
        assert_eq!(from_unsigned, spell);
        assert_eq!(from_signed, spell);
    }

    #[test]
    fn mainnet_transactions_match_the_transaction_event() {
        let proxy = "7f7ab9224782de7a20e89e6fc0de52ff6b48d8f0";
        let cases = [
            (
                "0x82439d38cb7a87912ab4da6016fa9b2b8598020ff9121ebf388056cc8ae6a7af",
                false,
                proxy,
            ),
            (
                "0xf9bf737f435fea4a2c8d3337b7dfc94040ac986800bf8a1c9ddbdf754ee86ce5",
                false,
                proxy,
            ),
            (
                "0x44a897c638cee33e62441af150a8c978f3303576b701dff3ada0974c017a1154",
                false,
                proxy,
            ),
            (
                "0xddbd6e2afd317aff3a761c273c0d7b0b7c33af23538dab5d5cc97e4e41f0999d",
                true,
                "e13283eebe57a75829e4d814186fcb8acfdcfecd",
            ),
        ];
        let topic0 = format!("{:x}", event::Transaction::SIGNATURE_HASH);
        assert_eq!(
            topic0,
            "ed7743a45edb0894d0ca5210b2ffda1c9caac2b5946f7a0aa77abb2cb9314d74"
        );
        for (hash, empty, to_hex) in cases {
            let raw_text = fixture(&format!("{hash}.raw.txt"));
            let raw = hex_bytes(&raw_text);
            assert_eq!(
                hex::encode(keccak256(&raw)),
                hash.trim_start_matches("0x"),
                "{hash} keccak"
            );
            let call = decode_ethereum_call(&raw).unwrap();
            assert_eq!(call.chain_id, Some(1), "{hash} chain id");
            let to = call.to.expect("destination");
            assert_eq!(hex::encode(to), to_hex, "{hash} to");
            let spell = spell_from_raw_transaction(&raw).unwrap();
            let (anchor, event_spell, topic1) = transaction_event(hash);
            if empty {
                assert_eq!(spell, empty_ethereum_spell(), "{hash} empty spell");
                assert_ne!(
                    event_spell,
                    util::write(&spell).unwrap(),
                    "{hash} facade spell lives in the log, not the calldata"
                );
                continue;
            }
            let cbor = util::write(&spell).unwrap();
            assert_eq!(cbor, event_spell, "{hash} spell bytes");
            let tx_id = ethereum_tx::eth_tx_id(call.chain_id.unwrap(), &to, Some(anchor), &cbor);
            assert_eq!(tx_id.as_slice(), topic1.as_slice(), "{hash} tx id");
        }
    }

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ethereum")
            .join(name);
        std::fs::read_to_string(path).unwrap()
    }

    fn receipt_json(hash: &str) -> serde_json::Value {
        serde_json::from_str(&fixture(&format!("{hash}.receipt.json"))).unwrap()
    }

    fn transaction_event(hash: &str) -> ([u8; 32], Vec<u8>, [u8; 32]) {
        let receipt = receipt_json(hash);
        let topic0 = format!("{:x}", event::Transaction::SIGNATURE_HASH);
        let log = receipt["logs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|log| {
                log["topics"][0]
                    .as_str()
                    .is_some_and(|topic| strip_0x(topic) == topic0)
            })
            .unwrap_or_else(|| panic!("{hash} has no Transaction log"));
        let topics = log["topics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|topic| topic.as_str().unwrap().parse().unwrap())
            .collect::<Vec<alloy_primitives::B256>>();
        let data = hex_bytes(log["data"].as_str().unwrap());
        let event = event::Transaction::decode_raw_log(topics, &data).unwrap();
        (event.anchor.0, event.spell.to_vec(), event.tx_id.0)
    }

    #[test]
    fn legacy_and_type_1_transactions_decode() {
        let input =
            ethereum_tx::transact_calldata(&empty_spell_with_one_output(), [1; 32], &[]).unwrap();
        let to = Address::from([0x44; 20]);
        let legacy = TxLegacy {
            chain_id: Some(1),
            nonce: 3,
            gas_price: 1,
            gas_limit: 21_000,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: Bytes::from(input),
        };
        let signature = Signature::from_scalars_and_parity(
            alloy_primitives::B256::from([0x11; 32]),
            alloy_primitives::B256::from([0x22; 32]),
            false,
        );
        let raw = legacy.into_signed(signature).encoded_2718();
        let call = decode_ethereum_call(&raw).unwrap();
        assert_eq!(call.chain_id, Some(1));
        assert_eq!(call.to, Some(to.into_array()));
        assert_eq!(
            spell_from_raw_transaction(&raw).unwrap(),
            empty_spell_with_one_output()
        );

        let typed = TxEip2930 {
            chain_id: 1,
            nonce: 4,
            gas_price: 1,
            gas_limit: 21_000,
            to: TxKind::Call(to),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from(transferCall::SELECTOR.to_vec()),
        };
        let raw = typed.into_signed(signature).encoded_2718();
        assert_eq!(
            spell_from_raw_transaction(&raw).unwrap(),
            empty_ethereum_spell()
        );
        assert_eq!(decode_ethereum_call(&raw).unwrap().chain_id, Some(1));
    }

    #[test]
    fn a_pre_eip155_legacy_transaction_decodes_without_a_chain_id() {
        let to = Address::from([0x44; 20]);
        let signature = Signature::from_scalars_and_parity(
            alloy_primitives::B256::from([0x11; 32]),
            alloy_primitives::B256::from([0x22; 32]),
            false,
        );
        let transact = TxLegacy {
            chain_id: None,
            nonce: 3,
            gas_price: 1,
            gas_limit: 21_000,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: Bytes::from(
                ethereum_tx::transact_calldata(&empty_spell_with_one_output(), [1; 32], &[])
                    .unwrap(),
            ),
        };
        let raw = transact.into_signed(signature).encoded_2718();
        let call = decode_ethereum_call(&raw).unwrap();
        assert_eq!(call.chain_id, None);
        assert_eq!(call.to, Some(to.into_array()));
        assert_eq!(
            spell_from_raw_transaction(&raw).unwrap(),
            empty_spell_with_one_output()
        );

        let transfer = TxLegacy {
            chain_id: None,
            nonce: 4,
            gas_price: 1,
            gas_limit: 21_000,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: Bytes::from(transferCall::SELECTOR.to_vec()),
        };
        let raw = transfer.into_signed(signature).encoded_2718();
        let call = decode_ethereum_call(&raw).unwrap();
        assert_eq!(call.chain_id, None);
        assert_eq!(
            spell_from_raw_transaction(&raw).unwrap(),
            empty_ethereum_spell()
        );
    }

    fn empty_spell_with_one_output() -> NormalizedSpell {
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(Vec::new());
        spell.tx.outs = vec![NormalizedCharms::new()];
        spell.tx.coins = Some(vec![eth_coin([0x11; 20])]);
        spell
    }

    #[test]
    fn malformed_inputs_do_not_panic() {
        let samples: &[&[u8]] = &[
            &[],
            &[0x02],
            &[0xff],
            &[0x05],
            &[0x02, 0xc0],
            &[0x02, 0x80],
            b"CHET",
            &[0x03, 0xc0],
            &[0xde, 0xad],
        ];
        for raw in samples {
            assert!(decode_ethereum_call(raw).is_err(), "{raw:?}");
            assert!(spell_from_raw_transaction(raw).is_err(), "{raw:?}");
        }
        assert_eq!(
            spell_from_raw_transaction(&[0x05]).unwrap_err().to_string(),
            "not an ethereum transaction"
        );

        let transfer = unsigned_to(
            TxKind::Call(Address::from([0x22; 20])),
            vec![0xde, 0xad, 0xbe, 0xef],
        );
        let err = spell_from_raw_transaction(&transfer).unwrap_err();
        assert_eq!(
            err.to_string(),
            "transaction input is not a Charms transact call or an ERC-20 transfer"
        );

        let create = unsigned_to(TxKind::Create, transferCall::SELECTOR.to_vec());
        let err = spell_from_raw_transaction(&create).unwrap_err();
        assert_eq!(
            err.to_string(),
            "transaction creates a contract and has no spell"
        );
    }

    fn unsigned_to(to: TxKind, input: Vec<u8>) -> Vec<u8> {
        let tx = TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to,
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from(input),
        };
        let mut raw = Vec::new();
        tx.encode_for_signing(&mut raw);
        raw
    }
}
