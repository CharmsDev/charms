//! Deterministic golden vectors for the CHIP-0020 Solidity `SpellCodec`.

mod json {
    use serde::Serialize;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Vectors {
        pub vault_vk: String,
        pub spells: Vec<SpellVector>,
        pub vaults: Vec<VaultVector>,
        pub tokens: Vec<TokenVector>,
        pub sp1: Sp1,
    }

    /// What a v15 Charms proof commits to: the SHA-256 of the Groth16 verifying key (the
    /// proof's first 4 bytes) and the SP1 recursion VK root.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Sp1 {
        pub groth16_vk_hash: String,
        pub vk_root: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ProofVector {
        pub version: u32,
        pub program_v_key: String,
        pub public_values: String,
        pub proof: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SpellVector {
        pub name: String,
        pub chain_id: u64,
        pub charms: String,
        pub anchor: String,
        pub program_v_key: String,
        pub spell: Spell,
        pub spell_cbor: String,
        pub public_values: String,
        pub eth_tx_id: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Spell {
        pub version: u32,
        pub apps: Vec<App>,
        pub public_inputs: Vec<String>,
        pub versioned_apps: Vec<Pin>,
        pub ins: Vec<Input>,
        pub refs: Vec<UtxoRef>,
        pub outs: Vec<Output>,
        pub beamed_outs: Vec<BeamedOut>,
        pub scrolls: Vec<u32>,
    }

    #[derive(Serialize)]
    pub struct App {
        pub tag: u32,
        pub identity: String,
        pub vk: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Pin {
        pub vk: String,
        pub version: u32,
        pub wasm_hash: String,
    }

    #[derive(Serialize)]
    pub struct Charm {
        pub app: u32,
        pub amount: u64,
        pub data: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct UtxoRef {
        pub tx_id: String,
        pub index: u32,
    }

    #[derive(Serialize)]
    pub struct Input {
        pub utxo: UtxoRef,
        pub charms: Vec<Charm>,
        pub pins: Vec<Pin>,
    }

    #[derive(Serialize)]
    pub struct Output {
        pub owner: String,
        pub charms: Vec<Charm>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BeamedOut {
        pub index: u32,
        pub dest_hash: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VaultVector {
        pub chain_id: u64,
        pub charms: String,
        pub token: String,
        pub identity: String,
        pub app_key: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TokenVector {
        pub charms: String,
        pub implementation: String,
        pub app: App,
        pub app_key: String,
        pub token_address: String,
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::Path;
use std::process;

use charms_client::NormalizedSpell;
use charms_client::NormalizedTransaction;
use charms_client::tx::to_serialized_pv;
use charms_data::util;
use charms_data::{App, B32, Data, NativeOutput, TxId, UtxoId, VersionedApp};
use ciborium::Value;

const TOKEN_TAG: u32 = 't' as u32;
const TX_DOMAIN: &[u8] = b"charms/ethereum/tx/v1";
const VAULT_DOMAIN: &[u8] = b"charms/ethereum/vault/v1";

const FIXTURE_CHARMS: [u8; 20] = [
    0x01, 0x17, 0x18, 0xff, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x20,
];

const FIXTURE_IMPL: [u8; 20] = [
    0x0a, 0x17, 0x18, 0xaa, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x21,
];

const USDC: [u8; 20] = [
    0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce,
    0x36, 0x06, 0xeb, 0x48,
];

const ALICE: [u8; 20] = [
    0x4a, 0x1f, 0x3f, 0x9e, 0xab, 0x6f, 0xcb, 0x38, 0x4e, 0xa5, 0x3a, 0x05, 0xf9, 0xb7, 0xec, 0x1e,
    0x53, 0xe4, 0xa1, 0x01,
];

const BOB: [u8; 20] = [
    0xd8, 0xda, 0x6b, 0xf2, 0x69, 0x64, 0xaf, 0x9d, 0x7e, 0xed, 0x9e, 0x03, 0xe5, 0x34, 0x15, 0xd3,
    0x7a, 0xa9, 0x60, 0x45,
];

/// Non-zero placeholder owner. `0x18` forces a two-byte CBOR uint in `coins[].dest`.
const PLACEHOLDER_OWNER: [u8; 20] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x18, 0x11,
];

const THIRD: [u8; 20] = [
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x17, 0x18, 0x22,
];

const AMOUNT_WIDTHS: [u64; 10] = [
    1,
    23,
    24,
    255,
    256,
    65_535,
    65_536,
    4_294_967_295,
    4_294_967_296,
    u64::MAX,
];

const CHAIN_CYCLE: [u64; 3] = [1, 11_155_111, 31_337];

struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "empty range");
        self.next_u64() % n
    }
}

struct DraftApp {
    tag: u32,
    identity: [u8; 32],
    vk: [u8; 32],
}

struct DraftPin {
    vk: [u8; 32],
    version: u32,
    wasm_hash: [u8; 32],
}

struct DraftUtxo {
    tx_id: [u8; 32],
    index: u32,
}

struct DraftCharm {
    app: u32,
    amount: u64,
    data: Vec<u8>,
}

struct DraftOut {
    owner: [u8; 20],
    charms: Vec<DraftCharm>,
}

struct DraftBeam {
    index: u32,
    dest_hash: [u8; 32],
}

struct DraftSpell {
    version: u32,
    apps: Vec<DraftApp>,
    public_inputs: Vec<Vec<u8>>,
    versioned_apps: Vec<DraftPin>,
    ins: Vec<DraftUtxo>,
    refs: Vec<DraftUtxo>,
    outs: Vec<DraftOut>,
    beamed_outs: Vec<DraftBeam>,
    scrolls: Vec<u32>,
}

struct Spec {
    name: String,
    chain_id: u64,
    charms: [u8; 20],
    anchor: [u8; 32],
    program_vkey: [u8; 32],
    draft: DraftSpell,
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn chain_be(chain_id: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&chain_id.to_be_bytes());
    out
}

fn vault_vk() -> [u8; 32] {
    sha256(&[VAULT_DOMAIN])
}

fn vault_identity(chain_id: u64, charms: &[u8; 20], token: &[u8; 20]) -> [u8; 32] {
    let chain = chain_be(chain_id);
    sha256(&[VAULT_DOMAIN, &chain, charms, token])
}

fn app_key(tag: u32, identity: &[u8; 32], vk: &[u8; 32]) -> [u8; 32] {
    let mut word = [0u8; 96];
    word[28..32].copy_from_slice(&tag.to_be_bytes());
    word[32..64].copy_from_slice(identity);
    word[64..96].copy_from_slice(vk);
    keccak256(&[&word])
}

fn eth_tx_id(chain_id: u64, charms: &[u8; 20], anchor: &[u8; 32], spell_cbor: &[u8]) -> [u8; 32] {
    let chain = chain_be(chain_id);
    keccak256(&[TX_DOMAIN, &chain, charms, anchor, spell_cbor])
}

fn labeled32(label: &str) -> [u8; 32] {
    sha256(&[b"charms/ethereum/vectors/", label.as_bytes()])
}

fn seq32(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = start.wrapping_add(i as u8);
    }
    out
}

/// The word sorts by `marker` and still contains both uint widths (`1` and `24`).
fn marked32(marker: u8) -> [u8; 32] {
    let mut out = seq32(0);
    out[0] = marker;
    out
}

fn hex_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex32(bytes: &[u8; 32]) -> String {
    let text = hex_bytes(bytes);
    assert_eq!(text.len(), 66);
    text
}

fn hex20(bytes: &[u8; 20]) -> String {
    let text = hex_bytes(bytes);
    assert_eq!(text.len(), 42);
    text
}

fn encode_value(value: &Value) -> Vec<u8> {
    let bytes = util::write(value).expect("write cbor value");
    let parsed: Value = util::read(bytes.as_slice()).expect("read cbor value");
    let again = util::write(&parsed).expect("rewrite cbor value");
    assert_eq!(bytes, again, "cbor value is not stable: {value:?}");
    let data = Data::try_from_bytes(&bytes).expect("Data::try_from_bytes");
    assert_eq!(
        util::write(&data).unwrap(),
        bytes,
        "Data wrapper changed bytes"
    );
    bytes
}

fn null_cbor() -> Vec<u8> {
    let bytes = encode_value(&Value::Null);
    assert_eq!(bytes, vec![0xf6]);
    bytes
}

fn to_rust_app(app: &DraftApp) -> App {
    App {
        tag: char::from_u32(app.tag)
            .unwrap_or_else(|| panic!("tag U+{:X} is not a scalar", app.tag)),
        identity: B32(app.identity),
        vk: B32(app.vk),
    }
}

fn to_utxo(utxo: &DraftUtxo) -> UtxoId {
    let mut raw = utxo.tx_id;
    raw.reverse();
    let built = UtxoId(TxId(raw), utxo.index);
    assert_eq!(
        built.0.to_string(),
        hex::encode(utxo.tx_id),
        "TxId display must be the typed keccak-order id"
    );
    built
}

fn assert_primitives() {
    let sha = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest([]))
    };
    assert_eq!(
        sha,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let keccak = {
        use sha3::Digest;
        hex::encode(sha3::Keccak256::digest([]))
    };
    assert_eq!(
        keccak,
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert_eq!(TX_DOMAIN.len(), 21);
    assert_eq!(VAULT_DOMAIN.len(), 24);
    assert_eq!(null_cbor(), vec![0xf6]);

    let expected: [(u64, &[u8]); 10] = [
        (1, &[0x01]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65_535, &[0x19, 0xff, 0xff]),
        (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (4_294_967_295, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
        (
            4_294_967_296,
            &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        ),
        (
            u64::MAX,
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];
    for (amount, want) in expected {
        let got = util::write(&Data::from(&amount)).unwrap();
        assert_eq!(got, want, "amount {amount} -> {}", hex::encode(&got));
    }

    assert_eq!(util::write(&Value::from(1.0_f64)).unwrap()[0], 0xf9, "f16");
    assert_eq!(
        util::write(&Value::from(f32_only())).unwrap()[0],
        0xfa,
        "f32"
    );
    assert_eq!(
        util::write(&Value::from(f64_only())).unwrap()[0],
        0xfb,
        "f64"
    );
}

fn f32_only() -> f64 {
    // Next f32 above 1. Exact in f32 and f64, not in f16.
    f64::from(f32::from_bits(0x3f80_0001))
}

fn f64_only() -> f64 {
    // Next f64 above 1. Exact only in f64.
    f64::from_bits(0x3ff0_0000_0000_0001)
}

fn materialize(spec: Spec) -> json::SpellVector {
    let Spec {
        name,
        chain_id,
        charms,
        anchor,
        program_vkey,
        draft,
    } = spec;
    let n_apps = draft.apps.len();
    let n_ins = draft.ins.len();
    let n_outs = draft.outs.len();
    assert!(n_apps <= 64, "{name}: apps");
    assert!(n_ins <= 64, "{name}: ins");
    assert!(n_outs <= 64, "{name}: outs");
    assert_eq!(draft.public_inputs.len(), n_apps, "{name}: public inputs");

    if n_ins == 0 {
        assert_ne!(anchor, [0u8; 32], "{name}: zero-input anchor is all zero");
    } else {
        assert_eq!(
            anchor, [0u8; 32],
            "{name}: anchor must be zero when ins is non-empty"
        );
    }

    let rust_apps: Vec<App> = draft.apps.iter().map(to_rust_app).collect();
    for pair in rust_apps.windows(2) {
        assert!(
            pair[0] < pair[1],
            "{name}: apps are not strictly increasing"
        );
    }
    for pair in draft.versioned_apps.windows(2) {
        assert!(
            pair[0].vk < pair[1].vk,
            "{name}: versioned apps are not strictly increasing by vk"
        );
    }
    for pair in draft.beamed_outs.windows(2) {
        assert!(
            pair[0].index < pair[1].index,
            "{name}: beamed outs not strictly increasing"
        );
    }
    for pair in draft.scrolls.windows(2) {
        assert!(pair[0] < pair[1], "{name}: scrolls not strictly increasing");
    }

    let mut beamed = BTreeSet::new();
    for beam in &draft.beamed_outs {
        assert!((beam.index as usize) < n_outs, "{name}: beamed index");
        assert!(beamed.insert(beam.index), "{name}: duplicate beam");
    }
    for index in &draft.scrolls {
        assert!((*index as usize) < n_outs, "{name}: scroll index");
    }

    for (i, out) in draft.outs.iter().enumerate() {
        let is_beamed = beamed.contains(&(i as u32));
        let is_zero = out.owner.iter().all(|b| *b == 0);
        assert_eq!(is_zero, is_beamed, "{name}: owner zero iff beamed at {i}");
        assert_eq!(out.owner.len(), 20);
        for pair in out.charms.windows(2) {
            assert!(
                pair[0].app < pair[1].app,
                "{name}: charms not strictly increasing"
            );
        }
        for charm in &out.charms {
            assert!((charm.app as usize) < n_apps, "{name}: charm app index");
            if draft.apps[charm.app as usize].tag == TOKEN_TAG {
                assert!(charm.amount > 0, "{name}: token amount");
                assert!(charm.data.is_empty(), "{name}: token data must be empty");
            } else {
                assert_eq!(charm.amount, 0, "{name}: non-token amount");
                assert!(!charm.data.is_empty(), "{name}: non-token data");
                let parsed: Value = util::read(charm.data.as_slice()).expect("charm data");
                assert_eq!(
                    util::write(&parsed).unwrap(),
                    charm.data,
                    "{name}: charm data unstable"
                );
            }
        }
    }
    for blob in &draft.public_inputs {
        let parsed: Value = util::read(blob.as_slice()).expect("public input");
        assert_eq!(
            util::write(&parsed).unwrap(),
            *blob,
            "{name}: public input unstable"
        );
    }

    let mut app_public_inputs = BTreeMap::new();
    for (app, blob) in rust_apps.iter().zip(&draft.public_inputs) {
        let data = Data::try_from_bytes(blob).expect("public input data");
        assert!(app_public_inputs.insert(app.clone(), data).is_none());
    }
    assert_eq!(app_public_inputs.len(), n_apps);

    let mut versioned_apps = BTreeMap::new();
    for pin in &draft.versioned_apps {
        let prev = versioned_apps.insert(
            B32(pin.vk),
            VersionedApp {
                version: pin.version,
                wasm_hash: B32(pin.wasm_hash),
            },
        );
        assert!(prev.is_none(), "{name}: duplicate pin vk");
    }

    let mut outs = Vec::with_capacity(n_outs);
    let mut coins = Vec::with_capacity(n_outs);
    for out in &draft.outs {
        let mut charms_map = BTreeMap::new();
        for charm in &out.charms {
            let data = if draft.apps[charm.app as usize].tag == TOKEN_TAG {
                Data::from(&charm.amount)
            } else {
                Data::try_from_bytes(&charm.data).unwrap()
            };
            assert!(charms_map.insert(charm.app, data).is_none());
        }
        outs.push(charms_map);
        coins.push(NativeOutput {
            amount: 0,
            dest: out.owner.to_vec(),
            content: None,
        });
    }

    let beamed_outs = if draft.beamed_outs.is_empty() {
        None
    } else {
        let mut map = BTreeMap::new();
        for beam in &draft.beamed_outs {
            map.insert(beam.index, B32(beam.dest_hash));
        }
        Some(map)
    };
    let scrolls = if draft.scrolls.is_empty() {
        None
    } else {
        Some(draft.scrolls.iter().copied().collect::<BTreeSet<u32>>())
    };

    let normalized = NormalizedSpell {
        version: draft.version,
        tx: NormalizedTransaction {
            ins: Some(draft.ins.iter().map(to_utxo).collect()),
            refs: if draft.refs.is_empty() {
                None
            } else {
                Some(draft.refs.iter().map(to_utxo).collect())
            },
            outs,
            beamed_outs,
            coins: Some(coins),
            scrolls,
        },
        app_public_inputs,
        versioned_apps,
        mock: false,
    };

    assert!(normalized.tx.ins.is_some(), "{name}");
    assert_eq!(
        normalized.tx.refs.is_none(),
        draft.refs.is_empty(),
        "{name}"
    );
    assert_eq!(
        normalized.tx.beamed_outs.is_none(),
        draft.beamed_outs.is_empty(),
        "{name}"
    );
    assert_eq!(
        normalized.tx.scrolls.is_none(),
        draft.scrolls.is_empty(),
        "{name}"
    );
    assert_eq!(
        normalized.tx.coins.as_ref().map(Vec::len),
        Some(n_outs),
        "{name}"
    );
    assert!(!normalized.mock, "{name}");

    let spell_cbor =
        util::write(&normalized).unwrap_or_else(|err| panic!("{name}: write spell: {err}"));
    let decoded: NormalizedSpell =
        util::read(spell_cbor.as_slice()).unwrap_or_else(|err| panic!("{name}: read spell: {err}"));
    assert_eq!(decoded, normalized, "{name}: spell CBOR roundtrip");

    let public_values = to_serialized_pv(draft.version, &program_vkey, &normalized);
    let mut expected_pv = vec![0x82];
    expected_pv.extend(util::write(&program_vkey).unwrap());
    expected_pv.extend(&spell_cbor);
    assert_eq!(public_values, expected_pv, "{name}: public values layout");

    let eth = eth_tx_id(chain_id, &charms, &anchor, &spell_cbor);

    json::SpellVector {
        name: name.to_string(),
        chain_id,
        charms: hex20(&charms),
        anchor: hex32(&anchor),
        program_v_key: hex32(&program_vkey),
        spell: draft_to_json(&draft),
        spell_cbor: hex_bytes(&spell_cbor),
        public_values: hex_bytes(&public_values),
        eth_tx_id: hex32(&eth),
    }
}

fn draft_to_json(draft: &DraftSpell) -> json::Spell {
    json::Spell {
        version: draft.version,
        apps: draft
            .apps
            .iter()
            .map(|app| json::App {
                tag: app.tag,
                identity: hex32(&app.identity),
                vk: hex32(&app.vk),
            })
            .collect(),
        public_inputs: draft.public_inputs.iter().map(|b| hex_bytes(b)).collect(),
        versioned_apps: draft
            .versioned_apps
            .iter()
            .map(|pin| json::Pin {
                vk: hex32(&pin.vk),
                version: pin.version,
                wasm_hash: hex32(&pin.wasm_hash),
            })
            .collect(),
        ins: draft.ins.iter().map(input_json).collect(),
        refs: draft.refs.iter().map(utxo_json).collect(),
        outs: draft
            .outs
            .iter()
            .map(|out| json::Output {
                owner: hex20(&out.owner),
                charms: out.charms.iter().map(charm_json).collect(),
            })
            .collect(),
        beamed_outs: draft
            .beamed_outs
            .iter()
            .map(|beam| json::BeamedOut {
                index: beam.index,
                dest_hash: hex32(&beam.dest_hash),
            })
            .collect(),
        scrolls: draft.scrolls.clone(),
    }
}

fn utxo_json(utxo: &DraftUtxo) -> json::UtxoRef {
    json::UtxoRef {
        tx_id: hex32(&utxo.tx_id),
        index: utxo.index,
    }
}

fn input_json(utxo: &DraftUtxo) -> json::Input {
    json::Input {
        utxo: utxo_json(utxo),
        charms: Vec::new(),
        pins: Vec::new(),
    }
}

fn charm_json(charm: &DraftCharm) -> json::Charm {
    json::Charm {
        app: charm.app,
        amount: charm.amount,
        data: hex_bytes(&charm.data),
    }
}

fn named(
    name: &'static str,
    chain_id: u64,
    anchor: [u8; 32],
    draft: DraftSpell,
) -> json::SpellVector {
    materialize(Spec {
        name: name.to_string(),
        chain_id,
        charms: FIXTURE_CHARMS,
        anchor,
        program_vkey: labeled32(&format!("vkey/{name}")),
        draft,
    })
}

fn empty_inputs(n_apps: usize) -> Vec<Vec<u8>> {
    let null = null_cbor();
    vec![null; n_apps]
}

fn token_app(identity: [u8; 32], vk: [u8; 32]) -> DraftApp {
    DraftApp {
        tag: TOKEN_TAG,
        identity,
        vk,
    }
}

fn placeholder() -> json::SpellVector {
    let draft = DraftSpell {
        version: 15,
        apps: Vec::new(),
        public_inputs: Vec::new(),
        versioned_apps: Vec::new(),
        ins: Vec::new(),
        refs: Vec::new(),
        outs: vec![DraftOut {
            owner: PLACEHOLDER_OWNER,
            charms: Vec::new(),
        }],
        beamed_outs: Vec::new(),
        scrolls: Vec::new(),
    };
    let spell = named("placeholder", 1, labeled32("anchor/placeholder"), draft);
    assert!(spell.spell.apps.is_empty());
    assert!(spell.spell.ins.is_empty());
    assert_eq!(spell.spell.outs.len(), 1);
    assert!(spell.spell.outs[0].charms.is_empty());
    spell
}

fn simple_transfer() -> json::SpellVector {
    let app = token_app(marked32(0x01), marked32(0x40));
    let draft = DraftSpell {
        version: 15,
        apps: vec![app],
        public_inputs: empty_inputs(1),
        versioned_apps: Vec::new(),
        ins: vec![DraftUtxo {
            tx_id: seq32(0xc0),
            index: 0,
        }],
        refs: Vec::new(),
        outs: vec![
            DraftOut {
                owner: ALICE,
                charms: vec![DraftCharm {
                    app: 0,
                    amount: 750,
                    data: Vec::new(),
                }],
            },
            DraftOut {
                owner: BOB,
                charms: vec![DraftCharm {
                    app: 0,
                    amount: 250,
                    data: Vec::new(),
                }],
            },
        ],
        beamed_outs: Vec::new(),
        scrolls: Vec::new(),
    };
    let spell = named("chip-simple-transfer", 1, [0u8; 32], draft);
    assert_eq!(spell.spell.outs[0].owner, hex20(&ALICE));
    assert_eq!(spell.spell.outs[1].owner, hex20(&BOB));
    assert_eq!(spell.spell.outs[0].charms[0].amount, 750);
    assert_eq!(spell.spell.outs[1].charms[0].amount, 250);
    spell
}

fn wrap() -> json::SpellVector {
    let identity = vault_identity(1, &FIXTURE_CHARMS, &USDC);
    let vk = vault_vk();
    let draft = DraftSpell {
        version: 15,
        apps: vec![token_app(identity, vk)],
        public_inputs: empty_inputs(1),
        versioned_apps: Vec::new(),
        ins: Vec::new(),
        refs: Vec::new(),
        outs: vec![DraftOut {
            owner: ALICE,
            charms: vec![DraftCharm {
                app: 0,
                amount: 1_000_000,
                data: Vec::new(),
            }],
        }],
        beamed_outs: Vec::new(),
        scrolls: Vec::new(),
    };
    let spell = named("wrap", 1, labeled32("anchor/wrap"), draft);
    assert_eq!(spell.spell.apps[0].tag, TOKEN_TAG);
    assert_eq!(spell.spell.apps[0].identity, hex32(&identity));
    assert_eq!(spell.spell.apps[0].vk, hex32(&vk));
    assert_eq!(spell.spell.outs[0].charms[0].amount, 1_000_000);
    spell
}

fn showcase_values() -> [Value; 7] {
    let map = Value::Map(vec![
        (Value::Text("name".into()), Value::Text("café".into())),
        (Value::Text("flag".into()), Value::Bool(true)),
        (Value::Text("n".into()), Value::from(-24_i64)),
        (
            Value::Text("list".into()),
            Value::Array(vec![
                Value::Bool(false),
                Value::from(23_u64),
                Value::from(24_u64),
            ]),
        ),
    ]);
    let negatives = Value::Array(vec![
        Value::from(-1_i64),
        Value::from(-23_i64),
        Value::from(-24_i64),
        Value::from(-25_i64),
        Value::from(-255_i64),
        Value::from(-256_i64),
        Value::from(-257_i64),
        Value::from(-65_535_i64),
        Value::from(-65_536_i64),
        Value::from(-65_537_i64),
        Value::from(-4_294_967_295_i64),
        Value::from(-4_294_967_296_i64),
        Value::from(-4_294_967_297_i64),
        Value::Bool(false),
        Value::Bool(true),
    ]);
    let text = Value::Text("héllo € 😀".into());
    let bytes = Value::Bytes(vec![0x00, 0x17, 0x18, 0x19, 0xff, 0x20, 0x7f, 0x80]);
    let floats = Value::Array(vec![
        Value::from(0.0_f64),
        Value::from(1.0_f64),
        Value::from(-1.0_f64),
        Value::from(0.5_f64),
        Value::from(65_504.0_f64),
        Value::from(f32_only()),
        Value::from(f64_only()),
    ]);
    let tags = Value::Array(vec![
        Value::Tag(0, Box::new(Value::Bool(true))),
        Value::Tag(23, Box::new(Value::from(1_u64))),
        Value::Tag(24, Box::new(Value::Text("€".into()))),
        Value::Tag(255, Box::new(Value::from(-1_i64))),
        Value::Tag(256, Box::new(Value::Bytes(vec![0x18, 0x17]))),
        Value::Tag(65_535, Box::new(Value::Bool(false))),
        Value::Tag(65_536, Box::new(Value::Text("😀".into()))),
        Value::Tag(4_294_967_296, Box::new(Value::from(0_u64))),
    ]);
    let nested = Value::Map(vec![(
        Value::Text("nest".into()),
        Value::Array(vec![Value::Tag(1, Box::new(Value::Text("😀".into())))]),
    )]);
    [map, negatives, text, bytes, floats, tags, nested]
}

fn everything() -> json::SpellVector {
    let tags = [
        'n' as u32, 's' as u32, 't' as u32, 'x' as u32, 0x00e9, 0x20ac, 0x1f600,
    ];
    let apps: Vec<DraftApp> = tags
        .into_iter()
        .enumerate()
        .map(|(i, tag)| DraftApp {
            tag,
            identity: marked32(0x10 + i as u8),
            vk: marked32(0x40 + i as u8),
        })
        .collect();
    let blobs: Vec<Vec<u8>> = showcase_values().iter().map(encode_value).collect();
    assert_eq!(blobs.len(), apps.len());

    let draft = DraftSpell {
        version: 16,
        public_inputs: blobs.clone(),
        versioned_apps: vec![
            DraftPin {
                vk: apps[0].vk,
                version: 1,
                wasm_hash: marked32(0x21),
            },
            DraftPin {
                vk: apps[3].vk,
                version: 24,
                wasm_hash: marked32(0x22),
            },
        ],
        ins: vec![
            DraftUtxo {
                tx_id: seq32(0x80),
                index: 0,
            },
            DraftUtxo {
                tx_id: seq32(0x90),
                index: 24,
            },
        ],
        refs: vec![
            DraftUtxo {
                tx_id: seq32(0xa0),
                index: 1,
            },
            DraftUtxo {
                tx_id: seq32(0xb0),
                index: 23,
            },
        ],
        outs: vec![
            DraftOut {
                owner: ALICE,
                charms: vec![
                    DraftCharm {
                        app: 0,
                        amount: 0,
                        data: blobs[0].clone(),
                    },
                    DraftCharm {
                        app: 2,
                        amount: 1000,
                        data: Vec::new(),
                    },
                ],
            },
            DraftOut {
                owner: BOB,
                charms: vec![
                    DraftCharm {
                        app: 1,
                        amount: 0,
                        data: blobs[1].clone(),
                    },
                    DraftCharm {
                        app: 3,
                        amount: 0,
                        data: blobs[3].clone(),
                    },
                ],
            },
            DraftOut {
                owner: [0u8; 20],
                charms: vec![
                    DraftCharm {
                        app: 2,
                        amount: 24,
                        data: Vec::new(),
                    },
                    DraftCharm {
                        app: 4,
                        amount: 0,
                        data: blobs[4].clone(),
                    },
                ],
            },
            DraftOut {
                owner: THIRD,
                charms: vec![
                    DraftCharm {
                        app: 5,
                        amount: 0,
                        data: blobs[5].clone(),
                    },
                    DraftCharm {
                        app: 6,
                        amount: 0,
                        data: blobs[6].clone(),
                    },
                ],
            },
        ],
        beamed_outs: vec![DraftBeam {
            index: 2,
            dest_hash: seq32(0x08),
        }],
        scrolls: vec![1, 3],
        apps,
    };
    let spell = named("everything", 1, [0u8; 32], draft);
    assert_eq!(spell.spell.version, 16);
    assert_eq!(spell.spell.apps.len(), 7);
    assert_eq!(spell.spell.versioned_apps.len(), 2);
    assert_eq!(spell.spell.refs.len(), 2);
    assert_eq!(spell.spell.beamed_outs.len(), 1);
    assert_eq!(spell.spell.scrolls, vec![1, 3]);
    spell
}

fn uint_widths() -> json::SpellVector {
    let apps = (0..26)
        .map(|i| token_app(marked32(i as u8), marked32(0x70)))
        .collect::<Vec<_>>();
    let outs = (0..30)
        .map(|i| {
            let beamed = i == 24;
            DraftOut {
                owner: if beamed {
                    [0u8; 20]
                } else if i % 2 == 0 {
                    ALICE
                } else {
                    BOB
                },
                charms: vec![DraftCharm {
                    app: (i % 26) as u32,
                    amount: AMOUNT_WIDTHS[i % AMOUNT_WIDTHS.len()],
                    data: Vec::new(),
                }],
            }
        })
        .collect::<Vec<_>>();
    let draft = DraftSpell {
        version: 15,
        public_inputs: empty_inputs(apps.len()),
        versioned_apps: Vec::new(),
        ins: vec![DraftUtxo {
            tx_id: seq32(0xe0),
            index: 0,
        }],
        refs: Vec::new(),
        beamed_outs: vec![DraftBeam {
            index: 24,
            dest_hash: marked32(0x24),
        }],
        scrolls: vec![25],
        apps,
        outs,
    };
    assert_eq!(draft.apps.len(), 26);
    assert_eq!(draft.outs.len(), 30);
    assert!(
        draft
            .outs
            .iter()
            .any(|out| out.charms.iter().any(|c| c.app >= 24))
    );
    let spell = named("uint-widths", 1, [0u8; 32], draft);
    let amounts: BTreeSet<u64> = spell
        .spell
        .outs
        .iter()
        .flat_map(|out| out.charms.iter().map(|c| c.amount))
        .collect();
    for amount in AMOUNT_WIDTHS {
        assert!(amounts.contains(&amount), "missing amount {amount}");
    }
    spell
}

fn max_counts() -> json::SpellVector {
    let apps = (0..64)
        .map(|i| token_app(marked32(i as u8), marked32(0x71)))
        .collect::<Vec<_>>();
    let ins = (0..64)
        .map(|i| DraftUtxo {
            tx_id: marked32(0x80_u8.wrapping_add(i as u8)),
            index: i as u32,
        })
        .collect();
    let outs = (0..64)
        .map(|i| DraftOut {
            owner: owner_for_index(i as u8),
            charms: vec![DraftCharm {
                app: i as u32,
                amount: 1,
                data: Vec::new(),
            }],
        })
        .collect();
    let draft = DraftSpell {
        version: 15,
        public_inputs: empty_inputs(64),
        versioned_apps: Vec::new(),
        ins,
        refs: Vec::new(),
        outs,
        beamed_outs: Vec::new(),
        scrolls: Vec::new(),
        apps,
    };
    let spell = named("max-counts", 1, [0u8; 32], draft);
    assert_eq!(spell.spell.apps.len(), 64);
    assert_eq!(spell.spell.ins.len(), 64);
    assert_eq!(spell.spell.outs.len(), 64);
    spell
}

fn owner_for_index(index: u8) -> [u8; 20] {
    let mut owner = [0x11_u8; 20];
    owner[0] = index % 24;
    owner[1] = 24 + (index % 200);
    owner[2] = 0x5a;
    owner
}

fn random_spells() -> Vec<json::SpellVector> {
    let mut rng = SplitMix64::new(0xC0FFEE);
    (0..40).map(|i| random_spell(&mut rng, i)).collect()
}

fn random_spell(rng: &mut SplitMix64, index: usize) -> json::SpellVector {
    let name = format!("random-{index:02}");
    // Counts first, so the bias draws are independent of later payload size.
    let n_apps = biased_small(rng, 64) as usize;
    let n_ins = biased_small(rng, 64) as usize;
    let n_outs = biased_small(rng, 64) as usize;
    let n_refs = biased_small(rng, 8) as usize;
    let n_pins = biased_small(rng, 8) as usize;

    let mut apps = Vec::with_capacity(n_apps);
    let mut guard = 0;
    while apps.len() < n_apps {
        guard += 1;
        assert!(guard < 10_000, "{name}: unique apps");
        let app = DraftApp {
            tag: random_tag(rng),
            identity: mixed(rng),
            vk: mixed(rng),
        };
        if apps.iter().any(|other: &DraftApp| same_app(other, &app)) {
            continue;
        }
        apps.push(app);
    }
    apps.sort_by(|a, b| to_rust_app(a).cmp(&to_rust_app(b)));

    let public_inputs = apps
        .iter()
        .map(|_| {
            if rng.below(2) == 0 {
                null_cbor()
            } else {
                encode_value(&random_value(rng, 1))
            }
        })
        .collect();

    let mut pins = Vec::with_capacity(n_pins);
    guard = 0;
    while pins.len() < n_pins {
        guard += 1;
        assert!(guard < 10_000, "{name}: unique pins");
        let vk = mixed(rng);
        if pins.iter().any(|pin: &DraftPin| pin.vk == vk) {
            continue;
        }
        pins.push(DraftPin {
            vk,
            version: mixed_u32(rng),
            wasm_hash: mixed(rng),
        });
    }
    pins.sort_by(|a, b| a.vk.cmp(&b.vk));

    let ins = (0..n_ins)
        .map(|_| DraftUtxo {
            tx_id: mixed(rng),
            index: mixed_u32(rng),
        })
        .collect();
    let refs = (0..n_refs)
        .map(|_| DraftUtxo {
            tx_id: mixed(rng),
            index: mixed_u32(rng),
        })
        .collect();

    let n_beamed = biased_small(rng, n_outs as u64) as usize;
    let beamed_idxs = choose_sorted(rng, n_outs, n_beamed);
    let beamed_outs = beamed_idxs
        .iter()
        .map(|&index| DraftBeam {
            index,
            dest_hash: mixed(rng),
        })
        .collect::<Vec<_>>();
    let n_scrolls = biased_small(rng, n_outs as u64) as usize;
    let scrolls = choose_sorted(rng, n_outs, n_scrolls);
    let beamed_set: BTreeSet<u32> = beamed_idxs.into_iter().collect();

    let outs = (0..n_outs)
        .map(|i| {
            let n_charms = if n_apps == 0 {
                0
            } else {
                biased_small(rng, n_apps as u64) as usize
            };
            let chosen = choose_sorted(rng, n_apps, n_charms);
            let charms = chosen
                .into_iter()
                .map(|app_index| {
                    if apps[app_index as usize].tag == TOKEN_TAG {
                        DraftCharm {
                            app: app_index,
                            amount: random_amount(rng),
                            data: Vec::new(),
                        }
                    } else {
                        DraftCharm {
                            app: app_index,
                            amount: 0,
                            data: encode_value(&random_value(rng, 1)),
                        }
                    }
                })
                .collect();
            let owner = if beamed_set.contains(&(i as u32)) {
                [0u8; 20]
            } else {
                mixed(rng)
            };
            DraftOut { owner, charms }
        })
        .collect();

    let charms = mixed(rng);
    let program_vkey = mixed(rng);
    let anchor = if n_ins == 0 { mixed(rng) } else { [0u8; 32] };

    materialize(Spec {
        name,
        chain_id: CHAIN_CYCLE[index % CHAIN_CYCLE.len()],
        charms,
        anchor,
        program_vkey,
        draft: DraftSpell {
            version: 15,
            apps,
            public_inputs,
            versioned_apps: pins,
            ins,
            refs,
            outs,
            beamed_outs,
            scrolls,
        },
    })
}

fn biased_small(rng: &mut SplitMix64, max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let cap = match rng.below(100) {
        0..=69 => 3,
        70..=89 => 8,
        90..=96 => 16,
        _ => max,
    };
    rng.below(cap.min(max) + 1)
}

fn choose_sorted(rng: &mut SplitMix64, n: usize, k: usize) -> Vec<u32> {
    assert!(k <= n);
    let mut idxs: Vec<u32> = (0..n as u32).collect();
    for i in 0..k {
        let j = i + rng.below((n - i) as u64) as usize;
        idxs.swap(i, j);
    }
    idxs.truncate(k);
    idxs.sort_unstable();
    idxs
}

fn same_app(a: &DraftApp, b: &DraftApp) -> bool {
    a.tag == b.tag && a.identity == b.identity && a.vk == b.vk
}

fn random_tag(rng: &mut SplitMix64) -> u32 {
    const FIXED: [u32; 7] = [
        't' as u32, 'n' as u32, 's' as u32, 'x' as u32, 0x00e9, 0x20ac, 0x1f600,
    ];
    match rng.below(8) as usize {
        i if i < FIXED.len() => FIXED[i],
        _ => random_scalar(rng),
    }
}

fn random_scalar(rng: &mut SplitMix64) -> u32 {
    loop {
        let value = rng.below(0x11_0000);
        if !(0xD800..0xE000).contains(&value) {
            return value as u32;
        }
    }
}

fn mixed<const N: usize>(rng: &mut SplitMix64) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = if i % 2 == 0 {
            rng.below(24) as u8
        } else {
            24 + rng.below(232) as u8
        };
    }
    out
}

fn mixed_u32(rng: &mut SplitMix64) -> u32 {
    match rng.below(5) {
        0 => rng.below(24) as u32,
        1 => 24 + rng.below(232) as u32,
        2 => 256 + rng.below(65_280) as u32,
        3 => 65_536 + rng.below(1000) as u32,
        _ => rng.next_u64() as u32,
    }
}

fn random_amount(rng: &mut SplitMix64) -> u64 {
    if rng.below(3) == 0 {
        AMOUNT_WIDTHS[rng.below(AMOUNT_WIDTHS.len() as u64) as usize]
    } else {
        match rng.below(4) {
            0 => 1 + rng.below(23),
            1 => 24 + rng.below(232),
            2 => 256 + rng.below(65_280),
            _ => {
                let value = rng.next_u64();
                if value == 0 { 1 } else { value }
            }
        }
    }
}

fn random_value(rng: &mut SplitMix64, depth: u32) -> Value {
    let kind = if depth < 4 {
        rng.below(10)
    } else {
        rng.below(7)
    };
    match kind {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 1),
        2 => random_uint(rng),
        3 => random_neg(rng),
        4 => Value::from(exact_floats()[rng.below(8) as usize]),
        5 => Value::Bytes(random_byte_vec(rng)),
        6 => Value::Text(TEXTS[rng.below(TEXTS.len() as u64) as usize].to_string()),
        7 => {
            let n = rng.below(4) as usize;
            Value::Array((0..n).map(|_| random_value(rng, depth + 1)).collect())
        }
        8 => {
            let n = rng.below(4) as usize;
            Value::Map(
                (0..n)
                    .map(|_| (random_value(rng, depth + 1), random_value(rng, depth + 1)))
                    .collect(),
            )
        }
        9 => Value::Tag(random_cbor_tag(rng), Box::new(random_value(rng, depth + 1))),
        _ => unreachable!("value kind"),
    }
}

fn random_uint(rng: &mut SplitMix64) -> Value {
    const BOUNDARIES: [u64; 10] = [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
        u64::MAX,
    ];
    if rng.below(2) == 0 {
        Value::from(BOUNDARIES[rng.below(10) as usize])
    } else {
        Value::from(rng.next_u64())
    }
}

fn random_neg(rng: &mut SplitMix64) -> Value {
    const BOUNDARIES: [i64; 14] = [
        -1,
        -23,
        -24,
        -25,
        -255,
        -256,
        -257,
        -65_535,
        -65_536,
        -65_537,
        -4_294_967_295,
        -4_294_967_296,
        -4_294_967_297,
        i64::MIN,
    ];
    if rng.below(2) == 0 {
        Value::from(BOUNDARIES[rng.below(BOUNDARIES.len() as u64) as usize])
    } else {
        let mag = rng.below(1_u64 << 63) as i64;
        Value::from(-1_i64 - mag)
    }
}

fn random_cbor_tag(rng: &mut SplitMix64) -> u64 {
    const BOUNDARIES: [u64; 8] = [0, 23, 24, 255, 256, 65_535, 65_536, 4_294_967_296];
    if rng.below(2) == 0 {
        BOUNDARIES[rng.below(8) as usize]
    } else {
        rng.below(10_000)
    }
}

fn random_byte_vec(rng: &mut SplitMix64) -> Vec<u8> {
    let n = rng.below(17) as usize;
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                rng.below(24) as u8
            } else {
                24 + rng.below(232) as u8
            }
        })
        .collect()
}

const TEXTS: &[&str] = &["", "a", "hi", "café", "€", "😀", "héllo € 😀", "東京"];

fn exact_floats() -> [f64; 8] {
    [0.0, 1.0, -1.0, 0.5, -0.5, 65_504.0, f32_only(), f64_only()]
}

fn vaults() -> Vec<json::VaultVector> {
    let mut rows = vec![
        vault_row(1, FIXTURE_CHARMS, [0u8; 20]),
        vault_row(1, FIXTURE_CHARMS, USDC),
        vault_row(31_337, FIXTURE_CHARMS, [0u8; 20]),
    ];
    // Independent of the spell stream so random-00 stays seeded at 0xC0FFEE.
    let mut rng = SplitMix64::new(0x5641_554C);
    rows.push(vault_row(31_337, mixed(&mut rng), mixed(&mut rng)));
    rows
}

fn vault_row(chain_id: u64, charms: [u8; 20], token: [u8; 20]) -> json::VaultVector {
    let identity = vault_identity(chain_id, &charms, &token);
    let key = app_key(TOKEN_TAG, &identity, &vault_vk());
    json::VaultVector {
        chain_id,
        charms: hex20(&charms),
        token: hex20(&token),
        identity: hex32(&identity),
        app_key: hex32(&key),
    }
}

fn tokens(spells: &[json::SpellVector]) -> Vec<json::TokenVector> {
    let simple = find(spells, "chip-simple-transfer");
    let wrap_spell = find(spells, "wrap");
    let mut rows = vec![
        token_row(FIXTURE_CHARMS, FIXTURE_IMPL, &simple.spell.apps[0]),
        token_row(FIXTURE_CHARMS, FIXTURE_IMPL, &wrap_spell.spell.apps[0]),
    ];
    let mut rng = SplitMix64::new(0x70CE);
    for _ in 0..2 {
        let app = json::App {
            tag: TOKEN_TAG,
            identity: hex32(&mixed(&mut rng)),
            vk: hex32(&mixed(&mut rng)),
        };
        rows.push(token_row(mixed(&mut rng), mixed(&mut rng), &app));
    }
    rows
}

fn token_row(charms: [u8; 20], implementation: [u8; 20], app: &json::App) -> json::TokenVector {
    assert_eq!(app.tag, TOKEN_TAG);
    let identity = decode32(&app.identity);
    let vk = decode32(&app.vk);
    let key = app_key(app.tag, &identity, &vk);
    let init = clone_init_code(&implementation, app.tag, &identity, &vk);
    assert_eq!(init.len(), 135, "clone init code is {} bytes", init.len());
    let address = create2(&charms, &key, &init);
    json::TokenVector {
        charms: hex20(&charms),
        implementation: hex20(&implementation),
        app: json::App {
            tag: app.tag,
            identity: app.identity.clone(),
            vk: app.vk.clone(),
        },
        app_key: hex32(&key),
        token_address: hex20(&address),
    }
}

fn clone_init_code(
    implementation: &[u8; 20],
    tag: u32,
    identity: &[u8; 32],
    vk: &[u8; 32],
) -> Vec<u8> {
    const CREATION: &str = "61007d3d81600a3d39f3";
    const PREFIX: &str = "3d3d3d3d363d3d376100466037363936610046013d73";
    const SUFFIX: &str = "5af43d3d93803e603557fd5bf3";
    let creation = hex::decode(CREATION).unwrap();
    let prefix = hex::decode(PREFIX).unwrap();
    let suffix = hex::decode(SUFFIX).unwrap();
    assert_eq!(creation.len(), 10);
    assert_eq!(prefix.len(), 22);
    assert_eq!(suffix.len(), 13);
    let mut code = Vec::with_capacity(135);
    code.extend(creation);
    code.extend(prefix);
    code.extend(implementation);
    code.extend(suffix);
    code.extend(tag.to_be_bytes());
    code.extend(identity);
    code.extend(vk);
    code.extend([0x00, 0x44]);
    code
}

fn create2(deployer: &[u8; 20], salt: &[u8; 32], init_code: &[u8]) -> [u8; 20] {
    let init_hash = keccak256(&[init_code]);
    let mut preimage = Vec::with_capacity(85);
    preimage.push(0xff);
    preimage.extend(deployer);
    preimage.extend(salt);
    preimage.extend(init_hash);
    let hash = keccak256(&[&preimage]);
    hash[12..].try_into().unwrap()
}

fn find<'a>(spells: &'a [json::SpellVector], name: &str) -> &'a json::SpellVector {
    spells
        .iter()
        .find(|spell| spell.name == name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn decode32(text: &str) -> [u8; 32] {
    let bytes = decode_hex(text);
    bytes
        .try_into()
        .unwrap_or_else(|got: Vec<u8>| panic!("expected 32 bytes, got {}", got.len()))
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.starts_with("0x"), "{text}");
    hex::decode(&text[2..]).unwrap_or_else(|err| panic!("hex {text}: {err}"))
}

fn cross_check(
    spells: &[json::SpellVector],
    vault_rows: &[json::VaultVector],
    token_rows: &[json::TokenVector],
) {
    let wrap_spell = find(spells, "wrap");
    let usdc = vault_rows
        .iter()
        .find(|row| row.chain_id == 1 && decode_hex(&row.token) == USDC)
        .unwrap();
    assert_eq!(usdc.charms, hex20(&FIXTURE_CHARMS));
    assert_eq!(usdc.identity, wrap_spell.spell.apps[0].identity);
    assert_eq!(wrap_spell.spell.apps[0].vk, hex32(&vault_vk()));
    assert_eq!(token_rows[1].app.identity, usdc.identity);
    assert_eq!(token_rows[1].app_key, usdc.app_key);
    assert_eq!(
        token_rows[0].app.identity,
        find(spells, "chip-simple-transfer").spell.apps[0].identity
    );
    assert_eq!(vault_rows.len(), 4);
    assert_eq!(token_rows.len(), 4);
    assert!(token_rows.iter().all(|row| row.app.tag == TOKEN_TAG));
}

fn render() -> String {
    assert_primitives();
    let mut spells = vec![
        placeholder(),
        simple_transfer(),
        wrap(),
        everything(),
        uint_widths(),
        max_counts(),
    ];
    spells.extend(random_spells());
    let vault_rows = vaults();
    let token_rows = tokens(&spells);
    cross_check(&spells, &vault_rows, &token_rows);

    let doc = json::Vectors {
        vault_vk: hex32(&vault_vk()),
        spells,
        vaults: vault_rows,
        tokens: token_rows,
        sp1: json::Sp1 {
            groth16_vk_hash: hex32(&sha256(&[charms_client::tx::groth16_vk(15, false).unwrap()])),
            vk_root: hex32(&sp1_verifier::VK_ROOT_BYTES),
        },
    };
    let mut json = serde_json::to_string_pretty(&doc).unwrap();
    json.push('\n');
    assert!(json.ends_with("}\n") && !json.ends_with("}\n\n"));
    assert_json_contract(&json);
    assert_serialized_key_order(&json);
    json
}

fn assert_json_contract(json: &str) {
    let root: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_keys(&root, &["vaultVk", "spells", "vaults", "tokens", "sp1"], "root");
    assert_hex(root["vaultVk"].as_str().unwrap(), Some(32), "vaultVk");
    let spells = root["spells"].as_array().unwrap();
    let vault_rows = root["vaults"].as_array().unwrap();
    let token_rows = root["tokens"].as_array().unwrap();
    assert_eq!(spells.len(), 46);
    assert_eq!(vault_rows.len(), 4);
    assert_eq!(token_rows.len(), 4);

    let mut names = Vec::new();
    for spell in spells {
        assert_keys(
            spell,
            &[
                "name",
                "chainId",
                "charms",
                "anchor",
                "programVKey",
                "spell",
                "spellCbor",
                "publicValues",
                "ethTxId",
            ],
            "spell vector",
        );
        names.push(spell["name"].as_str().unwrap().to_string());
        assert!(spell["chainId"].as_u64().is_some());
        assert_hex(spell["charms"].as_str().unwrap(), Some(20), "charms");
        assert_hex(spell["anchor"].as_str().unwrap(), Some(32), "anchor");
        assert_hex(
            spell["programVKey"].as_str().unwrap(),
            Some(32),
            "programVKey",
        );
        assert_hex(spell["spellCbor"].as_str().unwrap(), None, "spellCbor");
        assert_hex(
            spell["publicValues"].as_str().unwrap(),
            None,
            "publicValues",
        );
        assert_hex(spell["ethTxId"].as_str().unwrap(), Some(32), "ethTxId");
        let body = &spell["spell"];
        assert_keys(
            body,
            &[
                "version",
                "apps",
                "publicInputs",
                "versionedApps",
                "ins",
                "refs",
                "outs",
                "beamedOuts",
                "scrolls",
            ],
            "spell",
        );
        assert!(body["version"].as_u64().is_some());
        assert_eq!(
            body["apps"].as_array().unwrap().len(),
            body["publicInputs"].as_array().unwrap().len()
        );
        for app in body["apps"].as_array().unwrap() {
            assert_keys(app, &["tag", "identity", "vk"], "app");
            assert!(app["tag"].as_u64().is_some());
            assert_hex(app["identity"].as_str().unwrap(), Some(32), "identity");
            assert_hex(app["vk"].as_str().unwrap(), Some(32), "vk");
        }
        for blob in body["publicInputs"].as_array().unwrap() {
            assert_hex(blob.as_str().unwrap(), None, "public input");
        }
        for pin in body["versionedApps"].as_array().unwrap() {
            assert_keys(pin, &["vk", "version", "wasmHash"], "pin");
            assert_hex(pin["vk"].as_str().unwrap(), Some(32), "pin.vk");
            assert_hex(pin["wasmHash"].as_str().unwrap(), Some(32), "wasmHash");
        }
        for input in body["ins"].as_array().unwrap() {
            assert_keys(input, &["utxo", "charms", "pins"], "input");
            assert!(input["charms"].as_array().unwrap().is_empty());
            assert!(input["pins"].as_array().unwrap().is_empty());
            assert_keys(&input["utxo"], &["txId", "index"], "utxo");
        }
        for utxo in body["refs"].as_array().unwrap() {
            assert_keys(utxo, &["txId", "index"], "ref");
            assert_hex(utxo["txId"].as_str().unwrap(), Some(32), "ref.txId");
        }
        for out in body["outs"].as_array().unwrap() {
            assert_keys(out, &["owner", "charms"], "output");
            assert_hex(out["owner"].as_str().unwrap(), Some(20), "owner");
            for charm in out["charms"].as_array().unwrap() {
                assert_keys(charm, &["app", "amount", "data"], "charm");
                assert!(
                    charm["amount"].as_u64().is_some(),
                    "amount not a u64: {charm}"
                );
                assert_hex(charm["data"].as_str().unwrap(), None, "charm data");
            }
        }
        for beam in body["beamedOuts"].as_array().unwrap() {
            assert_keys(beam, &["index", "destHash"], "beamed");
            assert_hex(beam["destHash"].as_str().unwrap(), Some(32), "destHash");
        }
    }
    assert_eq!(names[0], "placeholder");
    assert_eq!(names[1], "chip-simple-transfer");
    assert_eq!(names[2], "wrap");
    assert_eq!(names[3], "everything");
    assert_eq!(names[4], "uint-widths");
    assert_eq!(names[5], "max-counts");
    for i in 0..40 {
        assert_eq!(names[6 + i], format!("random-{i:02}"));
    }

    let widths = spells.iter().find(|s| s["name"] == "uint-widths").unwrap();
    let huge = &widths["spell"]["outs"][9]["charms"][0]["amount"];
    assert_eq!(huge.as_u64(), Some(u64::MAX));

    for row in vault_rows {
        assert_keys(
            row,
            &["chainId", "charms", "token", "identity", "appKey"],
            "vault",
        );
        assert_hex(row["charms"].as_str().unwrap(), Some(20), "vault.charms");
        assert_hex(row["token"].as_str().unwrap(), Some(20), "vault.token");
        assert_hex(
            row["identity"].as_str().unwrap(),
            Some(32),
            "vault.identity",
        );
        assert_hex(row["appKey"].as_str().unwrap(), Some(32), "vault.appKey");
    }
    for row in token_rows {
        assert_keys(
            row,
            &["charms", "implementation", "app", "appKey", "tokenAddress"],
            "token",
        );
        assert_hex(
            row["implementation"].as_str().unwrap(),
            Some(20),
            "implementation",
        );
        assert_hex(
            row["tokenAddress"].as_str().unwrap(),
            Some(20),
            "tokenAddress",
        );
        assert_eq!(row["app"]["tag"].as_u64(), Some(u64::from(TOKEN_TAG)));
    }
}

fn assert_keys(value: &serde_json::Value, expected: &[&str], what: &str) {
    // `serde_json::Value` maps sort keys. Presence is checked here; the file's
    // key order is checked on the serialized text.
    let mut got: Vec<&str> = value
        .as_object()
        .unwrap_or_else(|| panic!("{what} is not an object"))
        .keys()
        .map(String::as_str)
        .collect();
    let mut want = expected.to_vec();
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want, "{what}");
}

fn assert_serialized_key_order(json: &str) {
    let vault_vk = json.find("\"vaultVk\"").unwrap();
    let spells = json.find("\"spells\"").unwrap();
    let vaults = json.find("\"vaults\"").unwrap();
    let tokens = json.find("\"tokens\"").unwrap();
    assert!(vault_vk < spells && spells < vaults && vaults < tokens);

    let spell = &json[spells..];
    let mut prev = 0;
    for key in [
        "\"name\"",
        "\"chainId\"",
        "\"charms\"",
        "\"anchor\"",
        "\"programVKey\"",
        "\"spell\"",
        "\"spellCbor\"",
        "\"publicValues\"",
        "\"ethTxId\"",
    ] {
        let at = spell.find(key).unwrap_or_else(|| panic!("missing {key}"));
        assert!(at >= prev, "{key} out of order");
        prev = at;
    }
}

fn assert_hex(text: &str, nbytes: Option<usize>, what: &str) {
    assert!(text.starts_with("0x"), "{what}: {text}");
    let rest = &text[2..];
    assert!(
        rest.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{what}: {text}"
    );
    assert_eq!(rest.len() % 2, 0, "{what}");
    if let Some(n) = nbytes {
        assert_eq!(rest.len(), n * 2, "{what} width");
    }
}

fn generate() -> String {
    let once = render();
    let twice = render();
    assert_eq!(once, twice, "generator is not deterministic");
    once
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [path] if !path.starts_with('-') => write_file(path, &generate()),
        [flag, path] if flag == "--check" => check_file(path, &generate()),
        [flag, tx, path] if flag == "--proof" => write_file(path, &proof_vector(tx)),
        _ => {
            eprintln!(
                "usage: charms-ethereum-vectors <out.json> | --check <path> \
                 | --proof <bitcoin-tx-hex-file> <out.json>"
            );
            process::exit(2);
        }
    }
}

fn proof_vector(tx_path: &str) -> String {
    use charms_client::tx::{EnchantedTx, Tx};

    let hex = fs::read_to_string(tx_path).unwrap_or_else(|err| panic!("read {tx_path}: {err}"));
    let tx = Tx::try_from(hex.trim()).expect("a Bitcoin or Cardano transaction");
    let Tx::Bitcoin(bitcoin_tx) = &tx else {
        panic!("expected a Bitcoin transaction");
    };
    let spell = tx
        .extract_and_verify_spell(&charms_lib::SPELL_VK, false)
        .expect("a v15 spell whose proof verifies");
    let (_, proof) =
        charms_client::bitcoin_tx::parse_spell_and_proof_from_op_return(bitcoin_tx.inner())
            .expect("spell in OP_RETURN");
    let vector = json::ProofVector {
        version: spell.version,
        program_v_key: hex32(&charms_lib::SPELL_VK),
        public_values: hex_bytes(&to_serialized_pv(
            spell.version,
            &charms_lib::SPELL_VK,
            &spell,
        )),
        proof: hex_bytes(&proof),
    };
    let mut json = serde_json::to_string_pretty(&vector).unwrap();
    json.push('\n');
    json
}

fn write_file(path: &str, json: &str) {
    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("mkdir {}: {err}", parent.display()));
    }
    fs::write(path, json).unwrap_or_else(|err| panic!("write {path}: {err}"));
}

fn check_file(path: &str, json: &str) {
    let existing = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("read {path}: {err}");
            process::exit(1);
        }
    };
    if existing != json.as_bytes() {
        let at = existing
            .iter()
            .zip(json.as_bytes())
            .position(|(a, b)| a != b)
            .unwrap_or(existing.len().min(json.len()));
        eprintln!(
            "mismatch {path}: file {} bytes, generated {} bytes, first difference at {at}",
            existing.len(),
            json.len()
        );
        process::exit(1);
    }
}
