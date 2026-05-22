use crate::{
    bitcoin_tx::SCROLLS_ADDRS_PUBKEY,
    tx::{EnchantedTx, Tx, by_txid, extended_normalized_spell},
};
use anyhow::{Context, anyhow, ensure};
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use charms_app_runner::AppRunner;
use charms_data::{
    App, AppInput, B32, Charms, Data, NativeOutput, SCROLL, TOKEN, Transaction, TxId, UtxoId,
    VersionedApp, check, is_simple_transfer, util,
};
use const_format::formatcp;
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, IfIsHumanReadable, serde_as};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub mod ark;
pub mod bitcoin_tx;
pub mod cardano_tx;
pub mod request;
pub mod sorted_app_map;
pub mod tx;

pub const MOCK_SPELL_VK: [u8; 32] =
    hex!("7c38e8639a2eac0074cee920982b92376513e8940f4a7ca6859f17a728af5b0e");

/// Verification key for version `0` of the protocol implemented by `charms-spell-checker` binary.
pub const V0_SPELL_VK: [u8; 32] =
    hex!("00e9398ac819e6dd281f81db3ada3fe5159c3cc40222b5ddb0e7584ed2327c5d");
/// Verification key for version `1` of the protocol implemented by `charms-spell-checker` binary.
pub const V1_SPELL_VK: [u8; 32] =
    hex!("009f38f590ebca4c08c1e97b4064f39e4cd336eea4069669c5f5170a38a1ff97");
/// Verification key for version `2` of the protocol implemented by `charms-spell-checker` binary.
pub const V2_SPELL_VK: [u8; 32] =
    hex!("00bd312b6026dbe4a2c16da1e8118d4fea31587a4b572b63155252d2daf69280");
/// Verification key for version `3` of the protocol implemented by `charms-spell-checker` binary.
pub const V3_SPELL_VK: [u8; 32] =
    hex!("0034872b5af38c95fe82fada696b09a448f7ab0928273b7ac8c58ba29db774b9");
/// Verification key for version `4` of the protocol implemented by `charms-spell-checker` binary.
pub const V4_SPELL_VK: [u8; 32] =
    hex!("00c707a155bf8dc18dc41db2994c214e93e906a3e97b4581db4345b3edd837c5");
/// Verification key for version `5` of the protocol implemented by `charms-spell-checker` binary.
pub const V5_SPELL_VK: [u8; 32] =
    hex!("00e98665c417bd2e6e81c449af63b26ed5ad5c400ef55811b592450bf62c67cd");
/// Verification key for version `6` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V6_SPELL_VK: [u8; 32] =
    hex!("005a1df17094445572e4dd474b3e5dd9093936cba62ca3a62bb2ce63d9db8cba");
/// Verification key for version `7` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V7_SPELL_VK: [u8; 32] =
    hex!("0041d9843ec25ba04797a0ce29af364389f7eda9f7126ef39390c357432ad9aa");
/// Verification key for version `8` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V8_SPELL_VK: [u8; 32] =
    hex!("00e440d40e331c16bc4c78d2dbc6bb35876e6ea944e943de359a075e07385abc");
/// Verification key for version `9` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V9_SPELL_VK: [u8; 32] =
    hex!("00713f077ec2bd68157512835dc678053565a889935ecd5789ce2fa097c93ee9");
/// Verification key for version `10` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V10_SPELL_VK: [u8; 32] =
    hex!("00ccf030317cae019a4cd3c8557b2c5b522050e7e562e3adf287cd5ad596511f");
/// Verification key for version `11` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V11_SPELL_VK: [u8; 32] =
    hex!("00d41d49f54303acee4e7d064a31e0c9bd2e1bbdb60f39170a1461c71015c308");
/// Verification key for version `12` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V12_SPELL_VK: [u8; 32] =
    hex!("00cd44537c67da0dc50b88e794deed43c4507a862070ed83c99941789811a6a0");
/// Verification key for version `13` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V13_SPELL_VK: [u8; 32] =
    hex!("004ef5bd2f6ed0c33b022dcc263bde479421d81a82ca0cb1a99d9ff361f89895");

/// Version `0` of the protocol.
pub const V0: u32 = 0;
/// Version `1` of the protocol.
pub const V1: u32 = 1;
/// Version `2` of the protocol.
pub const V2: u32 = 2;
/// Version `3` of the protocol.
pub const V3: u32 = 3;
/// Version `4` of the protocol.
pub const V4: u32 = 4;
/// Version `5` of the protocol.
pub const V5: u32 = 5;
/// Version `6` of the protocol.
pub const V6: u32 = 6;
/// Version `7` of the protocol.
pub const V7: u32 = 7;
/// Version `8` of the protocol.
pub const V8: u32 = 8;
/// Version `9` of the protocol.
pub const V9: u32 = 9;
/// Version `10` of the protocol.
pub const V10: u32 = 10;
/// Version `11` of the protocol.
pub const V11: u32 = 11;
/// Version `12` of the protocol.
pub const V12: u32 = 12;
/// Version `13` of the protocol.
pub const V13: u32 = 13;
/// Version `14` of the protocol.
pub const V14: u32 = 14;

/// Current version of the protocol.
pub const CURRENT_VERSION: u32 = V14;

pub const CHARMS_PROVE_API_URL: &'static str =
    formatcp!("https://v{CURRENT_VERSION}.charms.dev/spells/prove");

/// Source of a beamed input: the UTXO that beamed the charms, with an optional nonce.
///
/// When the nonce is `Some`, its LE bytes are appended to the destination UTXO ID bytes
/// before hashing for comparison with the hash in the beaming transaction's `beamed_outs`.
#[serde_as]
#[cfg_attr(test, derive(test_strategy::Arbitrary))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BeamSource(
    #[serde_as(as = "IfIsHumanReadable<DisplayFromStr>")] pub UtxoId,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub Option<u64>,
);

/// Maps the index of the charm's app (in [`NormalizedSpell`].`app_public_inputs`) to the charm's
/// data.
pub type NormalizedCharms = BTreeMap<u32, Data>;

/// Normalized representation of a Charms transaction.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct NormalizedTransaction {
    /// (Optional) input UTXO list. Is None when serialized in the transaction: the transaction
    /// already lists all inputs. **Must** be in the order of the transaction inputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ins: Option<Vec<UtxoId>>,

    /// Reference UTXO list. **May** be empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<UtxoId>>,

    /// Output charms. **Must** be in the order of the transaction outputs.
    /// When proving spell correctness, we can't know the transaction ID yet.
    /// We only know the index of each output charm.
    /// **Must** be in the order of the hosting transaction's outputs.
    /// **Must not** be larger than the number of outputs in the hosting transaction.
    pub outs: Vec<NormalizedCharms>,

    /// Optional mapping from the beamed output index to the destination UtxoId hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beamed_outs: Option<BTreeMap<u32, B32>>,

    /// Amounts of native coin in transaction outputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coins: Option<Vec<NativeOutput>>,

    /// Indexes of outputs that MUST be sent to a Scrolls-managed `scriptPubKey` on
    /// Bitcoin.
    ///
    /// Clients prepare a spell with these indexes listed and `coins[i].dest = vec![]`
    /// for each scroll output. The prover server then calls the
    /// `scrolls_bitcoin_v15` canister's `addresses()` endpoint to obtain a signed
    /// `output_index -> scriptPubKey` map, writes each `scriptPubKey` into
    /// `coins[i].dest`, and threads the signed map through to the zkVM as
    /// [`SpellProverInput::scroll_outputs`]. [`is_correct`] then verifies the
    /// canister's BIP-340 Schnorr signature, that this set equals the keys of the
    /// signed map, and that each signed `scriptPubKey` equals `tx.coins[i].dest`.
    ///
    /// On the client side (before the server hop), `is_correct` returns `Ok(false)`
    /// for spells with unbound scroll outputs; callers like `charms spell check` and
    /// the prove-request preflight tolerate that "not yet" signal.
    ///
    /// Every spell-output containing a charm whose app has tag [`charms_data::SCROLL`]
    /// MUST have its index listed here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scrolls: Option<BTreeSet<u32>>,
}

impl NormalizedTransaction {
    /// Return a sorted set of transaction IDs of the inputs.
    /// Including source tx_ids for beamed inputs.
    pub fn prev_txids(&self) -> Option<BTreeSet<&TxId>> {
        self.ins
            .as_ref()
            .map(|ins| ins.iter().map(|utxo_id| &utxo_id.0).collect())
    }
}

/// Proof of spell correctness.
pub type Proof = Vec<u8>;

/// Normalized representation of a spell.
/// Can be committed as public input.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NormalizedSpell {
    /// Protocol version.
    pub version: u32,
    /// Transaction data.
    pub tx: NormalizedTransaction,
    /// Maps all `App`s in the transaction to (potentially empty) public input data.
    #[serde(deserialize_with = "sorted_app_map::deserialize")]
    pub app_public_inputs: BTreeMap<App, Data>,
    /// For versioned app modules: maps an app's `vk` (SHA256 of its signing public key) to the
    /// `version` number and Wasm `wasm_hash` that this spell binds the app to. Apps whose `vk`
    /// is absent from this map are simple (immutable): their `vk` is the SHA256 of their Wasm
    /// binary directly.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub versioned_apps: BTreeMap<B32, VersionedApp>,
    /// Is this a mock spell?
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub mock: bool,
}

impl Default for NormalizedSpell {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            tx: Default::default(),
            app_public_inputs: Default::default(),
            versioned_apps: Default::default(),
            mock: false,
        }
    }
}

pub fn utxo_id_hash(utxo_id: &UtxoId) -> B32 {
    let hash = Sha256::digest(utxo_id.to_bytes());
    B32(hash.into())
}

pub fn utxo_id_hash_with_nonce(utxo_id: &UtxoId, nonce: Option<u64>) -> B32 {
    let mut hash = Sha256::default();
    hash.update(utxo_id.to_bytes());
    if let Some(nonce) = nonce {
        hash.update(&nonce.to_le_bytes());
    }
    B32(hash.finalize().into())
}

/// Extract spells from previous transactions.
#[tracing::instrument(level = "debug", skip(prev_txs, spell_vk))]
pub fn prev_spells(
    prev_txs: &[Tx],
    spell_vk: &[u8; 32],
    norm_spell: &NormalizedSpell,
) -> anyhow::Result<BTreeMap<TxId, (NormalizedSpell, usize)>> {
    prev_txs
        .iter()
        .map(|tx| {
            Ok((
                tx.tx_id(),
                (
                    extended_normalized_spell(spell_vk, norm_spell, tx)?,
                    tx.tx_outs_len(),
                ),
            ))
        })
        .collect()
}

/// Check if the spell is well-formed.
#[tracing::instrument(level = "debug", skip(spell, prev_spells))]
pub fn well_formed(
    spell: &NormalizedSpell,
    prev_spells: &BTreeMap<TxId, (NormalizedSpell, usize)>,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, BeamSource>,
) -> bool {
    check!(spell.version == CURRENT_VERSION);
    check!(ensure_no_zero_amounts(spell).is_ok());
    let directly_created_by_prev_txns = |utxo_id: &UtxoId| -> bool {
        let tx_id = utxo_id.0;
        prev_spells
            .get(&tx_id)
            .is_some_and(|(n_spell, num_tx_outs)| {
                let utxo_index = utxo_id.1;

                let is_beamed_out = beamed_out_to_hash(n_spell, utxo_index).is_some();

                utxo_index <= *num_tx_outs as u32 && !is_beamed_out
            })
    };
    check!({
        spell.tx.outs.iter().all(|n_charm| {
            n_charm
                .keys()
                .all(|&i| i < spell.app_public_inputs.len() as u32)
        })
    });
    // check that UTXOs we're spending or referencing in this tx
    // are created by pre-req transactions
    let Some(tx_ins) = &spell.tx.ins else {
        eprintln!("no tx.ins");
        return false;
    };
    check!(
        tx_ins.iter().all(directly_created_by_prev_txns)
            && (spell.tx.refs.iter().flatten()).all(directly_created_by_prev_txns)
    );
    let beamed_source_utxos_point_to_placeholder_dest_utxos = tx_ins_beamed_source_utxos
        .iter()
        .all(|(&i, beaming_source)| {
            let tx_in_utxo_id = &tx_ins[i];
            let prev_txid = tx_in_utxo_id.0;
            let prev_tx = prev_spells.get(&prev_txid);
            let Some((prev_spell, _tx_outs)) = prev_tx else {
                // prev_tx should be provided, so we know it doesn't carry a spell
                return false;
            };
            // tx_in_utxo must exist and either have no Charms or be beamed out
            check!(
                (prev_spell.tx.outs)
                    .get(tx_in_utxo_id.1 as usize)
                    .is_none_or(|charms| charms.is_empty()
                        || beamed_out_to_hash(prev_spell, tx_in_utxo_id.1).is_some())
            );

            let beaming_source_utxo_id = &beaming_source.0;
            let beaming_txid = beaming_source_utxo_id.0;
            let beaming_utxo_index = beaming_source_utxo_id.1;

            prev_spells
                .get(&beaming_txid)
                .and_then(|(n_spell, _tx_outs)| beamed_out_to_hash(n_spell, beaming_utxo_index))
                .is_some_and(|dest_utxo_hash| {
                    dest_utxo_hash == &utxo_id_hash_with_nonce(tx_in_utxo_id, beaming_source.1)
                })
        });
    check!(beamed_source_utxos_point_to_placeholder_dest_utxos);
    true
}

/// Return the list of apps in the spell.
pub fn apps(spell: &NormalizedSpell) -> Vec<App> {
    spell.app_public_inputs.keys().cloned().collect()
}

/// Convert normalized spell to [`charms_data::Transaction`].
pub fn to_tx(
    spell: &NormalizedSpell,
    prev_spells: &BTreeMap<TxId, (NormalizedSpell, usize)>,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, BeamSource>,
    prev_txs: &[Tx],
) -> Transaction {
    let Some(tx_ins) = &spell.tx.ins else {
        unreachable!("self.tx.ins MUST be Some at this point");
    };

    let tx_ins_beamed_source_utxos: BTreeMap<UtxoId, UtxoId> = tx_ins_beamed_source_utxos
        .iter()
        .map(|(&i, bs)| (tx_ins[i].clone(), bs.0.clone()))
        .collect();

    let from_utxo_id = |utxo_id: &UtxoId| -> (UtxoId, Charms) {
        let (prev_spell, _) = &prev_spells[&utxo_id.0];
        let charms = charms_in_utxo(prev_spell, utxo_id)
            .or_else(|| {
                tx_ins_beamed_source_utxos
                    .get(utxo_id)
                    .and_then(|beam_source_utxo_id| {
                        let prev_spell = &prev_spells[&beam_source_utxo_id.0].0;
                        charms_in_utxo(&prev_spell, beam_source_utxo_id)
                    })
            })
            .unwrap_or_default();
        (utxo_id.clone(), charms)
    };

    let from_normalized_charms =
        |n_charms: &NormalizedCharms| -> Charms { charms(spell, n_charms) };

    let coin_from_input = |utxo_id: &UtxoId| -> NativeOutput {
        let (prev_spell, _) = &prev_spells[&utxo_id.0];
        let prev_coins = prev_spell.tx.coins.as_ref().expect(
            "coins MUST NOT be none: we used `extended_normalized_spell` to get prev_spells",
        );
        prev_coins[utxo_id.1 as usize].clone()
    };

    let prev_txs = prev_txs.iter().map(|tx| (tx.tx_id(), tx.into())).collect();

    Transaction {
        ins: tx_ins.iter().map(from_utxo_id).collect(),
        refs: spell.tx.refs.iter().flatten().map(from_utxo_id).collect(),
        outs: spell.tx.outs.iter().map(from_normalized_charms).collect(),
        coin_ins: Some(tx_ins.iter().map(coin_from_input).collect()),
        coin_outs: spell.tx.coins.clone(),
        prev_txs,
        app_public_inputs: spell.app_public_inputs.clone(),
    }
}

pub fn charms_in_utxo(prev_spell: &NormalizedSpell, utxo_id: &UtxoId) -> Option<Charms> {
    (prev_spell.tx.outs)
        .get(utxo_id.1 as usize)
        .map(|n_charms| charms(prev_spell, n_charms))
        .filter(|c| !c.is_empty())
}

/// Return [`charms_data::Charms`] for the given [`NormalizedCharms`].
pub fn charms(spell: &NormalizedSpell, n_charms: &NormalizedCharms) -> Charms {
    let apps = apps(spell);
    n_charms
        .iter()
        .map(|(&i, data)| (apps[i as usize].clone(), data.clone()))
        .collect()
}

/// Output of the `scrolls_bitcoin_v15` canister's `addresses(...)` endpoint: a map
/// from spell-output index to its derived P2WPKH `scriptPubKey` (hex-encoded raw
/// script bytes — the same bytes that go into `tx.coins[i].dest`), plus a
/// hex-encoded BIP-340 Schnorr signature over the CBOR serialization of the map,
/// produced under the canister's chain key derivation path `[b"sign"]`. The
/// signature is verified against [`crate::bitcoin_tx::SCROLLS_ADDRS_PUBKEY`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedScrollOutputs {
    pub script_pubkeys: BTreeMap<u32, String>,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpellProverInput {
    pub self_spell_vk: [u8; 32],
    pub prev_txs: Vec<Tx>,
    pub spell: NormalizedSpell,
    pub tx_ins_beamed_source_utxos: BTreeMap<usize, BeamSource>,
    pub app_input: Option<AppInput>,
    /// Signed `output_index -> scriptPubKey` map for the spell's Scrolls outputs.
    /// MUST be `Some` whenever the spell is on Bitcoin and
    /// [`NormalizedTransaction::scrolls`] is non-empty. Verified inside
    /// [`is_correct`].
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scroll_outputs: Option<SignedScrollOutputs>,
}

/// Check if the spell is correct.
pub fn is_correct(
    spell: &NormalizedSpell,
    prev_txs: &Vec<Tx>,
    app_input: Option<AppInput>,
    spell_vk: &[u8; 32],
    tx_ins_beamed_source_utxos: &BTreeMap<usize, BeamSource>,
    scroll_outputs: Option<&SignedScrollOutputs>,
) -> anyhow::Result<bool> {
    ensure!(beaming_txs_have_finality_proofs(
        prev_txs,
        tx_ins_beamed_source_utxos
    ));

    let prev_spells = prev_spells(&prev_txs, spell_vk, &spell)?;

    ensure!(well_formed(spell, &prev_spells, tx_ins_beamed_source_utxos));

    let Some(prev_txids) = spell.tx.prev_txids() else {
        unreachable!("the spell is well formed: tx.ins MUST be Some");
    };
    let all_prev_txids: BTreeSet<_> = tx_ins_beamed_source_utxos
        .values()
        .map(|bs| &(bs.0).0)
        .chain(prev_txids)
        .collect();
    ensure!(all_prev_txids == prev_spells.keys().collect());

    ensure_no_orphan_versioned_apps(spell)?;
    check_input_apps_are_referenced(spell, &prev_spells, tx_ins_beamed_source_utxos)?;
    check_prev_versioned_apps_consistency(&prev_spells)?;
    check_scroll_outputs_are_listed(spell)?;

    // Scrolls scriptPubKey-map check. May return `Ok(false)` on the client
    // preflight path (the spell declares Scrolls outputs but the signed map
    // hasn't been fetched -- the prover server fills it in via
    // `fill_scroll_outputs`). We don't bail early on `false`: the rest of the
    // checks still run, and the "not yet" signal is folded into the final
    // result below. The zkVM spell-checker asserts `Ok(true)` and so refuses to
    // prove until the binding is in place; host-side callers that run before
    // the server hop tolerate `Ok(false)`.
    let scrolls_ok = !hosting_chain_is_bitcoin(spell, prev_txs)
        || check_scroll_outputs(spell, scroll_outputs)?;

    let apps = apps(spell);
    let charms_tx = to_tx(spell, &prev_spells, tx_ins_beamed_source_utxos, &prev_txs);

    check_app_version_continuity(spell, &prev_spells, tx_ins_beamed_source_utxos)?;

    // Apps whose version changes between any spent charm's prev spell and this spell.
    // Whenever the version changes, the new contract must actually run to authorize the
    // transition -- the previous spell only signed off on `(vk, prev_version, prev_wasm)`.
    let version_changed_apps =
        collect_version_changed_apps(spell, &prev_spells, tx_ins_beamed_source_utxos);

    authorize_version_changes(spell, &version_changed_apps, app_input.as_ref())?;

    match app_input {
        None => {
            // Every app must be a simple transfer; the previous spell's authentication of
            // `(vk, version, wasm_hash)` is the only authorization available.
            let non_simple_transfer_apps: Vec<_> = apps
                .iter()
                .filter(|app| !is_simple_transfer(app, &charms_tx))
                .map(|app| app.to_string())
                .collect();
            ensure!(
                non_simple_transfer_apps.is_empty(),
                "no app binaries provided, but the spell is not a simple transfer for: {:?}. \
                 Provide the app binaries so the contracts can run, or restructure the spell \
                 to preserve balances/state.",
                non_simple_transfer_apps
            );
        }
        Some(app_input) => {
            // `version_changed_apps` is passed through to `run_all`, which uses it to
            // bypass the simple-transfer fast path for these apps -- so `is_simple_transfer`
            // is called at most once per app (inside `run_all`).
            apps_satisfied(
                &app_input,
                &spell.versioned_apps,
                &spell.app_public_inputs,
                &charms_tx,
                &version_changed_apps,
            )?;
        }
    }

    Ok(scrolls_ok)
}

/// Gate on which a version change must hand off to the new app's contract: when any spent
/// charm's app version differs from the spending spell's, `app_input` MUST supply the new
/// Wasm binary so `run_all` can execute it and authorize the transition. Without binaries
/// (the `None` branch of `is_correct`), no version change is permitted at all.
fn authorize_version_changes(
    spell: &NormalizedSpell,
    version_changed_apps: &BTreeSet<App>,
    app_input: Option<&AppInput>,
) -> anyhow::Result<()> {
    if version_changed_apps.is_empty() {
        return Ok(());
    }
    let Some(app_input) = app_input else {
        return Err(anyhow!(
            "no app binaries provided, but versioned-app version changes were declared \
             for: {:?}. A version change requires running the new app binary to authorize \
             the transition.",
            version_changed_apps
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
        ));
    };
    for app in version_changed_apps {
        let cur_va = spell.versioned_apps.get(&app.vk).ok_or_else(|| {
            anyhow!(
                "internal: app {} is in version_changed_apps but has no versioned_apps \
                 entry in the spending spell",
                app
            )
        })?;
        ensure!(
            app_input.app_binaries.contains_key(&cur_va.wasm_hash),
            "app {}: version is changing to {}; its new binary (wasm_hash {}) must be \
             supplied so the new contract can run and authorize the transition",
            app,
            cur_va.version,
            cur_va.wasm_hash
        );
    }
    Ok(())
}

/// Collect the set of apps whose version differs between a spent charm's source spell and
/// the spending spell. Beamed inputs are resolved to their beam-source spell, the same way
/// [`check_app_version_continuity`] does.
pub fn collect_version_changed_apps(
    spell: &NormalizedSpell,
    prev_spells: &BTreeMap<TxId, (NormalizedSpell, usize)>,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, BeamSource>,
) -> BTreeSet<App> {
    let Some(tx_ins) = &spell.tx.ins else {
        return BTreeSet::new();
    };
    let mut changed = BTreeSet::new();
    for (i, input_utxo_id) in tx_ins.iter().enumerate() {
        let source_utxo_id = tx_ins_beamed_source_utxos
            .get(&i)
            .map(|bs| &bs.0)
            .unwrap_or(input_utxo_id);
        let Some((source_spell, _)) = prev_spells.get(&source_utxo_id.0) else {
            continue;
        };
        let Some(prev_charms) = charms_in_utxo(source_spell, source_utxo_id) else {
            continue;
        };
        for app in prev_charms.keys() {
            if let (Some(prev_va), Some(cur_va)) = (
                source_spell.versioned_apps.get(&app.vk),
                spell.versioned_apps.get(&app.vk),
            ) {
                if prev_va.version != cur_va.version {
                    changed.insert(app.clone());
                }
            }
        }
    }
    changed
}

/// Every entry in `spell.versioned_apps` must correspond to at least one app in
/// `spell.app_public_inputs`. Without this, a prover bypassing the host-side validator
/// could commit a spell carrying "orphan" version pins for vks no app references —
/// those orphans then become part of `prev_spells` for any future spend, where
/// [`check_prev_versioned_apps_consistency`] would happily compare them and could
/// reject otherwise-valid spends whose other prev spell legitimately pinned the same
/// `(vk, version)` to a different `wasm_hash`. The check therefore lives inside
/// [`is_correct`] (the function whose output is committed to the zkVM proof), not just
/// in host-side request validation.
pub fn ensure_no_orphan_versioned_apps(spell: &NormalizedSpell) -> anyhow::Result<()> {
    let app_vks: BTreeSet<&B32> = spell.app_public_inputs.keys().map(|app| &app.vk).collect();
    for vk in spell.versioned_apps.keys() {
        ensure!(
            app_vks.contains(vk),
            "versioned_apps contains unused vk: {}",
            vk
        );
    }
    Ok(())
}

/// Every app that appears in any spent input UTXO's charms MUST also appear in the
/// spell's `app_public_inputs`. Without this rule, a spell could spend an input carrying
/// a charm for app `X` without listing `X` — `apps_satisfied` iterates only
/// `app_public_inputs`, so `X`'s contract would be bypassed entirely. For a token that
/// lets value be burned without authorization; for an NFT it lets the NFT be destroyed
/// without the app's permission.
///
/// For beamed inputs the "spent charms" come from the beam source's spell, so we resolve
/// the source spell + utxo the same way [`check_app_version_continuity`] does.
pub fn check_input_apps_are_referenced(
    spell: &NormalizedSpell,
    prev_spells: &BTreeMap<TxId, (NormalizedSpell, usize)>,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, BeamSource>,
) -> anyhow::Result<()> {
    let Some(tx_ins) = &spell.tx.ins else {
        unreachable!("called after well_formed");
    };
    let referenced: BTreeSet<&App> = spell.app_public_inputs.keys().collect();

    for (i, input_utxo_id) in tx_ins.iter().enumerate() {
        let (source_spell, source_utxo_id) = match tx_ins_beamed_source_utxos.get(&i) {
            Some(beam_source) => {
                let beam_source_utxo_id = &beam_source.0;
                let (prev_spell, _) = prev_spells.get(&beam_source_utxo_id.0).ok_or_else(
                    || {
                        anyhow!(
                            "missing prev spell for beam source utxo {} (input #{})",
                            beam_source_utxo_id,
                            i
                        )
                    },
                )?;
                (prev_spell, beam_source_utxo_id)
            }
            None => {
                let (prev_spell, _) = prev_spells.get(&input_utxo_id.0).ok_or_else(|| {
                    anyhow!(
                        "missing prev spell for input utxo {} (input #{})",
                        input_utxo_id,
                        i
                    )
                })?;
                (prev_spell, input_utxo_id)
            }
        };
        let Some(input_charms) = charms_in_utxo(source_spell, source_utxo_id) else {
            continue;
        };
        for app in input_charms.keys() {
            ensure!(
                referenced.contains(app),
                "input #{} ({}) carries a charm for app {}, but the spending spell does not \
                 list it in `app_public_inputs`. Spending (or burning) the charm requires \
                 the app to be referenced so its contract can authorize the operation.",
                i,
                source_utxo_id,
                app
            );
        }
    }
    Ok(())
}

/// Enforce that all `prev_spells` agree on the Wasm binary hash for any `(vk, version)`
/// pair they share. A spending spell references several previous transactions and each one
/// independently declares `versioned_apps`; this check rejects the case where two of them
/// claim the same vk + version but bind it to different binaries.
pub fn check_prev_versioned_apps_consistency(
    prev_spells: &BTreeMap<TxId, (NormalizedSpell, usize)>,
) -> anyhow::Result<()> {
    let mut seen: BTreeMap<(&B32, u32), (&B32, &TxId)> = BTreeMap::new();
    for (tx_id, (prev_spell, _)) in prev_spells {
        for (vk, va) in &prev_spell.versioned_apps {
            let key = (vk, va.version);
            match seen.get(&key) {
                Some((prev_hash, prev_source)) => {
                    ensure!(
                        *prev_hash == &va.wasm_hash,
                        "inconsistent Wasm hash for versioned app (vk={}, version={}): {} (in tx {}) vs {} (in tx {})",
                        vk,
                        va.version,
                        prev_hash,
                        prev_source,
                        va.wasm_hash,
                        tx_id
                    );
                }
                None => {
                    seen.insert(key, (&va.wasm_hash, tx_id));
                }
            }
        }
    }
    Ok(())
}

/// Enforce versioned-app continuity from spent charms to the spending spell:
///
/// 1. If the app version stays the same, the Wasm binary hash MUST stay the same.
/// 2. The app version in the spending spell MUST be the same, higher, or `0`.
/// 3. Version `0` is immutable: if the spent charm's app version is `0`, the spending spell's
///    version MUST also be `0`.
///
/// Note: when the version *changes* (rule 2's "higher" or drop-to-`0` case), the spending
/// spell is required by [`is_correct`] to supply the new Wasm binary and actually run it,
/// so the new contract authorizes the transition. That requirement is enforced in
/// [`is_correct`], not here, which is why this function no longer needs to inspect whether
/// the spell is a "simple transfer" for the app.
///
/// The check is per-input-UTXO, per-app-vk. For beamed inputs, the "previous" spell is the
/// beam source's spell (since that is where the spent charm's metadata lives).
///
/// Scope notes:
/// - Reference inputs (`spell.tx.refs`) are **not** consulted here: refs are read-only and
///   don't "spend" a charm, so the version-bump rules don't apply. Cross-tx version
///   consistency for ref-source spells is still enforced by
///   [`check_prev_versioned_apps_consistency`], which sees every prev spell.
/// - This function tolerates the case where a spent charm's `vk` is not referenced by the
///   spending spell (no successor `(version, wasm_hash)` to constrain). In the full
///   `is_correct` flow that situation is independently rejected earlier by
///   [`check_input_apps_are_referenced`], because allowing it would let an app's contract
///   be bypassed entirely. Keeping the local tolerance here makes this function a pure
///   per-input rule that can be reasoned about in isolation.
pub fn check_app_version_continuity(
    spell: &NormalizedSpell,
    prev_spells: &BTreeMap<TxId, (NormalizedSpell, usize)>,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, BeamSource>,
) -> anyhow::Result<()> {
    let Some(tx_ins) = &spell.tx.ins else {
        unreachable!("called after well_formed");
    };

    let referenced_vks: BTreeSet<&B32> =
        spell.app_public_inputs.keys().map(|a| &a.vk).collect();

    for (i, input_utxo_id) in tx_ins.iter().enumerate() {
        // Resolve which prev spell + utxo carries the spent charms (handling beaming).
        let (source_spell, source_utxo_id) = match tx_ins_beamed_source_utxos.get(&i) {
            Some(beam_source) => {
                let beam_source_utxo_id = &beam_source.0;
                let (prev_spell, _) = prev_spells.get(&beam_source_utxo_id.0).ok_or_else(
                    || {
                        anyhow!(
                            "missing prev spell for beam source utxo {} (input #{})",
                            beam_source_utxo_id,
                            i
                        )
                    },
                )?;
                (prev_spell, beam_source_utxo_id)
            }
            None => {
                let (prev_spell, _) = prev_spells.get(&input_utxo_id.0).ok_or_else(|| {
                    anyhow!(
                        "missing prev spell for input utxo {} (input #{})",
                        input_utxo_id,
                        i
                    )
                })?;
                (prev_spell, input_utxo_id)
            }
        };

        let Some(prev_charms) = charms_in_utxo(source_spell, source_utxo_id) else {
            continue;
        };

        for app in prev_charms.keys() {
            let Some(prev_ver) = source_spell.versioned_apps.get(&app.vk) else {
                // Prev spell treated this app as a simple (immutable) app -- its `vk` is
                // SHA-256 of the binary itself. The spending spell must continue to treat
                // it as simple; introducing a `versioned_apps` entry here would silently
                // re-anchor the charm to an arbitrary `(version, wasm_hash)` that nobody
                // ever signed (the simple-transfer path would skip the signature check).
                ensure!(
                    !spell.versioned_apps.contains_key(&app.vk),
                    "input #{} ({}), app {}: the spent charm is from a previous spell that \
                     treated this app as simple (no `versioned_apps` entry); the spending \
                     spell cannot retroactively declare it versioned",
                    i,
                    source_utxo_id,
                    app
                );
                continue;
            };

            // Burn / drop: the spending spell doesn't reference this vk at all, so there
            // is no successor (version, wasm_hash) to constrain. In the full `is_correct`
            // flow this is unreachable (`check_input_apps_are_referenced` rejects it
            // first), but the function is also called in isolation by tests, so the
            // local tolerance stays.
            if !referenced_vks.contains(&app.vk) {
                continue;
            }

            let cur_ver = spell.versioned_apps.get(&app.vk).ok_or_else(|| {
                anyhow!(
                    "input #{} ({}): spent charm with versioned app {} is referenced in the \
                     spending spell, but the spending spell does not declare it in \
                     `versioned_apps`",
                    i,
                    source_utxo_id,
                    app
                )
            })?;

            if prev_ver.version == 0 {
                // Rule 3: version 0 is immutable.
                ensure!(
                    cur_ver.version == 0,
                    "input #{} ({}), app {}: spent version is 0, spending spell version must \
                     also be 0 (got {})",
                    i,
                    source_utxo_id,
                    app,
                    cur_ver.version
                );
            } else {
                // Rule 2: spending version must be same, higher, or 0.
                ensure!(
                    cur_ver.version == 0 || cur_ver.version >= prev_ver.version,
                    "input #{} ({}), app {}: spending version ({}) must be 0, equal to, or \
                     higher than the spent version ({})",
                    i,
                    source_utxo_id,
                    app,
                    cur_ver.version,
                    prev_ver.version
                );
            }

            // Rule 1: same version implies same Wasm binary hash.
            if cur_ver.version == prev_ver.version {
                ensure!(
                    cur_ver.wasm_hash == prev_ver.wasm_hash,
                    "input #{} ({}), app {}: spending and spent versions are both {}, but Wasm \
                     hashes differ (spent: {}, spending: {})",
                    i,
                    source_utxo_id,
                    app,
                    cur_ver.version,
                    prev_ver.wasm_hash,
                    cur_ver.wasm_hash
                );
            }
        }
    }
    Ok(())
}

fn beaming_txs_have_finality_proofs(
    prev_txs: &Vec<Tx>,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, BeamSource>,
) -> bool {
    let prev_txs_by_txid: BTreeMap<TxId, Tx> = by_txid(prev_txs);
    let beaming_source_txids: BTreeSet<&TxId> = tx_ins_beamed_source_utxos
        .values()
        .map(|bs| &(bs.0).0)
        .collect::<BTreeSet<_>>();
    beaming_source_txids.iter().all(|&txid| {
        prev_txs_by_txid
            .get(txid)
            .is_some_and(|tx| tx.proven_final())
    })
}

fn apps_satisfied(
    app_input: &AppInput,
    versioned_apps: &BTreeMap<B32, VersionedApp>,
    app_public_inputs: &BTreeMap<App, Data>,
    tx: &Transaction,
    version_changed_apps: &BTreeSet<App>,
) -> anyhow::Result<()> {
    let app_runner = AppRunner::new(false);
    app_runner
        .run_all(
            &app_input.app_binaries,
            versioned_apps,
            &app_input.app_signatures,
            &tx,
            app_public_inputs,
            &app_input.app_private_inputs,
            version_changed_apps,
        )
        .context("all apps should run successfully")?;
    Ok(())
}

/// The hosting tx's chain is the chain of the tx that created `spell.tx.ins[0]`. We
/// can't just look at *any* `prev_txs` entry: beam-source txs are also in `prev_txs`
/// and may live on a different chain than the hosting tx, so an `any(|t| Bitcoin)`
/// would misfire on a Cardano spell with a Bitcoin beam source.
fn hosting_chain_is_bitcoin(spell: &NormalizedSpell, prev_txs: &[Tx]) -> bool {
    let Some(first_in) = spell.tx.ins.as_ref().and_then(|ins| ins.first()) else {
        return false;
    };
    prev_txs
        .iter()
        .find(|tx| tx.tx_id() == first_in.0)
        .is_some_and(|tx| matches!(tx, Tx::Bitcoin(_)))
}

/// Every output that carries a charm whose app has tag [`SCROLL`] MUST have its index
/// listed in `spell.tx.scrolls`, and every index in `spell.tx.scrolls` MUST point at a
/// real spell output (`< spell.tx.outs.len()`). The chain-conditional signature check
/// lives in [`check_scroll_outputs`]; these structural rules apply regardless of chain
/// (on Cardano the SCROLL app behaves as a regular non-token app, but the index still
/// has to be declared so the spell shape stays uniform across chains).
fn check_scroll_outputs_are_listed(spell: &NormalizedSpell) -> anyhow::Result<()> {
    let outs_len = spell.tx.outs.len() as u32;
    if let Some(scrolls) = spell.tx.scrolls.as_ref() {
        for &i in scrolls {
            ensure!(
                i < outs_len,
                "`tx.scrolls` references output #{} but the spell only has {} output(s)",
                i,
                outs_len
            );
        }
    }
    let apps = apps(spell);
    for (i, n_charm) in spell.tx.outs.iter().enumerate() {
        let has_scroll = n_charm
            .keys()
            .any(|&app_i| apps[app_i as usize].tag == SCROLL);
        if has_scroll {
            let listed = spell
                .tx
                .scrolls
                .as_ref()
                .is_some_and(|s| s.contains(&(i as u32)));
            ensure!(
                listed,
                "output #{} carries a SCROLL-tagged charm but is not listed in `tx.scrolls`",
                i
            );
        }
    }
    Ok(())
}

/// Verify the canister-signed Scrolls `scriptPubKey` map. Called only when the spell
/// is on Bitcoin.
///
/// Returns:
///
/// * `Ok(true)` -- nothing to check (no Scrolls outputs declared), or the signed map
///   is present and every check passes.
/// * `Ok(false)` -- Scrolls outputs are declared but no signed map was supplied
///   (the client preflight path, where `coins[i].dest` for those outputs is also
///   still empty -- the prover server fills both in via `fill_scroll_outputs`).
/// * `Err(_)` -- the signed map is present but a structural or cryptographic check
///   failed.
///
/// When the signed map is present, these MUST all hold:
///
/// * its keys equal `spell.tx.scrolls`,
/// * each signed `scriptPubKey` equals `spell.tx.coins[i].dest` (hex-encoded),
///   pinning the Bitcoin output to the canister-controlled script,
/// * its BIP-340 Schnorr signature verifies under [`SCROLLS_ADDRS_PUBKEY`] over
///   `SHA-256(CBOR(script_pubkeys))` (the same digest the `scrolls_bitcoin_v15`
///   canister signs).
fn check_scroll_outputs(
    spell: &NormalizedSpell,
    scroll_outputs: Option<&SignedScrollOutputs>,
) -> anyhow::Result<bool> {
    let Some(scrolls) = spell.tx.scrolls.as_ref().filter(|s| !s.is_empty()) else {
        return Ok(true);
    };
    let Some(scroll_outputs) = scroll_outputs else {
        return Ok(false);
    };
    let signed_keys: BTreeSet<u32> = scroll_outputs.script_pubkeys.keys().copied().collect();
    ensure!(
        scrolls == &signed_keys,
        "signed Scrolls scriptPubKey map keys ({:?}) do not match `tx.scrolls` ({:?})",
        signed_keys,
        scrolls
    );
    let coins = spell
        .tx
        .coins
        .as_ref()
        .ok_or_else(|| anyhow!("Bitcoin spell with Scrolls outputs must have `tx.coins` set"))?;
    for (&i, signed_spk_hex) in &scroll_outputs.script_pubkeys {
        let coin = coins.get(i as usize).ok_or_else(|| {
            anyhow!(
                "tx.scrolls references output #{} but tx.coins only has {} entries",
                i,
                coins.len()
            )
        })?;
        let dest_hex = hex::encode(&coin.dest);
        ensure!(
            signed_spk_hex.eq_ignore_ascii_case(&dest_hex),
            "scroll output #{}: signed scriptPubKey ({}) does not match `tx.coins[{}].dest` ({})",
            i,
            signed_spk_hex,
            i,
            dest_hex
        );
    }
    verify_scroll_outputs_signature(scroll_outputs)?;
    Ok(true)
}

fn verify_scroll_outputs_signature(s: &SignedScrollOutputs) -> anyhow::Result<()> {
    let message_bytes = util::write(&s.script_pubkeys)
        .context("serializing Scrolls scriptPubKeys for signature check")?;
    let digest: [u8; 32] = Sha256::digest(&message_bytes).into();
    let msg = Message::from_digest(digest);

    let sig_bytes = hex::decode(&s.signature).context("decoding Scrolls signature hex")?;
    let sig =
        Signature::from_slice(&sig_bytes).context("parsing Scrolls BIP-340 Schnorr signature")?;
    let pk = XOnlyPublicKey::from_slice(&SCROLLS_ADDRS_PUBKEY)
        .context("parsing SCROLLS_ADDRS_PUBKEY as x-only secp256k1 key")?;

    Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &pk)
        .context("verifying Scrolls scriptPubKey-map Schnorr signature")
}

pub fn ensure_no_zero_amounts(norm_spell: &NormalizedSpell) -> anyhow::Result<()> {
    let apps = apps(norm_spell);
    for out in &norm_spell.tx.outs {
        for (i, data) in out {
            let app = apps
                .get(*i as usize)
                .ok_or(anyhow!("no app for index {}", i))?;
            if app.tag == TOKEN {
                ensure!(
                    data.value::<u64>()? != 0,
                    "zero output amount for app {}",
                    app
                );
            };
        }
    }
    Ok(())
}

pub fn beamed_out_to_hash(spell: &NormalizedSpell, i: u32) -> Option<&B32> {
    (spell.tx.beamed_outs)
        .as_ref()
        .and_then(|beamed| beamed.get(&i))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{BeamSource, NormalizedSpell};
    use charms_data::{App, Data, NativeOutput, UtxoId, VersionedApp, util};
    use std::str::FromStr;
    use test_strategy::proptest;

    #[test]
    fn dummy() {}

    fn b32(hex: &str) -> B32 {
        B32::from_str(hex).unwrap()
    }

    /// Build a `(spell, prev_spells)` pair where the spending spell has a single input UTXO
    /// pointing at a previous spell whose output 0 carries one charm for `app`.
    fn build_continuity_fixture(
        app: App,
        prev_ver: Option<VersionedApp>,
        cur_ver: Option<VersionedApp>,
        reference_in_spending: bool,
    ) -> (NormalizedSpell, BTreeMap<TxId, (NormalizedSpell, usize)>) {
        let prev_tx_id =
            TxId::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let prev_utxo = UtxoId(prev_tx_id, 0);

        let mut prev_spell = NormalizedSpell::default();
        prev_spell.tx.ins = Some(vec![]);
        prev_spell.tx.refs = Some(vec![]);
        prev_spell.tx.outs = vec![{
            let mut c = NormalizedCharms::new();
            c.insert(0, Data::empty());
            c
        }];
        prev_spell
            .tx
            .coins
            .get_or_insert_with(Vec::new)
            .push(NativeOutput {
                amount: 0,
                dest: vec![],
                content: None,
            });
        prev_spell
            .app_public_inputs
            .insert(app.clone(), Data::empty());
        if let Some(v) = prev_ver {
            prev_spell.versioned_apps.insert(app.vk.clone(), v);
        }

        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![prev_utxo.clone()]);
        spell.tx.outs = vec![];
        if reference_in_spending {
            spell.app_public_inputs.insert(app.clone(), Data::empty());
        }
        if let Some(v) = cur_ver {
            spell.versioned_apps.insert(app.vk.clone(), v);
        }

        let mut prev_spells = BTreeMap::new();
        prev_spells.insert(prev_tx_id, (prev_spell, 1usize));
        (spell, prev_spells)
    }

    fn versioned(version: u32, hash_hex: &str) -> VersionedApp {
        VersionedApp {
            version,
            wasm_hash: b32(hash_hex),
        }
    }

    /// Build the resolved `Transaction` for a fixture so we can sanity-check
    /// `is_simple_transfer` in tests.
    fn build_tx(
        spell: &NormalizedSpell,
        prev_spells: &BTreeMap<TxId, (NormalizedSpell, usize)>,
    ) -> Transaction {
        to_tx(spell, prev_spells, &BTreeMap::new(), &[])
    }

    fn an_app() -> App {
        App::from_str(
            "t/2222222222222222222222222222222222222222222222222222222222222222/\
             3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap()
    }

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn continuity_same_version_same_hash_ok() {
        let app = an_app();
        let (spell, prev_spells) = build_continuity_fixture(
            app,
            Some(versioned(3, HASH_A)),
            Some(versioned(3, HASH_A)),
            true,
        );
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn continuity_same_version_different_hash_rejected() {
        let app = an_app();
        let (spell, prev_spells) = build_continuity_fixture(
            app,
            Some(versioned(3, HASH_A)),
            Some(versioned(3, HASH_B)),
            true,
        );
        let err = check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("Wasm hashes differ"), "got: {err}");
    }

    #[test]
    fn continuity_higher_version_ok() {
        let app = an_app();
        let (spell, prev_spells) = build_continuity_fixture(
            app,
            Some(versioned(3, HASH_A)),
            Some(versioned(7, HASH_B)),
            true,
        );
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn continuity_lower_version_rejected() {
        let app = an_app();
        let (spell, prev_spells) = build_continuity_fixture(
            app,
            Some(versioned(7, HASH_A)),
            Some(versioned(3, HASH_B)),
            true,
        );
        let err = check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be 0, equal to, or higher"), "got: {err}");
    }

    #[test]
    fn continuity_drop_to_zero_from_positive_ok() {
        let app = an_app();
        let (spell, prev_spells) = build_continuity_fixture(
            app,
            Some(versioned(5, HASH_A)),
            Some(versioned(0, HASH_B)),
            true,
        );
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn continuity_zero_to_nonzero_rejected() {
        let app = an_app();
        let (spell, prev_spells) = build_continuity_fixture(
            app,
            Some(versioned(0, HASH_A)),
            Some(versioned(1, HASH_A)),
            true,
        );
        let err = check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("spent version is 0"), "got: {err}");
    }

    #[test]
    fn continuity_zero_to_zero_same_hash_ok() {
        let app = an_app();
        let (spell, prev_spells) = build_continuity_fixture(
            app,
            Some(versioned(0, HASH_A)),
            Some(versioned(0, HASH_A)),
            true,
        );
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn continuity_zero_to_zero_different_hash_rejected() {
        let app = an_app();
        let (spell, prev_spells) = build_continuity_fixture(
            app,
            Some(versioned(0, HASH_A)),
            Some(versioned(0, HASH_B)),
            true,
        );
        let err = check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("Wasm hashes differ"), "got: {err}");
    }

    #[test]
    fn continuity_versioned_in_prev_missing_in_spending_rejected() {
        let app = an_app();
        let (spell, prev_spells) =
            build_continuity_fixture(app, Some(versioned(3, HASH_A)), None, true);
        let err = check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not declare it in `versioned_apps`"),
            "got: {err}"
        );
    }

    #[test]
    fn continuity_skipped_when_spending_does_not_reference_vk() {
        let app = an_app();
        // Prev declares versioned, spending doesn't reference the app at all (e.g. burn).
        let (spell, prev_spells) =
            build_continuity_fixture(app, Some(versioned(3, HASH_A)), None, false);
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn continuity_retro_versionizing_simple_app_rejected() {
        let app = an_app();
        // Prev treats it as a simple app (no `versioned_apps` entry). The spending
        // spell tries to retroactively declare it versioned: rejected, because the
        // simple-transfer path would otherwise accept arbitrary `(version, wasm_hash)`
        // without anyone ever signing it.
        let (spell, prev_spells) =
            build_continuity_fixture(app, None, Some(versioned(2, HASH_A)), true);
        let err = check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot retroactively declare it versioned"),
            "got: {err}"
        );
    }

    #[test]
    fn continuity_simple_app_stays_simple_ok() {
        let app = an_app();
        // Both prev and current treat the app as simple. Continuity has nothing to
        // enforce; the function is a no-op for this vk.
        let (spell, prev_spells) = build_continuity_fixture(app, None, None, true);
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    fn an_nft_app() -> App {
        App::from_str(
            "n/4444444444444444444444444444444444444444444444444444444444444444/\
             5555555555555555555555555555555555555555555555555555555555555555",
        )
        .unwrap()
    }

    /// Build a spell pair where the prev spell has an NFT charm and the spending spell
    /// mirrors it in its output (a "simple transfer"). Both sides may carry an optional
    /// versioned-app entry for the NFT vk.
    fn build_simple_nft_transfer_fixture(
        app: App,
        prev_ver: Option<VersionedApp>,
        cur_ver: Option<VersionedApp>,
    ) -> (NormalizedSpell, BTreeMap<TxId, (NormalizedSpell, usize)>) {
        let prev_tx_id = TxId::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let prev_utxo = UtxoId(prev_tx_id, 0);

        let mut prev_spell = NormalizedSpell::default();
        prev_spell.tx.ins = Some(vec![]);
        prev_spell.tx.refs = Some(vec![]);
        prev_spell.tx.outs = vec![{
            let mut c = NormalizedCharms::new();
            c.insert(0, Data::empty());
            c
        }];
        prev_spell.tx.coins.get_or_insert_with(Vec::new).push(NativeOutput {
            amount: 0,
            dest: vec![],
            content: None,
        });
        prev_spell.app_public_inputs.insert(app.clone(), Data::empty());
        if let Some(v) = prev_ver {
            prev_spell.versioned_apps.insert(app.vk.clone(), v);
        }

        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![prev_utxo]);
        spell.tx.outs = vec![{
            let mut c = NormalizedCharms::new();
            c.insert(0, Data::empty()); // mirror the input NFT state -> simple transfer
            c
        }];
        spell.app_public_inputs.insert(app.clone(), Data::empty());
        if let Some(v) = cur_ver {
            spell.versioned_apps.insert(app.vk.clone(), v);
        }

        let mut prev_spells = BTreeMap::new();
        prev_spells.insert(prev_tx_id, (prev_spell, 1usize));
        (spell, prev_spells)
    }

    #[test]
    fn simple_transfer_version_unchanged_ok() {
        let app = an_nft_app();
        let (spell, prev_spells) = build_simple_nft_transfer_fixture(
            app.clone(),
            Some(versioned(3, HASH_A)),
            Some(versioned(3, HASH_A)),
        );
        let tx = build_tx(&spell, &prev_spells);
        // Sanity: this really is a simple transfer.
        assert!(is_simple_transfer(&app, &tx));
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn simple_transfer_version_bump_allowed_in_continuity() {
        let app = an_nft_app();
        // Continuity no longer rejects version bumps in a simple transfer (rule 4 was
        // dropped). The binary-present + must-run requirement now lives in `is_correct`.
        let (spell, prev_spells) = build_simple_nft_transfer_fixture(
            app.clone(),
            Some(versioned(3, HASH_A)),
            Some(versioned(4, HASH_B)),
        );
        let tx = build_tx(&spell, &prev_spells);
        assert!(is_simple_transfer(&app, &tx));
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn simple_transfer_drop_to_zero_allowed_in_continuity() {
        let app = an_nft_app();
        // Continuity allows drop-to-0 even for simple transfers (rule 2). Authorization
        // of the version change is enforced in `is_correct`, not here.
        let (spell, prev_spells) = build_simple_nft_transfer_fixture(
            app.clone(),
            Some(versioned(5, HASH_A)),
            Some(versioned(0, HASH_B)),
        );
        let tx = build_tx(&spell, &prev_spells);
        assert!(is_simple_transfer(&app, &tx));
        check_app_version_continuity(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn collect_version_changed_apps_detects_bump() {
        let app = an_nft_app();
        let (spell, prev_spells) = build_simple_nft_transfer_fixture(
            app.clone(),
            Some(versioned(3, HASH_A)),
            Some(versioned(4, HASH_B)),
        );
        let changed = collect_version_changed_apps(&spell, &prev_spells, &BTreeMap::new());
        assert!(changed.contains(&app));
    }

    #[test]
    fn collect_version_changed_apps_unchanged_is_empty() {
        let app = an_nft_app();
        let (spell, prev_spells) = build_simple_nft_transfer_fixture(
            app,
            Some(versioned(3, HASH_A)),
            Some(versioned(3, HASH_A)),
        );
        let changed = collect_version_changed_apps(&spell, &prev_spells, &BTreeMap::new());
        assert!(changed.is_empty());
    }

    fn app_input_with(
        binaries: BTreeMap<B32, Vec<u8>>,
        private_inputs: BTreeMap<App, Data>,
    ) -> charms_data::AppInput {
        charms_data::AppInput {
            app_binaries: binaries,
            app_private_inputs: private_inputs,
            app_signatures: BTreeMap::new(),
        }
    }

    #[test]
    fn authorize_version_changes_no_changes_ok_in_either_branch() {
        // Empty change set is always OK, regardless of whether app_input is provided.
        let spell = NormalizedSpell::default();
        let empty: BTreeSet<App> = BTreeSet::new();
        authorize_version_changes(&spell, &empty, None).unwrap();
        let input = app_input_with(BTreeMap::new(), BTreeMap::new());
        authorize_version_changes(&spell, &empty, Some(&input)).unwrap();
    }

    #[test]
    fn authorize_version_changes_without_app_input_rejected() {
        let app = an_nft_app();
        let (spell, _prev_spells) = build_simple_nft_transfer_fixture(
            app.clone(),
            Some(versioned(3, HASH_A)),
            Some(versioned(4, HASH_B)),
        );
        let mut changed = BTreeSet::new();
        changed.insert(app);
        let err = authorize_version_changes(&spell, &changed, None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no app binaries provided"),
            "got: {err}"
        );
        assert!(
            err.contains("A version change requires running the new app binary"),
            "got: {err}"
        );
    }

    #[test]
    fn authorize_version_changes_without_new_binary_rejected() {
        let app = an_nft_app();
        let (spell, _prev_spells) = build_simple_nft_transfer_fixture(
            app.clone(),
            Some(versioned(3, HASH_A)),
            Some(versioned(4, HASH_B)),
        );
        let mut changed = BTreeSet::new();
        changed.insert(app);
        // app_input is provided but lacks the new wasm binary (HASH_B).
        let input = app_input_with(BTreeMap::new(), BTreeMap::new());
        let err = authorize_version_changes(&spell, &changed, Some(&input))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("its new binary (wasm_hash")
                && err.contains(HASH_B)
                && err.contains("must be"),
            "got: {err}"
        );
    }

    #[test]
    fn authorize_version_changes_with_new_binary_ok() {
        let app = an_nft_app();
        let (spell, _prev_spells) = build_simple_nft_transfer_fixture(
            app.clone(),
            Some(versioned(3, HASH_A)),
            Some(versioned(4, HASH_B)),
        );
        let mut changed = BTreeSet::new();
        changed.insert(app);
        let mut binaries = BTreeMap::new();
        binaries.insert(b32(HASH_B), b"any-bytes".to_vec());
        let input = app_input_with(binaries, BTreeMap::new());
        authorize_version_changes(&spell, &changed, Some(&input)).unwrap();
    }

    #[test]
    fn input_apps_referenced_ok_when_listed() {
        let app = an_app();
        // Prev output 0 carries a charm for `app`; spending spell references `app`.
        let (spell, prev_spells) = build_continuity_fixture(app, None, None, true);
        check_input_apps_are_referenced(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    #[test]
    fn input_apps_referenced_burn_without_reference_rejected() {
        let app = an_app();
        // Prev output 0 carries a charm for `app`; spending spell omits it entirely
        // (the soundness-bug scenario: attempting to burn without authorizing the app).
        let (spell, prev_spells) = build_continuity_fixture(app, None, None, false);
        let err = check_input_apps_are_referenced(&spell, &prev_spells, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not list it in `app_public_inputs`"),
            "got: {err}"
        );
    }

    #[test]
    fn input_apps_referenced_no_input_charms_ok() {
        // Input UTXO has no charms attached -> nothing to require.
        let prev_tx_id = TxId::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let prev_utxo = UtxoId(prev_tx_id, 0);

        let mut prev_spell = NormalizedSpell::default();
        prev_spell.tx.ins = Some(vec![]);
        prev_spell.tx.refs = Some(vec![]);
        prev_spell.tx.outs = vec![NormalizedCharms::new()]; // empty charms
        prev_spell.tx.coins.get_or_insert_with(Vec::new).push(NativeOutput {
            amount: 0,
            dest: vec![],
            content: None,
        });

        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![prev_utxo]);
        spell.tx.outs = vec![];

        let mut prev_spells = BTreeMap::new();
        prev_spells.insert(prev_tx_id, (prev_spell, 1usize));
        check_input_apps_are_referenced(&spell, &prev_spells, &BTreeMap::new()).unwrap();
    }

    fn prev_spell_with_versioned(vk: &B32, va: VersionedApp) -> NormalizedSpell {
        let mut s = NormalizedSpell::default();
        s.tx.ins = Some(vec![]);
        s.tx.outs = vec![];
        s.versioned_apps.insert(vk.clone(), va);
        s
    }

    #[test]
    fn prev_versioned_apps_consistent_same_hash_ok() {
        let app = an_app();
        let tx1 = TxId::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let tx2 = TxId::from_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let mut prev_spells = BTreeMap::new();
        prev_spells.insert(
            tx1,
            (prev_spell_with_versioned(&app.vk, versioned(3, HASH_A)), 1),
        );
        prev_spells.insert(
            tx2,
            (prev_spell_with_versioned(&app.vk, versioned(3, HASH_A)), 1),
        );
        check_prev_versioned_apps_consistency(&prev_spells).unwrap();
    }

    #[test]
    fn prev_versioned_apps_different_hash_same_version_rejected() {
        let app = an_app();
        let tx1 = TxId::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let tx2 = TxId::from_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let mut prev_spells = BTreeMap::new();
        prev_spells.insert(
            tx1,
            (prev_spell_with_versioned(&app.vk, versioned(3, HASH_A)), 1),
        );
        prev_spells.insert(
            tx2,
            (prev_spell_with_versioned(&app.vk, versioned(3, HASH_B)), 1),
        );
        let err = check_prev_versioned_apps_consistency(&prev_spells)
            .unwrap_err()
            .to_string();
        assert!(err.contains("inconsistent Wasm hash"), "got: {err}");
    }

    #[test]
    fn prev_versioned_apps_different_versions_ok() {
        // Same vk, different versions, different hashes — fine, they're different versions.
        let app = an_app();
        let tx1 = TxId::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let tx2 = TxId::from_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let mut prev_spells = BTreeMap::new();
        prev_spells.insert(
            tx1,
            (prev_spell_with_versioned(&app.vk, versioned(3, HASH_A)), 1),
        );
        prev_spells.insert(
            tx2,
            (prev_spell_with_versioned(&app.vk, versioned(4, HASH_B)), 1),
        );
        check_prev_versioned_apps_consistency(&prev_spells).unwrap();
    }

    #[test]
    fn orphan_versioned_apps_rejected() {
        // versioned_apps lists a vk that doesn't appear in any app in app_public_inputs.
        // This must be rejected by `is_correct` (and so by the zkVM proof), not just by
        // the host-side validator.
        let app = an_app();
        let other_vk = b32(
            "9999999999999999999999999999999999999999999999999999999999999999",
        );
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![]);
        spell.tx.outs = vec![];
        spell.app_public_inputs.insert(app, Data::empty());
        spell
            .versioned_apps
            .insert(other_vk.clone(), versioned(1, HASH_A));
        let err = ensure_no_orphan_versioned_apps(&spell)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unused vk"), "got: {err}");
        assert!(err.contains(&other_vk.to_string()), "got: {err}");
    }

    #[test]
    fn no_orphan_when_vk_is_referenced() {
        let app = an_app();
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![]);
        spell.tx.outs = vec![];
        spell.app_public_inputs.insert(app.clone(), Data::empty());
        spell
            .versioned_apps
            .insert(app.vk.clone(), versioned(1, HASH_A));
        ensure_no_orphan_versioned_apps(&spell).unwrap();
    }

    #[test]
    fn decode_cbor() {
        let s = "a36776657273696f6e0c627478a363696e73825824769119fa89a524c08a7cc0998e9d911eb92151832daa3f7ddae68490860c8f570000000058247863c61916d5787e1e2dd2ef8e3e10bdbb6fa98f8a08b49ed0c6381af383146b03000000646f75747381a2011b00000005d21dba0000a7656d616b6572782a626331716a38766c3665347a356d74396c367365787238683438396e326b3933707674347937686c6d3769657865635f74797065a1677061727469616ca064736964656361736b657072696365821901a31a05f5e10066616d6f756e741a0001992e687175616e746974791b00000005d21dba00656173736574a165746f6b656e7883742f336437666537653463656136313231393437616637336437306535313139626562643861613562376564666537346266616636653737396131383437626439622f6339373564346530633239326662393565666264613563313333313264366163316438623561656666376630663165353537383634356132646137306666356665636f696e7381a266616d6f756e7419022264646573749600140d18b018490b183c0c181918a61854189d184d18fb188e18a518ca101880188c184318cb716170705f7075626c69635f696e70757473a283616298200000000000000000000000000000000000000000000000000000000000000000982018a4187118d318fc18c4183618ae187c18bc0e0c188218a6188c18dc188e00183e18e2181e18f8181918e118ac18f8183418e1181c184318ce184718d8f68361749820183d187f18e718e418ce18a6121819184718af187318d70e1851181918be18bd188a18a518b718ed18fe187418bf18af186e1877189a1818184718bd189b982018c9187518d418e018c2189218fb189518ef18bd18a518c118331218d618ac181d188b185a18ef18f718f018f118e518571886184518a218da187018ff185ff6";
        let ns: NormalizedSpell = util::read(hex::decode(s).unwrap().as_slice()).unwrap();
        dbg!(ns);
    }

    #[proptest]
    fn beaming_source_json_parse_with_nonce(utxo_id: UtxoId, nonce: u64) {
        let s0 = format!(r#"["{}",{}]"#, utxo_id, nonce);
        let bs: BeamSource = serde_json::from_str(&s0).unwrap();
        let s1 = serde_json::to_string(&bs).unwrap();
        assert_eq!(s1, s0);
    }

    #[proptest]
    fn beaming_source_json_parse_no_nonce(utxo_id: UtxoId) {
        let s0 = format!(r#"["{}"]"#, utxo_id);
        let bs: BeamSource = serde_json::from_str(&s0).unwrap();
        let s1 = serde_json::to_string(&bs).unwrap();
        assert_eq!(s1, s0);
    }

    #[proptest]
    fn beaming_source_json_print(bs0: BeamSource) {
        let s = serde_json::to_string(&bs0).unwrap();
        let bs1: BeamSource = serde_json::from_str(&s).unwrap();
        assert_eq!(bs1, bs0);
    }

    /// Build a minimal Bitcoin-shaped spell with `scrolls = {1}`, coin at index 1
    /// carrying `dest_hex` as a hex-decoded scriptPubKey.
    fn spell_with_scroll_output_at(dest_hex: &str) -> NormalizedSpell {
        let mut spell = NormalizedSpell::default();
        let mut scrolls = BTreeSet::new();
        scrolls.insert(1u32);
        spell.tx.scrolls = Some(scrolls);
        spell.tx.coins = Some(vec![
            NativeOutput {
                amount: 0,
                dest: vec![],
                content: None,
            },
            NativeOutput {
                amount: 0,
                dest: hex::decode(dest_hex).unwrap(),
                content: None,
            },
        ]);
        spell
    }

    fn signed_scrolls_for(index: u32, spk_hex: &str) -> SignedScrollOutputs {
        let mut script_pubkeys = BTreeMap::new();
        script_pubkeys.insert(index, spk_hex.to_string());
        SignedScrollOutputs {
            script_pubkeys,
            // Signature isn't validated here — these tests cover the structural
            // checks that run *before* `verify_scroll_outputs_signature`.
            signature: "00".repeat(64),
        }
    }

    /// Sample P2WPKH scriptPubKey: `OP_0 <20-byte hash>` (24 hex chars after the
    /// `0014` prefix). Any 20-byte payload works for these structural checks.
    const SAMPLE_P2WPKH_SPK: &str = "0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_P2WPKH_SPK: &str = "0014bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn check_scroll_outputs_returns_true_when_no_scrolls() {
        // Empty / absent `tx.scrolls` means there's nothing to check; the function
        // returns `Ok(true)` even without a signed map.
        let mut spell = NormalizedSpell::default();
        spell.tx.coins = Some(vec![]);
        assert!(check_scroll_outputs(&spell, None).unwrap());
        spell.tx.scrolls = Some(BTreeSet::new());
        assert!(check_scroll_outputs(&spell, None).unwrap());
    }

    #[test]
    fn check_scroll_outputs_returns_false_when_signed_map_absent() {
        // Client preflight: spell declares Scrolls outputs but the prover server
        // hasn't filled in the signed `scriptPubKey` map yet. Function returns
        // `Ok(false)` rather than bailing -- host-side callers tolerate.
        let spell = spell_with_scroll_output_at(SAMPLE_P2WPKH_SPK);
        assert!(!check_scroll_outputs(&spell, None).unwrap());
    }

    #[test]
    fn check_scroll_outputs_rejects_signed_keys_mismatch() {
        let spell = spell_with_scroll_output_at(SAMPLE_P2WPKH_SPK);
        // Signed map declares output #2, but the spell's `tx.scrolls` is {1}.
        let signed = signed_scrolls_for(2, SAMPLE_P2WPKH_SPK);
        let err = check_scroll_outputs(&spell, Some(&signed))
            .unwrap_err()
            .to_string();
        assert!(err.contains("do not match `tx.scrolls`"), "got: {err}");
    }

    #[test]
    fn check_scroll_outputs_rejects_spk_mismatch_with_dest() {
        // Signed scriptPubKey is `OTHER_P2WPKH_SPK`, but the spell's
        // `coins[1].dest` was filled with `SAMPLE_P2WPKH_SPK`.
        let spell = spell_with_scroll_output_at(SAMPLE_P2WPKH_SPK);
        let signed = signed_scrolls_for(1, OTHER_P2WPKH_SPK);
        let err = check_scroll_outputs(&spell, Some(&signed))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not match `tx.coins[1].dest`"),
            "got: {err}"
        );
    }

    #[test]
    fn scroll_outputs_listed_rejects_out_of_range_index() {
        // `tx.outs` has 1 entry (index 0 only), but `tx.scrolls` claims index 1.
        let mut spell = NormalizedSpell::default();
        spell.tx.outs = vec![NormalizedCharms::new()];
        let mut scrolls = BTreeSet::new();
        scrolls.insert(1u32);
        spell.tx.scrolls = Some(scrolls);
        let err = check_scroll_outputs_are_listed(&spell)
            .unwrap_err()
            .to_string();
        assert!(err.contains("references output #1"), "got: {err}");
        assert!(err.contains("only has 1 output"), "got: {err}");
    }

    #[test]
    fn scroll_outputs_listed_accepts_in_range_non_scroll_index() {
        // An output index can be declared in `tx.scrolls` even when it carries no
        // SCROLL charm (the canister signature is the practical gatekeeper on Bitcoin
        // -- see the reply to greptile on PR #192).
        let mut spell = NormalizedSpell::default();
        spell.tx.outs = vec![NormalizedCharms::new(), NormalizedCharms::new()];
        let mut scrolls = BTreeSet::new();
        scrolls.insert(1u32);
        spell.tx.scrolls = Some(scrolls);
        check_scroll_outputs_are_listed(&spell).unwrap();
    }

    /// Compact-format Bitcoin tx hex (no spell). Reused from `tx::tests::ser_to_json`
    /// so the test doesn't drag in a separate fixture.
    const SAMPLE_BTC_TX_HEX: &str = "0200000000010115ccf0534b7969e5ac0f4699e51bf7805168244057059caa333397fcf8a9acdd0000000000fdffffff027a6faf85150000001600147b458433d0c04323426ef88365bd4cfef141ac7520a107000000000022512087a397fc19d816b6f938dad182a54c778d2d5db8b31f4528a758b989d42f0b78024730440220072d64b2e3bbcd27bd79cb8859c83ca524dad60dc6310569c2a04c997d116381022071d4df703d037a9fe16ccb1a2b8061f10cda86ccbb330a49c5dcc95197436c960121030db9616d96a7b7a8656191b340f77e905ee2885a09a7a1e80b9c8b64ec746fb300000000";
    const SAMPLE_CARDANO_TX_HEX: &str = "84a400d901028182582011a2338987035057f6c36286cf5aadc02573059b2cde9790017eb4e148f0c67a0001828258390174f84e13070bb755eaa01cb717da8c7450daf379948e979f6de99d26ba89ff199fde572546b9a044eb129ad2edb184bd79cde63ab4b47aec1a01312d008258390184f1c3b1fff5241088acc4ce0aec81f45a71a70e35c94e30a70b7cdfeb0785cdec744029db6b4f344b1123497c9cabfeeb94af20fcfddfe01a33e578fd021a000299e90758201e8eb8575d879922d701c12daa7366cb71b6518a9500e083a966a8e66b56ed23a10081825820ea444825bbd5cc97b6c795437849fe55694b52e2f51485ac76ca2d9f991e83305840d59db4fa0b4bb233504f5e6826261a2e18b2e22cb3df4f631ab77d94d62e8df3200536271f3f3a625bc86919714972964f070f909f145b342f2889f58ccc210ff5a11902a2a1636d736765546f6b656f";

    #[test]
    fn hosting_chain_follows_first_input_not_any_prev_tx() {
        use crate::tx::EnchantedTx;

        let btc_tx = Tx::try_from(SAMPLE_BTC_TX_HEX).unwrap();
        let cardano_tx = Tx::try_from(SAMPLE_CARDANO_TX_HEX).unwrap();
        let btc_txid = btc_tx.tx_id();
        let cardano_txid = cardano_tx.tx_id();

        // Spell's first input points at the *Cardano* tx -> hosting chain is Cardano,
        // even though a Bitcoin tx is also present in `prev_txs` (as it would be for
        // a Cardano spell beaming charms in from a Bitcoin source).
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![UtxoId(cardano_txid, 0)]);
        let prev_txs = vec![cardano_tx.clone(), btc_tx.clone()];
        assert!(!hosting_chain_is_bitcoin(&spell, &prev_txs));

        // Mirror image: first input points at the Bitcoin tx -> Bitcoin host.
        spell.tx.ins = Some(vec![UtxoId(btc_txid, 0)]);
        assert!(hosting_chain_is_bitcoin(&spell, &prev_txs));
    }
}
