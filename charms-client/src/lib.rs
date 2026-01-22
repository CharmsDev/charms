use crate::tx::{EnchantedTx, Tx, by_txid, extended_normalized_spell};
use anyhow::{anyhow, ensure};
use charms_app_runner::AppRunner;
use charms_data::{
    App, AppInput, B32, Charms, Data, NativeOutput, TOKEN, Transaction, TxId, UtxoId, check,
    is_simple_transfer,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub mod ark;
pub mod bitcoin_tx;
pub mod cardano_tx;
pub mod tx;

pub const MOCK_SPELL_VK: &str = "7c38e8639a2eac0074cee920982b92376513e8940f4a7ca6859f17a728af5b0e";

/// Verification key for version `0` of the protocol implemented by `charms-spell-checker` binary.
pub const V0_SPELL_VK: &str = "0x00e9398ac819e6dd281f81db3ada3fe5159c3cc40222b5ddb0e7584ed2327c5d";
/// Verification key for version `1` of the protocol implemented by `charms-spell-checker` binary.
pub const V1_SPELL_VK: &str = "0x009f38f590ebca4c08c1e97b4064f39e4cd336eea4069669c5f5170a38a1ff97";
/// Verification key for version `2` of the protocol implemented by `charms-spell-checker` binary.
pub const V2_SPELL_VK: &str = "0x00bd312b6026dbe4a2c16da1e8118d4fea31587a4b572b63155252d2daf69280";
/// Verification key for version `3` of the protocol implemented by `charms-spell-checker` binary.
pub const V3_SPELL_VK: &str = "0x0034872b5af38c95fe82fada696b09a448f7ab0928273b7ac8c58ba29db774b9";
/// Verification key for version `4` of the protocol implemented by `charms-spell-checker` binary.
pub const V4_SPELL_VK: &str = "0x00c707a155bf8dc18dc41db2994c214e93e906a3e97b4581db4345b3edd837c5";
/// Verification key for version `5` of the protocol implemented by `charms-spell-checker` binary.
pub const V5_SPELL_VK: &str = "0x00e98665c417bd2e6e81c449af63b26ed5ad5c400ef55811b592450bf62c67cd";
/// Verification key for version `6` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V6_SPELL_VK: &str = "0x005a1df17094445572e4dd474b3e5dd9093936cba62ca3a62bb2ce63d9db8cba";
/// Verification key for version `7` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V7_SPELL_VK: &str = "0x0041d9843ec25ba04797a0ce29af364389f7eda9f7126ef39390c357432ad9aa";
/// Verification key for version `8` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V8_SPELL_VK: &str = "0x00e440d40e331c16bc4c78d2dbc6bb35876e6ea944e943de359a075e07385abc";
/// Verification key for version `9` of the protocol implemented by `charms-proof-wrapper` binary.
pub const V9_SPELL_VK: &str = "0x00713f077ec2bd68157512835dc678053565a889935ecd5789ce2fa097c93ee9";

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

/// Current version of the protocol.
pub const CURRENT_VERSION: u32 = V10;

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
    pub app_public_inputs: BTreeMap<App, Data>,
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
            mock: false,
        }
    }
}

pub fn utxo_id_hash(utxo_id: &UtxoId) -> B32 {
    let hash = Sha256::digest(utxo_id.to_bytes());
    B32(hash.into())
}

/// Extract spells from previous transactions.
#[tracing::instrument(level = "debug", skip(prev_txs, spell_vk))]
pub fn prev_spells(
    prev_txs: &[Tx],
    spell_vk: &str,
    mock: bool,
) -> BTreeMap<TxId, (NormalizedSpell, usize)> {
    prev_txs
        .iter()
        .map(|tx| {
            (
                tx.tx_id(),
                (
                    extended_normalized_spell(spell_vk, tx, mock),
                    tx.tx_outs_len(),
                ),
            )
        })
        .collect()
}

/// Check if the spell is well-formed.
#[tracing::instrument(level = "debug", skip(spell, prev_spells))]
pub fn well_formed(
    spell: &NormalizedSpell,
    prev_spells: &BTreeMap<TxId, (NormalizedSpell, usize)>,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, UtxoId>,
) -> bool {
    check!(spell.version == CURRENT_VERSION);
    check!(ensure_no_zero_amounts(spell).is_ok());
    let directly_created_by_prev_txns = |utxo_id: &UtxoId| -> bool {
        let tx_id = utxo_id.0;
        prev_spells
            .get(&tx_id)
            .is_some_and(|(n_spell, num_tx_outs)| {
                let utxo_index = utxo_id.1;

                let is_beamed_out = (n_spell.tx.beamed_outs.as_ref())
                    .and_then(|beamed_outs| beamed_outs.get(&utxo_index))
                    .is_some();

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
        .all(|(&i, beaming_source_utxo_id)| {
            let tx_in_utxo_id = &tx_ins[i];
            let prev_txid = tx_in_utxo_id.0;
            let prev_tx = prev_spells.get(&prev_txid);
            let Some((prev_spell, _tx_outs)) = prev_tx else {
                // prev_tx should be provided, so we know it doesn't carry a spell
                return false;
            };
            // tx_in_utxo must exist but not have any Charms
            check!(
                (prev_spell.tx.outs)
                    .get(tx_in_utxo_id.1 as usize)
                    .is_none_or(|charms| charms.is_empty())
            );

            let beaming_txid = beaming_source_utxo_id.0;
            let beaming_utxo_index = beaming_source_utxo_id.1;

            prev_spells
                .get(&beaming_txid)
                .and_then(|(n_spell, _tx_outs)| {
                    (n_spell.tx.beamed_outs.as_ref())
                        .and_then(|beamed_outs| beamed_outs.get(&beaming_utxo_index))
                })
                .is_some_and(|dest_utxo_hash| dest_utxo_hash == &utxo_id_hash(tx_in_utxo_id))
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
    tx_ins_beamed_source_utxos: &BTreeMap<usize, UtxoId>,
    prev_txs: &[Tx],
) -> Transaction {
    let Some(tx_ins) = &spell.tx.ins else {
        unreachable!("self.tx.ins MUST be Some at this point");
    };

    let tx_ins_beamed_source_utxos: BTreeMap<UtxoId, UtxoId> = tx_ins_beamed_source_utxos
        .iter()
        .map(|(&i, utxo_id)| (tx_ins[i].clone(), utxo_id.clone()))
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

fn charms_in_utxo(prev_spell: &NormalizedSpell, utxo_id: &UtxoId) -> Option<Charms> {
    (prev_spell.tx.outs)
        .get(utxo_id.1 as usize)
        .map(|n_charms| charms(prev_spell, n_charms))
}

/// Return [`charms_data::Charms`] for the given [`NormalizedCharms`].
pub fn charms(spell: &NormalizedSpell, n_charms: &NormalizedCharms) -> Charms {
    let apps = apps(spell);
    n_charms
        .iter()
        .map(|(&i, data)| (apps[i as usize].clone(), data.clone()))
        .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpellProverInput {
    pub self_spell_vk: String,
    pub prev_txs: Vec<Tx>,
    pub spell: NormalizedSpell,
    pub tx_ins_beamed_source_utxos: BTreeMap<usize, UtxoId>,
    pub app_input: Option<AppInput>,
}

/// Check if the spell is correct.
pub fn is_correct(
    spell: &NormalizedSpell,
    prev_txs: &Vec<Tx>,
    app_input: Option<AppInput>,
    spell_vk: &str,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, UtxoId>,
) -> bool {
    check!(beaming_txs_have_finality_proofs(
        prev_txs,
        tx_ins_beamed_source_utxos
    ));

    let prev_spells = prev_spells(&prev_txs, spell_vk, spell.mock);

    check!(well_formed(spell, &prev_spells, tx_ins_beamed_source_utxos));

    let Some(prev_txids) = spell.tx.prev_txids() else {
        unreachable!("the spell is well formed: tx.ins MUST be Some");
    };
    let all_prev_txids: BTreeSet<_> = tx_ins_beamed_source_utxos
        .values()
        .map(|u| &u.0)
        .chain(prev_txids)
        .collect();
    check!(all_prev_txids == prev_spells.keys().collect());

    let apps = apps(spell);

    let charms_tx = to_tx(spell, &prev_spells, tx_ins_beamed_source_utxos, &prev_txs);
    let tx_is_simple_transfer_or_app_contracts_satisfied =
        apps.iter().all(|app| is_simple_transfer(app, &charms_tx)) && app_input.is_none()
            || app_input.is_some_and(|app_input| {
                apps_satisfied(&app_input, &spell.app_public_inputs, &charms_tx)
            });
    check!(tx_is_simple_transfer_or_app_contracts_satisfied);

    true
}

fn beaming_txs_have_finality_proofs(
    prev_txs: &Vec<Tx>,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, UtxoId>,
) -> bool {
    let prev_txs_by_txid: BTreeMap<TxId, Tx> = by_txid(prev_txs);
    let beaming_source_txids: BTreeSet<&TxId> = tx_ins_beamed_source_utxos
        .values()
        .map(|u| &u.0)
        .collect::<BTreeSet<_>>();
    beaming_source_txids.iter().all(|&txid| {
        prev_txs_by_txid
            .get(txid)
            .is_some_and(|tx| tx.proven_final())
    })
}

fn apps_satisfied(
    app_input: &AppInput,
    app_public_inputs: &BTreeMap<App, Data>,
    tx: &Transaction,
) -> bool {
    let app_runner = AppRunner::new(false);
    app_runner
        .run_all(
            &app_input.app_binaries,
            &tx,
            app_public_inputs,
            &app_input.app_private_inputs,
        )
        .expect("all apps should run successfully");
    true
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

#[cfg(test)]
mod test {
    #[test]
    fn dummy() {}
}
