use crate::spell::Spell;
use charms_client::{
    NormalizedSpell,
    tx::{EnchantedTx, Tx},
};
use charms_data::TxId;
use charms_lib::SPELL_VK;
use std::collections::BTreeMap;

pub mod bitcoin_tx;
pub mod cardano_tx;

#[tracing::instrument(level = "debug", skip_all)]
pub fn norm_spell(tx: &Tx, mock: bool) -> Option<NormalizedSpell> {
    charms_client::tx::committed_normalized_spell(SPELL_VK, tx, mock)
        .map_err(|e| {
            tracing::debug!("spell verification failed: {:?}", e);
            e
        })
        .ok()
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn spell(tx: &Tx, mock: bool) -> anyhow::Result<Option<Spell>> {
    match norm_spell(tx, mock) {
        Some(norm_spell) => Ok(Some(Spell::denormalized(&norm_spell)?)),
        None => Ok(None),
    }
}

pub fn txs_by_txid(prev_txs: &[Tx]) -> BTreeMap<TxId, Tx> {
    prev_txs
        .iter()
        .map(|prev_tx| (prev_tx.tx_id(), prev_tx.clone()))
        .collect::<BTreeMap<_, _>>()
}
