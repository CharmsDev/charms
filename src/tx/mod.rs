use crate::spell::SpellInput;
use charms_client::{NormalizedSpell, tx::Tx};
use charms_lib::SPELL_VK;

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
pub fn spell(tx: &Tx, mock: bool) -> Option<SpellInput> {
    norm_spell(tx, mock).map(|ns| SpellInput::from_normalized_spell(&ns))
}
