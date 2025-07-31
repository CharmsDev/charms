pub mod app;
pub mod spell_checker;

use crate::app::to_public_values;
use charms_client::{tx::Tx, AppProverOutput, NormalizedSpell, APP_VK};
use charms_data::{check, is_simple_transfer, UtxoId};
use serde::Serialize;
use sp1_zkvm::lib::verify::verify_sp1_proof;
use std::collections::{BTreeMap, BTreeSet};

/// Check if the spell is correct.
pub(crate) fn is_correct(
    spell: &NormalizedSpell,
    prev_txs: &Vec<Tx>,
    app_prover_output: Option<AppProverOutput>,
    spell_vk: &String,
    tx_ins_beamed_source_utxos: &BTreeMap<UtxoId, UtxoId>,
) -> bool {
    let prev_spells = charms_client::prev_spells(prev_txs, spell_vk);

    check!(charms_client::well_formed(
        spell,
        &prev_spells,
        tx_ins_beamed_source_utxos
    ));

    let Some(prev_txids) = spell.tx.prev_txids() else {
        unreachable!("the spell is well formed: tx.ins MUST be Some");
    };
    let all_prev_txids: BTreeSet<_> = tx_ins_beamed_source_utxos
        .values()
        .map(|u| &u.0)
        .chain(prev_txids)
        .collect();
    check!(all_prev_txids == prev_spells.keys().collect());

    let apps = charms_client::apps(spell);

    let charms_tx = charms_client::to_tx(spell, &prev_spells, tx_ins_beamed_source_utxos);
    let tx_is_simple_transfer_or_app_proof_is_correct =
        apps.iter().all(|app| is_simple_transfer(app, &charms_tx))
            || app_prover_output
                .is_some_and(|app_prover_output| verify_proof(&APP_VK, &app_prover_output));
    check!(tx_is_simple_transfer_or_app_proof_is_correct);

    true
}

fn verify_proof<T: Serialize>(vk: &[u32; 8], committed_data: &T) -> bool {
    let Ok(pv) = to_public_values(committed_data).hash().try_into() else {
        unreachable!()
    };
    verify_sp1_proof(vk, &pv);
    true
}

#[cfg(test)]
mod test {
    #[test]
    fn dummy() {}
}
