pub mod bin;

use charms_client::{
    NormalizedSpell,
    tx::{Tx, by_txid},
};
use charms_data::{App, AppInput, Data, Transaction, UtxoId, check, is_simple_transfer};
use std::collections::{BTreeMap, BTreeSet};

/// Check if the spell is correct.
pub(crate) fn is_correct(
    spell: &NormalizedSpell,
    prev_txs: &Vec<Tx>,
    app_input: Option<AppInput>,
    spell_vk: &String,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, UtxoId>,
) -> bool {
    let prev_spells = charms_client::prev_spells(&prev_txs, spell_vk, false);

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

    let charms_tx =
        charms_client::to_tx(spell, &prev_spells, tx_ins_beamed_source_utxos, &prev_txs);
    let tx_is_simple_transfer_or_app_contracts_satisfied =
        apps.iter().all(|app| is_simple_transfer(app, &charms_tx)) && app_input.is_none()
            || app_input.is_some_and(|app_input| {
                apps_satisfied(&app_input, &spell.app_public_inputs, &charms_tx)
            });
    check!(tx_is_simple_transfer_or_app_contracts_satisfied);

    true
}

fn apps_satisfied(
    app_input: &AppInput,
    app_public_inputs: &BTreeMap<App, Data>,
    tx: &Transaction,
) -> bool {
    let app_runner = charms_app_runner::AppRunner::new(false);
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

#[cfg(test)]
mod test {
    #[test]
    fn dummy() {}
}
