use super::prove_spell_tx::ProveSpellTxImpl;
use crate::tx::bitcoin_tx::from_spell;
use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::Network;
use charms_app_runner::AppRunner;
use charms_client::{
    BeamSource, NormalizedSpell,
    cardano_tx::OutputContent,
    tx::{Chain, Tx, by_txid},
};
use charms_data::{App, AppInput, B32, Data, TxId, util};
use charms_lib::SPELL_VK;
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use super::get_charms_fee;

pub fn ensure_exact_app_binaries(
    norm_spell: &NormalizedSpell,
    app_private_inputs: &BTreeMap<App, Data>,
    tx: &charms_data::Transaction,
    binaries: &BTreeMap<B32, Vec<u8>>,
) -> anyhow::Result<()> {
    let required_vks: BTreeSet<_> = norm_spell
        .app_public_inputs
        .iter()
        .filter(|(app, data)| {
            !data.is_empty()
                || !app_private_inputs
                    .get(app)
                    .is_none_or(|data| data.is_empty())
                || !charms_data::is_simple_transfer(app, tx)
        })
        .map(|(app, _)| &app.vk)
        .collect();

    let provided_vks: BTreeSet<_> = binaries.keys().collect();

    ensure!(
        required_vks == provided_vks,
        "binaries must contain exactly the required app binaries.\n\
         Required VKs: {:?}\n\
         Provided VKs: {:?}",
        required_vks,
        provided_vks
    );

    Ok(())
}

pub fn ensure_all_prev_txs_are_present(
    spell: &NormalizedSpell,
    tx_ins_beamed_source_utxos: &BTreeMap<usize, BeamSource>,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
) -> anyhow::Result<()> {
    let spell_ins = spell
        .tx
        .ins
        .as_ref()
        .ok_or_else(|| anyhow!("spell.tx.ins must be present"))?;

    ensure!(
        spell_ins
            .iter()
            .all(|utxo_id| prev_txs_by_id.contains_key(&utxo_id.0)),
        "prev_txs MUST contain transactions creating input UTXOs"
    );
    ensure!(
        spell.tx.refs.as_ref().is_none_or(|ins| {
            ins.iter()
                .all(|utxo_id| prev_txs_by_id.contains_key(&utxo_id.0))
        }),
        "prev_txs MUST contain transactions creating ref UTXOs"
    );
    ensure!(
        tx_ins_beamed_source_utxos
            .iter()
            .all(|(&i, beaming_source)| {
                spell_ins.get(i).is_some_and(|utxo_id| {
                    prev_txs_by_id.contains_key(&utxo_id.0)
                        && prev_txs_by_id.contains_key(&(beaming_source.0).0)
                })
            }),
        "prev_txs MUST contain transactions creating beaming source and destination UTXOs"
    );

    // Ensure prev_txs contains ONLY the required transactions (no extras)
    let mut required_txids = BTreeSet::new();

    // Add transaction IDs from spell inputs
    required_txids.extend(spell_ins.iter().map(|utxo_id| &utxo_id.0));

    // Add transaction IDs from spell refs
    if let Some(refs) = spell.tx.refs.as_ref() {
        required_txids.extend(refs.iter().map(|utxo_id| &utxo_id.0));
    }

    // Add transaction IDs from beaming source UTXOs
    required_txids.extend(tx_ins_beamed_source_utxos.values().map(|bs| &(bs.0).0));

    // Check that prev_txs contains exactly the required transactions
    let provided_txids: BTreeSet<_> = prev_txs_by_id.keys().collect();

    ensure!(
        required_txids == provided_txids,
        "prev_txs must contain exactly the transactions producing spell inputs and beaming sources.\n\
         Required: {:?}\n\
         Provided: {:?}",
        required_txids,
        provided_txids
    );

    Ok(())
}

/// Adjust `NativeOutput.content` fields in `norm_spell.tx.coins` according to the target chain.
///
/// - **Cardano**: each `content` is canonicalized through JSON→[`OutputContent`]→[`Data`]
///   round-trip.  If `content` is `None`, the default (empty) [`OutputContent`] is used.
/// - **Bitcoin**: every `content` field **must** be `None`; otherwise an error is returned.
pub fn adjust_coin_contents(
    norm_spell: &mut NormalizedSpell,
    chain: Chain,
) -> anyhow::Result<()> {
    let Some(coins) = norm_spell.tx.coins.as_mut() else {
        return Ok(());
    };

    for (i, coin) in coins.iter_mut().enumerate() {
        match chain {
            Chain::Bitcoin => {
                ensure!(
                    coin.content.is_none(),
                    "coins[{i}].content must be None for Bitcoin"
                );
            }
            Chain::Cardano => {
                let output_content: OutputContent = match coin.content.take() {
                    Some(content) => {
                        let json = serde_json::to_value(&content).with_context(|| {
                            format!("coins[{i}].content: failed to serialize to JSON")
                        })?;
                        serde_json::from_value(json).with_context(|| {
                            format!("coins[{i}].content: failed to parse as OutputContent")
                        })?
                    }
                    None => OutputContent::default(),
                };
                coin.content = Some((&output_content).into());
            }
        }
    }

    Ok(())
}

impl ProveSpellTxImpl {
    pub fn validate_prove_request(
        &self,
        prove_request: &super::request::ProveRequest,
    ) -> anyhow::Result<(NormalizedSpell, u64)> {
        ensure!(
            prove_request.spell.mock == self.mock,
            "cannot prove a mock=={} spell on a mock=={} prover",
            prove_request.spell.mock,
            self.mock
        );

        let prev_txs = &prove_request.prev_txs;
        let prev_txs_by_id = by_txid(prev_txs);

        let mut norm_spell = prove_request.spell.clone();
        adjust_coin_contents(&mut norm_spell, prove_request.chain)?;
        let norm_spell = &norm_spell;
        let app_private_inputs = &prove_request.app_private_inputs;
        let tx_ins_beamed_source_utxos = &prove_request.tx_ins_beamed_source_utxos;

        ensure_all_prev_txs_are_present(norm_spell, tx_ins_beamed_source_utxos, &prev_txs_by_id)?;

        let prev_spells = charms_client::prev_spells(prev_txs, SPELL_VK, norm_spell.mock);

        let tx = charms_client::to_tx(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos,
            &prev_txs,
        );

        ensure_exact_app_binaries(
            &norm_spell,
            &app_private_inputs,
            &tx,
            &prove_request.binaries,
        )?;

        let app_input = match prove_request.binaries.is_empty() {
            true => None,
            false => Some(AppInput {
                app_binaries: prove_request.binaries.clone(),
                app_private_inputs: app_private_inputs.clone(),
            }),
        };

        ensure!(
            charms_client::is_correct(
                &norm_spell,
                &prev_txs,
                app_input.clone(),
                SPELL_VK,
                &tx_ins_beamed_source_utxos,
            ),
            "spell verification failed"
        );

        // Calculate cycles for fee estimation
        let total_cycles = if let Some(app_input) = &app_input {
            let cycles = AppRunner::new(true).run_all(
                &app_input.app_binaries,
                &tx,
                &norm_spell.app_public_inputs,
                &app_input.app_private_inputs,
            )?;
            cycles.iter().sum()
        } else {
            0
        };

        match prove_request.chain {
            Chain::Bitcoin => {
                let change_address = bitcoin::Address::from_str(&prove_request.change_address)?;

                let network = match &change_address {
                    a if a.is_valid_for_network(Network::Bitcoin) => Network::Bitcoin,
                    a if a.is_valid_for_network(Network::Testnet4) => Network::Testnet4,
                    a if a.is_valid_for_network(Network::Regtest) && self.mock => Network::Regtest,
                    _ => bail!(
                        "Unsupported network of change address: {:?}",
                        change_address
                    ),
                };
                let coin_outs = (norm_spell.tx.coins.as_ref()).expect("coin outputs are expected");

                // Validate that all output addresses are valid for the network
                ensure!(
                    coin_outs.iter().all(|o| {
                        bitcoin::Address::from_script(
                            &bitcoin::ScriptBuf::from_bytes(o.dest.clone()),
                            network,
                        )
                        .is_ok()
                    }),
                    "all output addresses must be valid for the network"
                );

                let charms_fee = get_charms_fee(&self.charms_fee_settings, total_cycles).to_sat();

                let spell_ins = norm_spell
                    .tx
                    .ins
                    .as_ref()
                    .expect("spell inputs are expected");
                let total_sats_in: u64 = spell_ins
                    .iter()
                    .map(|utxo_id| {
                        prev_txs_by_id
                            .get(&utxo_id.0)
                            .and_then(|prev_tx| {
                                if let Tx::Bitcoin(bitcoin_tx) = prev_tx {
                                    bitcoin_tx
                                        .inner()
                                        .output
                                        .get(utxo_id.1 as usize)
                                        .map(|o| o.value.to_sat())
                                } else {
                                    None
                                }
                            })
                            .ok_or(anyhow!("utxo not found in prev_txs: {}", utxo_id))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?
                    .iter()
                    .sum();
                let total_sats_out: u64 = coin_outs.iter().map(|o| o.amount).sum();

                let bitcoin_tx = from_spell(&norm_spell)?;
                let tx_size = bitcoin_tx.inner().vsize();
                let mut norm_spell_for_size = norm_spell.clone();
                norm_spell_for_size.tx.ins = None;
                let proof_dummy: Vec<u8> = vec![0xff; 128];
                let spell_cbor = util::write(&(norm_spell_for_size, proof_dummy))?;
                let num_inputs = bitcoin_tx.inner().input.len();
                let estimated_bitcoin_fee: u64 = (111
                    + (spell_cbor.len() as u64 + 372) / 4
                    + tx_size as u64
                    + 28 * num_inputs as u64)
                    * prove_request.fee_rate as u64;

                tracing::info!(
                    total_sats_in,
                    total_sats_out,
                    charms_fee,
                    estimated_bitcoin_fee
                );

                ensure!(
                    total_sats_in > total_sats_out + charms_fee + estimated_bitcoin_fee,
                    "spell inputs must have sufficient value to cover outputs and fees"
                );
                Ok((norm_spell.clone(), total_cycles))
            }
            Chain::Cardano => {
                // TODO
                tracing::warn!("spell validation for cardano is not yet implemented");
                Ok((norm_spell.clone(), total_cycles))
            }
        }
    }
}
