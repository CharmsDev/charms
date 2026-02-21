use crate::{
    cli,
    cli::{SpellCheckParams, SpellProveParams},
    spell::{
        ProveRequest, ProveSpellTx, ProveSpellTxImpl, SpellInput, adjust_coin_contents,
        ensure_all_prev_txs_are_present, ensure_exact_app_binaries, from_strings,
    },
};
use anyhow::{Result, ensure};
use charms_app_runner::AppRunner;
use charms_client::{
    CURRENT_VERSION,
    tx::{Chain, Tx, by_txid},
};
use charms_data::UtxoId;
use charms_lib::SPELL_VK;
use serde_json::json;
use std::{future::Future, str::FromStr};

pub trait Check {
    fn check(&self, params: SpellCheckParams) -> Result<()>;
}

pub trait Prove {
    fn prove(&self, params: SpellProveParams) -> impl Future<Output = Result<()>>;
}

pub struct SpellCli {
    pub app_runner: AppRunner,
}

impl SpellCli {
    pub(crate) fn print_vk(&self, mock: bool) -> Result<()> {
        #[cfg(feature = "prover")]
        let is_prover = true;
        #[cfg(not(feature = "prover"))]
        let is_prover = false;
        let json = match mock {
            true => json!({
                "mock": true,
                "prover": is_prover,
                "version": CURRENT_VERSION,
                "vk": SPELL_VK.to_string(),
            }),
            false => json!({
                "prover": is_prover,
                "version": CURRENT_VERSION,
                "vk": SPELL_VK.to_string(),
            }),
        };

        println!("{}", json);
        Ok(())
    }
}

impl Prove for SpellCli {
    async fn prove(&self, params: SpellProveParams) -> Result<()> {
        let SpellProveParams {
            spell,
            prev_txs,
            app_bins,
            change_address,
            fee_rate,
            chain,
            mock,
            collateral_utxo,
        } = params;

        let spell_prover = ProveSpellTxImpl::new(mock);

        let collateral_utxo = collateral_utxo
            .map(|utxo| UtxoId::from_str(&utxo))
            .transpose()?;

        ensure!(fee_rate >= 1.0, "fee rate must be >= 1.0");

        let spell_input: SpellInput = serde_yaml::from_slice(&std::fs::read(spell)?)?;
        let spell_input = adjust_coin_contents(spell_input, chain)?;

        let prev_txs = from_strings(&prev_txs)?;

        let binaries = cli::app::binaries_by_vk(&self.app_runner, app_bins)?;

        let (norm_spell, app_private_inputs, tx_ins_beamed_source_utxos) = spell_input.into_parts();

        let prove_request = ProveRequest {
            spell: norm_spell,
            app_private_inputs,
            tx_ins_beamed_source_utxos,
            binaries,
            prev_txs,
            change_address,
            fee_rate,
            chain,
            collateral_utxo,
        };
        let transactions = spell_prover.prove_spell_tx(prove_request).await?;

        match chain {
            Chain::Bitcoin => {
                // Convert transactions to hex and create JSON array
                let hex_txs: Vec<Tx> = transactions;

                // Print JSON array of transaction hexes
                println!("{}", serde_json::to_string(&hex_txs)?);
            }
            Chain::Cardano => {
                let Some(tx) = transactions.into_iter().next() else {
                    unreachable!()
                };
                let tx_draft = json!({
                    "type": "Witnessed Tx ConwayEra",
                    "description": "Ledger Cddl Format",
                    "cborHex": tx.hex(),
                });
                println!("{}", tx_draft);
            }
        }

        Ok(())
    }
}

impl Check for SpellCli {
    #[tracing::instrument(level = "debug", skip(self, spell, app_bins))]
    fn check(
        &self,
        SpellCheckParams {
            spell,
            app_bins,
            prev_txs,
            chain,
            mock,
        }: SpellCheckParams,
    ) -> Result<()> {
        let spell_input: SpellInput = serde_yaml::from_slice(&std::fs::read(spell)?)?;
        let spell_input = adjust_coin_contents(spell_input, chain)?;

        let prev_txs = prev_txs.unwrap_or_else(|| vec![]);

        let prev_txs = from_strings(&prev_txs)?;

        let (norm_spell, app_private_inputs, tx_ins_beamed_source_utxos) = spell_input.into_parts();

        ensure_all_prev_txs_are_present(
            &norm_spell,
            &tx_ins_beamed_source_utxos,
            &by_txid(&prev_txs),
        )?;

        let binaries = cli::app::binaries_by_vk(&self.app_runner, app_bins)?;

        let prev_spells = charms_client::prev_spells(&prev_txs, SPELL_VK, norm_spell.mock);

        let charms_tx = charms_client::to_tx(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos,
            &prev_txs,
        );

        ensure_exact_app_binaries(&norm_spell, &app_private_inputs, &charms_tx, &binaries)?;

        let app_input = match binaries.is_empty() {
            true => None,
            false => Some(charms_data::AppInput {
                app_binaries: binaries.clone(),
                app_private_inputs: app_private_inputs.clone(),
            }),
        };

        ensure!(
            charms_client::is_correct(
                &norm_spell,
                &prev_txs,
                app_input,
                SPELL_VK,
                &tx_ins_beamed_source_utxos,
            ),
            "spell verification failed"
        );

        let cycles_spent = self.app_runner.run_all(
            &binaries,
            &charms_tx,
            &norm_spell.app_public_inputs,
            &app_private_inputs,
        )?;

        eprintln!("cycles spent: {:?}", cycles_spent);

        Ok(())
    }
}
