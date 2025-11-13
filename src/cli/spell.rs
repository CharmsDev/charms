use crate::{
    cli,
    cli::{BITCOIN, CARDANO, SpellCheckParams, SpellProveParams},
    spell::{ProveRequest, ProveSpellTx, ProveSpellTxImpl, Spell, ensure_no_zero_amounts},
};
use anyhow::{Result, ensure};
use charms_app_runner::AppRunner;
use charms_client::{
    CURRENT_VERSION,
    tx::{Tx, by_txid},
};
use charms_data::UtxoId;
use charms_lib::SPELL_VK;
use serde_json::json;
use std::future::Future;

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
            funding_utxo,
            funding_utxo_value,
            change_address,
            fee_rate,
            chain,
            mock,
        } = params;

        let spell_prover = ProveSpellTxImpl::new(mock);

        // Parse funding UTXO early: to fail fast
        let funding_utxo = UtxoId::from_str(&funding_utxo)?;

        ensure!(fee_rate >= 1.0, "fee rate must be >= 1.0");

        let spell: Spell = serde_yaml::from_slice(&std::fs::read(spell)?)?;

        let binaries = cli::app::binaries_by_vk(&self.app_runner, app_bins)?;

        let prove_request = ProveRequest {
            spell,
            binaries,
            prev_txs,
            funding_utxo,
            funding_utxo_value,
            change_address,
            fee_rate,
            chain: chain.clone(),
        };
        let transactions = spell_prover.prove_spell_tx(prove_request).await?;

        match chain.as_str() {
            BITCOIN => {
                // Convert transactions to hex and create JSON array
                let hex_txs: Vec<String> = transactions;

                // Print JSON array of transaction hexes
                println!("{}", serde_json::to_string(&hex_txs)?);
            }
            CARDANO => {
                let Some(tx_hex) = transactions.into_iter().next() else {
                    unreachable!()
                };
                let tx_draft = json!({
                    "type": "Unwitnessed Tx ConwayEra",
                    "description": "Ledger Cddl Format",
                    "cborHex": tx_hex,
                });
                println!("{}", tx_draft);
            }
            _ => unreachable!(),
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
            mock,
        }: SpellCheckParams,
    ) -> Result<()> {
        let mut spell: Spell = serde_yaml::from_slice(&std::fs::read(spell)?)?;
        for u in spell.outs.iter_mut() {
            u.amount.get_or_insert(crate::cli::wallet::MIN_SATS);
        }

        // make sure spell inputs all have utxo_id
        ensure!(
            spell.ins.iter().all(|u| u.utxo_id.is_some()),
            "all spell inputs must have utxo_id"
        );

        let prev_txs = prev_txs.unwrap_or_else(|| vec![]);

        let prev_txs = prev_txs
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|tx_hex| Tx::from_hex(tx_hex))
            .collect::<Result<Vec<_>, _>>()?;

        let prev_spells = charms_client::prev_spells(&prev_txs, &SPELL_VK, mock);

        let (norm_spell, app_private_inputs, tx_ins_beamed_source_utxos) = spell.normalized()?;

        ensure_no_zero_amounts(&norm_spell)?;

        ensure!(
            charms_client::well_formed(&norm_spell, &prev_spells, &tx_ins_beamed_source_utxos),
            "spell is not well-formed"
        );

        let binaries = cli::app::binaries_by_vk(&self.app_runner, app_bins)?;

        let charms_tx = spell.to_tx(by_txid(&prev_txs))?;
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
