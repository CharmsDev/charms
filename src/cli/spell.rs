use crate::{
    cli,
    cli::{Output, SpellCheckParams, SpellProveParams},
    spell::{
        NormalizedSpell, ProveRequest, ProveSpellTx, ProveSpellTxImpl, adjust_coin_contents,
        ensure_all_prev_txs_are_present, ensure_exact_app_binaries,
        ensure_no_orphan_versioned_apps, ensure_versioned_apps_have_signatures, from_strings,
        read_private_inputs,
    },
};
use anyhow::{Context, Result, ensure};
use charms_app_runner::AppRunner;
use charms_client::{
    CURRENT_VERSION,
    tx::{Chain, Tx, by_txid},
};
use charms_data::{AppSignature, B32, UtxoId, util};
use charms_lib::SPELL_VK;
use serde_json::json;
use std::{collections::BTreeMap, future::Future, io::Write, str::FromStr};

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
                "vk": charms_client::tx::vk_hex(&SPELL_VK),
            }),
            false => json!({
                "prover": is_prover,
                "version": CURRENT_VERSION,
                "vk": charms_client::tx::vk_hex(&SPELL_VK),
            }),
        };

        println!("{}", json);
        Ok(())
    }
}

impl Prove for SpellCli {
    async fn prove(&self, params: SpellProveParams) -> Result<()> {
        if params.chain == Chain::Ethereum {
            println!("{}", ethereum_placeholder_json(&params)?);
            return Ok(());
        }
        reject_ethereum_only_options(&params)?;

        let SpellProveParams {
            spell,
            payload,
            output: format,
            private_inputs,
            beamed_from,
            prev_txs,
            app_bins,
            app_signatures,
            change_address,
            fee_rate,
            chain,
            mock,
            collateral_utxo,
            ..
        } = params;
        let change_address =
            change_address.context("--change-address is required for this chain")?;

        let spell_prover = ProveSpellTxImpl::new(mock);

        let collateral_utxo = collateral_utxo
            .map(|utxo| UtxoId::from_str(&utxo))
            .transpose()?;

        ensure!(fee_rate >= 1.0, "fee rate must be >= 1.0");

        let norm_spell: NormalizedSpell = serde_yaml::from_slice(&std::fs::read(spell)?)?;

        let app_private_inputs = private_inputs
            .map(|p| read_private_inputs(&p))
            .transpose()?
            .unwrap_or_default();

        let tx_ins_beamed_source_utxos = beamed_from
            .map(|s| serde_yaml::from_str(&s))
            .transpose()?
            .unwrap_or_default();

        let prev_txs = from_strings(&prev_txs)?;

        let binaries = cli::app::binaries_by_vk(&self.app_runner, app_bins)?;
        let app_signatures: BTreeMap<B32, AppSignature> = app_signatures
            .map(|p| cli::app::read_app_signatures(&p))
            .transpose()?
            .unwrap_or_default();
        ensure_no_orphan_versioned_apps(&norm_spell)?;
        // Note: `ensure_versioned_apps_have_signatures` needs the resolved tx (to know
        // which apps are simple transfers and thus skip the signature requirement). The
        // server-side `validate_prove_request` runs that check authoritatively; we don't
        // duplicate it here because building the tx requires loading prev spells.
        let app_input = match binaries.is_empty() && app_signatures.is_empty() {
            true => None,
            false => Some(charms_data::AppInput {
                app_binaries: binaries.clone(),
                app_private_inputs: app_private_inputs.clone(),
                app_signatures: app_signatures.clone(),
            }),
        };

        let mut prove_request = ProveRequest {
            spell: norm_spell,
            app_private_inputs,
            tx_ins_beamed_source_utxos,
            binaries,
            app_signatures,
            prev_txs,
            change_address,
            fee_rate,
            chain,
            collateral_utxo,
        };

        if payload {
            // Normalize the prove request so that the emitted payload matches what
            // would actually be sent to the proving API (e.g., adjust coin contents
            // based on the selected chain). We do NOT call the Scrolls canister
            // here: `coins[i].dest` stays empty for Scrolls outputs, and the prover
            // server fills both `dest` and the signed scriptPubKey map at prove
            // time. `is_correct` returns `Ok(false)` in that case, which we
            // tolerate (with a warning).
            adjust_coin_contents(&mut prove_request.spell, chain)?;

            let verified = charms_client::is_correct(
                &prove_request.spell,
                &prove_request.prev_txs,
                app_input,
                &SPELL_VK,
                &prove_request.tx_ins_beamed_source_utxos,
                None,
            )?;
            if !verified {
                eprintln!(
                    "warning: spell has Scrolls outputs whose scriptPubKeys are not \
                     yet bound; binding happens at proving time on the prover server"
                );
            }

            match format {
                Output::Json => println!("{}", serde_json::to_string(&prove_request)?),
                Output::Cbor => {
                    let bytes = util::write(&prove_request)?;
                    std::io::stdout().write_all(&bytes)?;
                }
            }
            return Ok(());
        }

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
            Chain::Ethereum => unreachable!(),
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
            private_inputs,
            beamed_from,
            app_bins,
            app_signatures,
            prev_txs,
            chain,
            mock,
        }: SpellCheckParams,
    ) -> Result<()> {
        let mut norm_spell: NormalizedSpell = serde_yaml::from_slice(&std::fs::read(spell)?)?;

        let app_private_inputs = private_inputs
            .map(|p| read_private_inputs(&p))
            .transpose()?
            .unwrap_or_default();

        let tx_ins_beamed_source_utxos = beamed_from
            .map(|s| serde_yaml::from_str(&s))
            .transpose()?
            .unwrap_or_default();

        let prev_txs = prev_txs.unwrap_or_else(|| vec![]);

        let prev_txs = from_strings(&prev_txs)?;
        adjust_coin_contents(&mut norm_spell, chain)?;

        ensure_all_prev_txs_are_present(
            &norm_spell,
            &tx_ins_beamed_source_utxos,
            &by_txid(&prev_txs),
        )?;

        let binaries = cli::app::binaries_by_vk(&self.app_runner, app_bins)?;
        let app_signatures: BTreeMap<B32, AppSignature> = app_signatures
            .map(|p| cli::app::read_app_signatures(&p))
            .transpose()?
            .unwrap_or_default();
        ensure_no_orphan_versioned_apps(&norm_spell)?;

        let prev_spells = charms_client::prev_spells(&prev_txs, &SPELL_VK, &norm_spell)?;

        let charms_tx = charms_client::to_tx(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos,
            &prev_txs,
        );

        ensure_exact_app_binaries(&norm_spell, &app_private_inputs, &charms_tx, &binaries)?;
        ensure_versioned_apps_have_signatures(
            &norm_spell,
            &app_private_inputs,
            &charms_tx,
            &app_signatures,
        )?;

        let app_input = match binaries.is_empty() && app_signatures.is_empty() {
            true => None,
            false => Some(charms_data::AppInput {
                app_binaries: binaries.clone(),
                app_private_inputs: app_private_inputs.clone(),
                app_signatures: app_signatures.clone(),
            }),
        };

        // No canister call: `charms spell check` is purely client-side. The signed
        // scriptPubKey map for Bitcoin Scrolls outputs is the prover server's job;
        // `is_correct` returns `Ok(false)` in that case and we tolerate it (with a
        // warning) so authors can sanity-check their spell shape locally.
        let verified = charms_client::is_correct(
            &norm_spell,
            &prev_txs,
            app_input,
            &SPELL_VK,
            &tx_ins_beamed_source_utxos,
            None,
        )?;
        if !verified {
            eprintln!(
                "warning: spell has Scrolls outputs whose scriptPubKeys are not yet \
                 bound; binding happens at proving time on the prover server"
            );
        }

        let version_changed_apps = charms_client::collect_version_changed_apps(
            &norm_spell,
            &prev_spells,
            &tx_ins_beamed_source_utxos,
        );
        let cycles_spent = self.app_runner.run_all(
            &binaries,
            &norm_spell.versioned_apps,
            &app_signatures,
            &charms_tx,
            &norm_spell.app_public_inputs,
            &app_private_inputs,
            &version_changed_apps,
        )?;

        eprintln!("cycles spent: {:?}", cycles_spent);

        Ok(())
    }
}

fn reject_ethereum_only_options(params: &SpellProveParams) -> Result<()> {
    ensure!(
        params.caller.is_none(),
        "--caller requires --chain ethereum"
    );
    ensure!(params.salt.is_none(), "--salt requires --chain ethereum");
    ensure!(
        params.chain_id.is_none(),
        "--chain-id requires --chain ethereum"
    );
    ensure!(
        params.charms.is_none(),
        "--charms requires --chain ethereum"
    );
    ensure!(params.nonce.is_none(), "--nonce requires --chain ethereum");
    Ok(())
}

pub(crate) fn ethereum_placeholder_json(params: &SpellProveParams) -> Result<String> {
    ensure!(
        params.change_address.is_none(),
        "--change-address is not used for an Ethereum placeholder"
    );
    ensure!(
        !params.payload,
        "--payload is the prover API. An Ethereum placeholder is built locally"
    );
    ensure!(
        params.prev_txs.is_empty(),
        "--prev-txs is not used for an Ethereum placeholder"
    );
    ensure!(
        params.beamed_from.is_none(),
        "--beamed-from is the claim side, not the placeholder"
    );
    ensure!(
        params.app_bins.is_empty(),
        "a placeholder has no app binaries"
    );
    ensure!(
        params.private_inputs.is_none(),
        "a placeholder has no private inputs"
    );
    ensure!(
        params.app_signatures.is_none(),
        "a placeholder has no app signatures"
    );
    ensure!(
        params.collateral_utxo.is_none(),
        "--collateral-utxo is not used on Ethereum"
    );
    ensure!(!params.mock, "an Ethereum placeholder has no proof to mock");

    let caller = parse_fixed(
        params
            .caller
            .as_deref()
            .context("--caller is required for --chain ethereum")?,
    )?;
    let salt = parse_fixed(
        params
            .salt
            .as_deref()
            .context("--salt is required for --chain ethereum")?,
    )?;
    let chain_id = params
        .chain_id
        .context("--chain-id is required for --chain ethereum")?;
    let charms = parse_fixed(
        params
            .charms
            .as_deref()
            .context("--charms is required for --chain ethereum")?,
    )?;
    let spell: NormalizedSpell = serde_yaml::from_slice(&std::fs::read(&params.spell)?)?;
    let plan = charms_client::ethereum_tx::plan_placeholder(
        &spell,
        &charms_client::ethereum_tx::PlaceholderRequest {
            chain_id,
            charms,
            caller,
            salt,
            nonce: params.nonce,
        },
    )?;
    let body = json!({
        "tx": Tx::Ethereum(plan.record),
        "tx_id": plan.tx_id,
        "utxo_ids": plan.utxo_ids,
        "beamed_outs": plan.beamed_outs,
        "nonce": plan.nonce,
        "call": plan.call,
    });
    Ok(serde_json::to_string(&body)?)
}

fn parse_fixed<const N: usize>(text: &str) -> Result<[u8; N]> {
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let bytes = hex::decode(text).context("expected hex")?;
    ensure!(bytes.len() == N, "expected {N} bytes, got {}", bytes.len());
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected {N} bytes"))
}
