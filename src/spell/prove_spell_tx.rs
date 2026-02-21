use super::prove::Prove;
use super::request::{CharmsFee, ProveRequest};
#[cfg(feature = "prover")]
use crate::utils::block_on;
#[cfg(not(feature = "prover"))]
use crate::utils::retry;
use crate::{
    cli::{charms_fee_settings, prove_impl},
    tx::{bitcoin_tx, cardano_tx},
};
use anyhow::bail;
use charms_client::{
    CURRENT_VERSION, NormalizedSpell,
    tx::{Chain, Tx, by_txid},
};
use charms_data::util;
use const_format::formatcp;
#[cfg(feature = "prover")]
use redis::AsyncCommands;
#[cfg(feature = "prover")]
use redis_macros::{FromRedisValue, ToRedisArgs};
#[cfg(not(feature = "prover"))]
use reqwest::Client;
#[cfg(feature = "prover")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "prover")]
use std::time::Duration;
use std::future::Future;

pub trait ProveSpellTx: Send + Sync {
    fn new(mock: bool) -> Self;

    fn prove_spell_tx(
        &self,
        prove_request: ProveRequest,
    ) -> impl Future<Output = anyhow::Result<Vec<Tx>>>;
}

pub struct ProveSpellTxImpl {
    pub mock: bool,

    pub charms_fee_settings: Option<CharmsFee>,
    pub charms_prove_api_url: String,

    #[cfg(feature = "prover")]
    pub cache_client: Option<(redis::Client, rslock::LockManager)>,

    pub prover: Box<dyn Prove>,
    #[cfg(not(feature = "prover"))]
    pub client: Client,
}

const CHARMS_PROVE_API_URL: &'static str =
    formatcp!("https://v{CURRENT_VERSION}.charms.dev/spells/prove");

#[cfg(feature = "prover")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestData {
    committed_data_hash: [u8; 32],
}

#[cfg(feature = "prover")]
#[derive(Clone, Debug, Serialize, Deserialize, FromRedisValue, ToRedisArgs)]
pub enum ProofState {
    Processing {
        request_data: RequestData,
    },
    Done {
        request_data: RequestData,
        result: Vec<Tx>,
    },
}

pub fn committed_data_hash(normalized_spell: &NormalizedSpell) -> anyhow::Result<[u8; 32]> {
    let bytes =
        util::write(&normalized_spell).context("Failed to serialize normalized spell for hash")?;
    Ok(Sha256::digest(&bytes).into())
}

use anyhow::Context;

impl ProveSpellTxImpl {
    pub(super) async fn do_prove_spell_tx(
        &self,
        prove_request: ProveRequest,
        app_cycles: u64,
    ) -> anyhow::Result<Vec<Tx>> {
        let total_app_cycles = app_cycles;
        let ProveRequest {
            spell: norm_spell,
            app_private_inputs,
            tx_ins_beamed_source_utxos,
            binaries,
            prev_txs,
            change_address,
            fee_rate,
            chain,
            collateral_utxo,
        } = prove_request;

        if chain == Chain::Cardano && collateral_utxo.is_none() {
            bail!("Collateral UTXO is required for Cardano spells");
        }

        let prev_txs_by_id = by_txid(&prev_txs);

        let (truncated_norm_spell, proof, proof_app_cycles) = self.prover.prove(
            norm_spell.clone(),
            binaries,
            app_private_inputs,
            prev_txs,
            tx_ins_beamed_source_utxos,
        )?;

        let total_cycles = if !self.mock {
            total_app_cycles
        } else {
            proof_app_cycles // mock prover computes app run cycles
        };

        tracing::info!("proof generated. total app cycles: {}", total_cycles);

        // Serialize spell into CBOR
        let spell_data = util::write(&(&truncated_norm_spell, &proof))?;

        let charms_fee = self.charms_fee_settings.clone();

        match chain {
            Chain::Bitcoin => {
                let txs = bitcoin_tx::make_transactions(
                    &norm_spell,
                    &change_address,
                    &prev_txs_by_id,
                    &spell_data,
                    fee_rate,
                    charms_fee,
                    total_cycles,
                )?;
                Ok(txs)
            }
            Chain::Cardano => {
                let txs = cardano_tx::make_transactions(
                    &norm_spell,
                    &change_address,
                    &spell_data,
                    &prev_txs_by_id,
                    None,
                    charms_fee,
                    total_cycles,
                    collateral_utxo,
                )
                .await?;
                Ok(txs)
            }
        }
    }
}

impl ProveSpellTx for ProveSpellTxImpl {
    #[tracing::instrument(level = "debug")]
    fn new(mock: bool) -> Self {
        let charms_fee_settings = charms_fee_settings();

        let charms_prove_api_url = std::env::var("CHARMS_PROVE_API_URL")
            .ok()
            .unwrap_or(CHARMS_PROVE_API_URL.to_string());
        tracing::info!(charms_prove_api_url);

        let prover = prove_impl(mock);

        #[cfg(feature = "prover")]
        let cache_client: Option<(_, _)> = {
            std::env::var("REDIS_URL").ok().and_then(|redis_url| {
                match redis::Client::open(redis_url) {
                    Ok(redis_client) => {
                        let lock_manager =
                            rslock::LockManager::from_clients(vec![redis_client.clone()]);
                        Some((redis_client, lock_manager))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create Redis client, caching disabled: {}", e);
                        None
                    }
                }
            })
        };

        #[cfg(not(feature = "prover"))]
        let client = Client::builder()
            .use_rustls_tls() // avoids system OpenSSL issues
            .http2_prior_knowledge()
            .http2_adaptive_window(true)
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("HTTP client should be created successfully");

        Self {
            mock,
            charms_fee_settings,
            charms_prove_api_url,
            #[cfg(feature = "prover")]
            cache_client,
            prover,
            #[cfg(not(feature = "prover"))]
            client,
        }
    }

    #[cfg(feature = "prover")]
    async fn prove_spell_tx(&self, prove_request: ProveRequest) -> anyhow::Result<Vec<Tx>> {
        let (norm_spell, app_cycles) = self.validate_prove_request(&prove_request)?;

        if let Some((cache_client, lock_manager)) = self.cache_client.as_ref() {
            let committed_data_hash = committed_data_hash(&norm_spell)?;
            let request_key = hex::encode(committed_data_hash);
            let lock_key = format!("LOCK_{}", request_key.as_str());

            let mut con = cache_client.get_multiplexed_async_connection().await?;

            match con.get(request_key.as_str()).await? {
                Some(ProofState::Done { result, .. }) => Ok(result),
                _ => {
                    const LOCK_TTL: Duration = Duration::from_secs(5);

                    let mut con = con.clone();
                    let request_key = request_key.clone();

                    let result: Vec<Tx> = lock_manager
                        .using(lock_key.as_bytes(), LOCK_TTL, || async move {
                            match con.get(request_key.as_str()).await? {
                                Some(ProofState::Done { result, .. }) => {
                                    return Ok(result);
                                }
                                _ => {}
                            };

                            let _: () = block_on(con.set(
                                request_key.as_str(),
                                ProofState::Processing {
                                    request_data: RequestData {
                                        committed_data_hash,
                                    },
                                },
                            ))?;

                            let r: Vec<Tx> =
                                self.do_prove_spell_tx(prove_request, app_cycles).await?;

                            let _: () = block_on(con.set(
                                request_key.as_str(),
                                ProofState::Done {
                                    request_data: RequestData {
                                        committed_data_hash,
                                    },
                                    result: r.clone(),
                                },
                            ))?;

                            Ok::<_, anyhow::Error>(r)
                        })
                        .await??;

                    // TODO save permanent error to the cache

                    Ok(result)
                }
            }
        } else {
            self.do_prove_spell_tx(prove_request, app_cycles).await
        }
    }

    #[cfg(not(feature = "prover"))]
    #[tracing::instrument(level = "info", skip_all)]
    async fn prove_spell_tx(&self, prove_request: ProveRequest) -> anyhow::Result<Vec<Tx>> {
        let (_norm_spell, app_cycles) = self.validate_prove_request(&prove_request)?;
        if self.mock {
            return Self::do_prove_spell_tx(self, prove_request, app_cycles).await;
        }

        let response = retry(0, || async {
            let cbor_body = util::write(&prove_request)?;
            let response = self
                .client
                .post(&self.charms_prove_api_url)
                .header("Content-Type", "application/cbor")
                .body(cbor_body)
                .send()
                .await?;
            if response.status().is_server_error() {
                bail!("server error: {}", response.status());
            }
            Ok(response)
        })
        .await?;
        if response.status().is_client_error() {
            let status = response.status();
            let body = response.text().await?;
            bail!("client error: {}: {}", status, body);
        }
        let bytes = response.bytes().await?;
        let txs: Vec<Tx> = util::read(&bytes[..])?;
        Ok(txs)
    }
}
