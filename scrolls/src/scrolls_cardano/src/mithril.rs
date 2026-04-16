use anyhow::{anyhow, ensure};
use async_trait::async_trait;
use ic_cdk::management_canister::{
    HttpMethod, HttpRequestArgs, HttpRequestResult, TransformArgs, http_request,
    transform_context_from_query,
};
use mithril_client::{
    CardanoTransactionSnapshot, CardanoTransactionSnapshotListItem, CardanoTransactionsProofs,
    MithrilResult,
    cardano_transaction_client::{CardanoTransactionAggregatorRequest, CardanoTransactionClient},
};
use std::sync::{Arc, LazyLock};

use crate::AGGREGATOR_ENDPOINT;

const MAX_RESPONSE_BYTES: u64 = 2_000_000;

/// HTTP client that uses ICP's http_outcall API to make requests to the Mithril aggregator.
struct IcpHttpClient {
    endpoint: String,
}

impl IcpHttpClient {
    fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
        }
    }

    async fn get(&self, route: &str) -> MithrilResult<(u16, Vec<u8>)> {
        let url = format!("{}/{}", self.endpoint, route);

        let request = HttpRequestArgs {
            url,
            max_response_bytes: Some(MAX_RESPONSE_BYTES),
            method: HttpMethod::GET,
            headers: vec![],
            body: None,
            transform: Some(transform_context_from_query(
                "transform_http".to_string(),
                vec![],
            )),
            is_replicated: None,
        };

        let response = http_request(&request)
            .await
            .map_err(|e| anyhow!("HTTP outcall failed: {}", e))?;

        let status: u16 = response
            .status
            .0
            .try_into()
            .map_err(|_| anyhow!("Invalid HTTP status"))?;

        Ok((status, response.body))
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, route: &str) -> MithrilResult<T> {
        let (status, body) = self.get(route).await?;
        if status != 200 {
            return Err(anyhow!(
                "HTTP {} from aggregator for route '{}'",
                status,
                route
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|e| anyhow!("Failed to deserialize response for '{}': {}", route, e))
    }

    async fn get_json_option<T: serde::de::DeserializeOwned>(
        &self,
        route: &str,
    ) -> MithrilResult<Option<T>> {
        let (status, body) = self.get(route).await?;
        match status {
            200 => {
                let value = serde_json::from_slice(&body).map_err(|e| {
                    anyhow!("Failed to deserialize response for '{}': {}", route, e)
                })?;
                Ok(Some(value))
            }
            404 => Ok(None),
            _ => Err(anyhow!(
                "HTTP {} from aggregator for route '{}'",
                status,
                route
            )),
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CardanoTransactionAggregatorRequest for IcpHttpClient {
    async fn get_proof(
        &self,
        hashes: &[String],
    ) -> MithrilResult<Option<CardanoTransactionsProofs>> {
        let joined = hashes.join(",");
        self.get_json_option(&format!(
            "proof/cardano-transaction?transaction_hashes={}",
            joined
        ))
        .await
    }

    async fn list_latest_snapshots(
        &self,
    ) -> MithrilResult<Vec<CardanoTransactionSnapshotListItem>> {
        self.get_json("artifact/cardano-transactions").await
    }

    async fn get_snapshot(&self, hash: &str) -> MithrilResult<Option<CardanoTransactionSnapshot>> {
        self.get_json_option(&format!("artifact/cardano-transaction/{}", hash))
            .await
    }
}

static HTTP_CLIENT: LazyLock<Arc<IcpHttpClient>> =
    LazyLock::new(|| Arc::new(IcpHttpClient::new(AGGREGATOR_ENDPOINT)));

static TX_CLIENT: LazyLock<CardanoTransactionClient> = LazyLock::new(|| {
    CardanoTransactionClient::new(
        HTTP_CLIENT.clone() as Arc<dyn CardanoTransactionAggregatorRequest>
    )
});

/// Verify that a transaction has been finalized on the Cardano blockchain using Mithril
/// certificate chain and transaction proof verification.
pub async fn verify_transaction_finality(tx_hash_hex: &str) -> anyhow::Result<()> {
    // Get proof for the transaction
    let cardano_transaction_proof = TX_CLIENT.get_proofs(&[tx_hash_hex]).await?;

    // Verify the Merkle proofs
    let verified_transactions = cardano_transaction_proof.verify()?;

    // Check that our transaction is in the certified set
    ensure!(
        verified_transactions
            .certified_transactions()
            .iter()
            .any(|tx| *tx == tx_hash_hex),
        "Transaction {} not found in certified transactions",
        tx_hash_hex
    );

    Ok(())
}

/// Transform function for HTTP outcalls. Strips headers so all replicas reach consensus
/// on the same response (headers may differ between replicas due to timestamps, request IDs, etc.).
#[ic_cdk::query]
fn transform_http(args: TransformArgs) -> HttpRequestResult {
    HttpRequestResult {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}
