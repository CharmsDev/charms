use crate::{
    cli::ServerConfig,
    spell::{ProveRequest, ProveSpellTx, ProveSpellTxImpl},
    utils::TRANSIENT_PROVER_FAILURE,
};
use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequest, State},
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use charms_client::tx::Tx;
use charms_data::util as cbor;
use serde::{Serialize, de::DeserializeOwned};
use std::{sync::Arc, time::Duration};
use tower_http::cors::{Any, CorsLayer};

pub struct Server {
    pub config: ServerConfig,
    pub prover: Arc<ProveSpellTxImpl>,
}

/// Creates a permissive CORS configuration layer for the API server.
///
/// This configuration:
/// - Allows requests from any origin
/// - Allows all HTTP methods
/// - Allows all headers to be sent
/// - Exposes all headers to the client
/// - Sets a max age of 1 hour (3600 seconds) for preflight requests
fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any)
        .max_age(Duration::from_secs(3600))
}

const MAX_BODY_SIZE: usize = 1024 * 1024 * 32;

#[derive(Debug, Clone, Copy)]
enum ContentFormat {
    Json,
    Cbor,
}

/// Extractor and response wrapper that supports both JSON and CBOR
struct Flexible<T>(T, ContentFormat);

impl<S, T> FromRequest<S> for Flexible<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(
        req: axum::http::Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json");

        let format = if content_type.contains("application/cbor") {
            ContentFormat::Cbor
        } else {
            ContentFormat::Json
        };

        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        let value = match format {
            ContentFormat::Json => serde_json::from_slice(&bytes)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)))?,
            ContentFormat::Cbor => cbor::read(&bytes[..])
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid CBOR: {}", e)))?,
        };

        Ok(Flexible(value, format))
    }
}

impl<T: Serialize> IntoResponse for Flexible<T> {
    fn into_response(self) -> Response {
        let Flexible(data, format) = self;

        match format {
            ContentFormat::Json => {
                let json = match serde_json::to_vec(&data) {
                    Ok(json) => json,
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to serialize JSON: {}", e),
                        )
                            .into_response();
                    }
                };
                ([(CONTENT_TYPE, "application/json")], json).into_response()
            }
            ContentFormat::Cbor => {
                let bytes = match cbor::write(&data) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to serialize CBOR: {}", e),
                        )
                            .into_response();
                    }
                };
                ([(CONTENT_TYPE, "application/cbor")], bytes).into_response()
            }
        }
    }
}

impl Server {
    pub fn new(config: ServerConfig, prover: ProveSpellTxImpl) -> Self {
        let prover = Arc::new(prover);
        Self { config, prover }
    }

    pub async fn serve(&self) -> Result<()> {
        let ServerConfig { ip, port, .. } = &self.config;

        // Build router with CORS middleware
        let app = Router::new();
        let app = app
            .route("/spells/prove", post(prove_spell))
            .with_state(self.prover.clone())
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
            .route("/ready", get(|| async { "OK" }))
            .layer(cors_layer());

        // Run server
        let addr = format!("{}:{}", ip, port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("Server running on {}", &addr);

        axum::serve(listener, app).await?;
        Ok(())
    }
}

// #[axum_macros::debug_handler]
#[tracing::instrument(level = "debug", skip_all)]
async fn prove_spell(
    State(prover): State<Arc<ProveSpellTxImpl>>,
    Flexible(payload, format): Flexible<ProveRequest>,
) -> Result<Flexible<Vec<Tx>>, (StatusCode, String)> {
    let result = prover.prove_spell_tx(payload).await.map_err(|e| {
        if e.to_string().contains(TRANSIENT_PROVER_FAILURE) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
        (StatusCode::BAD_REQUEST, e.to_string())
    })?;
    Ok(Flexible(result, format))
}
