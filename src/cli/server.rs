use crate::{
    cli::ServerConfig,
    spell::{ProveRequest, ProveSpellTx, ProveSpellTxImpl},
    utils::TRANSIENT_PROVER_FAILURE,
};
use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
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
    Json(payload): Json<ProveRequest>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<String>)> {
    let result = prover.prove_spell_tx(payload).await.map_err(|e| {
        if e.to_string().contains(TRANSIENT_PROVER_FAILURE) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string()));
        }
        (StatusCode::BAD_REQUEST, Json(e.to_string()))
    })?;
    Ok(Json(result))
}
