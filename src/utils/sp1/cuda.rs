use crate::utils::retry;
use anyhow::bail;
use async_trait::async_trait;
use reqwest::{Request, Response};
use sp1_core_machine::{io::SP1Stdin, reduce::SP1ReduceProof, utils::SP1CoreProverError};
use sp1_cuda::{
    CompressRequestPayload, ShrinkRequestPayload, StatelessProveCoreRequestPayload,
    WrapRequestPayload, block_on,
    proto::api::{ProverServiceClient, ReadyRequest},
};
use sp1_prover::{
    InnerSC, OuterSC, SP1CoreProof, SP1ProvingKey, SP1RecursionProverError, SP1VerifyingKey,
};
use std::io;
use twirp::{
    Client, Middleware, Next, async_trait,
    reqwest::{self},
    url::Url,
};

/// A remote client to [sp1_prover::SP1Prover] that runs inside a container.
///
/// This is currently used to provide experimental support for GPU hardware acceleration.
///
/// **WARNING**: This is an experimental feature and may not work as expected.
pub struct SP1CudaProver {
    /// The gRPC client to communicate with the container.
    pub client: Client,
}

const RETRY_SECS: u64 = 60;

impl SP1CudaProver {
    /// Creates a new [SP1Prover] that runs inside a Docker container and returns a
    /// [SP1ProverClient] that can be used to communicate with the container.
    pub fn new(gpu_service_url: String) -> anyhow::Result<Self> {
        let client = Client::new(
            Url::parse(&gpu_service_url).expect("failed to parse url"),
            reqwest::Client::new(),
            vec![Box::new(LoggingMiddleware)],
        )?;

        Ok(Self { client })
    }

    #[tracing::instrument(level = "info", skip_all)]
    pub fn ready(&self) -> anyhow::Result<()> {
        tracing::info!("waiting for proving server to be ready");
        block_on(retry(RETRY_SECS, || async {
            match self.client.ready(ReadyRequest {}).await {
                Ok(response) if response.ready => Ok(()),
                Ok(_) => bail!("proving server is not ready"),
                Err(e) => bail!("Error checking server readiness: {}", e),
            }
        }))
    }

    /// Executes the [sp1_prover::SP1Prover::prove_core] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    #[tracing::instrument(level = "info", skip_all)]
    pub fn prove_core_stateless(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
    ) -> sp1_cuda::Result<SP1CoreProof, SP1CoreProverError> {
        let payload = StatelessProveCoreRequestPayload {
            pk: pk.clone(),
            stdin: stdin.clone(),
        };
        let request = sp1_cuda::proto::api::ProveCoreRequest {
            data: bincode::serialize(&payload)
                .map_err(|e| SP1CoreProverError::SerializationError(e))?,
        };
        let response = block_on(retry(RETRY_SECS, || {
            self.client.prove_core_stateless(request.clone())
        }))
        .map_err(|e| {
            tracing::error!("{:?}", e);
            SP1CoreProverError::IoError(io::Error::other(e))
        })?;
        let proof: SP1CoreProof = bincode::deserialize(&response.result)
            .map_err(|e| SP1CoreProverError::SerializationError(e))?;
        Ok(proof)
    }

    /// Executes the [sp1_prover::SP1Prover::compress] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    #[tracing::instrument(level = "info", skip_all)]
    pub fn compress(
        &self,
        vk: &SP1VerifyingKey,
        proof: SP1CoreProof,
        deferred_proofs: Vec<SP1ReduceProof<InnerSC>>,
    ) -> sp1_cuda::Result<SP1ReduceProof<InnerSC>, SP1RecursionProverError> {
        let payload = CompressRequestPayload {
            vk: vk.clone(),
            proof,
            deferred_proofs,
        };
        let request = sp1_cuda::proto::api::CompressRequest {
            data: bincode::serialize(&payload)
                .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))?,
        };

        let response = block_on(retry(RETRY_SECS, || self.client.compress(request.clone())))
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))?;
        let proof: SP1ReduceProof<InnerSC> = bincode::deserialize(&response.result)
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))?;
        Ok(proof)
    }

    /// Executes the [sp1_prover::SP1Prover::shrink] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn shrink(
        &self,
        reduced_proof: SP1ReduceProof<InnerSC>,
    ) -> sp1_cuda::Result<SP1ReduceProof<InnerSC>, SP1RecursionProverError> {
        let payload = ShrinkRequestPayload {
            reduced_proof: reduced_proof.clone(),
        };
        let data = bincode::serialize(&payload).map_err(|e| {
            SP1RecursionProverError::RuntimeError(format!(
                "Failed to serialize shrink request: {}",
                e
            ))
        })?;
        let request = sp1_cuda::proto::api::ShrinkRequest { data };

        let response = block_on(retry(RETRY_SECS, || self.client.shrink(request.clone())))
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))?;
        let proof: SP1ReduceProof<InnerSC> = bincode::deserialize(&response.result)
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))?;
        Ok(proof)
    }

    /// Executes the [sp1_prover::SP1Prover::wrap_bn254] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn wrap_bn254(
        &self,
        reduced_proof: SP1ReduceProof<InnerSC>,
    ) -> sp1_cuda::Result<SP1ReduceProof<OuterSC>, SP1RecursionProverError> {
        let payload = WrapRequestPayload {
            reduced_proof: reduced_proof.clone(),
        };
        let data = bincode::serialize(&payload).map_err(|e| {
            SP1RecursionProverError::RuntimeError(format!(
                "Failed to serialize wrap request: {}",
                e
            ))
        })?;
        let request = sp1_cuda::proto::api::WrapRequest { data };

        let response = block_on(retry(RETRY_SECS, || self.client.wrap(request.clone())))
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))?;
        let proof: SP1ReduceProof<OuterSC> = bincode::deserialize(&response.result)
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))?;
        Ok(proof)
    }
}

struct LoggingMiddleware;

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn handle(&self, req: Request, next: Next<'_>) -> sp1_cuda::Result<Response> {
        tracing::debug!("{:?}", req);
        let response = next.run(req).await;
        match response {
            Ok(response) => {
                tracing::info!("{:?}", response);
                Ok(response)
            }
            Err(e) => Err(e),
        }
    }
}
