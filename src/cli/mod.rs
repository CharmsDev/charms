pub mod app;
pub mod server;
pub mod spell;
pub mod tx;
pub mod wallet;

#[cfg(feature = "prover")]
use crate::utils::sp1::cuda::SP1CudaProver;
use crate::{
    cli::{
        server::Server,
        spell::{Check, Prove, SpellCli},
        wallet::{List, WalletCli},
    },
    spell::{CharmsFee, Prover},
    utils::{self, BoxedSP1Prover, Shared},
};
use bitcoin::{address::NetworkUnchecked, Address};
use btc_finality::{prove_consensus, prove_tx_inclusion};
use charms_app_runner::AppRunner;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
#[cfg(not(feature = "prover"))]
use reqwest::Client;
use serde::Serialize;
use sp1_sdk::{install::try_install_circuit_artifacts, CpuProver, ProverClient};
use std::{io, net::IpAddr, path::PathBuf, str::FromStr, sync::Arc};
use utils::AsyncShared;

pub const BITCOIN: &str = "bitcoin";
pub const CARDANO: &str = "cardano";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args)]
pub struct ServerConfig {
    /// IP address to listen on, defaults to `0.0.0.0` (all on IPv4).
    #[arg(long, default_value = "0.0.0.0")]
    ip: IpAddr,

    /// Port to listen on, defaults to 17784.
    #[arg(long, default_value = "17784")]
    port: u16,

    /// bitcoind RPC URL. Set via RPC_URL env var.
    #[arg(long, env, default_value = "http://localhost:48332")]
    #[cfg(not(feature = "prover"))]
    rpc_url: String,

    /// bitcoind RPC user. Recommended to set via RPC_USER env var.
    #[arg(long, env, default_value = "hello")]
    #[cfg(not(feature = "prover"))]
    rpc_user: String,

    /// bitcoind RPC password. Recommended to set via RPC_PASSWORD env var.
    /// Use the .cookie file in the bitcoind data directory to look up the password:
    /// the format is `__cookie__:password`.
    #[arg(long, env, default_value = "world")]
    #[cfg(not(feature = "prover"))]
    rpc_password: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Charms API Server.
    Server(#[command(flatten)] ServerConfig),

    /// Work with spells.
    Spell {
        #[command(subcommand)]
        command: SpellCommands,
    },

    /// Work with underlying blockchain transactions.
    Tx {
        #[command(subcommand)]
        command: TxCommands,
    },

    /// Manage apps.
    App {
        #[command(subcommand)]
        command: AppCommands,
    },

    /// Wallet commands.
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },

    /// Generate shell completion scripts
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Utils
    #[clap(hide = true)]
    Utils {
        #[command(subcommand)]
        command: UtilsCommands,
    },
}

#[derive(Args)]
pub struct SpellProveParams {
    /// Spell source file (YAML/JSON).
    #[arg(long, default_value = "/dev/stdin")]
    spell: PathBuf,

    /// Pre-requisite transactions (hex-encoded) separated by commas (`,`).
    /// These are the transactions that create the UTXOs that the `tx` (and the spell) spends.
    /// If the spell has any reference UTXOs, the transactions creating them must also be included.
    #[arg(long, value_delimiter = ',')]
    prev_txs: Vec<String>,

    /// Path to the app binaries (RISC-V ELF files) referenced by the spell.
    #[arg(long, value_delimiter = ',')]
    app_bins: Vec<PathBuf>,

    /// UTXO ID of the funding transaction output (txid:vout).
    /// This UTXO will be spent to pay the fees (at the `fee-rate` per vB) for the commit and spell
    /// transactions. The rest of the value will be returned to the `change-address`.
    #[arg(long, alias = "funding-utxo-id")]
    funding_utxo: String,

    /// Value of the funding UTXO in sats (for Bitcoin) or lovelace (for Cardano).
    #[arg(long)]
    funding_utxo_value: u64,

    /// Address to send the change to.
    #[arg(long)]
    change_address: String,

    /// Fee rate: in sats/vB for Bitcoin.
    #[arg(long, default_value = "2.0")]
    fee_rate: f64,

    /// Target chain, defaults to `bitcoin`.
    #[arg(long, default_value = "bitcoin")]
    chain: String,
}

#[derive(Args)]
pub struct SpellCheckParams {
    /// Path to spell source file (YAML/JSON).
    #[arg(long, default_value = "/dev/stdin")]
    spell: PathBuf,

    /// Path to the apps' RISC-V binaries.
    #[arg(long, value_delimiter = ',')]
    app_bins: Vec<PathBuf>,

    /// Pre-requisite transactions (hex-encoded) separated by commas (`,`).
    /// These are the transactions that create the UTXOs that the `tx` (and the spell) spends.
    /// If the spell has any reference UTXOs, the transactions creating them must also be included.
    #[arg(long, value_delimiter = ',')]
    prev_txs: Option<Vec<String>>,

    /// Target chain, defaults to `bitcoin`. Can be `bitcoin` or `cardano`.
    #[arg(long, default_value = "bitcoin")]
    chain: String,
}

#[derive(Subcommand)]
pub enum SpellCommands {
    /// Check the spell is correct.
    Check(#[command(flatten)] SpellCheckParams),
    /// Prove the spell is correct.
    Prove(#[command(flatten)] SpellProveParams),
    /// Print the current protocol version and spell VK (verification key) in JSON.
    Vk,
}

#[derive(Subcommand)]
#[command(rename_all = "kebab-case")]
pub enum TxCommands {
    /// Show the spell in a transaction. If the transaction has a spell and its valid proof, it
    /// will be printed to stdout.
    ShowSpell {
        #[arg(long, default_value = "bitcoin")]
        chain: String,

        /// Hex-encoded transaction.
        #[arg(long)]
        tx: String,

        /// Output in JSON format (default is YAML).
        #[arg(long)]
        json: bool,
    },
    #[command(name = "prove-btc-consensus")]
    ProveBitcoinConsensus {
        // Path to previous proof (if not genesis case)
        #[arg(long)]
        previous_proof: Option<String>,

        // Number of headers to validate after previous block
        #[arg(long)]
        block_height: u32,
    },
    #[command(name = "prove-btc-inclusion")]
    ProveBitcoinInclusion {
        // TxId included in given block root
        #[arg(long)]
        tx: String,

        // Consensus proof at given block root
        #[arg(long)]
        consensus_proof: String,

        // Height at given block root
        #[arg(long)]
        block_height: u32,
    },
}

#[derive(Subcommand)]
pub enum AppCommands {
    /// Create a new app.
    New {
        /// Name of the app. Directory <NAME> will be created.
        name: String,
    },

    /// Build the app.
    Build,

    /// Show verification key for an app.
    Vk {
        /// Path to the app's RISC-V binary.
        path: Option<PathBuf>,
    },

    /// Test the app for a spell.
    Run {
        /// Path to spell source file (YAML/JSON).
        #[arg(long, default_value = "/dev/stdin")]
        spell: PathBuf,

        /// Path to the app's RISC-V binary.
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum WalletCommands {
    /// List outputs with charms in the user's wallet.
    List(#[command(flatten)] WalletListParams),
}

#[derive(Args)]
pub struct WalletListParams {
    /// Output in JSON format (default is YAML)
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct SpellCastParams {
    /// Path to spell source file (YAML/JSON).
    #[arg(long, default_value = "/dev/stdin")]
    spell: PathBuf,

    /// Path to the apps' RISC-V binaries.
    #[arg(long, value_delimiter = ',')]
    app_bins: Vec<PathBuf>,

    /// Funding UTXO ID (`txid:vout`).
    #[arg(long, alias = "funding-utxo-id")]
    funding_utxo: String,

    /// Fee rate: in sats/vB for Bitcoin.
    #[arg(long, default_value = "2.0")]
    fee_rate: f64,

    /// Target chain, defaults to `bitcoin`.
    #[arg(long, default_value = "bitcoin")]
    chain: String,

    /// Pre-requisite transactions (hex-encoded) separated by commas (`,`).
    /// These are the transactions that create the UTXOs that the `tx` (and the spell) spends.
    /// If the spell has any reference UTXOs, the transactions creating them must also be included.
    #[arg(long, value_delimiter = ',')]
    prev_txs: Option<Vec<String>>,
}

#[derive(Subcommand)]
pub enum UtilsCommands {
    /// Install circuit files.
    InstallCircuitFiles,
}

pub const DEFAULT_BTC_FINALITY_PATH: &str = "./btc_finality_data.json";

pub async fn run() -> anyhow::Result<()> {
    utils::logger::setup_logger();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server(server_config) => {
            let server = server(server_config);
            server.serve().await
        }
        Commands::Spell { command } => {
            let spell_cli = spell_cli();
            match command {
                SpellCommands::Check(params) => spell_cli.check(params),
                SpellCommands::Prove(params) => spell_cli.prove(params).await,
                SpellCommands::Vk => spell_cli.print_vk(),
            }
        }
        Commands::Tx { command } => match command {
            TxCommands::ShowSpell { chain, tx, json } => tx::tx_show_spell(chain, tx, json),
            TxCommands::ProveBitcoinConsensus {
                previous_proof,
                block_height,
            } => prove_consensus(previous_proof, block_height),
            TxCommands::ProveBitcoinInclusion {
                tx,
                consensus_proof,
                block_height,
            } => prove_tx_inclusion(tx, consensus_proof, block_height),
        },
        Commands::App { command } => match command {
            AppCommands::New { name } => app::new(&name),
            AppCommands::Vk { path } => app::vk(path),
            AppCommands::Build => app::build(),
            AppCommands::Run { spell, path } => app::run(spell, path),
        },
        Commands::Wallet { command } => {
            let wallet_cli = wallet_cli();
            match command {
                WalletCommands::List(params) => wallet_cli.list(params),
            }
        }
        Commands::Completions { shell } => generate_completions(shell),
        Commands::Utils { command } => match command {
            UtilsCommands::InstallCircuitFiles => {
                let _ = try_install_circuit_artifacts("groth16");
                Ok(())
            }
        },
    }
}

fn server(server_config: ServerConfig) -> Server {
    let prover = AsyncShared::new(spell_prover);
    Server::new(server_config, prover)
}

#[tracing::instrument(level = "debug")]
fn spell_prover() -> Prover {
    let app_prover = Arc::new(app::Prover {
        sp1_client: Arc::new(Shared::new(app_sp1_client)),
        runner: AppRunner::new(),
    });

    let spell_sp1_client = spell_sp1_client(&app_prover.sp1_client);

    let charms_fee_settings = charms_fee_settings();

    let charms_prove_api_url = std::env::var("CHARMS_PROVE_API_URL")
        .ok()
        .unwrap_or("https://prove.charms.dev/spells/prove".to_string());

    #[cfg(not(feature = "prover"))]
    let client = Client::builder()
        .use_rustls_tls() // avoids system OpenSSL issues
        .http2_prior_knowledge()
        .http2_adaptive_window(true)
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("HTTP client should be created successfully");

    let spell_prover = Prover {
        app_prover: app_prover.clone(),
        prover_client: spell_sp1_client.clone(),
        charms_fee_settings,
        charms_prove_api_url,
        #[cfg(not(feature = "prover"))]
        client,
    };
    spell_prover
}

fn charms_fee_settings() -> Option<CharmsFee> {
    charms_fee_address().map(|fee_address| {
        let charms_fee_rate = charms_fee_rate();
        let charms_fee_base = charms_fee_base();
        CharmsFee {
            fee_address: fee_address.assume_checked().to_string(),
            fee_rate: charms_fee_rate,
            fee_base: charms_fee_base,
        }
    })
}

fn charms_fee_address() -> Option<Address<NetworkUnchecked>> {
    std::env::var("CHARMS_FEE_ADDRESS")
        .ok()
        .map(|s| Address::from_str(&s).expect("CHARMS_FEE_ADDRESS must be a valid Bitcoin address"))
}

fn charms_fee_rate() -> u64 {
    std::env::var("CHARMS_FEE_RATE")
        .ok()
        .map(|s| {
            s.parse::<u64>()
                .expect("CHARMS_FEE_RATE must be an unsigned integer")
        })
        .unwrap_or(500)
}

fn charms_fee_base() -> u64 {
    std::env::var("CHARMS_FEE_BASE")
        .ok()
        .map(|s| {
            s.parse::<u64>()
                .expect("CHARMS_FEE_BASE must be an unsigned integer")
        })
        .unwrap_or(1000)
}

fn spell_cli() -> SpellCli {
    let spell_prover = spell_prover();

    let spell_cli = SpellCli {
        app_prover: spell_prover.app_prover.clone(),
        spell_prover: Arc::new(spell_prover),
        app_runner: AppRunner::new(),
    };
    spell_cli
}

fn app_sp1_client() -> BoxedSP1Prover {
    let name = std::env::var("APP_SP1_PROVER").unwrap_or_default();
    sp1_named_env_client(name.as_str())
}

fn spell_sp1_client(app_sp1_client: &Arc<Shared<BoxedSP1Prover>>) -> Arc<Shared<BoxedSP1Prover>> {
    let name = std::env::var("SPELL_SP1_PROVER").unwrap_or_default();
    match name.as_str() {
        "app" => app_sp1_client.clone(),
        "env" | "" => Arc::new(Shared::new(sp1_env_client)),
        _ => unreachable!("Only 'app' or 'env' are supported as SPELL_SP1_PROVER values"),
    }
}

#[tracing::instrument(level = "info")]
#[cfg(feature = "prover")]
fn charms_sp1_cuda_client() -> utils::sp1::CudaProver {
    utils::sp1::CudaProver::new(
        sp1_prover::SP1Prover::new(),
        SP1CudaProver::new(gpu_service_url()).unwrap(),
    )
}

#[cfg(feature = "prover")]
fn gpu_service_url() -> String {
    std::env::var("SP1_GPU_SERVICE_URL").unwrap_or("http://localhost:3000/twirp/".to_string())
}

#[tracing::instrument(level = "info")]
pub fn sp1_cpu_client() -> CpuProver {
    ProverClient::builder().cpu().build()
}

#[tracing::instrument(level = "debug")]
fn sp1_env_client() -> BoxedSP1Prover {
    sp1_named_env_client("env")
}

#[tracing::instrument(level = "debug")]
fn sp1_named_env_client(name: &str) -> BoxedSP1Prover {
    let sp1_prover_env_var = std::env::var("SP1_PROVER").unwrap_or_default();
    let name = match name {
        "env" => sp1_prover_env_var.as_str(),
        _ => name,
    };
    match name {
        #[cfg(feature = "prover")]
        "cuda" => Box::new(charms_sp1_cuda_client()),
        "cpu" => Box::new(sp1_cpu_client()),
        _ => Box::new(ProverClient::from_env()),
    }
}

fn wallet_cli() -> WalletCli {
    let wallet_cli = WalletCli {};
    wallet_cli
}

fn generate_completions(shell: Shell) -> anyhow::Result<()> {
    let cmd = &mut Cli::command();
    generate(shell, cmd, cmd.get_name().to_string(), &mut io::stdout());
    Ok(())
}

fn print_output<T: Serialize>(output: &T, json: bool) -> anyhow::Result<()> {
    match json {
        true => serde_json::to_writer_pretty(io::stdout(), &output)?,
        false => serde_yaml::to_writer(io::stdout(), &output)?,
    };
    Ok(())
}

#[cfg(test)]
mod test {

    #[test]
    fn dummy() {}
}
