pub mod app;
pub mod server;
pub mod spell;
pub mod tx;
pub mod wallet;

use crate::{
    cli::{
        server::Server,
        spell::{Check, Prove, SpellCli},
        wallet::{List, WalletCli},
    },
    spell::{CharmsFee, MockProver, ProveSpellTx, ProveSpellTxImpl},
    utils,
    utils::BoxedSP1Prover,
};
#[cfg(feature = "prover")]
use crate::{
    spell::Prover,
    utils::{Shared, sp1::cuda::SP1CudaProver},
};
use bitcoin::{Address, Network};
use charms_app_runner::AppRunner;
use charms_client::tx::Chain;
use charms_data::check;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use serde::Serialize;
use sp1_sdk::{CpuProver, NetworkProver, ProverClient, install::try_install_circuit_artifacts};
use std::{io, net::IpAddr, path::PathBuf, str::FromStr, sync::Arc};

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

    /// Private inputs file (YAML/JSON).
    #[arg(long)]
    private_inputs: Option<PathBuf>,

    /// Beamed-from file (YAML/JSON).
    #[arg(long)]
    beamed_from: Option<PathBuf>,

    /// Pre-requisite transactions (hex-encoded).
    /// These are the transactions that create the UTXOs that the `tx` (and the spell) spends.
    /// If the spell has any reference UTXOs, the transactions creating them must also be included.
    #[arg(long)]
    prev_txs: Vec<String>,

    /// Paths to the apps' Wasm binaries.
    #[arg(long)]
    app_bins: Vec<PathBuf>,

    /// Address to send the change to.
    #[arg(long)]
    change_address: String,

    /// Fee rate: in sats/vB for Bitcoin.
    #[arg(long, default_value = "2.0")]
    fee_rate: f64,

    /// Target chain, defaults to `bitcoin`.
    #[arg(long, default_value = "bitcoin")]
    chain: Chain,

    /// Is mock mode enabled?
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,

    #[arg(long, alias = "collateral")]
    collateral_utxo: Option<String>,
}

#[derive(Args)]
pub struct SpellCheckParams {
    /// Path to spell source file (YAML/JSON).
    #[arg(long, default_value = "/dev/stdin")]
    spell: PathBuf,

    /// Private inputs file (YAML/JSON).
    #[arg(long)]
    private_inputs: Option<PathBuf>,

    /// Beamed-from file (YAML/JSON).
    #[arg(long)]
    beamed_from: Option<PathBuf>,

    /// Paths to the apps' Wasm binaries.
    #[arg(long)]
    app_bins: Vec<PathBuf>,

    /// Pre-requisite transactions (hex-encoded).
    /// These are the transactions that create the UTXOs that the `tx` (and the spell) spends.
    /// If the spell has any reference UTXOs, the transactions creating them must also be included.
    #[arg(long)]
    prev_txs: Option<Vec<String>>,

    /// Target chain, defaults to `bitcoin`.
    #[arg(long, default_value = "bitcoin")]
    chain: Chain,

    /// Is mock mode enabled?
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

#[derive(Args)]
pub struct SpellVkParams {
    /// Is mock mode enabled?
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

#[derive(Subcommand)]
pub enum SpellCommands {
    /// Check the spell is correct.
    Check(#[command(flatten)] SpellCheckParams),
    /// Prove the spell is correct.
    Prove(#[command(flatten)] SpellProveParams),
    /// Print the current protocol version and spell VK (verification key) in JSON.
    Vk(#[command(flatten)] SpellVkParams),
}

#[derive(Args)]
pub struct ShowSpellParams {
    #[arg(long, default_value = "bitcoin")]
    chain: Chain,

    /// Hex-encoded transaction.
    #[arg(long)]
    tx: String,

    /// Output in JSON format (default is YAML).
    #[arg(long)]
    json: bool,

    /// Is mock mode enabled?
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

#[derive(Subcommand)]
pub enum TxCommands {
    /// Show the spell in a transaction. If the transaction has a spell and its valid proof, it
    /// will be printed to stdout.
    ShowSpell(#[command(flatten)] ShowSpellParams),
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
        /// Path to the app's Wasm binary.
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

    /// Is mock mode enabled?
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

#[derive(Subcommand)]
pub enum UtilsCommands {
    /// Install circuit files.
    InstallCircuitFiles,
}

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
                SpellCommands::Vk(params) => spell_cli.print_vk(params.mock),
            }
        }
        Commands::Tx { command } => match command {
            TxCommands::ShowSpell(params) => tx::tx_show_spell(params),
        },
        Commands::App { command } => match command {
            AppCommands::New { name } => app::new(&name),
            AppCommands::Vk { path } => app::vk(path),
            AppCommands::Build => app::build(),
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
    let prover = ProveSpellTxImpl::new(false);
    Server::new(server_config, prover)
}

pub fn prove_impl(mock: bool) -> Box<dyn crate::spell::Prove> {
    tracing::debug!(mock);
    #[cfg(feature = "prover")]
    match mock {
        false => {
            let app_prover = Arc::new(crate::app::Prover {
                sp1_client: Arc::new(Shared::new(crate::cli::app_sp1_client)),
                runner: AppRunner::new(false),
            });
            let spell_sp1_client = crate::cli::spell_sp1_client(&app_prover.sp1_client);
            Box::new(Prover::new(app_prover, spell_sp1_client))
        }
        true => Box::new(MockProver {
            spell_prover_client: Arc::new(utils::Shared::new(|| Box::new(sp1_cpu_prover()))),
        }),
    }
    #[cfg(not(feature = "prover"))]
    {
        Box::new(MockProver {
            spell_prover_client: Arc::new(utils::Shared::new(|| Box::new(sp1_cpu_prover()))),
        })
    }
}

pub(crate) fn charms_fee_settings() -> Option<CharmsFee> {
    let fee_settings_file = std::env::var("CHARMS_FEE_SETTINGS").ok()?;
    let fee_settings: CharmsFee = serde_yaml::from_reader(
        &std::fs::File::open(fee_settings_file)
            .expect("should be able to open the fee settings file"),
    )
    .expect("should be able to parse the fee settings file");

    assert!(
        fee_settings.fee_addresses[&Chain::Bitcoin]
            .iter()
            .all(|(network, address)| {
                let network = Network::from_core_arg(network)
                    .expect("network should be a valid `bitcoind -chain` argument");
                check!(
                    Address::from_str(address)
                        .is_ok_and(|address| address.is_valid_for_network(network))
                );
                true
            }),
        "a fee address is not valid for the specified network"
    );

    Some(fee_settings)
}

fn spell_cli() -> SpellCli {
    let spell_cli = SpellCli {
        app_runner: AppRunner::new(true),
    };
    spell_cli
}

#[cfg(feature = "prover")]
fn app_sp1_client() -> BoxedSP1Prover {
    let name = std::env::var("APP_SP1_PROVER").unwrap_or_default();
    sp1_named_env_client(name.as_str())
}

#[cfg(feature = "prover")]
fn spell_sp1_client(app_sp1_client: &Arc<Shared<BoxedSP1Prover>>) -> Arc<Shared<BoxedSP1Prover>> {
    let name = std::env::var("SPELL_SP1_PROVER").unwrap_or_default();
    match name.as_str() {
        "app" => app_sp1_client.clone(),
        "network" => Arc::new(Shared::new(sp1_network_client)),
        _ => unreachable!("Only 'app' or 'network' are supported as SPELL_SP1_PROVER values"),
    }
}

#[tracing::instrument(level = "info")]
#[cfg(feature = "prover")]
fn charms_sp1_cuda_prover() -> utils::sp1::CudaProver {
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
pub fn sp1_cpu_prover() -> CpuProver {
    ProverClient::builder().cpu().build()
}

#[tracing::instrument(level = "info")]
pub fn sp1_network_prover() -> NetworkProver {
    ProverClient::builder().network().build()
}

#[tracing::instrument(level = "info")]
pub fn sp1_network_client() -> BoxedSP1Prover {
    sp1_named_env_client("network")
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
        "cuda" => Box::new(charms_sp1_cuda_prover()),
        "cpu" => Box::new(sp1_cpu_prover()),
        "network" => Box::new(sp1_network_prover()),
        _ => unimplemented!("only 'cuda', 'cpu' and 'network' are supported as prover values"),
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
