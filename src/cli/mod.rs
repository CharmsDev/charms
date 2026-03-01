pub mod app;
pub mod server;
pub mod spell;
pub mod tx;
pub mod util;
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
use charms_data::{App, check};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use serde::Serialize;
use sp1_sdk::{CpuProver, NetworkProver, ProverClient, install::try_install_circuit_artifacts};
use std::{io, net::IpAddr, path::PathBuf, str::FromStr, sync::Arc};

#[derive(Parser)]
#[command(author, version, about, long_about = "Charms CLI: create, prove, and manage programmable assets (charms) on Bitcoin and Cardano using zero-knowledge proofs.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args)]
pub struct ServerConfig {
    /// IP address to listen on.
    #[arg(long, default_value = "0.0.0.0")]
    ip: IpAddr,

    /// Port to listen on.
    #[arg(long, default_value = "17784")]
    port: u16,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the Charms REST API server (POST /spells/prove, GET /ready).
    Server(#[command(flatten)] ServerConfig),

    /// Create, verify, and prove spells (transaction metadata that defines charm operations).
    Spell {
        #[command(subcommand)]
        command: SpellCommands,
    },

    /// Inspect blockchain transactions for embedded spells.
    Tx {
        #[command(subcommand)]
        command: TxCommands,
    },

    /// Create, build, and inspect Charms apps (WebAssembly programs).
    App {
        #[command(subcommand)]
        command: AppCommands,
    },

    /// List UTXOs with charms in the connected wallet.
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

    /// Utility commands
    Util {
        #[command(subcommand)]
        command: UtilCommands,
    },
}

#[derive(Args)]
pub struct SpellProveParams {
    /// Path to the spell file (YAML or JSON).
    #[arg(long, default_value = "/dev/stdin")]
    spell: PathBuf,

    /// Path to the private inputs file (YAML or JSON).
    #[arg(long)]
    private_inputs: Option<PathBuf>,

    /// Beamed-from mapping as a YAML/JSON string (e.g. '{0: "txid:vout"}').
    #[arg(long)]
    beamed_from: Option<String>,

    /// Hex-encoded pre-requisite transactions.
    /// Must include the transactions that create the UTXOs spent by the spell.
    /// If the spell has reference UTXOs, transactions creating them must also be included.
    #[arg(long)]
    prev_txs: Vec<String>,

    /// Paths to app Wasm binaries (.wasm files).
    #[arg(long)]
    app_bins: Vec<PathBuf>,

    /// Bitcoin or Cardano address to send the change to.
    #[arg(long)]
    change_address: String,

    /// Fee rate in sats/vB (Bitcoin only).
    #[arg(long, default_value = "2.0")]
    fee_rate: f64,

    /// Target chain.
    #[arg(long, default_value = "bitcoin")]
    chain: Chain,

    /// Use mock mode (skip proof generation).
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,

    /// Collateral UTXO for Cardano transactions, as txid:vout (required for --chain cardano).
    #[arg(long, alias = "collateral")]
    collateral_utxo: Option<String>,
}

#[derive(Args)]
pub struct SpellCheckParams {
    /// Path to the spell file (YAML or JSON).
    #[arg(long, default_value = "/dev/stdin")]
    spell: PathBuf,

    /// Path to the private inputs file (YAML or JSON).
    #[arg(long)]
    private_inputs: Option<PathBuf>,

    /// Beamed-from mapping as a YAML/JSON string (e.g. '{0: "txid:vout"}').
    #[arg(long)]
    beamed_from: Option<String>,

    /// Paths to app Wasm binaries (.wasm files).
    #[arg(long)]
    app_bins: Vec<PathBuf>,

    /// Hex-encoded pre-requisite transactions.
    /// Must include the transactions that create the UTXOs spent by the spell.
    /// If the spell has reference UTXOs, transactions creating them must also be included.
    #[arg(long)]
    prev_txs: Option<Vec<String>>,

    /// Target chain.
    #[arg(long, default_value = "bitcoin")]
    chain: Chain,

    /// Use mock mode (skip proof generation).
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

#[derive(Args)]
pub struct SpellVkParams {
    /// Use mock mode (show mock verification key).
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

const SPELL_DATA_HELP: &str = "\
DATA STRUCTURES:

  Spell file (--spell):
    version: 11                     # protocol version
    tx:
      ins:                          # input UTXOs (txid:vout)
        - deadbeef...:0
      outs:                         # output charms (app_index: value)
        - 0: ~                      # output 0: app 0 has no data
        - 1: 4000000                # output 1: app 1 = 4000000
          2: 10000000               #            app 2 = 10000000
      beamed_outs:                  # (optional) beamed output index -> dest hash
        1: 009fb489...
      coins:                        # native coin outputs
        - amount: 4000000           #   amount in lovelace (Cardano) or sats (Bitcoin)
          dest: 716fc738...         #   hex-encoded destination (use `charms util dest`)
          content:                  #   (optional, Cardano) native tokens
            multiasset:
              <policy_id_hex>:
                <asset_name_hex>: <quantity>
    app_public_inputs:              # map of app -> public input data
      t/<identity_hex>/<vk_hex>:    #   token app (t), NFT (n), or contract (c)
      c/0000...0000/<vk_hex>:       #   value can be null or app-specific data

  Private inputs file (--private-inputs):
    t/<identity_hex>/<vk_hex>: <app-specific data>
    c/0000...0000/<vk_hex>: <app-specific data>

  Previous transactions (--prev-txs):
    Each value is one of:
      - raw hex (auto-detected as Bitcoin or Cardano)
      - YAML-tagged: '!bitcoin <hex>' or '!cardano <hex>'
      - YAML-tagged with finality proof:
          '!cardano {tx: <hex>, signature: <hex>}'
      - JSON: '{\"bitcoin\": \"<hex>\"}' or '{\"cardano\": \"<hex>\"}'

  Beamed-from mapping (--beamed-from):
    YAML/JSON mapping: input_index -> [source_utxo, nonce]
    Example: '{0: [712fcb00...f66c:1, 4538918914141394474]}'
";

#[derive(Subcommand)]
pub enum SpellCommands {
    /// Check spell correctness by running app contracts locally (no proof generation).
    #[command(after_long_help = SPELL_DATA_HELP)]
    Check(#[command(flatten)] SpellCheckParams),
    /// Prove spell correctness and build a ready-to-broadcast transaction.
    ///
    /// Outputs a JSON array of hex-encoded transactions (Bitcoin)
    /// or a Ledger CDDL JSON envelope (Cardano).
    #[command(after_long_help = SPELL_DATA_HELP)]
    Prove(#[command(flatten)] SpellProveParams),
    /// Print the current protocol version and spell verification key (VK) as JSON to stdout.
    Vk(#[command(flatten)] SpellVkParams),
}

#[derive(Args)]
pub struct ShowSpellParams {
    /// Target chain.
    #[arg(long, default_value = "bitcoin")]
    chain: Chain,

    /// Hex-encoded transaction.
    #[arg(long)]
    tx: String,

    /// Output in JSON format (default is YAML).
    #[arg(long)]
    json: bool,

    /// Use mock mode (accept mock proofs).
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

#[derive(Subcommand)]
pub enum TxCommands {
    /// Extract and display the spell from a transaction.
    ///
    /// Prints the spell as YAML (default) or JSON if the transaction contains a valid proof.
    ShowSpell(#[command(flatten)] ShowSpellParams),
}

#[derive(Subcommand)]
pub enum AppCommands {
    /// Create a new app from template.
    New {
        /// Name of the app. A directory with this name will be created.
        name: String,
    },

    /// Build the app to WebAssembly (wasm32-wasip1).
    ///
    /// Prints the path to the built .wasm binary to stdout.
    Build,

    /// Show verification key (SHA-256 of Wasm binary) for an app.
    ///
    /// Prints the hex-encoded VK to stdout.
    Vk {
        /// Path to app Wasm binary (builds the app if omitted).
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum WalletCommands {
    /// List outputs with charms in the user's wallet.
    ///
    /// Outputs YAML (default) or JSON. Requires `bitcoin-cli` to be available.
    List(#[command(flatten)] WalletListParams),
}

#[derive(Args)]
pub struct WalletListParams {
    /// Output in JSON format (default is YAML).
    #[arg(long)]
    json: bool,

    /// Use mock mode (accept mock proofs).
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

#[derive(Args)]
pub struct DestParams {
    /// Bitcoin or Cardano address to convert.
    #[arg(long)]
    addr: Option<String>,

    /// Charms apps for proxy script address (format: tag/identity_hex/vk_hex).
    #[arg(long)]
    apps: Vec<App>,

    /// Target chain (auto-detected from address if omitted).
    #[arg(long)]
    chain: Option<Chain>,
}

#[derive(Subcommand)]
pub enum UtilCommands {
    /// Install circuit files.
    #[clap(hide = true)]
    InstallCircuitFiles,

    /// Print hex-encoded `dest` value for use in spell YAML.
    ///
    /// Accepts either --addr (Bitcoin/Cardano address) or --apps (Cardano only).
    /// Prints the hex-encoded destination bytes to stdout.
    Dest(#[command(flatten)] DestParams),
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
        Commands::Util { command } => match command {
            UtilCommands::InstallCircuitFiles => {
                let _ = try_install_circuit_artifacts("groth16");
                Ok(())
            }
            UtilCommands::Dest(params) => util::dest(params),
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
