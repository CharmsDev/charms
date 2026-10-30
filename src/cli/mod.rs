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
    utils::{BoxedSP1Prover, block_on},
};
#[cfg(feature = "prover")]
use crate::{spell::Prover, utils::Shared};
use bitcoin::{Address, Network};
use charms_app_runner::AppRunner;
use charms_client::tx::Chain;
use charms_data::{App, check};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{CompleteEnv, Shell, generate};
use serde::Serialize;
use sp1_sdk::{CpuProver, NetworkProver, ProverClient, install::try_install_circuit_artifacts};
use std::{io, net::IpAddr, path::PathBuf, str::FromStr, sync::Arc};

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Charms CLI: create, prove, and manage programmable assets (charms) on Bitcoin and Cardano using zero-knowledge proofs."
)]
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

    /// Generate shell completion scripts (static).
    ///
    /// For dynamic completions (recommended), run `charms completions --help`.
    #[command(after_long_help = "\
DYNAMIC COMPLETIONS (RECOMMENDED):

  Dynamic completions stay up-to-date automatically when charms is upgraded.

  Bash (add to ~/.bashrc):
    source <(COMPLETE=bash charms)

  Zsh (add to ~/.zshrc):
    source <(COMPLETE=zsh charms)

  Fish (add to ~/.config/fish/completions/charms.fish):
    COMPLETE=fish charms | source

  Elvish (add to ~/.elvish/rc.elv):
    eval (E:COMPLETE=elvish charms | slurp)

STATIC COMPLETIONS:

  Use this if you prefer pre-generated scripts or if dynamic completions
  don't work in your environment.

  Bash (add to ~/.bashrc):
    source <(charms completions bash)

  Zsh (add to ~/.zshrc):
    source <(charms completions zsh)

  Fish (run once):
    charms completions fish > ~/.config/fish/completions/charms.fish

  PowerShell (add to $PROFILE):
    charms completions powershell | Out-String | Invoke-Expression

  Elvish (add to ~/.elvish/rc.elv):
    eval (charms completions elvish | slurp)

After setup, restart your shell or source the config file.
Then type `charms <TAB>` to see available commands and options.")]
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

#[derive(Clone, Debug, ValueEnum)]
pub enum Output {
    #[value(name = "cbor")]
    Cbor,
    #[value(name = "json")]
    Json,
}

/// How `spell prove --chain ethereum` prints its result.
///
/// `--output` is the prover payload encoding (`--payload` only). This flag is
/// the Ethereum transaction encoding and does not replace it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum EthereumTxFormat {
    /// JSON array of one CHET record hex string.
    #[value(name = "record")]
    Record,
    /// One `0x`-prefixed unsigned EIP-1559 transaction.
    #[value(name = "unsigned-tx")]
    UnsignedTx,
}

#[derive(Args)]
pub struct SpellProveParams {
    /// Path to the spell file (YAML or JSON).
    #[arg(long, default_value = "/dev/stdin")]
    spell: PathBuf,

    /// Output proving API payload instead of calling the API.
    #[arg(long, default_value = "false", hide_env = true)]
    payload: bool,

    /// Output format for payload (JSON or CBOR).
    #[arg(
        long,
        short = 'o',
        default_value = "json",
        value_enum,
        requires = "payload"
    )]
    output: Output,

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

    /// Path to a YAML/JSON file mapping a versioned app's `vk` (hex) to its
    /// `{public_key, signature}` (hex). Required for versioned apps; omitted for simple
    /// (immutable) apps.
    #[arg(long)]
    app_signatures: Option<PathBuf>,

    /// Bitcoin or Cardano address to send the change to.
    /// Required for Bitcoin and Cardano. Not used for an Ethereum placeholder.
    #[arg(long)]
    change_address: Option<String>,

    /// Fee rate in sats/vB (Bitcoin only).
    #[arg(long, default_value = "2.0")]
    fee_rate: f64,

    /// Target chain.
    #[arg(long, default_value = "bitcoin")]
    chain: Chain,

    /// Ethereum account that submits the placeholder. This is `msg.sender` in the anchor,
    /// not the output owner. Required for `--chain ethereum`.
    #[arg(long)]
    caller: Option<String>,

    /// 32-byte salt for an empty-input Ethereum spell. Required for `--chain ethereum`.
    /// This is not the beam nonce.
    #[arg(long)]
    salt: Option<String>,

    /// EVM chain id mixed into the placeholder UTXO id. Required for `--chain ethereum`.
    #[arg(long)]
    chain_id: Option<u64>,

    /// Charms proxy address mixed into the placeholder UTXO id. Required for `--chain ethereum`.
    #[arg(long)]
    charms: Option<String>,

    /// Ethereum prove output. `record` (default) is the CHET envelope.
    /// `unsigned-tx` is one 0x-prefixed unsigned type-2 transaction.
    /// `--output` selects the prover payload encoding and is a different flag.
    #[arg(long, value_enum, default_value = "record")]
    tx_format: EthereumTxFormat,

    /// Account nonce. Required when `--tx-format` is `unsigned-tx`. Ethereum only.
    #[arg(
        long,
        required_if_eq("tx_format", "unsigned-tx"),
        conflicts_with = "payload"
    )]
    nonce: Option<u64>,

    /// Gas limit. Required when `--tx-format` is `unsigned-tx`. Ethereum only.
    #[arg(
        long,
        required_if_eq("tx_format", "unsigned-tx"),
        conflicts_with = "payload"
    )]
    gas_limit: Option<u64>,

    /// Max fee per gas, in wei. Required when `--tx-format` is `unsigned-tx`. Ethereum only.
    #[arg(
        long,
        required_if_eq("tx_format", "unsigned-tx"),
        conflicts_with = "payload"
    )]
    max_fee_per_gas: Option<u128>,

    /// Max priority fee per gas, in wei. Required when `--tx-format` is `unsigned-tx`.
    /// Ethereum only.
    #[arg(
        long,
        required_if_eq("tx_format", "unsigned-tx"),
        conflicts_with = "payload"
    )]
    max_priority_fee_per_gas: Option<u128>,

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

    /// Path to a YAML/JSON file mapping a versioned app's `vk` (hex) to its
    /// `{public_key, signature}` (hex). Required for versioned apps; omitted for simple
    /// (immutable) apps.
    #[arg(long)]
    app_signatures: Option<PathBuf>,

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
        An Ethereum record may include \"signature\", the 64-byte
        scrolls_ethereum signature as hex. Without it the record is not final.

  Beamed-from mapping (--beamed-from):
    YAML/JSON mapping: input_index -> [source_utxo, nonce]
    Example: '{0: [712fcb00...f66c:1, 4538918914141394474]}'
";

#[derive(Subcommand)]
pub enum SpellCommands {
    /// Check spell correctness by running app contracts locally (no proof generation).
    #[command(after_long_help = SPELL_DATA_HELP)]
    Check(#[command(flatten)] SpellCheckParams),
    /// Prove a spell and print the chain result.
    ///
    /// Bitcoin prints a JSON array of hex-encoded transactions.
    /// Cardano prints a Ledger CDDL JSON envelope.
    /// Ethereum defaults to `--tx-format record`: a JSON array of one hex string.
    /// The hex is the Charms record. `tx build` encodes that hex into the signable call.
    /// `--tx-format unsigned-tx` prints one 0x-prefixed unsigned type-2 transaction instead.
    /// That form needs `--nonce`, `--gas-limit`, `--max-fee-per-gas`, and
    /// `--max-priority-fee-per-gas`. The transaction value is 0.
    /// `--output` is the prover payload encoding and does not select this format.
    /// An empty Ethereum UTXO does not call the prover and does not take `--prev-txs`.
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

    /// Transaction hex.
    ///
    /// Bitcoin and Cardano take the raw transaction.
    /// Ethereum takes the CHET record from `spell prove`, or a raw transaction
    /// from `cast tx <hash> --raw` (signed or unsigned type 2, type 1, or legacy).
    /// A `0x` prefix and surrounding whitespace are accepted.
    #[arg(long)]
    tx: String,

    /// Output in JSON format (default is YAML).
    #[arg(long)]
    json: bool,

    /// Use mock mode (accept mock proofs).
    #[arg(long, default_value = "false", hide_env = true)]
    mock: bool,
}

#[derive(Args)]
pub struct TxBuildParams {
    /// Target chain.
    #[arg(long, default_value = "bitcoin")]
    chain: Chain,

    /// Hex-encoded Charms record from `spell prove --chain ethereum`.
    /// One element of that JSON array. This hex is not a signable transaction.
    #[arg(long)]
    tx: String,
}

#[derive(Subcommand)]
pub enum TxCommands {
    /// Extract and display the spell from a transaction.
    ///
    /// Prints YAML by default, or JSON with `--json`.
    ///
    /// Bitcoin and Cardano print the spell when the proof is valid.
    /// Ethereum accepts the CHET record from `spell prove` (the proof is checked)
    /// or a raw transaction. A `transact` call prints the spell from the calldata.
    /// An ERC-20 `transfer` or `transferFrom` prints an empty spell: protocol
    /// version 16, no inputs, no outputs, and no apps. The facade token builds
    /// the real spell inside the contract, so the calldata has none. Any other
    /// calldata is an error.
    ShowSpell(#[command(flatten)] ShowSpellParams),

    /// Encode a Charms record as the signable contract call.
    ///
    /// Ethereum reads the record hex from `spell prove` and prints
    /// `{from, to, data, value}`. `data` is `transact` calldata. The wallet
    /// adds the account nonce, the gas fields, and the signature.
    Build(#[command(flatten)] TxBuildParams),
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
    /// Prints the path to the built .wasm binary to stdout. If `.charms/app-key.json`
    /// exists (from `app keygen`), also signs the binary and writes `<wasm-path>.sig.yaml`.
    Build,

    /// Show verification key (VK) for an app.
    ///
    /// For a simple (immutable) app the VK is SHA-256 of the Wasm binary.
    /// For a versioned app, pass `--pubkey` to compute SHA-256 of the signing public key.
    /// When neither `<PATH>` nor `--pubkey` is given, uses the `vk` from `.charms/app-key.json`
    /// if that file exists (from `app keygen`); otherwise builds the app and hashes the Wasm.
    /// Prints the hex-encoded VK to stdout.
    Vk {
        /// Path to app Wasm binary (ignored when `--pubkey` is set; otherwise builds the app
        /// if omitted and `.charms/app-key.json` does not exist).
        path: Option<PathBuf>,

        /// Path to a BIP-340 x-only public key (secp256k1) in hex, or app keypair JSON.
        /// When set, prints the VK of the corresponding versioned app
        /// (SHA-256 of the public key).
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },

    /// Generate a new BIP-340 Schnorr signing keypair (secp256k1) for a versioned app.
    ///
    /// Writes a JSON object with hex-encoded `public_key`, `secret_key`, and computed `vk`
    /// (SHA-256 of public key) to `--out` (default: `.charms/app-key.json`).
    ///
    /// **Security:** the `secret_key` field is sensitive. Do not commit it to source
    /// control or paste it into chats/logs.
    Keygen {
        /// Path to write the keypair JSON to (default: `.charms/app-key.json`).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Sign a Wasm binary's SHA-256 hash with an app signing key.
    ///
    /// The signature is a BIP-340 Schnorr signature (over secp256k1) of the binary's
    /// SHA-256 hash. By default writes `<wasm-path>.sig.yaml` (same as `app build`
    /// auto-signing).
    Sign {
        /// Path to the keypair JSON produced by `app keygen` (default: `.charms/app-key.json`).
        #[arg(long, default_value = ".charms/app-key.json")]
        key: PathBuf,

        /// Path to the Wasm binary to sign (uses the release build output if omitted).
        #[arg(long)]
        bin: Option<PathBuf>,

        /// Path to write the signature to (default: `<wasm-path>.sig.yaml`).
        /// `.yaml`/`.yml` extensions write a VK-keyed YAML map; other extensions write JSON.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Verify a Wasm binary signature produced by `app sign`.
    ///
    /// Checks the BIP-340 Schnorr signature over the binary's SHA-256 hash.
    /// By default reads `<wasm-path>.sig.yaml` (same as `app sign` / `app build` auto-signing).
    Verify {
        /// Path to the Wasm binary to verify (uses the release build output if omitted).
        #[arg(long)]
        bin: Option<PathBuf>,

        /// Path to the signature file (default: `<wasm-path>.sig.yaml`).
        #[arg(long)]
        sig: Option<PathBuf>,
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

    CompleteEnv::with_factory(Cli::command).complete();
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
            TxCommands::Build(params) => tx::tx_build(params),
        },
        Commands::App { command } => match command {
            AppCommands::New { name } => app::new(&name),
            AppCommands::Vk { path, pubkey } => app::vk(path, pubkey),
            AppCommands::Build => app::build(),
            AppCommands::Keygen { out } => app::keygen(out),
            AppCommands::Sign { key, bin, out } => app::sign(key, bin, out),
            AppCommands::Verify { bin, sig } => app::verify(bin, sig),
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
pub fn sp1_cpu_prover() -> CpuProver {
    block_on(ProverClient::builder().cpu().build())
}

#[tracing::instrument(level = "info")]
pub fn sp1_network_prover() -> NetworkProver {
    block_on(ProverClient::builder().network().build())
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
    use super::*;
    use crate::cli::spell::ethereum_placeholder_json;
    use charms_client::ethereum_tx::from_envelope_hex;
    use charms_client::tx::EnchantedTx;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TX_ID: &str = "8cb5ef4b8fd977bd570fbe98db1eaed4f1bb223086ab3e8d0b1b6e892abe2b5d";
    const CALLER: &str = "1111111111111111111111111111111111111111";
    const SALT: &str = "0000000000000000000000000000000000000000000000000000000000000007";
    const CHARMS: &str = "3333333333333333333333333333333333333333";

    fn spell_file(name: &str, body: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "charms-placeholder-{}-{n}-{name}.yaml",
            std::process::id()
        ));
        fs::write(&path, body).unwrap();
        path
    }

    fn placeholder_spell() -> &'static str {
        r#"
version: 16
tx:
  outs:
    - {}
  coins:
    - amount: 0
      dest: "0102030405060708090a0b0c0d0e0f1011121314"
app_public_inputs: {}
"#
    }

    #[test]
    fn ethereum_prove_prints_one_record_hex() {
        let path = spell_file("beam", placeholder_spell());
        let cli = Cli::try_parse_from([
            "charms",
            "spell",
            "prove",
            "--chain",
            "ethereum",
            "--spell",
            path.to_str().unwrap(),
            "--caller",
            "0x1111111111111111111111111111111111111111",
            "--salt",
            "0x0000000000000000000000000000000000000000000000000000000000000007",
            "--chain-id",
            "1",
            "--charms",
            "0x3333333333333333333333333333333333333333",
        ])
        .unwrap();
        let Commands::Spell {
            command: SpellCommands::Prove(params),
        } = cli.command
        else {
            panic!("spell prove");
        };
        let printed = ethereum_placeholder_json(&params).unwrap();
        let hexes: Vec<String> = serde_json::from_str(&printed).unwrap();
        assert_eq!(hexes.len(), 1);
        assert_eq!(printed, format!("[\"{}\"]", hexes[0]));
        assert!(hexes[0].starts_with("43484554"));
        let record = from_envelope_hex(&hexes[0]).unwrap().unwrap();
        assert_eq!(record.chain_id, 1);
        assert_eq!(hex::encode(record.charms), CHARMS);
        assert_eq!(hex::encode(record.caller.unwrap()), CALLER);
        assert_eq!(hex::encode(record.salt.unwrap()), SALT);
        assert!(record.proof.is_empty());
        assert_eq!(record.tx_id().to_string(), TX_ID);
        tx::tx_show_spell(ShowSpellParams {
            chain: Chain::Ethereum,
            tx: hexes[0].clone(),
            json: true,
            mock: false,
        })
        .unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ethereum_tx_build_encodes_the_printed_tx() {
        let path = spell_file("build", placeholder_spell());
        let cli = Cli::try_parse_from([
            "charms",
            "spell",
            "prove",
            "--chain",
            "ethereum",
            "--spell",
            path.to_str().unwrap(),
            "--caller",
            "0x1111111111111111111111111111111111111111",
            "--salt",
            "0x0000000000000000000000000000000000000000000000000000000000000007",
            "--chain-id",
            "1",
            "--charms",
            "0x3333333333333333333333333333333333333333",
        ])
        .unwrap();
        let Commands::Spell {
            command: SpellCommands::Prove(params),
        } = cli.command
        else {
            panic!("spell prove");
        };
        let printed = ethereum_placeholder_json(&params).unwrap();
        let hexes: Vec<String> = serde_json::from_str(&printed).unwrap();
        let built_json = tx::ethereum_transact_json(&hexes[0]).unwrap();
        let built: serde_json::Value = serde_json::from_str(&built_json).unwrap();
        assert_eq!(
            built.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["data", "from", "to", "value"]
        );
        assert!(built_json.starts_with("{\"from\":"));
        assert_eq!(built["from"], "0x1111111111111111111111111111111111111111");
        assert_eq!(built["to"], "0x3333333333333333333333333333333333333333");
        assert_eq!(built["value"], "0");
        let data = built["data"].as_str().unwrap();
        assert_eq!(data.len(), 1738);
        assert!(data.starts_with("0x27485a93"));
        assert_eq!(
            hex::encode(Sha256::digest(data.as_bytes())),
            "59553ae6f8643ca5d2382a821b28b613f7e5a671e8c19daf41950eb72043945d",
            "sha256 of the empty-UTXO transact calldata"
        );
        let err = tx::ethereum_transact_json(&printed).unwrap_err();
        assert_eq!(err.to_string(), "expected the Ethereum record hex");

        let parsed = Cli::try_parse_from([
            "charms",
            "tx",
            "build",
            "--chain",
            "ethereum",
            "--tx",
            hexes[0].as_str(),
        ])
        .unwrap();
        let Commands::Tx {
            command: TxCommands::Build(build),
        } = parsed.command
        else {
            panic!("tx build");
        };
        assert_eq!(build.chain, Chain::Ethereum);
        let err = tx::tx_build(TxBuildParams {
            chain: Chain::Bitcoin,
            tx: hexes[0].clone(),
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "tx build is implemented for ethereum");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ethereum_tx_build_does_not_print_a_call_for_a_broken_record() {
        let path = spell_file("reject", placeholder_spell());
        let cli = Cli::try_parse_from([
            "charms",
            "spell",
            "prove",
            "--chain",
            "ethereum",
            "--spell",
            path.to_str().unwrap(),
            "--caller",
            "0x1111111111111111111111111111111111111111",
            "--salt",
            "0x0000000000000000000000000000000000000000000000000000000000000007",
            "--chain-id",
            "1",
            "--charms",
            "0x3333333333333333333333333333333333333333",
        ])
        .unwrap();
        let Commands::Spell {
            command: SpellCommands::Prove(params),
        } = cli.command
        else {
            panic!("spell prove");
        };
        let printed = ethereum_placeholder_json(&params).unwrap();
        let hexes: Vec<String> = serde_json::from_str(&printed).unwrap();
        let record = from_envelope_hex(&hexes[0]).unwrap().unwrap();
        let mut missing_salt = record.clone();
        missing_salt.salt = None;
        let mut changed_caller = record.clone();
        changed_caller.caller = Some([0x22; 20]);
        let mut changed_salt = record;
        let mut salt = changed_salt.salt.unwrap();
        salt[31] = salt[31].wrapping_add(1);
        changed_salt.salt = Some(salt);
        let cases = [
            (missing_salt.hex(), "ethereum placeholder is missing a salt"),
            (
                changed_caller.hex(),
                "ethereum placeholder anchor does not match the caller and salt",
            ),
            (
                changed_salt.hex(),
                "ethereum placeholder anchor does not match the caller and salt",
            ),
        ];
        for (tx_hex, message) in cases {
            let err = tx::ethereum_transact_json(&tx_hex).unwrap_err();
            assert_eq!(err.to_string(), message);
            let err = tx::tx_build(TxBuildParams {
                chain: Chain::Ethereum,
                tx: tx_hex,
            })
            .unwrap_err();
            assert_eq!(err.to_string(), message);
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ethereum_prove_for_an_empty_utxo_takes_no_prev_txs() {
        let path = spell_file("prev", placeholder_spell());
        let cli = Cli::try_parse_from([
            "charms",
            "spell",
            "prove",
            "--chain",
            "ethereum",
            "--spell",
            path.to_str().unwrap(),
            "--caller",
            "1111111111111111111111111111111111111111",
            "--salt",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "--chain-id",
            "1",
            "--charms",
            "3333333333333333333333333333333333333333",
            "--prev-txs",
            "00",
        ])
        .unwrap();
        let Commands::Spell {
            command: SpellCommands::Prove(params),
        } = cli.command
        else {
            panic!("spell prove");
        };
        let err = ethereum_placeholder_json(&params).unwrap_err();
        assert_eq!(
            err.to_string(),
            "--prev-txs is not used for an Ethereum placeholder"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ethereum_prove_rejects_a_short_salt() {
        let path = spell_file("salt", placeholder_spell());
        let cli = Cli::try_parse_from([
            "charms",
            "spell",
            "prove",
            "--chain",
            "ethereum",
            "--spell",
            path.to_str().unwrap(),
            "--caller",
            "1111111111111111111111111111111111111111",
            "--salt",
            "07",
            "--chain-id",
            "1",
            "--charms",
            "3333333333333333333333333333333333333333",
        ])
        .unwrap();
        let Commands::Spell {
            command: SpellCommands::Prove(params),
        } = cli.command
        else {
            panic!("spell prove");
        };
        let err = ethereum_placeholder_json(&params).unwrap_err();
        assert_eq!(err.to_string(), "expected 32 bytes, got 1");
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn bitcoin_and_cardano_prove_reject_ethereum_options() {
        let cases = [
            ("--caller", "11", "--caller requires --chain ethereum"),
            ("--salt", "00", "--salt requires --chain ethereum"),
            ("--chain-id", "1", "--chain-id requires --chain ethereum"),
            ("--charms", "33", "--charms requires --chain ethereum"),
            ("--nonce", "1", "--nonce requires --chain ethereum"),
            (
                "--gas-limit",
                "21000",
                "--gas-limit requires --chain ethereum",
            ),
            (
                "--max-fee-per-gas",
                "1",
                "--max-fee-per-gas requires --chain ethereum",
            ),
            (
                "--max-priority-fee-per-gas",
                "1",
                "--max-priority-fee-per-gas requires --chain ethereum",
            ),
        ];
        for chain in ["bitcoin", "cardano"] {
            let cli = Cli::try_parse_from([
                "charms",
                "spell",
                "prove",
                "--chain",
                chain,
                "--spell",
                "unused.yaml",
                "--tx-format",
                "unsigned-tx",
                "--nonce",
                "1",
                "--gas-limit",
                "21000",
                "--max-fee-per-gas",
                "1",
                "--max-priority-fee-per-gas",
                "1",
            ])
            .unwrap();
            let Commands::Spell {
                command: SpellCommands::Prove(params),
            } = cli.command
            else {
                panic!("spell prove");
            };
            let err = super::spell_cli().prove(params).await.unwrap_err();
            assert_eq!(
                err.to_string(),
                "--tx-format unsigned-tx requires --chain ethereum",
                "{chain} --tx-format"
            );
            for (flag, value, message) in cases {
                let cli = Cli::try_parse_from([
                    "charms",
                    "spell",
                    "prove",
                    "--chain",
                    chain,
                    "--spell",
                    "unused.yaml",
                    flag,
                    value,
                ])
                .unwrap();
                let Commands::Spell {
                    command: SpellCommands::Prove(params),
                } = cli.command
                else {
                    panic!("spell prove");
                };
                let err = super::spell_cli().prove(params).await.unwrap_err();
                assert_eq!(err.to_string(), message, "{chain} {flag}");
            }
        }
    }

    #[tokio::test]
    async fn bitcoin_prove_still_requires_a_change_address() {
        let cli =
            Cli::try_parse_from(["charms", "spell", "prove", "--spell", "unused.yaml"]).unwrap();
        let Commands::Spell {
            command: SpellCommands::Prove(params),
        } = cli.command
        else {
            panic!("spell prove");
        };
        let err = super::spell_cli().prove(params).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "--change-address is required for this chain"
        );
    }

    fn ethereum_prove_params(extra: &[&str]) -> SpellProveParams {
        let path = spell_file("flags", placeholder_spell());
        let mut args = vec![
            "charms",
            "spell",
            "prove",
            "--chain",
            "ethereum",
            "--spell",
            path.to_str().unwrap(),
            "--caller",
            "0x1111111111111111111111111111111111111111",
            "--salt",
            "0x0000000000000000000000000000000000000000000000000000000000000007",
            "--chain-id",
            "1",
            "--charms",
            "0x3333333333333333333333333333333333333333",
        ];
        args.extend(extra);
        let cli = Cli::try_parse_from(args).unwrap();
        let Commands::Spell {
            command: SpellCommands::Prove(params),
        } = cli.command
        else {
            panic!("spell prove");
        };
        params
    }

    #[test]
    fn ethereum_prove_can_print_an_unsigned_transaction() {
        let params = ethereum_prove_params(&[
            "--tx-format",
            "unsigned-tx",
            "--nonce",
            "7",
            "--gas-limit",
            "500000",
            "--max-fee-per-gas",
            "2000000000",
            "--max-priority-fee-per-gas",
            "1000000",
        ]);
        let printed = ethereum_placeholder_json(&params).unwrap();
        assert!(printed.starts_with("0x02"), "{printed}");
        let raw = hex::decode(printed.trim_start_matches("0x")).unwrap();
        let shown = crate::ethereum_raw::spell_from_raw_transaction(&raw).unwrap();
        let record_params = ethereum_prove_params(&[]);
        let record_json = ethereum_placeholder_json(&record_params).unwrap();
        let hexes: Vec<String> = serde_json::from_str(&record_json).unwrap();
        let record = from_envelope_hex(&hexes[0]).unwrap().unwrap();
        assert_eq!(shown, record.decode().unwrap());
        tx::tx_show_spell(ShowSpellParams {
            chain: Chain::Ethereum,
            tx: printed,
            json: true,
            mock: false,
        })
        .unwrap();
        tx::tx_show_spell(ShowSpellParams {
            chain: Chain::Ethereum,
            tx: format!("0x{}\n", hexes[0]),
            json: false,
            mock: false,
        })
        .unwrap();
        let _ = fs::remove_file(&params.spell);
        let _ = fs::remove_file(&record_params.spell);
    }

    #[test]
    fn ethereum_unsigned_tx_requires_the_fee_fields() {
        let path = spell_file("fees", placeholder_spell());
        let missing = Cli::try_parse_from([
            "charms",
            "spell",
            "prove",
            "--chain",
            "ethereum",
            "--spell",
            path.to_str().unwrap(),
            "--caller",
            "0x1111111111111111111111111111111111111111",
            "--salt",
            "0x0000000000000000000000000000000000000000000000000000000000000007",
            "--chain-id",
            "1",
            "--charms",
            "0x3333333333333333333333333333333333333333",
            "--tx-format",
            "unsigned-tx",
            "--gas-limit",
            "21000",
            "--max-fee-per-gas",
            "1",
            "--max-priority-fee-per-gas",
            "1",
        ]);
        let err = match missing {
            Ok(_) => panic!("unsigned-tx without --nonce parsed"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("required") && err.contains("--nonce"), "{err}");
        let stray_nonce = ethereum_prove_params(&["--nonce", "1"]);
        let err = ethereum_placeholder_json(&stray_nonce).unwrap_err();
        assert_eq!(err.to_string(), "--nonce requires --tx-format unsigned-tx");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&stray_nonce.spell);
    }

    #[test]
    fn ethereum_show_spell_accepts_raw_mainnet_transactions() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ethereum");
        for hash in [
            "0x82439d38cb7a87912ab4da6016fa9b2b8598020ff9121ebf388056cc8ae6a7af",
            "0xf9bf737f435fea4a2c8d3337b7dfc94040ac986800bf8a1c9ddbdf754ee86ce5",
            "0x44a897c638cee33e62441af150a8c978f3303576b701dff3ada0974c017a1154",
            "0xddbd6e2afd317aff3a761c273c0d7b0b7c33af23538dab5d5cc97e4e41f0999d",
        ] {
            let raw = fs::read_to_string(dir.join(format!("{hash}.raw.txt"))).unwrap();
            tx::tx_show_spell(ShowSpellParams {
                chain: Chain::Ethereum,
                tx: raw,
                json: false,
                mock: false,
            })
            .unwrap();
        }
        let err = tx::tx_show_spell(ShowSpellParams {
            chain: Chain::Ethereum,
            tx: "0x05".into(),
            json: false,
            mock: false,
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "not an ethereum transaction");
    }
}
