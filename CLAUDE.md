# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build the main CLI (without prover)
cargo build --profile=test

# Build with prover feature (requires GPU/CUDA support)
cargo build --profile=test --features prover

# Install CLI locally
cargo install --profile=test --path . --locked

# Install CLI locally with prover feature
cargo install --profile=test --path . --locked --features prover

# Run tests
cargo test

# Run a single test
cargo test <test_name>

# Build an app to WASM
charms app build
```

## Project Overview

Charms is a Rust framework for programmable assets on Bitcoin and Cardano using zero-knowledge proofs. Users create "spells" (transaction metadata) that define creation/transformation of "charms" (bundles of tokens, NFTs, and app state) attached to UTXOs.

## Workspace Architecture

The project is organized as a Cargo workspace with these crates:

- **charms** (root) - Main CLI binary and REST API server. Entry point for spell proving, transaction building, and app management.

- **charms-data** - Core data types: `UtxoId`, `Charms`, `Transaction`, `App`, `Data`. Uses CBOR serialization via ciborium.

- **charms-client** - Client library for multi-chain transaction handling (Bitcoin/Cardano) and spell verification. Contains verification keys for all protocol versions. Depends on `pallas-*` and `cml-*` crates for Cardano, `bitcoin` crate for Bitcoin.

- **charms-sdk** - Minimal SDK for app developers. Provides `main!` macro and re-exports `charms_data`.

- **charms-app-runner** - WASM execution environment using wasmi. Runs apps compiled to `wasm32-wasip1` with WASI syscalls.

- **charms-spell-checker** (excluded from workspace) - RISC-V binary for SP1 zkVM that recursively validates spells. Has its own workspace declaration.

- **charms-proof-wrapper** - SNARK wrapper for spell proofs using SP1.

- **charms-lib** - Library (`cdylib` + `rlib`) with optional WASM bindings for JavaScript integration via `wasm-bindgen`.

## Key Concepts

**Spell**: YAML/JSON structure defining inputs, outputs, apps, and charm transformations for a transaction. Located in `src/spell.rs`.

**App**: WebAssembly program implementing `app_contract(app: &App, tx: &Transaction, x: &Data, w: &Data) -> bool`. An `App` is identified by three fields: `tag` (char: `'t'` for token, `'n'` for NFT), `identity` (32-byte hash), and `vk` (32-byte verification key, SHA256 of WASM binary). String format: `tag/identity_hex/vk_hex`.

**Charms**: `BTreeMap<App, Data>` — a bundle of app states attached to a UTXO.

**Data**: CBOR-based dynamic value wrapping `ciborium::Value`.

**Proof Pipeline**: Spells are validated via SP1 zkVM execution, then wrapped in Groth16 SNARKs. Current protocol version is V10.

**Transaction Protocol**:
- **Bitcoin**: Two-transaction protocol — a commit transaction (funds the spell output) followed by a spell transaction (spends commit and includes proof in witness data).
- **Cardano**: Single transaction — spell and proof are embedded in one Cardano transaction (Plutus data/redeemer). Requires a `--collateral-utxo` argument.

## CLI Structure

Main commands in `src/cli/`:
- `server` - REST API server (`POST /spells/prove`, `GET /ready`; default port 17784)
- `spell check` - Check spell correctness (`--spell`, `--app-bins`, `--prev-txs`, `--mock`)
- `spell prove` - Prove spell correctness (adds `--change-address`, `--fee-rate`, `--chain <bitcoin|cardano>`, `--collateral-utxo`)
- `spell vk` - Print protocol version and spell verification key
- `app new <NAME>` - Create new app from template (uses `cargo-generate`)
- `app build` - Build app to `wasm32-wasip1`
- `app vk [PATH]` - Show verification key (SHA256 of WASM binary)
- `tx show-spell` - Extract and display spell from a transaction (`--chain`, `--tx`, `--json`, `--mock`)
- `wallet list` - List UTXOs with charms (calls `bitcoin-cli listunspent`)
- `completions <SHELL>` - Generate shell completion scripts

## Prover Configuration

The prover mode is controlled by feature flags and environment variables:

- `--features prover` enables real proving (CPU/CUDA/Network)
- Without `prover` feature, uses mock prover
- `APP_SP1_PROVER` - Selects prover type for app proving (`cuda`, `cpu`, `network`)
- `SPELL_SP1_PROVER` - Selects prover type for spell proving (`app` = same as app prover, `network`)
- `SP1_GPU_SERVICE_URL` - GPU service URL (default: `http://localhost:3000/twirp/`)
- `CHARMS_PROVE_API_URL` - Override remote proving API URL
- `CHARMS_FEE_SETTINGS` - Path to YAML fee configuration file
- `REDIS_URL` - Redis-based proof caching/deduplication (prover feature only)
- `MOCK=1` or `--mock` flag - Mock proving mode (skips proof generation)

## Testing

Tests use property-based testing with proptest. Mock mode (`--mock` flag or `MOCK=1` env var) skips expensive proof generation for faster testing.

## Rust Toolchain

Uses Rust 1.91 (Edition 2024). See `rust-toolchain.toml`.
