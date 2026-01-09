# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build the main CLI (without prover)
cargo build --release

# Build with prover feature (requires GPU/CUDA support)
cargo build --release --features prover

# Install CLI locally
cargo install --path . --locked

# Run tests
cargo test

# Run a single test
cargo test <test_name>

# Build an app to WASM
cargo build --target wasm32-wasip1 --release
```

## Project Overview

Charms is a Rust framework for programmable tokens and NFTs on Bitcoin using zero-knowledge proofs. Users create "spells" (transaction metadata) that define creation/transformation of "charms" (bundles of tokens, NFTs, and app state) attached to Bitcoin UTXOs.

## Workspace Architecture

The project is organized as a Cargo workspace with these crates:

- **charms** (root) - Main CLI binary and REST API server. Entry point for spell proving, transaction building, and app management.

- **charms-data** - Core data types: `UtxoId`, `Charms`, `Transaction`, `App`, `Data`. Uses CBOR serialization via ciborium.

- **charms-client** - Client library for multi-chain transaction handling (Bitcoin/Cardano) and spell verification. Contains verification keys for all protocol versions.

- **charms-sdk** - Minimal SDK for app developers. Provides `main!` macro and re-exports `charms_data`.

- **charms-app-runner** - WASM execution environment using wasmi. Runs apps compiled to `wasm32-wasip1` with WASI syscalls.

- **charms-spell-checker** (excluded from workspace) - RISC-V binary for SP1 zkVM that recursively validates spells.

- **charms-proof-wrapper** - SNARK wrapper for spell proofs using SP1.

- **charms-lib** - Library with optional WASM bindings for JavaScript integration.

## Key Concepts

**Spell**: YAML/JSON structure defining inputs, outputs, apps, and charm transformations for a transaction. Located in `src/spell.rs`.

**App**: WebAssembly program implementing `app_contract(app: &App, tx: &Transaction, x: &Data, w: &Data) -> bool`. Apps are identified by their SHA256 hash (verification key).

**Proof Pipeline**: Spells are validated via SP1 zkVM execution, then wrapped in Groth16 SNARKs. The proof is embedded in Bitcoin transaction witness data.

**Two-Transaction Protocol**: Bitcoin spells require a commit transaction (funds the spell output) followed by a spell transaction (spends commit and includes witness).

## CLI Structure

Main commands in `src/cli/`:
- `server` - REST API for proof proving (default port 17784)
- `spell check/prove/vk` - Spell validation and proving
- `app new/build/vk` - App template generation and WASM compilation
- `tx show-spell` - Extract spell from transaction
- `wallet list` - List UTXOs with charms

## Prover Configuration

The prover mode is controlled by feature flags and environment variables:

- `--features prover` enables real proving (CPU/CUDA/Network)
- Without `prover` feature, uses mock prover
- `SP1_PROVER` env var selects prover type
- `SP1_GPU_SERVICE_URL` for GPU proving service

## Testing

Tests use property-based testing with proptest. Mock mode (`--mock` flag or `MOCK=1` env var) skips expensive proof generation for faster testing.

## Rust Toolchain

Uses Rust 1.91 (Edition 2024). See `rust-toolchain.toml`.