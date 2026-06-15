# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build the main CLI (without prover)
cargo build --profile=test

# Build with prover feature (real SP1 proving; produces the `charms-prover` binary)
cargo build --profile=test --features prover

# Install the CLI locally
cargo install --profile=test --path . --locked

# Install the prover server locally (run `charms-prover server` rather than `cargo run`)
cargo install --path . --locked --bin charms-prover --features prover

# Run tests
cargo test

# Run a single test
cargo test <test_name>

# Build an app to WASM
charms app build
```

## Project Overview

Charms is a Rust framework for programmable assets on Bitcoin and Cardano using zero-knowledge proofs. Users create "spells" (transaction metadata) that define creation/transformation of "charms" (bundles of tokens, NFTs, and app state) attached to UTXOs. The current protocol version is **V15**.

## Binaries

Both binaries are built from the same root `charms` crate (`src/main.rs`):

- **`charms`** (default features) — the CLI. `charms spell prove` forwards proving to a hosted Prover API.
- **`charms-prover`** (`--features prover`) — the proving server with real SP1 proving built in. Run with `charms-prover server`. The `prover` feature also pulls in `redis`/`rslock` for proof caching.

The hosted prover URL is derived from the protocol version: `https://v15.charms.dev/spells/prove` (override with `CHARMS_PROVE_API_URL`).

## Workspace Architecture

The project is organized as a Cargo workspace with these crates:

- **charms** (root) - Main CLI binary and REST API server. Entry point for spell proving, transaction building, and app management.

- **charms-data** - Core data types: `UtxoId`, `Charms`, `Transaction`, `App`, `Data`, plus `VersionedApp`/`AppSignature` for versioned apps. Uses CBOR serialization via ciborium.

- **charms-client** - Client library for multi-chain transaction handling (Bitcoin/Cardano) and spell verification. Defines `NormalizedSpell`/`NormalizedTransaction`, the `ProveRequest` (in `request.rs`), and verification keys for all protocol versions. Depends on `pallas-*`/`cml-*` for Cardano and the `bitcoin` crate for Bitcoin.

- **charms-sdk** - Minimal SDK for app developers. Provides the `main!` and `app_version!` macros and re-exports `charms_data` as `charms_sdk::data`.

- **charms-app-runner** - WASM execution environment using wasmi. Runs apps compiled to `wasm32-wasip1` with a minimal WASI shim, meters cycles via fuel, and verifies versioned-app signatures.

- **charms-spell-checker** (excluded from workspace) - RISC-V binary for the SP1 zkVM that recursively validates spells. Has its own workspace declaration.

- **charms-proof-wrapper** - SP1 program that recursively verifies the spell-checker proof and is itself proven in Groth16 mode.

- **charms-lib** - Library (`cdylib` + `rlib`) with optional WASM bindings for JavaScript integration via `wasm-bindgen`. Exposes `extractAndVerifySpell` and the `SPELL_VK`.

- **scrolls/** - A separate workspace of Internet Computer canisters (`scrolls_bitcoin`, `scrolls_cardano`) that sign Bitcoin/Cardano transactions using ICP threshold cryptography. The v15 Bitcoin canister is `scrolls_bitcoin_v15` (`rpgc6-oqaaa-aaaak-qy3uq-cai`).

## Key Concepts

**Spell**: YAML/JSON structure (deserialized directly into `NormalizedSpell`) defining inputs, outputs, apps, and charm transformations. CLI handling in `src/cli/spell.rs` and `src/spell/`; types in `charms-client/src/lib.rs`.

**App**: WebAssembly program implementing `app_contract(app: &App, tx: &Transaction, x: &Data, w: &Data) -> bool`. An `App` is `tag` (char: `'t'` token, `'n'` NFT, `'s'` Scroll, or custom), `identity` (32-byte hash), and `vk` (32-byte verification key). String format: `tag/identity_hex/vk_hex`.

- **Immutable app**: `vk = SHA256(wasm binary)`.
- **Versioned app**: `vk = SHA256(signing public key)`; each spell carries a BIP-340 `AppSignature` authorizing the binary/version. Managed with `app keygen`/`app sign`/`app verify`; `app build` auto-signs when `.charms/app-key.json` exists.

**Charms**: `BTreeMap<App, Data>` — a bundle of app states attached to a UTXO.

**Data**: CBOR-based dynamic value wrapping `ciborium::Value`.

**Proof Pipeline**: Spells are validated via SP1 zkVM execution (`charms-spell-checker`, Compressed mode), then wrapped into a Groth16 SNARK over BN254 (`charms-proof-wrapper`, Groth16 mode). The proof is recursive (it absorbs prerequisite transactions' proofs). v15 commits public values as CBOR of `([u8; 32] spell_vk, NormalizedSpell)`.

**Transaction Protocol**:
- **Bitcoin**: A **single** transaction. The CBOR-encoded `(NormalizedSpell, Proof)` pair is placed in an `OP_RETURN` output (`OP_RETURN "spell" <cbor>`), alongside the coin outputs, an optional Charms-fee output, and change. There is no commit/reveal. See `src/tx/bitcoin_tx.rs`.
- **Cardano**: A single transaction. The `(spell, proof)` pair is attached as a Plutus inline datum; charms are native assets minted/burned by per-app PlutusV3 policies; requires a `--collateral-utxo`; co-signed by the Scrolls Cardano canister. See `src/tx/cardano_tx/`.

**Beaming**: Cross-chain charm movement. The source spell marks an output in `beamed_outs` (hash of the destination UTXO id [+ nonce]); the destination spell claims it via `tx_ins_beamed_source_utxos` (`--beamed-from`). The source tx must be proven final — Bitcoin via a PoW `MerkleBlock` + headers proof, Cardano via a Scrolls Ed25519 finality signature — passed through `--prev-txs`.

**Scrolls**: ICP canisters acting as keyless signers. A Bitcoin output carrying a `SCROLL` charm is pinned to a canister-controlled address; the prover fills these via the canister's `addresses` method while proving, and spending requires the canister's `sign_and_submit` (which enforces a valid spell + fee, then broadcasts).

## CLI Structure

Main commands in `src/cli/`:
- `server` - REST API server (`POST /spells/prove`, `GET /ready`; `--ip` default `0.0.0.0`, `--port` default `17784`)
- `spell check` - Run app contracts locally in WASM (`--spell`, `--app-bins`, `--private-inputs`, `--app-signatures`, `--prev-txs`, `--beamed-from`, `--chain`, `--mock`)
- `spell prove` - Prove a spell (adds `--change-address`, `--fee-rate`, `--collateral-utxo`, `--payload`, `-o/--output json|cbor`)
- `spell vk` - Print `{prover, version, vk}` (`--mock` for the mock key)
- `tx show-spell` - Extract and display a spell from a transaction (`--tx`, `--chain`, `--json`, `--mock`)
- `app new <NAME>` - Create a new app from the `charms-app` template (uses `cargo-generate`)
- `app build` - Build the app to `wasm32-wasip1` (auto-signs versioned apps)
- `app vk [PATH] [--pubkey <FILE>]` - Show the verification key (SHA256 of the WASM binary, or of the public key for versioned apps)
- `app keygen [--out <FILE>]` - Generate a BIP-340 signing key (default `.charms/app-key.json`)
- `app sign [--key] [--bin] [--out]` - Sign an app binary (default out `<wasm>.sig.yaml`)
- `app verify [--bin] [--sig]` - Verify an app binary's signature(s)
- `wallet list` - List UTXOs with charms (calls `bitcoin-cli listunspent`)
- `util dest` - Derive a hex `dest` from an address (`--addr`) or Cardano proxy address (`--apps`)
- `completions <SHELL>` - Generate shell completion scripts

## Prover Configuration

The prover mode is controlled by feature flags and environment variables:

- `--features prover` enables real proving; without it the CLI uses the remote API (or the mock prover with `--mock`)
- `APP_SP1_PROVER` - Backend for app + spell-checker proving (`cpu`, `network`; `cuda` is currently unimplemented)
- `SPELL_SP1_PROVER` - Backend for the Groth16 wrapper (`app` = reuse the app prover, or `network`)
- `NETWORK_PRIVATE_KEY` - **Required** when a backend is `network`: the Succinct Prover Network account key
- `NETWORK_RPC_URL` - Override the SP1 Prover Network RPC (default `https://rpc.mainnet.succinct.xyz`)
- `SP1_GPU_SERVICE_URL` - GPU service URL (default `http://localhost:3000/twirp/`)
- `CHARMS_PROVE_API_URL` - Override the remote proving API URL
- `CHARMS_FEE_SETTINGS` - Path to a YAML fee configuration file
- `REDIS_URL` - Redis-based proof caching/deduplication (prover feature only)
- `MOCK=1` or `--mock` flag - Mock proving mode (skips real proof generation)

## Testing

Tests use property-based testing with proptest. Mock mode (`--mock` flag or `MOCK=1` env var) skips expensive proof generation for faster testing.

## Rust Toolchain

Uses Rust 1.91 (Edition 2024). See `rust-toolchain.toml`. Apps target `wasm32-wasip1`.
