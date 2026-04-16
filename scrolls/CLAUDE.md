# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Scrolls is a set of Internet Computer (ICP) canisters that sign Bitcoin and Cardano transactions. It also includes a Cloudflare Workers API that wraps the Bitcoin canister. The canisters use ICP's threshold cryptography (ECDSA for Bitcoin, Schnorr/Ed25519 for Cardano) to derive keys and sign transactions without holding private keys directly.

## Build & Development Commands

**Prerequisites:** Install [DFX](https://internetcomputer.org/docs/current/developer-docs/setup/install) (version 0.30.1).

```bash
# Build canisters
dfx build scrolls_bitcoin
dfx build scrolls_cardano

# Run all workspace tests
cargo test

# Run tests for a specific canister
cargo test --package scrolls_bitcoin
cargo test --package scrolls_cardano

# Run Cardano integration tests (requires dfx + network access to IC mainnet)
cargo test --package scrolls_cardano --test canister_integration -- --ignored

# Format and lint
cargo fmt --all
cargo clippy --all

# Local deployment
dfx start --background
dfx deploy

# Deploy to IC mainnet
dfx deploy --network ic
```

**scrolls-api** (Cloudflare Workers) is a separate workspace under `src/scrolls-api/` — build and deploy it with `wrangler`.

## Architecture

### Workspace Structure

The Cargo workspace contains two crates (`scrolls-api` is excluded — it has its own workspace):

- **`src/scrolls_bitcoin/`** — ICP canister for Bitcoin transaction signing (P2WPKH, Secp256k1 ECDSA)
- **`src/scrolls_cardano/`** — ICP canister for Cardano transaction signing (Ed25519 Schnorr)
- **`src/scrolls-api/`** — Cloudflare Workers HTTP API wrapping the Bitcoin canister (axum + ic-agent)

### Key Concepts

- **Nonce-based key derivation:** Bitcoin addresses are derived using derivation path `["scrolls", nonce_bytes]`. Cardano uses a fixed path `["scrolls"]`.
- **Fee validation:** Bitcoin canister validates that transactions include a fee output to configured addresses before signing. Cardano validates a fixed cost.
- **Spell verification:** Both canisters use `charms-lib` to extract and verify "spells" from transactions. Cardano has a special bypass for CIP-68 reference NFT minting.
- **`certify_final`:** Cardano canister can sign a final transaction with a certification signature (separate from the regular `sign` flow).
- **Config from YAML:** Each canister loads its fee addresses and cost parameters from a `config.yaml` embedded at compile time.

### Canister IDs (IC Mainnet)

- scrolls_bitcoin: `lmbwh-3qaaa-aaaak-qunha-cai`
- scrolls_cardano: `tty7k-waaaa-aaaak-qvngq-cai`

### Crate-specific notes

- Both canister crates use Rust edition 2024; `scrolls-api` uses edition 2021.
- The workspace patches `getrandom` and `chrono` with JS-free forks for ICP/Wasm compatibility.
- `rustfmt.toml` sets `max_width = 100`.
- Test profile uses `opt-level = 3` with LTO off for faster test compilation.

### Networks

- Bitcoin: `main`, `testnet4`
- Cardano: `mainnet`, `preprod`
