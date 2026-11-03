---
title: enum_dispatch gives each field type one From impl
date: 2026-11-03
category: tooling-decisions
module: charms-client Tx
problem_type: tooling_decision
component: tooling
severity: medium
applies_when:
  - "A new Tx variant would store a field type another variant already stores"
  - "Litecoin finality would store BitcoinTx in the Litecoin variant"
retire_when: "enum_dispatch no longer emits one From impl per variant field type. Check the enum_dispatch version in charms-client/Cargo.toml and that version's generate_from_impls."
tags:
  - enum-dispatch
  - litecoin
  - newtype
  - e0119
  - charms-client
  - tx
---

# enum_dispatch gives each field type one From impl

## Context

`Tx` is an `#[enum_dispatch(EnchantedTx)]` enum (`charms-client/src/tx.rs:52-65`). Pull request 268 added the Litecoin variant. That variant stores `LitecoinTx`, a newtype whose field is `bitcoin::Transaction` (`charms-client/src/bitcoin_tx.rs:68-78`).

`enum_dispatch` 0.3.13 is the pin (`charms-client/Cargo.toml:32`). Its `generate_from_impls` emits `impl From<Field> for Tx` once per variant, and `Field` is that variant's field type. `Tx::Bitcoin` already stores `BitcoinTx`. A Litecoin variant that also stored `BitcoinTx` would emit a second `impl From<BitcoinTx> for Tx`. Rust rejects the duplicate as E0119. The same expansion emits `impl TryInto<Field> for Tx` once per variant, so those two variants also collide on `TryInto<BitcoinTx>`.

## Guidance

Keep a distinct field type on every `EnchantedTx` variant for as long as `charms-client` depends on `enum_dispatch` 0.3.13.

```rust
pub enum Tx {
    Bitcoin(BitcoinTx),
    Cardano(CardanoTx),
    Ethereum(EthereumTx),
    Litecoin(LitecoinTx),
}
```

`Tx::new` takes `impl Into<Tx>` (`charms-client/src/tx.rs:85-88`). That bound is the generated `From`. A variant written `Litecoin(BitcoinTx)` duplicates both `From<BitcoinTx>` and `TryInto<BitcoinTx>`.

## Why This Matters

Bitcoin and Litecoin already implement `EnchantedTx` differently, and that split is in the tree. Bitcoin reads an OP_RETURN and then a taproot witness (`charms-client/src/bitcoin_tx.rs:100-108`). Litecoin reads the OP_RETURN only (`charms-client/src/bitcoin_tx.rs:173-180`). Bitcoin finality is the `WithBlockProof` variant (`charms-client/src/bitcoin_tx.rs:163-169`). `LitecoinTx::proven_final` returns false (`charms-client/src/bitcoin_tx.rs:230-232`).

The coherence limit lives in `generate_from_impls`. The Charm sources do not restate it. Litecoin proof-of-work finality that stores `BitcoinTx` in `Tx::Litecoin`, in order to reuse `WithBlockProof`, hits the same E0119. A new chain variant that stores `CardanoTx`, `EthereumTx`, or `LitecoinTx` hits it too.

`TryFrom<&str> for Tx` returns `Tx::Bitcoin` when the hex decodes as a Bitcoin transaction (`charms-client/src/tx.rs:75-76`). Litecoin uses that consensus encoding, so this path does not construct `Tx::Litecoin`. Chain-aware callers build the variant themselves: `Tx::Litecoin(LitecoinTx::new(tx))` (`src/tx/bitcoin_tx.rs:431`) and `LitecoinTx::from_hex` (`src/cli/tx.rs:26`).

The enum sets `rename_all = "snake_case"` and does not set `untagged` (`charms-client/src/tx.rs:52-66`). Serde's default representation tags the variant, so the JSON key is `litecoin`. `LitecoinTx` is `transparent` (`charms-client/src/bitcoin_tx.rs:68-71`), and the payload is the transaction hex.

## When to Apply

- A new `Tx` variant would store a field type another variant already stores.
- Litecoin finality would store `BitcoinTx` in the Litecoin variant.

## Examples

This shape is what `generate_from_impls` rejects:

```rust
pub enum Tx {
    Bitcoin(BitcoinTx),
    Litecoin(BitcoinTx),
}
```

The 0.3.13 generator walks each variant and emits:

```rust
impl ::core::convert::From<Field> for Tx {
    fn from(v: Field) -> Tx {
        Tx::VariantName(v)
    }
}
```

`Field` is the variant's field type. There is no deduplication when two variants share a type.

## Related

- Merged in [pull request 268](https://github.com/CharmsDev/charms/pull/268).
