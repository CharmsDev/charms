---
title: Ethereum host spell stays out of the guest
date: 2026-10-30
category: architecture-patterns
module: charms ethereum host spell
problem_type: architecture_pattern
component: spell_guest
severity: high
applies_when:
  - Host show-spell decodes a raw Ethereum transaction, or unsigned prove encodes one, in the root charms crate
  - Spell-struct ABI dynamic-array offsets are relative to the head after the length word
  - An empty ins key must stay Some([]) because NormalizedSpell::default omits ins and event-spell CBOR must match byte for byte
  - Facade ERC-20 transfer or transferFrom calldata carries no spell
  - Host-only decode belongs in the root crate because the spell-checker guest compiles charms-client and guests.yml rebuilds that guest
tags:
  - ethereum
  - host-spell
  - cbor
  - charms-client
  - guest-drift
  - abi
  - normalized-spell
  - show-spell
---

# Ethereum host spell stays out of the guest

## Context

`encode_spell` in `charms-client` builds the ABI tuple inside `transact` calldata. The host reads that calldata back in `src/ethereum_raw.rs` and rebuilds the `NormalizedSpell`. The committed spell is CBOR from `util::write`, which `eth_tx_id` hashes. Three details of that round trip are easy to get wrong. The decoder stays in the root crate. The spell-checker guest compiles `charms-client`, and guest CI rebuilds that guest when `charms-client/**` changes.

## Guidance

Leave `encode_spell`, `tuple`, and `array` in `charms-client`. Decode on the host with the `sol!` `CharmsSpell` layout, then map fields in `spell_from_abi`.

`encode_spell` wraps the spell as one dynamic tuple (`charms-client/src/ethereum_tx.rs:1265-1275`). `tuple` writes each dynamic field's offset as `heads + tail.len()`, counted from the first byte of that tuple (`charms-client/src/ethereum_tx.rs:1309-1329`). `array` writes a length word and then that tuple (`charms-client/src/ethereum_tx.rs:1332-1336`). Offsets inside an array are relative to the head that starts after the length word. The parent tuple's offset points at the length word. `alloy_sol_types::sol` decodes that layout. `spell_from_abi` does not recompute the offsets (`src/ethereum_raw.rs:7-8`, `src/ethereum_raw.rs:164-172`).

`NormalizedTransaction` skips `ins` and `coins` when they are `None` (`charms-client/src/lib.rs:142-143`, `charms-client/src/lib.rs:160-161`). `NormalizedSpell::default` leaves both `None` (`charms-client/src/lib.rs:221-229`). `charms_data::util::write` emits CBOR (`charms-data/src/util.rs:16-23`). A `None` field omits the key. `Some([])` keeps the key and an empty array.

A decoded `transact` always stores `ins: Some(ins)` and `coins: Some(coins)`, including when those vectors are empty (`src/ethereum_raw.rs:255-263`). Empty `refs`, `beamed_outs`, and `scrolls` stay `None` (`src/ethereum_raw.rs:259-263`, `src/ethereum_raw.rs:337-347`). `transact_calldata_roundtrips_a_placeholder` checks that the decoded CBOR equals the record's spell bytes (`src/ethereum_raw.rs:423-426`). `eth_tx_id` hashes that CBOR (`charms-client/src/ethereum_tx.rs:827-842`).

`transfer(address,uint256)` and `transferFrom(address,address,uint256)` decode as `empty_ethereum_spell`, which is `NormalizedSpell::default` (`src/ethereum_raw.rs:73-86`, `src/ethereum_raw.rs:184-186`). The checked-in transfer's input contains selector `a9059cbb` (`tests/fixtures/ethereum/0xddbd6e2afd317aff3a761c273c0d7b0b7c33af23538dab5d5cc97e4e41f0999d.raw.txt:1`). `mainnet_transactions_match_the_transaction_event` asserts that fixture equals the empty spell, and asserts the `Transaction` log's spell bytes differ (`src/ethereum_raw.rs:658-666`). Any other selector is an error (`src/ethereum_raw.rs:187`, `src/ethereum_raw.rs:787-795`).

Keep raw-tx decode, the ABI inverse, and `unsigned_transact_eip1559` in `src/ethereum_raw.rs` (`src/ethereum_raw.rs:107-160`). Call `transact_call`, `eth_tx_id`, and `TRANSACT_SIGNATURE` from `charms-client` (`charms-client/src/ethereum_tx.rs:22`, `charms-client/src/ethereum_tx.rs:828`, `charms-client/src/ethereum_tx.rs:971`). The spell-checker guest depends on `charms-client` (`charms-spell-checker/Cargo.toml:14`, `charms-spell-checker/src/lib.rs:1`). `.github/workflows/guests.yml` lists `charms-client/**` and runs `charms-spell-checker/check-guests.sh` (`.github/workflows/guests.yml:11`, `.github/workflows/guests.yml:45-46`). That script rebuilds the guests and exits 1 when committed guest bytes differ (`charms-spell-checker/check-guests.sh:7`, `charms-spell-checker/check-guests.sh:37-44`). The guest image builds `charms-spell-checker` with `cargo prove build` (`charms-spell-checker/Dockerfile:13-16`).

## Why This Matters

A decoder that folds the length word into an array's offsets reads the wrong tail and rebuilds the wrong spell.

CBOR key presence is part of the committed spell. Dropping `ins` on a `transact` with no inputs changes the bytes `eth_tx_id` hashes, so the id and the receipt log diverge. Keeping `Some([])` on a facade transfer changes the bytes the other way. The transfer test requires the calldata spell and the log spell to differ.

An unknown selector must fail. Mapping it to the default spell would present a call the host cannot interpret as an empty spell.

The spell-checker guest links `charms-client` and does not depend on the root crate (`charms-spell-checker/Cargo.toml:14-16`). Guest ELFs and verification keys are committed. `.github/workflows/guests.yml` rebuilds them when `charms-client/**` changes, and `check-guests.sh` exits 1 if those bytes differ. Host-only decode stays in the root crate.

## When to Apply

- Decoding `transact` calldata back to `NormalizedSpell`, or checking that CBOR against a `Transaction` log.
- `show-spell` or a raw decoder sees an ERC-20 `transfer` or `transferFrom`. Print the default spell. The facade builds the real spell in the contract (`src/cli/mod.rs:443-447`).
- A `transact` has an empty input list and the bytes must match the contract. Set `ins` and `coins` to `Some`.
- Adding raw transaction decode, an ABI inverse, or unsigned EIP-1559 encoding. Put that code in `src/ethereum_raw.rs`.

## Examples

`array` puts the length word in front of the tuple. `tuple` offsets stay relative to the tuple that follows that word.

```rust
fn array(items: Vec<Abi>) -> Abi {
    let mut encoded = word(items.len() as u64).to_vec();
    encoded.extend(tuple(items));
    Abi::Dynamic(encoded)
}
```

A decoded `transact` with no inputs still emits `ins`. The facade empty spell does not.

```rust
// spell_from_abi, including a zero-length input list
ins: Some(ins),
coins: Some(coins),

// ERC-20 transfer and transferFrom
NormalizedSpell::default() // ins is None, so CBOR omits the key
```

## Related

- [One spell version has one verification key](one-spell-version-one-verification-key.md). A guest rebuild moves that key. This note keeps host decode out of the guest so that rebuild does not run.
