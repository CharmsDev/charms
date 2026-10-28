---
title: One spell version has one verification key
date: 2026-10-28
category: architecture-patterns
module: charms-client spell verification
problem_type: architecture_pattern
component: spell_guest
severity: critical
applies_when:
  - A guest rebuild moves the version-16 spell key before that version is released
  - A version-16 proof already exists under an earlier key
tags:
  - spell-vk
  - groth16
  - bitcoin
  - ethereum
  - version-16
---

# One spell version has one verification key

## Context

Spell version 16 is not released. Rebuilding the spell-checker moves `charms-lib`'s `SPELL_VK`, because the wrapper hardcodes `SPELL_CHECKER_VK` and the guest ELF is not stripped. A comment-only edit in a crate the guest links is enough to move the key.

## Guidance

Version 16 has one verification key. That key is the one `charms spell vk` prints, and it is the `PROGRAM_VKEY` in the `CharmsApply` built for this guest. For this tree the key is `0x00b355b648d4efac98ca94aa15ad24300452b40762a269c599cd682d14b001c0`. `spell_vk` returns it for version 16. `verify_snark_proof` checks that one key.

`ETHEREUM_FINALITY.charms` is the proxy this guest treats as the Ethereum host, `0x7f7ab9224782dE7a20e89E6fc0DE52Ff6b48d8f0`. `Deploy.s.sol` creates that proxy with salt `keccak256("charms-proxy-v2")`, a new `CharmsApply`, and new token contracts. The initializer salt is `keccak256("charms-initializer-v2")`. The `CharmsApply` is constructed with this `PROGRAM_VKEY`. The proxy address is part of the guest, so a different proxy is a new guest build and a new key. The contract is deployed from the guest that names that proxy.

## Why This Matters

`BitcoinTx::virtual_spell` turns a failed `extract_and_verify_spell` into an empty spell with the transaction's inputs and no outputs. A later spell then sees no charms on that input. Ethereum `virtual_spell` returns the extract error.

Trying a second key for version 16 kept those charms visible after the guest moved. One version then verified under two keys. The version is not released, so the previous key is not a version-16 key. A proof that commits `0x00da533974a87fa489f6f9831c9ea2447b456b38ef3a5c6dc9e421af52831f8d` does not verify in this guest.

The checked-in Groth16 vector commits that previous key. It is not a proof this `CharmsApply` accepts.

## When to Apply

A guest rebuild before release replaces the version-16 key. The replacement is the only key `verify_snark_proof` tries for that version. Pinning the previous key is a new spell version.

## Related

- `CHIPs/CHIP-0020/README.md` protocol version section
- `ethereum/script/Deploy.s.sol`
