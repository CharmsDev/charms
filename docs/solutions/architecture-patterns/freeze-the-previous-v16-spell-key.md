---
title: Freeze the previous version-16 spell key when the guest changes
date: 2026-10-28
category: architecture-patterns
module: charms-client spell verification
problem_type: architecture_pattern
component: spell_guest
severity: critical
applies_when:
  - A guest change recompiles the spell-checker and the wrapper key moves
  - Version-16 proofs are already confirmed on Bitcoin or Ethereum
tags:
  - spell-vk
  - groth16
  - bitcoin
  - ethereum
  - version-16
---

# Freeze the previous version-16 spell key when the guest changes

## Context

Protocol version 16 is already on Bitcoin and on the Ethereum Charms proxy. A later guest change, such as accepting a proof-free Ethereum record, recompiles `charms-spell-checker`. The wrapper hardcodes `SPELL_CHECKER_VK`, so `charms-lib`'s `SPELL_VK` moves. The proofs already mined still commit the previous key.

## Guidance

Stay on spell version 16. Proving commits the live `SPELL_VK`. Verification of a version-16 proof tries that live key, then the frozen key the previous guest committed.

`proof_pairs` in `charms-client/src/tx.rs` is verify-only. `spell_vk` for version 16 returns the live key and does not return `V16_FROZEN_SPELL_VK`. The frozen Groth16 bytes stay on `V14_GROTH16_VK_BYTES` when a rebuild leaves `charms-client/vk/v14/groth16_vk.bin` unchanged. The Ethereum stock verifier can stay. `PROGRAM_VKEY` in `CharmsApply` is immutable, so a proved Ethereum spell that commits the live key needs a new `CharmsApply` behind the same proxy. A proof-free transfer or beam-out does not, because `CharmsApply` skips `verifyProof` when `_isNative` is true.

Do not bump `CURRENT_VERSION` to carry the new key. `CharmsApply` reverts when `s.version != SPELL_VERSION`, and the deployed implementation's `SPELL_VERSION` is 16. A new version would make the beam-out itself wait on `upgradeToAndCall`.

## Why This Matters

`BitcoinTx::virtual_spell` turns a failed `extract_and_verify_spell` into an empty spell with the transaction's inputs and no outputs. A spending spell then sees no charms on that input. Replacing the only version-16 key does that to every already-proved Bitcoin output, including the mint `cfe002ad4fea566b8a927196c278a22751975f72394263dde7a4bb1bee9c0892`. Ethereum `virtual_spell` returns the extract error instead, so the same rotation fails closed there and fails open on Bitcoin.

PRs 249 and 251 rebuilt the guest and replaced the only version-16 key. That was safe only while no version-16 Bitcoin output had to be spent under the new guest. After the mint confirmed, the previous key has to remain reachable.

## When to Apply

- The spell-checker ELF changes and `charms spell vk` prints a new key.
- Version-16 transactions are already confirmed.
- The Groth16 verifying key file is unchanged, so the on-chain verifier can stay.

## Examples

The live key after the proof-free Ethereum guest is `0x0089479ae9152d200d9678e19e92d958e62f7bbebc3850e47586acac6e431b4a`. The guest ELF is not stripped, so a later edit in a crate the guest links, including a comment-only edit, moves that live key. The frozen key is `0x00da533974a87fa489f6f9831c9ea2447b456b38ef3a5c6dc9e421af52831f8d`. `version_16_verifies_the_frozen_spell_vk_and_the_live_one` locks both. `test_realV16ProofChangesState` still runs the checked-in proof under the frozen key. `test_checkedInV16ProofIsInvalidUnderTheLiveKey` shows the live `CharmsApply` rejects that proof.

## Related

- Pending pull request 259
- `CHIPs/CHIP-0020/README.md` protocol version section
- PRs 249 and 251, which replaced the only version-16 key
