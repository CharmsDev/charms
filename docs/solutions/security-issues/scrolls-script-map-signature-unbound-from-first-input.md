---
title: Scrolls script signature does not bind the first input
date: 2026-11-03
category: security-issues
module: scrolls bitcoin script pubkey signatures
problem_type: security_issue
component: spell_guest
symptoms:
  - Before the binding change, a Schnorr signature over the script map alone verified on a spell whose first input was a different outpoint
  - A coinbase spell's first input is the null outpoint, so one signed map was reusable on every coinbase spell and those outputs could not be withdrawn
root_cause: missing_validation
resolution_type: code_fix
severity: critical
tags:
  - scrolls
  - script-pubkey
  - first-input
  - signature-binding
  - schnorr
  - bitcoin
  - spell-guest
---

# Scrolls script signature does not bind the first input

## Problem

The Scrolls canister signed a Bitcoin script map without the creating transaction's first input, and `check_scroll_outputs` accepted that signature. A signed map could be reused on another transaction. A script Scrolls will never withdraw from could still count as a Scrolls output. The binding fix is opened in #269 and is unmerged as of this writing.

## Symptoms

`addresses` already received the creating transaction's first-input outpoint and used it to derive each P2WPKH script. The signature returned with the map did not cover that outpoint. The pre-#269 signer hashed CBOR of the script map alone. The checker hashed that same CBOR, so it passed whatever the first input was when `tx.scrolls` equaled the map's keys and each script equaled `tx.coins[i].dest`.

The spending key is a different derivation. `derivation_path_for_output` (`scrolls/src/scrolls_bitcoin/src/lib.rs:552-559`) is the secret prefix, `b"scrolls"`, `tx_in_0.to_bytes()`, and the output index. `UtxoId::to_bytes` (`charms-data/src/lib.rs:92-96`) is the 32-byte txid plus the little-endian vout. When the spell's first input is a different outpoint, `sign_tx` rebuilds a different path and will not produce a withdrawal signature for that script. The spell check still treated the output as Scrolls-controlled.

Before the binding change, a signature over the bare script map made the check succeed, and a signature over the spell's first input failed verification. The tests below expect the reverse.

## What Didn't Work

A second carried copy of the outpoint was the wrong shape. `SignedScrollOutputs` has `script_pubkeys` and `signature` and no outpoint field (`charms-client/src/lib.rs:422-425`). The canister `Addresses` record is the same pair. After proof verification fills inputs, the spell already has the first input. A second field would be another copy and would need its own equality check against `spell.tx.ins[0]`.

A host-only guard outside `is_correct` would not be inside the proof. The spell-checker guest asserts `is_correct(...).unwrap()` (`charms-spell-checker/src/lib.rs:27-37`), returns `(self_spell_vk, spell)` (`charms-spell-checker/src/lib.rs:41`), and `main` commits that tuple (`charms-spell-checker/src/lib.rs:11-13`). `scroll_outputs` is a witness on `SpellProverInput` (`charms-client/src/lib.rs:429-441`), not part of that committed output. The same reason already keeps orphan `versioned_apps` inside `is_correct` (`charms-client/src/lib.rs:493`).

## Solution

#269 makes the canister and the spell check use one preimage. `signed_scroll_script_pubkeys_preimage` (`charms-data/src/lib.rs:204-209`) writes CBOR of `(tx_in_0, script_pubkeys)`.

`addresses_impl` parses the caller's `tx_in_0`, derives each script from it, and passes that same value into `sign_script_pubkeys` (`scrolls/src/scrolls_bitcoin/src/lib.rs:497-516`). The signer signs SHA-256 of the preimage with the Schnorr key at derivation path `[b"sign"]` (`scrolls/src/scrolls_bitcoin/src/lib.rs:528-535`). `SIGN` is `b"sign"` (`scrolls/src/scrolls_bitcoin/src/lib.rs:38`).

The checker takes the spell's first input and verifies against it (`charms-client/src/lib.rs:1177-1183`). `fill_scroll_outputs` sends `spell.tx.ins[0]` to the canister (`src/tx/scrolls_bitcoin.rs:40-42`) only after refusing a coinbase (`src/tx/scrolls_bitcoin.rs:36`). There is still no outpoint field on `SignedScrollOutputs`.

## Why This Works

The Bitcoin, Litecoin, and Cardano spell embedded in the chain transaction has `ins = None`. `NormalizedTransaction::ins` is documented as absent in that serialization because the transaction already lists its inputs (`charms-client/src/lib.rs:140-142`). A proved Ethereum spell is stored with its inputs. `clear_inputs_and_coins` clears `ins` and `coins` (`src/spell/prove.rs:256-259`). The Bitcoin and Litecoin prove path serializes that truncated spell and places it after `OP_RETURN` (`src/spell/prove_spell_tx.rs:162-176`, `src/tx/bitcoin_tx.rs:234-241`).

`BitcoinTx::extract_and_verify_spell` (`charms-client/src/bitcoin_tx.rs:93-112`) calls `finish_extract`, which requires `spell.tx.ins.is_none()` (`charms-client/src/bitcoin_tx.rs:296-298`). `spell_with_committed_ins_and_coins` copies the hosting transaction's inputs, in order, onto the spell (`charms-client/src/bitcoin_tx.rs:327-338`). `spell_ins` reads each input's previous outpoint (`charms-client/src/bitcoin_tx.rs:147-156`). Only then does `finish_extract` build public values and check the SNARK (`charms-client/src/bitcoin_tx.rs:304-310`). For version 16 those public values are CBOR of `(spell_vk, spell)` (`charms-client/src/tx.rs:231-233`).

The prover passes the spell that still has its inputs (`src/spell/prove.rs:141-148`). Stripping happens after `prove` returns. The guest runs `is_correct` on that spell and commits it. Verification rebuilds the public values from the filled spell, so the proved inputs are the hosting transaction's inputs. A check of `spell.tx.ins[0]` inside that proved `is_correct` binds the hosting transaction's first input. On version 16 the whole input list is copied. Versions before v10 drop the last input (`charms-client/src/bitcoin_tx.rs:334-336`), which does not change which input is first.

`well_formed` returns false when `ins` is `None` (`charms-client/src/lib.rs:299-302`), so `is_correct` never reaches the scroll check for the stored Bitcoin spell. `host_scrolls` calls `check_scroll_outputs` when the hosting transaction is Bitcoin (`charms-client/src/lib.rs:1050-1051`). `is_correct` calls `host_scrolls` after the coinbase ban (`charms-client/src/lib.rs:498`). `hosting_tx` returns `None` when there is no first input (`charms-client/src/lib.rs:1029-1031`), and `host_scrolls` then returns `Ok(true)` without the signature check. A Litecoin host that lists scroll outputs fails before that check. The stored Bitcoin spell is not what gets proved. `check_scroll_outputs_with_pubkey` returns the missing-input error only once a matching signed map and `tx.coins` are present (`charms-client/src/lib.rs:1136-1183`). Returning success there would skip `verify_scroll_outputs_signature`. The stored spell still fails earlier, because `coins` is `None` and `well_formed` fails when `ins` is `None`.

A coinbase transaction cannot create Scrolls outputs. `is_null_outpoint` (`charms-data/src/lib.rs:213-215`) is an all-zero txid and vout `0xffffffff`, the outpoint every coinbase input spends. `spell_ins` copies that outpoint from the hosting transaction onto the spell (`charms-client/src/bitcoin_tx.rs:147-156`). `ensure_no_coinbase_scroll_outputs` (`charms-client/src/lib.rs:1122-1133`) reads that committed list, not a separate client-supplied list, and rejects the spell when it also declares Scrolls outputs. `is_correct` runs the ban before `well_formed` (`charms-client/src/lib.rs:476-481`), because the null outpoint has no parent transaction and `well_formed` would otherwise hide the error. `host_scrolls` sends a null first input through `check_scroll_outputs` (`charms-client/src/lib.rs:1039-1048`): `hosting_tx` cannot find a previous transaction whose id is all zeros, and skipping the check would accept the outputs. A valid signature over the null outpoint does not pass.

`fill_scroll_outputs` returns the same error before it asks the canister to sign (`src/tx/scrolls_bitcoin.rs:36`). `addresses` refuses that anchor (`scrolls/src/scrolls_bitcoin/src/lib.rs:500-505`). `sign_tx` is unchanged. When spending an output a coinbase already created, it still rebuilds the anchor as the all-zero txid plus the block height from the coinbase script (`scrolls/src/scrolls_bitcoin/src/lib.rs:1076-1085`, parser at `scrolls/src/scrolls_bitcoin/src/lib.rs:1025-1031`). That spend path is not a way to create Scrolls outputs. A coinbase spell that lists no Scrolls outputs is not rejected by this ban.

A replacement that spends the same first input and keeps the same script map keeps both the key and the signature. The P2WPKH path contains `tx_in_0.to_bytes()`, and the signed preimage contains that same `tx_in_0`. Neither one is the creating transaction's id. A different script map fails the destination check even when the first input is unchanged. The Schnorr key that attests the map is the chain key at `[b"sign"]`, not a per-outpoint key (`scrolls/src/scrolls_bitcoin/src/lib.rs:533-535`).

The signed map's keys must still equal `tx.scrolls`, and each signed script must still equal `tx.coins[i].dest` (`charms-client/src/lib.rs:1149-1175`).

## Prevention

Keep the canister and the client on `signed_scroll_script_pubkeys_preimage`. A second serializer will accept a map the other side will not.

Do not treat a missing first input as success. The stored spell has no inputs. The binding exists only on the filled spell inside `is_correct`.

Do not sign the creating transaction id. Sign the outpoint `sign_tx` rebuilds for a normal creator. A coinbase cannot create Scrolls outputs: the filled first input is the null outpoint, and every coinbase shares it. `sign_tx` still uses the block height when spending an output a coinbase already created. That path stays as it is.

Do not special-case an app. The check does not look at app identity. An index may be listed in `tx.scrolls` with no `SCROLL` charm (`charms-client/src/lib.rs:2208-2217`).

`scrolls_bitcoin_v15` (`rpgc6-oqaaa-aaaak-qy3uq-cai`, `src/tx/scrolls_bitcoin.rs:9`) has to run this signing code before a client that verifies the bound preimage will accept its signatures. Do not install this wasm on `scrolls_bitcoin_v14`. `scrolls/BITCOIN-V16.md` already says that canister still serves the v14 `sign` and `address` methods.

The guest that produces the proof has to be the guest that runs this `is_correct`. A proof from the previous spell-checker does not enforce the binding. Replacing that guest replaces the single version-16 program key. See `docs/solutions/architecture-patterns/one-spell-version-one-verification-key.md`.

Tests that lock the binding:

- `scroll_script_pubkey_preimage_binds_the_first_input` (`charms-data/src/lib.rs:800-817`) checks that CBOR of `(first input, scripts)` differs from the same scripts under another outpoint and from CBOR of the bare map, and that the bytes decode back to that pair.
- `check_scroll_outputs_accepts_map_bound_to_the_spells_first_input` (`charms-client/src/lib.rs:2076-2080`) expects the bound preimage to pass.
- `check_scroll_outputs_rejects_a_reused_or_foreign_signed_map` (`charms-client/src/lib.rs:2084-2106`) expects both a bare-map signature and a signature bound to a different outpoint to fail, and the error to contain `Schnorr`.
- `coinbase_spell_with_scroll_outputs_is_rejected` (`charms-client/src/lib.rs:2129-2164`) fills the spell's inputs from a coinbase via `spell_ins`, accepts a normal bound map on the client-supplied input, and rejects a map signed for the filled null outpoint. `is_correct` returns the coinbase error.
- `coinbase_spell_without_scroll_outputs_still_passes_the_scroll_check` (`charms-client/src/lib.rs:2168-2184`) expects the scroll check to return true, and `is_correct` not to fail with the coinbase error.

## Related

- `docs/solutions/architecture-patterns/one-spell-version-one-verification-key.md`
- `docs/solutions/architecture-patterns/ethereum-host-spell-stays-out-of-the-guest.md` records that CBOR omits `ins` when it is `None`. This note is the Bitcoin fill that restores those inputs at verification, after the guest has already run the Scrolls check on the unstripped spell.
- #269
- `scrolls/BITCOIN-V16.md`
