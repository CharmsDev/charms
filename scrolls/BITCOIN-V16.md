# scrolls_bitcoin for spell version 16

`scrolls_bitcoin_v14` is `lmbwh-3qaaa-aaaak-qunha-cai`. That canister stays on its current wasm. It serves the v14 methods `sign` and `address`. This crate does not export either method. `rpgc6-oqaaa-aaaak-qy3uq-cai` calls `sign` on `lmbwh` to sign vault inputs that spend v14 outputs. Installing this wasm there removes `sign` and `address`, and those inputs can no longer be signed.

`scrolls_bitcoin_v15` is the existing canister `rpgc6-oqaaa-aaaak-qy3uq-cai`. Upgrade that canister from this tree. The id is already `scrolls_bitcoin_v15` in `.icp/data/mappings/ic.ids.json`. `--no-create` errors when that name is missing from the map, so the upgrade does not create a canister. There is no separate version-16 canister id. The identity that runs the upgrade has to be a controller of `rpgc6`. This runbook does not clear controllers.

This tree's `CURRENT_VERSION` is 16. A wasm built from it verifies version 16 in the canister and embeds this tree's `SPELL_VK`. Version 16 has one key. `NEXT_SCROLLS_BITCOIN_CANISTER_ID` is a const match on `option_env!("NEXT_SCROLLS_BITCOIN_CANISTER_ID")`: `Some(id) => id`, `None => ""`. It is not an init argument. Version 16 does not consult it. Leave it unset on every command that compiles the wasm, so this id does not forward. `init` stays `service : () ->`. The upgrade commands pass no `--args`.

Until this upgrade, the deployed `rpgc6` wasm still embeds the previous version-16 key. After the upgrade, that same canister id embeds the key from this tree.

The host keeps calling `addresses` on `rpgc6`. Upgrade mode keeps that id and its threshold keys, so `SCROLLS_ADDRS_PUBKEY` still matches. Forwarding checks a spell. It does not sign.

Do not run these commands as part of a code change. This pull request does not deploy or upgrade anything. Ivan upgrades `rpgc6` from his own machine after this merges.

## Upgrade

`icp build` and `icp deploy` both compile. `icp deploy` compiles again, so both commands unset `NEXT_SCROLLS_BITCOIN_CANISTER_ID`. The `@dfinity/rust` recipe in `icp.yaml` runs `cargo`, and cargo inherits that process environment. `option_env!` reads it. `--mode upgrade` preserves canister state and runs the upgrade hook. `--cycles` pays for creation and conflicts with `--no-create`, so the deploy command does not pass it.

The wasm this installs is the `scrolls_bitcoin` package, written to `.icp/cache/artifacts/scrolls_bitcoin_v15`. The Litecoin wasm is a different artifact and a different canister. `BITCOIN-V16.md` upgrades `rpgc6`. `LITECOIN.md` upgrades `ya3wx-vqaaa-aaaak-qzmja-cai`.

```bash
cd scrolls
env -u NEXT_SCROLLS_BITCOIN_CANISTER_ID icp build scrolls_bitcoin_v15 -e ic
env -u NEXT_SCROLLS_BITCOIN_CANISTER_ID icp deploy scrolls_bitcoin_v15 --mode upgrade --no-create -e ic --yes
```

Confirm the artifact exists:

```bash
set -euo pipefail
wasm=.icp/cache/artifacts/scrolls_bitcoin_v15
test -s "$wasm"
```

This Bitcoin wasm contains `lmbwh-3qaaa-aaaak-qunha-cai` on purpose. `rpgc6` calls that canister's `sign`. A principal scan of this file finds `lmbwh`.

## Cycles

icp-cli pays from the cycles ledger of the identity running the command. The admin cycles wallet `qcncw-aqaaa-aaaac-qhmma-cai` is empty, and these commands do not use it. The admin identity's cycles ledger holds about 3.8T cycles. `icp canister top-up` draws that ledger balance onto the canister's operating balance. `icp cycles transfer` only credits a principal's ledger balance, so it does not fund `rpgc6`.

Read status before the upgrade. When the cycles balance is too low to upgrade, top up, then run the deploy above.

```bash
cd scrolls
icp cycles balance -e ic
icp canister status scrolls_bitcoin_v15 -e ic
icp canister top-up rpgc6-oqaaa-aaaak-qy3uq-cai --amount 1T -e ic
```

## Verify

```bash
cd scrolls
icp canister status rpgc6-oqaaa-aaaak-qy3uq-cai -e ic
icp canister call scrolls_bitcoin_v15 config --query -e ic
icp canister call scrolls_bitcoin_v15 cycles_balance --query -e ic
```

`lmbwh-3qaaa-aaaak-qunha-cai` stays on its current wasm. `scrolls_cardano` (`tty7k-waaaa-aaaak-qvngq-cai`), `charms_metadata` (`z4e4c-oqaaa-aaaak-qzlqq-cai`), and the Ethereum proxy `0x7f7ab9224782dE7a20e89E6fc0DE52Ff6b48d8f0` stay on their current deployments.
