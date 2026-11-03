# scrolls_litecoin

`scrolls_litecoin` is the existing canister `ya3wx-vqaaa-aaaak-qzmja-cai`. Upgrade that canister from this tree. The id is already recorded as `scrolls_litecoin` in `.icp/data/mappings/ic.ids.json` and in `canister_ids.json`. These commands install the `scrolls_litecoin` wasm on that id.

Do not run these commands as part of a code change. This pull request does not deploy or upgrade anything. Ivan upgrades `ya3wx` from his own machine after this merges.

`init` takes no arguments. The candid service is `service : () ->`. The upgrade commands pass no `--args`. `do_init` reads the fee addresses embedded from `src/scrolls_litecoin/config.yaml`. There is no setter for those addresses.

`NEXT_SCROLLS_LITECOIN_CANISTER_ID` is `option_env!` at compile time. It is not an init argument. `icp build` and `icp deploy` both compile, and `icp deploy` compiles again after `icp build`. The `@dfinity/rust` recipe in `icp.yaml` runs `cargo`, which inherits the process environment that `option_env!` reads. Every command below that compiles the wasm unsets the variable, so the installed wasm does not forward to a later id.

`addresses` signs the first-input preimage with this canister's chain key and pays for Schnorr from the canister's own cycle balance. Callers of `addresses` attach no cycles. `deposit_cycles` still accepts cycles. It rejects an attached amount below `MIN_DEPOSIT_CYCLES` (`1000000000000`). `cycles_balance` and `config` are queries.

The Litecoin scroll key pinned in `charms-client` is `SCROLLS_LITECOIN_ADDRS_PUBKEY` `1ed9e3732a0b1df786044973959dbdd0aec8e0e23bbb9bdbe3459e5d57c4728f`. That is the BIP-340 x-only public key of `ya3wx-vqaaa-aaaak-qzmja-cai`, derivation path `[b"sign"]`, key id `key_1`. It is not the spell verification key, and it stays the same when the spell key changes. The host calls `addresses` on `ya3wx`.

The fee addresses are literals in `src/scrolls_litecoin/config.yaml`:

- `main`: `ltc1qxxxjm06n50uugxewxe5r5w5tskqwq4gk2lpt90`
- `test`: `tltc1qrk6da5g0592sx6lmgpchaf5qy2lgn8am8s7hp5`

To change them, edit only that file, then run the same unset-variable build and upgrade. That edit does not touch the Bitcoin fee config.

## Upgrade

Run this from `scrolls/`, where `icp.yaml` lives. `--mode upgrade` keeps the canister id, its state, and its threshold keys, and runs the upgrade hook. `--no-create` errors when `scrolls_litecoin` is missing from the `ic` id map, so a second canister is not created. `--cycles` pays for creation and conflicts with `--no-create`, so the deploy command does not pass it.

```bash
cd scrolls
env -u NEXT_SCROLLS_LITECOIN_CANISTER_ID icp build scrolls_litecoin -e ic
env -u NEXT_SCROLLS_LITECOIN_CANISTER_ID icp deploy scrolls_litecoin --mode upgrade --no-create -e ic --yes
```

## Cycles

icp-cli pays from the cycles ledger of the identity running the command. The admin cycles wallet `qcncw-aqaaa-aaaac-qhmma-cai` is empty, and these commands do not use it. The admin identity's cycles ledger holds about 3.8T cycles. `icp cycles balance` reads that ledger. `icp canister top-up` draws the ledger onto the canister's operating balance. `icp cycles transfer` only credits a principal's ledger balance, so it does not fund this canister.

Read the ledger and the canister before the upgrade. When the canister balance is too low to upgrade, top it up, then run the deploy above.

```bash
cd scrolls
icp cycles balance -e ic
icp canister status scrolls_litecoin -e ic
icp canister top-up ya3wx-vqaaa-aaaak-qzmja-cai --amount 1T -e ic
```

## Verify

Run these after the upgrade. This pull request does not run them.

1. `icp canister status` on `ya3wx-vqaaa-aaaak-qzmja-cai` shows the wasm from this build.
2. `config` returns the Litecoin fee addresses from `src/scrolls_litecoin/config.yaml`.
3. `cycles_balance` returns a balance above zero.

```bash
cd scrolls
icp canister status ya3wx-vqaaa-aaaak-qzmja-cai -e ic
icp canister call scrolls_litecoin config --query -e ic
icp canister call scrolls_litecoin cycles_balance --query -e ic
```

4. The wasm built with the forwarding variable unset does not embed a canister principal. The error text names that variable even when its value is empty, so this check does not search for that name. `test -s` fails when the wasm is absent. A principal in the file fails the check. icp-cli writes the artifact at `.icp/cache/artifacts/scrolls_litecoin`, with no `.wasm` suffix.

```bash
set -euo pipefail
wasm=.icp/cache/artifacts/scrolls_litecoin
test -s "$wasm"
status=0
found=$(strings -n 27 "$wasm" | grep -E '[a-z2-7]{5}(-[a-z2-7]{5}){3}-[a-z2-7]{1,5}') || status=$?
test "$status" -eq 1
test -z "$found"
```

5. This wasm stays off `rpgc6-oqaaa-aaaak-qy3uq-cai` and `lmbwh-3qaaa-aaaak-qunha-cai`. `rpgc6` is upgraded from `BITCOIN-V16.md` with the Bitcoin wasm. `lmbwh-3qaaa-aaaak-qunha-cai` stays on its current wasm.

```bash
set -euo pipefail
wasm=.icp/cache/artifacts/scrolls_litecoin
test -s "$wasm"
status=0
strings "$wasm" | grep -E 'rpgc6-|lmbwh-' || status=$?
test "$status" -eq 1
```

These deployments stay on their current wasm:

- `lmbwh-3qaaa-aaaak-qunha-cai`
- `tty7k-waaaa-aaaak-qvngq-cai`
- `z4e4c-oqaaa-aaaak-qzlqq-cai`
- Ethereum proxy `0x7f7ab9224782dE7a20e89E6fc0DE52Ff6b48d8f0`
