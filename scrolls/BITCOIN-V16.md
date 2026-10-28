# scrolls_bitcoin for spell version 16

`scrolls_bitcoin_v14` is `lmbwh-3qaaa-aaaak-qunha-cai`. `scrolls_bitcoin_v15` is `rpgc6-oqaaa-aaaak-qy3uq-cai`. Both were built from this crate before it verified spell version 16, so `verify_spell` on those deployments returns `unsupported spell version 16 (NEXT_SCROLLS_BITCOIN_CANISTER_ID not set)`.

This tree's `CURRENT_VERSION` is 16. A wasm built from it verifies version 16 locally and does not consult `NEXT_SCROLLS_BITCOIN_CANISTER_ID` for that version. `verify_spell` accepts a version-16 proof that commits this tree's `SPELL_VK`. `NEXT` is `option_env!("NEXT_SCROLLS_BITCOIN_CANISTER_ID").unwrap_or("")`. It is not an init argument. `init` stays `service : () -> { ... }`.

The host keeps calling `addresses` on v15. A new canister id derives new threshold keys. Spending a scroll output still requires `sign_and_submit` on the canister whose key controls that output. Forwarding checks a spell. It does not sign.

Do not run these commands as part of a code change. The deploy is separate.

## New canister

Build with the variable unset, so a later version is not forwarded at this id. `dfx build` passes the process environment through to `cargo`, which is what `option_env!` reads. If dfx reuses a wasm, delete that canister's output under `.dfx` and build again.

```bash
cd scrolls
env -u NEXT_SCROLLS_BITCOIN_CANISTER_ID dfx build scrolls_bitcoin_v16
dfx canister create scrolls_bitcoin_v16 --network ic
dfx deploy scrolls_bitcoin_v16 --network ic --yes
dfx canister id scrolls_bitcoin_v16 --network ic
```

`dfx deploy` passes no `--argument`. The new id is whatever `dfx canister id` prints. The wasm path is the one `dfx build` prints. Confirm the unset build does not contain a canister id that was only supplied for a later upgrade:

```bash
strings .dfx/local/canisters/scrolls_bitcoin_v16/scrolls_bitcoin_v16.wasm | grep NEXT_SCROLLS || true
```

## Already deployed canisters

Read controllers before changing either deployment:

```bash
dfx canister status lmbwh-3qaaa-aaaak-qunha-cai --network ic
dfx canister status rpgc6-oqaaa-aaaak-qy3uq-cai --network ic
```

Controllers empty: stop for that canister. Do not upgrade it. It will keep returning `unsupported spell version 16 (NEXT_SCROLLS_BITCOIN_CANISTER_ID not set)`. Call `verify_spell` on the new canister directly. `sign_and_submit` for an output controlled by that canister cannot move to the new id, because the keys did not move. A version-16 spell that spends or creates a scroll output at that key cannot be signed until the canister that holds the key runs this wasm. Spells that do not touch those outputs do not need it.

Controllers present: install this tree's wasm there. Version 16 is verified locally, so version 16 does not consult `NEXT`. Set `NEXT` anyway so a version this build does not know forwards to the new canister. Build that wasm only after the new id exists, and do not reuse the wasm built with the variable unset.

```bash
NEXT_SCROLLS_BITCOIN_CANISTER_ID=<new-id> dfx build scrolls_bitcoin_v15
dfx canister install rpgc6-oqaaa-aaaak-qy3uq-cai --network ic --mode upgrade --yes --wasm .dfx/local/canisters/scrolls_bitcoin_v15/scrolls_bitcoin_v15.wasm
```

Repeat with `scrolls_bitcoin_v14` and `lmbwh-3qaaa-aaaak-qunha-cai`. Upgrade mode keeps the canister id and its threshold keys, so v15 still signs the outputs it already controls, and `addresses` on v15 still matches the host.

The repo does not record whether those controllers are already gone. The status command is the branch.

## Removing controllers from the new canister

Clearing controllers is irreversible. Do it only after status has shown the canister operators intend to keep, and only if that canister is the one `verify_spell` should call:

```bash
dfx canister update-settings scrolls_bitcoin_v16 --network ic --controllers ''
dfx canister status scrolls_bitcoin_v16 --network ic
```

Status must show no controllers. If dfx rejects the empty list, the call to make is the management-canister settings update that sets `controllers` to the empty vector. Do not substitute a personal principal.
