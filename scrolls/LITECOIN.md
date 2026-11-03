# scrolls_litecoin

This canister signs Litecoin scroll outputs. It is a new canister id. Do not run these commands as part of a code change. Do not deploy from this pull request.

`init` takes no arguments. The candid service is `service : () ->`. `dfx deploy` passes no `--argument`. `do_init` reads the fee addresses embedded from `src/scrolls_litecoin/config.yaml`. `dfx.json` sets no create-time cycle balance, and this runbook does not pass a cycle amount to `dfx canister create` or `dfx deploy`.

`NEXT_SCROLLS_LITECOIN_CANISTER_ID` is `option_env!` at compile time. It is not an init argument. Build with the variable unset so this wasm does not forward to a later id.

`deposit_cycles` rejects an attached amount below `MIN_DEPOSIT_CYCLES` `1000000000000`. `cycles_balance` is a query.

`addresses` accepts caller cycles before `sign_with_schnorr`. The amount is the quote from `cost_sign_with_schnorr` for key `key_1` and that request. The IC cycle-cost reference lists `26153846153` cycles for the production key. The canister accepts that quote and does not keep a surplus as a fee. An empty `out_is` is rejected before the signing call. Attaching no cycles does not sign.

The fee addresses `config` returns are the P2WPKH programs already published for the Bitcoin fee addresses, encoded with Litecoin HRPs:

- `main`: `ltc1qxxxjm06n50uugxewxe5r5w5tskqwq4gk2lpt90`
- `test`: `tltc1qrk6da5g0592sx6lmgpchaf5qy2lgn8am8s7hp5`

The threshold key of the new id is not in this tree. Litecoin scroll outputs stay rejected until a later change pins that key.

## Create

```bash
cd scrolls
env -u NEXT_SCROLLS_LITECOIN_CANISTER_ID dfx build scrolls_litecoin
dfx canister create scrolls_litecoin --network ic
dfx deploy scrolls_litecoin --network ic --yes
```

Top up after create by attaching cycles to `deposit_cycles`. The minimum is `1000000000000`.

```bash
dfx canister call scrolls_litecoin deposit_cycles --network ic --with-cycles 1000000000000
dfx canister call scrolls_litecoin cycles_balance --network ic
```

## Verify a mainnet deploy

Run these after the canister exists. This pull request does not run them.

1. `dfx canister id scrolls_litecoin --network ic` prints the new id.
2. `dfx canister status` on that id shows the wasm from that build.

```bash
dfx canister status "$(dfx canister id scrolls_litecoin --network ic)" --network ic
```

3. `dfx canister call scrolls_litecoin config --network ic` returns the Litecoin fee addresses from that canister's yaml.
4. `dfx canister call scrolls_litecoin cycles_balance --network ic` returns a balance above zero.
5. The wasm built with the forwarding variable unset does not embed a canister principal. The error text names that variable even when its value is empty, so this check does not search for that name. `test -s` fails when the wasm is absent. A principal in the file fails the check.

```bash
set -euo pipefail
wasm=.dfx/local/canisters/scrolls_litecoin/scrolls_litecoin.wasm
test -s "$wasm"
status=0
found=$(strings -n 27 "$wasm" | grep -E '[a-z2-7]{5}(-[a-z2-7]{5}){3}-[a-z2-7]{1,5}') || status=$?
test "$status" -eq 1
test -z "$found"
```

6. Do not install this wasm onto `rpgc6-oqaaa-aaaak-qy3uq-cai` or `lmbwh-3qaaa-aaaak-qunha-cai`.

```bash
set -euo pipefail
wasm=.dfx/local/canisters/scrolls_litecoin/scrolls_litecoin.wasm
test -s "$wasm"
status=0
strings "$wasm" | grep -E 'rpgc6-|lmbwh-' || status=$?
test "$status" -eq 1
```

Leave these deployments on their current wasm:

- `rpgc6-oqaaa-aaaak-qy3uq-cai`
- `lmbwh-3qaaa-aaaak-qunha-cai`
- `tty7k-waaaa-aaaak-qvngq-cai`
- `z4e4c-oqaaa-aaaak-qzlqq-cai`
- Ethereum proxy `0x7f7ab9224782dE7a20e89E6fc0DE52Ff6b48d8f0`
