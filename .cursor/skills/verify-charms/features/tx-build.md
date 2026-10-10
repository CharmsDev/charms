# Build an Ethereum transaction

`charms tx build --chain ethereum` reads the `tx` object printed by `spell prove` and prints the signable `transact` call. The user sends that call. The command does not call the prover and does not take a spell file.

## Sub-features

- `tx-build-ethereum` prints `{from, to, data, value}` for an empty UTXO record.
- `tx-build-not-ethereum` rejects a build that is not `--chain ethereum`.

## How to get to it (user POV)

- Run `charms spell prove --chain ethereum --spell <file> --caller <address> --salt <32-byte-hex> --chain-id <id> --charms <proxy>`.
- Run `charms tx build --chain ethereum --tx <json>`.
- Run `charms tx build --tx <json>` and see it reject the default chain.

## Driving it with control-charms

Preconditions:

- `control-charms doctor` prints `ready: yes`.
- `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/placeholder.yaml` is the placeholder from [Prove a spell](./spell-prove.md).

- **Empty UTXO record.** Run `control-charms cli --feature tx-build --evidence tx-build-prove -- spell prove --chain ethereum --spell /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/placeholder.yaml --caller 0x1111111111111111111111111111111111111111 --salt 0x0000000000000000000000000000000000000000000000000000000000000007 --chain-id 1 --charms 0x3333333333333333333333333333333333333333`. Exit code `0`. Stdout JSON has one field, `tx`.
- **Signable call.** Run `control-charms cli --feature tx-build --evidence tx-build-ethereum -- tx build --chain ethereum --tx "$(jq -c .tx /tmp/charms-verify-evidence/$CHARMS_VERIFY_RUN_ID/tx-build-prove.stdout)"`. Exit code `0`. Stdout is one JSON object whose keys are `data`, `from`, `to`, and `value`. `from` is `0x1111111111111111111111111111111111111111`. `to` is `0x3333333333333333333333333333333333333333`. `value` is `0`. `data` starts with `0x27485a93`.
- **Default chain.** Run `control-charms cli --feature tx-build --evidence tx-build-not-ethereum -- tx build --tx "$(jq -c .tx /tmp/charms-verify-evidence/$CHARMS_VERIFY_RUN_ID/tx-build-prove.stdout)"`. Exit code is non-zero. Stderr contains `tx build is implemented for ethereum`.
- **Proof.** `tx-build-ethereum.txt` shows the four fields and the `transact` selector. `tx-build-not-ethereum.txt` shows the rejection. Neither transcript is a chain receipt.

## Gotchas

- `--tx` is the JSON object at `.tx`, not the whole prove output and not a file path.
- `--chain` defaults to `bitcoin`. An Ethereum record still needs `--chain ethereum`.
- The printed call has no account nonce, gas fields, or signature. Those belong to the wallet that sends it.
- This entry does not deploy a contract and does not prove that the call was mined.
