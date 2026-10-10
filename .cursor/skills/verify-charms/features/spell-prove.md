# Prove a spell

`charms spell prove` is how a user turns a spell into a transaction. The binary from `control-charms launch` does not run the SP1 prover. Bitcoin and Cardano proving without `--payload` submits the request to the hosted prove API. `--payload` prints that request and stops. Ethereum prints a local placeholder and an empty proof. A later run that must produce a real Groth16 proof uses `charms-prover` and the SP1 prover network.

## Sub-features

- `prove-vk` prints the protocol version and the spell verification key.
- `prove-payload` prints the prove request and does not call the API.
- `prove-ethereum` prints an Ethereum placeholder whose proof is empty.
- `prove-network` generates a Bitcoin or Cardano proof on the SP1 prover network.

## How to get to it (user POV)

- Run `charms spell vk [--mock]`.
- Run `charms spell prove --spell <file> --change-address <address> [--chain bitcoin|cardano] [--payload] [--fee-rate <sats/vB>]`.
- Run `charms spell prove --chain ethereum --spell <file> --caller <address> --salt <32-byte-hex> --chain-id <id> --charms <proxy>`.
- For a real proof, run `charms-prover spell prove` as documented under **Network proof** below.

## Driving it with control-charms

Preconditions:

- `control-charms doctor` prints `ready: yes` for the default `charms` binary (`prover` is false).
- `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/empty.yaml` is the empty spell from [Check a spell](./spell-check.md).
- `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/placeholder.yaml` is:

```yaml
version: 15
tx:
  outs:
    - {}
  coins:
    - amount: 0
      dest: "0102030405060708090a0b0c0d0e0f1011121314"
app_public_inputs: {}
```

- **Spell verification key.** Run `control-charms cli --feature spell-prove --evidence prove-vk -- spell vk`. Exit code `0` and stdout is `{"prover":false,"version":15,"vk":"0x00425796f4c4fa050043eee14d801b4f935244e44aad6a28de0cd5cb3de0ae52"}`.
- **Mock verification key.** Run `control-charms cli --feature spell-prove --evidence prove-vk-mock -- spell vk --mock`. Exit code `0` and stdout is `{"mock":true,"prover":false,"version":15,"vk":"0x00425796f4c4fa050043eee14d801b4f935244e44aad6a28de0cd5cb3de0ae52"}`.
- **Payload.** Point the API URL at a closed port and ask for the payload. Run `CHARMS_PROVE_API_URL=http://127.0.0.1:9 control-charms cli --feature spell-prove --evidence prove-payload -- spell prove --spell /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/empty.yaml --change-address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 --chain bitcoin --payload`. Exit code `0`. Stdout is one JSON object containing `change_address`, `chain`, and `spell`. The closed port did not stop the command, which is the observation that no request was sent.
- **Ethereum placeholder.** Run `control-charms cli --feature spell-prove --evidence prove-ethereum -- spell prove --chain ethereum --spell /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/placeholder.yaml --caller 0x1111111111111111111111111111111111111111 --salt 0x0000000000000000000000000000000000000000000000000000000000000007 --chain-id 1 --charms 0x3333333333333333333333333333333333333333`. Exit code `0`. Stdout JSON has one field, `tx`. `tx.ethereum.chain_id` is `1`, `tx.ethereum.charms` is `3333333333333333333333333333333333333333`, `tx.ethereum.caller` is `1111111111111111111111111111111111111111`, `tx.ethereum.salt` is `0000000000000000000000000000000000000000000000000000000000000007`, and `tx.ethereum.proof` is an empty string. The object has no `tx_id`, `utxo_ids`, `call`, `beamed_outs`, or `nonce`.
- **Network proof.** This entry does not use the launch binary, `empty.yaml`, or `placeholder.yaml`. Build the prover into the repository target directory: `CARGO_TARGET_DIR="$CHARMS_VERIFY_REPO/target" cargo build --profile=test --bin charms-prover --features prover`. The binary is `$CHARMS_VERIFY_REPO/target/debug/charms-prover`. `NETWORK_PRIVATE_KEY` must already be exported. Do not echo it and do not write it into the repository, the skill, the evidence files, or a pull request. If it is unset, stop and report that the proof did not run. `spell check` has no `--change-address` flag. First accept the funded spell with check, using the spell, app binary, and prerequisite transactions that prove will use. Run `control-charms cli --feature spell-check --evidence spell-check-funded -- spell check --spell /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/spell.yaml --app-bins /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm --prev-txs "$(cat /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/prev-tx.hex)" --chain bitcoin`. Exit code `0`. `spell.yaml`, `app.wasm`, and `prev-tx.hex` are those inputs. Repeat `--prev-txs` once for each extra prerequisite hex, and pass the same flags to prove. Then run `APP_SP1_PROVER=network SPELL_SP1_PROVER=network control-charms cli --bin "$CHARMS_VERIFY_REPO/target/debug/charms-prover" --feature spell-prove --evidence prove-network --timeout 7200 -- spell prove --spell /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/spell.yaml --app-bins /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm --prev-txs "$(cat /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/prev-tx.hex)" --change-address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 --chain bitcoin`. `--change-address` is only on prove. Exit code `0` and stdout is a JSON array of transaction hex. Keep that transcript separate from `prove-payload` and `prove-ethereum`. The handover proof of this skill does not run this entry.
- **Proof of this map's non-network entries.** Keep `prove-vk.txt`, `prove-payload.txt`, and `prove-ethereum.txt`. State in the report which of those ran. Do not call the placeholder or the payload a Groth16 proof.

## Gotchas

- The launch binary prints `"prover":false`. `charms-prover` prints `"prover":true`. A mismatch means the wrong binary was driven. Select the prover with `--bin`, not with `CHARMS_BIN`. Doctor keeps using the binary launch recorded unless `--bin` is set.
- `spell vk` prefixes the key with `0x`. `app vk` does not.
- `--payload` still requires `--change-address` on Bitcoin and Cardano. It returns before any HTTP call. A dead `CHARMS_PROVE_API_URL` must not fail this entry. The same URL must fail a prove that omits `--payload`, and that failure is not a generated proof.
- Ethereum placeholders reject `--mock`, `--payload`, `--change-address`, `--prev-txs`, `--beamed-from`, `--app-bins`, `--private-inputs`, `--app-signatures`, and `--collateral-utxo`. Bitcoin and Cardano reject `--caller`, `--salt`, `--chain-id`, and `--charms`.
- A short `--salt` fails with `expected 32 bytes`.
- `--fee-rate` must be at least `1.0` for Bitcoin and Cardano. The default is `2.0`.
- `SPELL_SP1_PROVER` must be `network` or `app` on the prover binary. Any other value, including unset, panics. `APP_SP1_PROVER` for a network proof is `network`. `cuda` is unimplemented.
- `--mock` skips proof generation. Do not report it as `prove-network`.
