# Check a spell

`charms spell check` runs the spell's app contracts on this machine and prints the cycle counts. It does not generate a proof and it does not call the prove API.

## Sub-features

- `spell-check-empty` accepts a spell with no inputs, no outputs, and no apps.
- `spell-check-missing-ins` rejects a spell that omits `tx.ins`.

## How to get to it (user POV)

- Run `charms spell check --spell <file> [--app-bins <wasm>] [--private-inputs <file>] [--app-signatures <file>] [--prev-txs <hex>] [--beamed-from <yaml>] [--chain bitcoin|cardano|ethereum] [--mock]`.
- Omit `--spell` to read the spell from stdin. The default path is `/dev/stdin`.

## Driving it with control-charms

Preconditions:

- `control-charms doctor` prints `ready: yes`.
- Write `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/empty.yaml` with this body:

```yaml
version: 15
tx:
  ins: []
  outs: []
  coins: []
app_public_inputs: {}
```

- Write `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/missing-ins.yaml` with `ins` removed and the same `outs`, `coins`, and `app_public_inputs`.

- **Empty spell.** Check the empty spell. Run `control-charms cli --feature spell-check --evidence spell-check-empty -- spell check --spell /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/empty.yaml --chain bitcoin`. Exit code `0`, stdout is empty, and stderr contains `cycles spent: []`.
- **Missing inputs.** Check the spell with no `ins` key. Run `control-charms cli --feature spell-check --evidence spell-check-missing-ins -- spell check --spell /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/missing-ins.yaml --chain bitcoin`. Exit code is non-zero and stderr contains `Error: spell.tx.ins must be present`.
- **Proof.** `spell-check-empty.txt` records exit code `0` and `cycles spent: []`. `spell-check-missing-ins.txt` records the non-zero exit and `Error: spell.tx.ins must be present`. Neither transcript is a proof.

## Gotchas

- `tx.ins` must be present. An omitted key fails with `Error: spell.tx.ins must be present`. An empty list is present.
- `tx.coins` must be present and the same length as `tx.outs`. A missing `coins` key fails with `coins must be present`.
- The protocol version in the file must be `15`.
- Apps that are not simple transfers need `--app-bins`. The failure names the apps and says `no app binaries provided`.
- A spell with unbound Scrolls outputs can still exit 0 after a stderr warning: `spell has Scrolls outputs whose scriptPubKeys are not yet bound`. That warning is not a successful binding.
- `--mock` does not turn this command into a proof. Cycle output is the local contract run.
- Checking a spell does not write a transaction. Confirm that the work directory gained no transaction file.
