# Show a spell

`charms tx show-spell` reads a transaction hex and prints the spell embedded in it. The user sees YAML by default, or JSON with `--json`. A transaction with no verifiable spell prints a single stderr line and still exits 0.

## Sub-features

- `show-spell-mock` prints the spell from the checked-in Bitcoin fixture when mock verification is enabled.
- `show-spell-absent` reports that a normal Bitcoin transaction has no spell.

## How to get to it (user POV)

- Run `charms tx show-spell --tx <hex> [--chain bitcoin|cardano|ethereum] [--json] [--mock]`.

## Driving it with control-charms

Preconditions:

- `control-charms doctor` prints `ready: yes`.
- `CHARMS_VERIFY_REPO` is the repository root. The fixture file is `$CHARMS_VERIFY_REPO/charms-lib/test/bitcoin-tx.json` and its `bitcoin` field is the transaction hex.

- **Mock fixture.** Extract the spell as JSON. Run `control-charms cli --feature show-spell --evidence show-spell-mock -- tx show-spell --chain bitcoin --mock --json --tx "$(python3 -c 'import json,os; print(json.load(open(os.environ["CHARMS_VERIFY_REPO"]+"/charms-lib/test/bitcoin-tx.json"))["bitcoin"])')"`. Exit code `0` and stdout is pretty-printed JSON that contains a `version` field. This is the fixture `charms-lib` extracts with mock verification.
- **Same fixture as YAML.** Run `control-charms cli --feature show-spell --evidence show-spell-mock-yaml -- tx show-spell --chain bitcoin --mock --tx "$(python3 -c 'import json,os; print(json.load(open(os.environ["CHARMS_VERIFY_REPO"]+"/charms-lib/test/bitcoin-tx.json"))["bitcoin"])')"`. Exit code `0` and stdout contains `version:`.
- **No spell.** Use the raw transaction `0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000`. Run `control-charms cli --feature show-spell --evidence show-spell-absent -- tx show-spell --chain bitcoin --tx 0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000`. Exit code `0`, stdout is empty, and stderr contains `No spell found in the transaction`.
- **Proof.** `show-spell-mock.txt` shows the JSON spell. `show-spell-absent.txt` shows exit code `0`, empty stdout, and `No spell found in the transaction`. The exit code is the same in both files; the stdout and stderr are the proof.

## Gotchas

- Exit code `0` with stderr `No spell found in the transaction` means no spell was shown. Require the spell text in stdout before calling the extract verified.
- The checked-in Bitcoin fixture is extracted in `charms-lib` with mock verification. Drive it with `--mock`. Omitting `--mock` is a different entry and must be reported on its own.
- `--json` is pretty-printed JSON. The default is YAML.
- `--chain` defaults to `bitcoin`. A Cardano or Ethereum hex needs the matching `--chain`.
- Invalid hex fails the command. That error is not the no-spell line.
