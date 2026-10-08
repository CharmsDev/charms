# Derive a destination

`charms util dest` prints the hex `dest` a user pastes into spell YAML for a coin output. An address becomes the chain's raw destination bytes. A list of apps becomes the Cardano proxy script address for those apps.

## Sub-features

- `dest-ethereum` encodes a 20-byte Ethereum address.
- `dest-bitcoin` encodes a Bitcoin address as its scriptPubKey.
- `dest-cardano-addr` encodes a Cardano bech32 address as its raw bytes.
- `dest-apps` encodes one or more `tag/identity/vk` apps as a Cardano proxy destination.
- `dest-reject` rejects a missing selector, both selectors, and `--apps` on Bitcoin or Ethereum.

## How to get to it (user POV)

- Run `charms util dest --addr <address> [--chain bitcoin|cardano|ethereum]`.
- Run `charms util dest --apps <tag/identity_hex/vk_hex> [--chain cardano]`. Repeat `--apps` for more than one app.

## Driving it with control-charms

Preconditions:

- `control-charms doctor` prints `ready: yes`.
- No spell file or wallet is required.

- **Ethereum address.** Encode the 20-byte address. Run `control-charms cli --feature dest --evidence dest-ethereum -- util dest --addr 0x0102030405060708090a0b0c0d0e0f1011121314 --chain ethereum`. Exit code `0`, stdout is `0102030405060708090a0b0c0d0e0f1011121314`, and stderr is empty.
- **Bitcoin address.** Encode the BIP173 vector. Run `control-charms cli --feature dest --evidence dest-bitcoin -- util dest --addr bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 --chain bitcoin`. Exit code `0`, stdout is `0014751e76e8199196d454941c45d1b3a323f1433bd6`, and stderr is empty.
- **Bitcoin auto-detect.** Omit `--chain` for the same address. Run `control-charms cli --feature dest --evidence dest-bitcoin-auto -- util dest --addr bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`. Exit code `0` and stdout matches `dest-bitcoin.stdout`.
- **Cardano address.** Encode a mainnet bech32 address. Run `control-charms cli --feature dest --evidence dest-cardano -- util dest --addr addr1qyp2t40fprytezw5nnlj6qjxn82ck3yhkvdy3ze9muqzvj2x2862gdndh8y3vc3yja94sf98cyyu2qsjhy8y5949w37qyt3lnt --chain cardano`. Exit code `0`, stdout is `0102a5d5e908c8bc89d49cff2d024699d58b4497b31a488b25df0026494651f4a4366db9c9166224974b5824a7c109c50212b90e4a16a5747c`, and stderr is empty.
- **Cardano auto-detect.** Omit `--chain` for that address. Run `control-charms cli --feature dest --evidence dest-cardano-auto -- util dest --addr addr1qyp2t40fprytezw5nnlj6qjxn82ck3yhkvdy3ze9muqzvj2x2862gdndh8y3vc3yja94sf98cyyu2qsjhy8y5949w37qyt3lnt`. Exit code `0` and stdout matches `dest-cardano.stdout`.
- **Cardano apps.** Encode a proxy for a zero identity and zero verification key. Run `control-charms cli --feature dest --evidence dest-apps -- util dest --apps t/0000000000000000000000000000000000000000000000000000000000000000/0000000000000000000000000000000000000000000000000000000000000000 --chain cardano`. Exit code `0` and stdout is one line of lowercase hex.
- **Apps default chain.** Repeat without `--chain`. Run `control-charms cli --feature dest --evidence dest-apps-auto -- util dest --apps t/0000000000000000000000000000000000000000000000000000000000000000/0000000000000000000000000000000000000000000000000000000000000000`. Exit code `0` and stdout matches `dest-apps.stdout`.
- **Reject none.** Pass no selector. Run `control-charms cli --feature dest --evidence dest-reject-none -- util dest`. Exit code is non-zero and stderr contains `Error: exactly one of --addr or --apps must be provided`.
- **Reject both.** Pass an address and an app. Run `control-charms cli --feature dest --evidence dest-reject-both -- util dest --addr 0x0102030405060708090a0b0c0d0e0f1011121314 --apps t/0000000000000000000000000000000000000000000000000000000000000000/0000000000000000000000000000000000000000000000000000000000000000`. Exit code is non-zero and stderr contains `Error: exactly one of --addr or --apps must be provided`.
- **Reject apps on Bitcoin.** Run `control-charms cli --feature dest --evidence dest-reject-apps-bitcoin -- util dest --apps t/0000000000000000000000000000000000000000000000000000000000000000/0000000000000000000000000000000000000000000000000000000000000000 --chain bitcoin`. Exit code is non-zero and stderr contains `Error: --apps only works with Cardano`.
- **Proof.** Keep `dest-ethereum.txt` and `dest-bitcoin.txt`. Each file names feature `dest`, the argv, exit code `0`, and the stdout hex above.

## Gotchas

- Auto-detect tries a Cardano bech32 address before Bitcoin. A Bitcoin address still resolves. An unrecognized string fails with `could not parse address as Bitcoin or Cardano; try specifying --chain`.
- Ethereum requires `--chain ethereum`. Auto-detect does not treat a hex address as Ethereum.
- `--addr` and `--apps` are exclusive. The error text is `exactly one of --addr or --apps must be provided`.
- `--apps` is Cardano-only. Bitcoin and Ethereum fail with `--apps only works with Cardano`.
- Stdout is the hex destination with no `0x` prefix. Assert the whole line, not a prefix.
