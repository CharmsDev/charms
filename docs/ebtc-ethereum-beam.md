# eBTC beam from Bitcoin to Ethereum

Protocol version 16. This run created an empty Charms UTXO on Ethereum mainnet, minted 1000 eBTC on Bitcoin mainnet, beamed that output to the empty UTXO, and claimed it on Ethereum.

The receiving address is `0xcCc6dD3c85DAa7bBB33B5ea22bbFBF28B6fA8Cc8`. The ERC-20 clone for this app is Charm (CHARM), 0 decimals, at `0x97af4B32037C065700799cadB9adaAB6ee1ACF86`. That page shows the 1,000 CHARM balance and the claim transfer:

<https://etherscan.io/token/0x97af4b32037c065700799cadb9adaab6ee1acf86?a=0xcCc6dD3c85DAa7bBB33B5ea22bbFBF28B6fA8Cc8>

The claim transaction:

<https://etherscan.io/tx/0xd63766db7e9d656894bd3788ce9d2573da0c4ef74874729b925fe161f2d9faff>

## Parties

| | |
| --- | --- |
| Charms proxy | `0xB7BF53A8f4870dF4D4be66E5C019882be4490C96` |
| Placeholder owner and broadcaster | `0x0Fec1E72F9702681dFDC30c46530FBD1B9797453` |
| eBTC receiver | `0xcCc6dD3c85DAa7bBB33B5ea22bbFBF28B6fA8Cc8` |
| eBTC app | `t/0796f63ed48144b4ec69fb794fbc2290ae63acf945fb035d5474648b50ee43b6/fd0cac892e457454be0212fa7d9a0e1517d5bd6a33aa7c66a1f10f55e375c290` |
| App source | <https://github.com/CharmsDev/eBTC> |

The token app and the vault app share that identity and verification key. The tag is `t` for the token and `c` for the vault. In a spell that lists both, `c` is app index 0 and `t` is app index 1.

## 1. Empty Ethereum UTXO

The placeholder spell has no inputs. Its single output is empty and owned by the broadcaster, so the later claim can spend it.

```yaml
version: 16
tx:
  outs:
    - {}
  coins:
    - amount: 0
      dest: "0fec1e72f9702681dfdc30c46530fbd1b9797453"
app_public_inputs: {}
```

`charms spell prove --chain ethereum` prints the Charms record for this spell. It does not call a prover. The salt is `06a53d8411bd66bc0cc361c80559d4099d4ecaccdbbb0e1167fc2ddb967521e4`, the chain id is 1, and `--charms` is the proxy above.

`charms tx build --chain ethereum` turns that record into the `transact` call. The broadcaster submitted it.

| | |
| --- | --- |
| Transaction | [`0xd575cecf8f1a2a289a54952b4d921ed7ac888b071a26aed9d59fc8e1e20cd640`](https://etherscan.io/tx/0xd575cecf8f1a2a289a54952b4d921ed7ac888b071a26aed9d59fc8e1e20cd640) |
| Block | 26187325 |
| Placeholder id | `16092b44f8b90334ea9539ed1c828608af25335efef64631cc43228feb8002ce:0` |
| Beam hash | `1e26c76c247534d5fb17ae6d133e2be9de03e9edf84871a405336735d9d5284a` |

The beam hash is what a Bitcoin output puts in `beamed_outs` to name this placeholder.

## 2. Mint eBTC and beam it

The mint spends Bitcoin input `0f0bde824e7f5833550a508dcabbdc9afef82ccfcb49a15cf5ad396a4930ef2b:2`. Output 0 carries 1000 of the token app and is beamed. Output 1 carries the vault app. The 330 sats on the beamed output are the coin amount; the eBTC amount is the charm.

```yaml
version: 16
tx:
  ins:
    - 0f0bde824e7f5833550a508dcabbdc9afef82ccfcb49a15cf5ad396a4930ef2b:2
  outs:
    - 1: 1000
    - 0: ~
  beamed_outs:
    0: 1e26c76c247534d5fb17ae6d133e2be9de03e9edf84871a405336735d9d5284a
  coins:
    - amount: 330
      dest: "00146cc45054ee8bd66b9e34aa949818e3b9ad2de598"
    - amount: 1300
      dest: "00141ccbe7f8b1e364fe23110c9f720c2b5c2a37527e"
app_public_inputs:
  c/0796f63ed48144b4ec69fb794fbc2290ae63acf945fb035d5474648b50ee43b6/fd0cac892e457454be0212fa7d9a0e1517d5bd6a33aa7c66a1f10f55e375c290: ~
  t/0796f63ed48144b4ec69fb794fbc2290ae63acf945fb035d5474648b50ee43b6/fd0cac892e457454be0212fa7d9a0e1517d5bd6a33aa7c66a1f10f55e375c290: ~
```

`charms-prover spell prove` with `APP_SP1_PROVER=network` and `SPELL_SP1_PROVER=network` printed the unsigned Bitcoin transaction. The wallet that held the funding output signed and broadcast it.

| | |
| --- | --- |
| Transaction | [`7762dc7d5afb95c9ee6e5dd5dd0060d06714a76d98b0cd526c13a19ae837ce1b`](https://mempool.space/tx/7762dc7d5afb95c9ee6e5dd5dd0060d06714a76d98b0cd526c13a19ae837ce1b) |
| Confirming block | 971336 (`0000000000000000000034b669324d820472e2b4dc1c79152e833636e0ad9abd`), 2026-10-14 02:18:00 UTC |
| Beamed output | vout 0, 330 sats, 1000 eBTC |
| Vault output | vout 1, 1300 sats, `bc1qrn970793udj0ugc3pj0hyrptts4rw5n7qxeya2` |

## 3. Bitcoin finality

The claim waits until that Bitcoin transaction is final under the Charms work threshold. The proof passed to the claim is the raw transaction, its Merkle block, and the headers of blocks 971337 through 971342. The header of 971337 chains to block 971336.

## 4. Claim on Ethereum

The ERC-20 clone was not deployed yet. `ensureToken` for this app created it before the claim.

| | |
| --- | --- |
| `ensureToken` | [`0x82dee4c14dabeed98bfde817e6717994287393ee442f7a6b7449f89dc16d3153`](https://etherscan.io/tx/0x82dee4c14dabeed98bfde817e6717994287393ee442f7a6b7449f89dc16d3153) |
| Token | `0x97af4B32037C065700799cadB9adaAB6ee1ACF86` |

The claim spends the placeholder and takes the beamed Bitcoin output as input 0. It lists only the token app, so the received 1000 is app index 0. The amounts match, and `charms spell check` reports a simple transfer, so the prove command takes no app binary.

```yaml
version: 16
tx:
  ins:
    - 16092b44f8b90334ea9539ed1c828608af25335efef64631cc43228feb8002ce:0
  outs:
    - 0: 1000
  coins:
    - amount: 0
      dest: "ccc6dd3c85daa7bbb33b5ea22bbfbf28b6fa8cc8"
app_public_inputs:
  t/0796f63ed48144b4ec69fb794fbc2290ae63acf945fb035d5474648b50ee43b6/fd0cac892e457454be0212fa7d9a0e1517d5bd6a33aa7c66a1f10f55e375c290: ~
```

`charms-prover spell prove --chain ethereum` again uses `APP_SP1_PROVER=network` and `SPELL_SP1_PROVER=network`. `--prev-txs` is the placeholder record and the Bitcoin finality proof. `--beamed-from` is `{0: ["7762dc7d5afb95c9ee6e5dd5dd0060d06714a76d98b0cd526c13a19ae837ce1b:0"]}`.

`charms tx build --chain ethereum` prints the `transact` call. The generated `from` is the receiver, `0xcCc6dD3c85DAa7bBB33B5ea22bbFBF28B6fA8Cc8`. Replace that `from` with the placeholder owner's address, `0x0Fec1E72F9702681dFDC30c46530FBD1B9797453`, before sending the claim. Sending the generated call unchanged fails with `BadSignature`, because the claim has to be sent by the placeholder owner, with no extra signature.

| | |
| --- | --- |
| Claim transaction | [`0xd63766db7e9d656894bd3788ce9d2573da0c4ef74874729b925fe161f2d9faff`](https://etherscan.io/tx/0xd63766db7e9d656894bd3788ce9d2573da0c4ef74874729b925fe161f2d9faff) |
| Block | 26187996 |
| New Charms output | `d014d622962835f3ee46acfb9f9952e67c7cdb27201f4f8442f46103c6f9e14b:0` |
| Token balance | 1000 CHARM at `0xcCc6dD3c85DAa7bBB33B5ea22bbFBF28B6fA8Cc8` |

The balance and the claim transfer are on the token page linked at the top.
