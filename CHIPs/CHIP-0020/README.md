---
CHIP: "0020"
Title: Charms on Ethereum
Status: Draft
Authors:
  - Ivan Mikushin (@imikushin)
Created: 2026-10-04
---

# CHIP-0020. Charms on Ethereum

Ethereum hosts Charms spells, UTXOs, and beams. Charm tokens live in one `Charms` contract and are exposed as ERC-20s. Locked ERC-20s and ETH become vault charms. Those charms beam to Bitcoin and Cardano. Burning the charm on Ethereum unlocks the underlying asset.

`Charms` checks each Ethereum Charms transaction. Local UTXOs, ERC-20 transfers, and the vault use protocol v15 and the current spell-checker guest. A beam that reads an Ethereum transaction uses protocol v16 and a rebuilt guest.

## Decisions

| Question | Decision |
|---|---|
| UTXO model | One `Charms.transact` creates every output of one Charms transaction. Each output is its own `UtxoId`. A later transaction spends that output on its own. |
| UTXO id | `ethTxId = keccak256(preimage)` from [Identity](#identity). `TxId.0` is `reverse(ethTxId)`, the same byte order as `cardano_tx::tx_id`. |
| Simple transfer | The contract checks the spell. `proof` is empty. A non-empty proof reverts with `ProofNotRequired`. |
| Proved spell | The contract verifies Groth16 on Ethereum. Public values are CBOR of `([u8; 32] spell_vk, NormalizedSpell)` with `ins` and `coins` filled, the same bytes Bitcoin and Cardano verify. |
| ERC-20 facade | One CREATE2 clone per `t` app. `balanceOf` sums that token across the address's unspent, non-beamed UTXOs. `transfer` spends whole UTXOs through the same apply path as `transact`. |
| ETH and existing ERC-20s | `Charms` enforces the vault rules. `VAULT_VK` is a constant with no wasm preimage and no BIP-340 preimage. On other chains the charm transfers and beams. |
| Finality into Ethereum | The v16 proof calls the existing `proven_final`. Bitcoin uses work. Cardano uses the Scrolls signature. |
| Finality out of Ethereum | `scrolls_ethereum` signs the Charms tx id after the execution block is beacon-finalized. The check matches Cardano's `FINALITY_VKEY`. |
| Guest | v15 for Ethereum-local use. One v16 rebuild when `Tx` gains an `Ethereum` arm. |

## Call sites

### An ERC-20 call

```solidity
ICharms.App memory app = ICharms.App({tag: 0x74, identity: ID, vk: VK});
IERC20 token = IERC20(charms.tokenAddress(app)); // CREATE2, known before deploy
token.transferFrom(msg.sender, address(this), amount);
token.transfer(msg.sender, amount);
```

`tokenAddress` is a pure function of the `App` and the `Charms` address. `transfer` spends the sender's UTXOs of that app. It creates one output for the recipient and one change output. The change output keeps every other `t` or `n` charm from the inputs. A custom-tag bundle counts in `balanceOf`. `transfer` skips it. Spending that bundle is `transact` with a proof. See [Balances and bundles](#balances-and-bundles).

### Wrap, beam, and unwrap

```solidity
usdc.approve(address(charms), 1_000_000);
bytes32 txId = charms.wrap(address(usdc), 1_000_000, alice, salt);
// later, after the charm has come back
charms.unwrap(address(usdc), 400_000, alice);
```

ETH uses `charms.wrap{value: amount * 10^scale}(address(0), amount, alice, salt)`. The charm amount counts vault units. ETH uses `scale = 10`, so one unit is 10 gwei. A token with `decimals <= 8` uses `scale = 0` and keeps its own smallest unit. See [Vault](#vault).

### Spell YAML

```yaml
version: 16
tx:
  ins: ["<eth-txid>:<index>"]
  outs:
    - 0: 750
    - 0: 250
  coins:
    - {amount: 0, dest: "4a1f3f9eab6fcb384ea53a05f9b7ec1e53e4a101"}
    - {amount: 0, dest: "d8da6bf26964af9d7eed9e03e53415d37aa96045"}
app_public_inputs:
  "t/<identity>/<vk>": null
```

`coins[i].amount` is 0. `coins[i].dest` is the raw 20-byte owner. `charms util dest --chain ethereum --addr 0x…` prints those 20 bytes. ETH as a charm is the vault token.

Beaming uses `beamed_outs` and `tx_ins_beamed_source_utxos`.

```bash
# Placeholder on Ethereum. Empty proof. The id is known before the transaction is sent.
charms spell prove --chain ethereum --spell placeholder.yaml --caller 0xAlice --salt 0x… > ph.json
cast send "$CHARMS" "$(jq -r .call.data ph.json)"

# Bitcoin sets beamed_outs to sha256(UtxoId::to_bytes() of that id).
# After Bitcoin finality, the Ethereum claim carries a proof.
charms spell prove --chain ethereum --spell claim.yaml \
  --beamed-from '{0: ["<btc-txid>:<vout>"]}' \
  --prev-txs "$(jq -c .tx ph.json)" --prev-txs btc-with-block-proof.json > claim.json
```

A beam-out whose token sums still balance, with the beamed output included in the sum, is a native spell. Its proof is empty. After beacon finality, `charms tx fetch --chain ethereum --tx-id <id> --finality` returns `EthereumTx::WithFinalityProof`. The Bitcoin or Cardano claim is an ordinary spell.

## Contracts

Deploy three contracts. Keep every other rule inside `Charms`.

- `Charms` is immutable and has no proxy. It stores UTXOs, supply, balances, the vault, anchors, and the version registry. It deploys token clones.
- `CharmToken` is one EIP-1167 clone per `t` app. It stores allowances, EIP-2612 nonces, and metadata. Balances stay in `Charms`.
- `SP1VerifierGroth16` is Succinct's immutable verifier. `Charms` calls `verifyProof` on that contract.

`CharmToken.transfer` and `transferFrom` call `Charms.tokenTransfer`. `tokenTransfer` builds a simple-transfer spell and runs the same `_apply` path as `transact`. It is an internal call. An external `transact` from the token would set `msg.sender` to the token.

```solidity
interface ICharms {
    /// Unicode scalar. 't' = 0x74, 'n' = 0x6e, 's' = 0x73.
    struct App { uint32 tag; bytes32 identity; bytes32 vk; }

    struct Pin { bytes32 vk; uint32 version; bytes32 wasmHash; }

    /// tag 't': amount > 0 and data empty. The contract writes the CBOR uint.
    /// any other tag: amount == 0 and data is exactly one CBOR item.
    struct Charm { uint32 app; uint64 amount; bytes data; }

    /// ethTxId in keccak byte order, plus the output index.
    struct UtxoRef { bytes32 txId; uint32 index; }

    struct Input { UtxoRef utxo; Charm[] charms; Pin[] pins; }

    /// owner == address(0) iff this output's index is in beamedOuts.
    struct Output { address owner; Charm[] charms; }

    struct BeamedOut { uint32 index; bytes32 destHash; }

    /// Typed mirror of NormalizedSpell. The contract fills tx.ins and tx.coins.
    struct Spell {
        uint32 version;
        App[] apps;            // app_public_inputs keys, strictly increasing
        bytes[] publicInputs; // one CBOR data item each; hex"f6" is null
        Pin[] versionedApps;   // strictly increasing by vk
        Input[] ins;
        UtxoRef[] refs;
        Output[] outs;
        BeamedOut[] beamedOuts;
        uint32[] scrolls;
    }

    event Transacted(bytes32 indexed txId, bytes32 anchor, bytes spell);

    /// proof is empty iff the spell is a simple transfer the contract can check.
    /// salt is used iff ins is empty. Otherwise salt must be 0.
    /// signatures: one per input owner other than msg.sender, in order of first
    /// appearance, over EIP-712 Spend(bytes32 txId). ECDSA or ERC-1271 staticcall.
    function transact(
        Spell calldata spell,
        bytes32 salt,
        bytes calldata proof,
        bytes[] calldata signatures
    ) external returns (bytes32 txId);

    /// Lock `amount * 10**scale` of token (address(0) is ETH) and mint the vault charm.
    function wrap(address token, uint64 amount, address owner, bytes32 salt)
        external payable returns (bytes32 txId);

    /// Burn `amount` of msg.sender's vault charm and send the underlying to `to`.
    function unwrap(address token, uint64 amount, address to) external returns (bytes32 txId);

    /// Only the CREATE2 token for `app` may call this.
    function tokenTransfer(App calldata app, address from, address to, uint256 amount) external;

    function txIdOf(Spell calldata spell, address caller, bytes32 salt) external view returns (bytes32);
    function tokenAddress(App calldata app) external view returns (address);
    function totalSupply(bytes32 appKey) external view returns (uint256);
    function balanceOf(bytes32 appKey, address owner) external view returns (uint256);
    function utxosOf(bytes32 appKey, address owner, uint256 cursor, uint256 limit)
        external view returns (UtxoRef[] memory page, uint256 nextCursor);
    function vaultOf(address token) external view returns (App memory app, uint8 scale, uint256 locked);
    function beamSourceAt(bytes32 txId) external view returns (uint256 blockNumber);
}
```

`ICharmToken` is IERC-20, IERC-20 metadata, and EIP-2612. It adds `charms()`, `app()`, and `emitTransfer(from, to, amount)`. Only `Charms` calls `emitTransfer`. The token stores allowances. It decrements the allowance, then calls `tokenTransfer`. It leaves an infinite allowance unchanged.

CREATE2 salt is `appKey = keccak256(abi.encode(uint32 tag, bytes32 identity, bytes32 vk))`. The clone's immutable args are the packed `App`. `tokenAddress(app)` is valid before the clone exists. `_apply` deploys the clone the first time that app gets a non-zero Ethereum-resident supply. The caller of that transact pays for the deploy.

## State

`_apply` is the only writer. Store supply, per-owner balance, and a per-owner UTXO index. Also store one record per UTXO, because a spell names UTXOs by id and a multi-charm UTXO appears under more than one app. Empty UTXOs have no app, so they need `emptyUtxos`.

| Store | Key | Value | Role |
|---|---|---|---|
| `supply` | `appKey` | `uint256` | Ethereum-resident supply. Beamed outputs are excluded. This is `totalSupply`. |
| `balance` | `owner`, `appKey` | `uint256` | Sum of this token on the owner's unspent, non-beamed UTXOs. This is `balanceOf`. |
| `utxos` | `owner`, `appKey` | deque of `utxoKey` | Selection index. A multi-charm UTXO is listed under every `t` app it carries. |
| `emptyUtxos` | `owner` | list of `utxoKey` | Placeholders. |
| `head` | `utxoKey` | owner, kind, token amount or body hash, deque slot | The UTXO. A spend starts here. |
| `body` | `utxoKey` | charms CBOR, pins | Set for a bundle. Plain and empty UTXOs leave it unset. |
| `usedAnchors` | `anchor` | `bool` | A zero-input id is single-use. |
| `beamSourceAt` | `ethTxId` | block number, or 0 | Written when the spell has `beamed_outs`. The canister reads this. |
| `vaults` | token address | `appKey`, `scale`, `locked` | Underlying custody. `address(0)` is ETH. |
| `versions` | protocol version | verifier, `programVKey`, `activeAt`, `retired` | Append-only. See [Protocol version](#protocol-version). |

`utxoKey = keccak256(abi.encodePacked(ethTxId, uint32 index))` is the storage key. The `UtxoId` is the 36-byte form in [Identity](#identity).

Kind is one function of the output's charms:

| Charms on the output | Kind | Stored |
|---|---|---|
| none | Empty | `head`, plus `emptyUtxos[owner]` |
| one charm, tag `t`, no pin | Plain | amount in `head`. The deque slot names the app. |
| anything else | Bundle | `body` holds the charm map and pins. Listed in `utxos` for each `t` app it contains. |

A beamed output occupies an index, so `tx_outs_len` and `beamed_out_to_hash` see it. It has no `head` entry, no balance, and no supply.

The deque puts change at the front. Change is an output whose owner also owned an input of this transact. Every other receipt goes at the back. `tokenTransfer` pops from the front. When the selected inputs already cover the amount and another front UTXO exists, it spends that extra UTXO too. An address that only receives transfers then keeps a stable UTXO count. It skips the extra input when the `u64` sum would overflow.

## Identity

One `transact`, `wrap`, `unwrap`, or `tokenTransfer` is one Charms transaction. One Ethereum transaction may contain several of them, because a smart account can batch calls. Use `ethTxId` below. The EVM does not expose the hash of the transaction that is executing.

`ethTxId = keccak256(preimage)` with this concatenation:

| Offset | Bytes | Field |
|---|---|---|
| 0 | 21 | ASCII `charms/ethereum/tx/v1` |
| 21 | 32 | `block.chainid` as a big-endian uint256 |
| 53 | 20 | `address(Charms)` |
| 73 | 32 | `anchor` |
| 105 | n | committed spell CBOR |

When `ins` is empty, `anchor` is `keccak256(abi.encode(msg.sender, salt))`. Otherwise `anchor` is `bytes32(0)` and `salt` is 0. The caller picks `salt`. A counter would move if another call landed first, and a placeholder id already published in `beamed_outs` could not be created.

Byte order follows `cardano_tx::tx_id`:

| Value | Bytes |
|---|---|
| `TxId.0` | `reverse(ethTxId)` |
| `UtxoId::to_bytes()` | `TxId.0 \|\| index` as `u32` little-endian. 36 bytes. |
| Display and `FromStr` | `hex(ethTxId):index`. `Display` reverses `TxId.0`. |
| Beam hash | `SHA256(to_bytes() \|\| optional nonce as u64 little-endian)`. `beamed_outs[i]` is that hash. `BeamSource` stays `(UtxoId, Option<u64>)`. |

`txIdOf` returns the id before the Ethereum transaction is signed. Placeholder creation, EIP-712 `Spend` signatures, and the source chain's `beamed_outs` all use that id.

`_apply` makes each id single-use. A zero-input transact consumes its anchor. Every other transact consumes its inputs. A second claim of the same placeholder reverts.

## The committed spell

The id hashes `util::write(&NormalizedSpell)` after the same fill as Bitcoin's `spell_with_committed_ins_and_coins`:

- `tx.ins` is the input `UtxoId`s, in order. It is `Some`. It is an empty vector only for a zero-input transact.
- `tx.coins[i]` is `NativeOutput { amount: 0, dest: owner_i, content: None }`. A beamed output has 20 zero bytes in `dest`.
- Omit `refs`, `beamed_outs`, `scrolls`, and `versioned_apps` when they are empty. Encode absence. An empty container is a different spell.
- Omit `mock` when it is false.

`SpellCodec` encodes those bytes from the typed `Spell`. The caller-supplied bytes it copies are `Data` blobs: NFT data, custom-app data, and app public inputs. On the proved path each blob is one definite-length CBOR item, depth at most 16, with no trailing bytes. `CborWellFormed` checks that by skipping, and it extracts no values. A blob that swallows the next field would make the proof attest one spell while the contract accounts another. On the native path, bundle data is copied from the input `body` stored when that UTXO was created.

Calldata arrives in CBOR key order. The contract checks that order:

- `apps` by `(tag, identity, vk)`, which is `App`'s `Ord`
- charms in an output by app index
- `beamedOuts` and `scrolls` by index
- `versionedApps` by `vk`

`SpellCodec` matches ciborium's non-human-readable serde:

| Rust value | CBOR |
|---|---|
| `NormalizedSpell` | map, text keys in struct order: `version`, `tx`, `app_public_inputs`, then `versioned_apps` and `mock` only when present |
| `NormalizedTransaction` | map: `ins`, optional `refs`, `outs`, optional `beamed_outs`, `coins`, optional `scrolls` |
| `UtxoId` | byte string of 36 bytes |
| `[u8; 32]` and `B32` | array of 32 uints. The header is `0x98 0x20`, then each byte as a uint. A byte string is a different value and fails verification. |
| `App` | array of 3: UTF-8 text of the tag, identity, vk |
| `NativeOutput.dest` | array of uints. This serde writes `Vec<u8>` as a sequence. 20 bytes means 20 uints. |
| token `Data` | the CBOR uint of the `u64`, shortest form |
| `Data::empty()` | null, `0xf6` |
| public values | array of 2: the spell vk as an array of 32 uints, then the spell map |

Public values are `0x82 ‖ encode([u8; 32] of programVKey) ‖ spellCbor`. That is `to_serialized_pv` for v15 and later. The same byte string is the id preimage and the proof input. Golden vectors from `charms_data::util::write` are the test that both encoders match.

A spell has at most 64 inputs, 64 outputs, and 64 apps. Public values are at most 96 KiB.

## transact

```
_apply(spell, anchor, proof, signatures, vaultDelta):
    require the version registry entry is active and not retired
    require canonical shape, counts, and owner == 0 iff beamed
    if ins is empty: require the anchor is unused, and the spell is a placeholder or a wrap
    for each ref: require it is live
    for each input: require it is live and the opening matches head/body
    cbor = SpellCodec.encode(...)
    txId = keccak256(tag ‖ chainid ‖ this ‖ anchor ‖ cbor)
    require every input owner is msg.sender or signed Spend(txId)
    if native(spell, openings, vaultDelta): require proof is empty
    else: require ins is non-empty, blobs are well-formed, and the verifier accepts
    if beamedOuts is non-empty: require this version has a verifier
    write outputs, delete inputs, update supply, balance, deques, vault, pins
    if ins is empty: mark the anchor used
    emit Transacted(txId, anchor, cbor)
    emit ERC-20 Transfer events from the per-holder deltas
```

`native` is the guest's simple-transfer path, `is_correct` with no app binaries, plus the checks this contract can see:

1. Every app is tag `t` or tag `n`. Every public input is null. The spell has no refs, no scrolls, and no beam-in. A beam-in spends an input whose stored charms are empty, or whose output was itself beamed, and creates outputs that gain charms. The contract has no separate beam-source list, so that increase fails the native sum check.
2. For each `t` app, the checked `u64` sum of inputs equals the sum of outputs. Beamed outputs count.
3. For each `n` app, the multiset of data bytes is the same on inputs and outputs.
4. Pins stay as they are. `versionedApps` equals the pins on the inputs.
5. `vaultDelta` is 0, except when `wrap` or `unwrap` called `_apply`. Then the vault app's output sum differs from its input sum by that delta. Every other app's sum stays equal.
6. Zero inputs are a placeholder, with every output empty, or a `wrap`.

A spell that passes these rules carries an empty proof. Any other spell carries a proof. The errors are `ProofNotRequired` and `ProofRequired`.

On both paths the contract checks:

- Each input exists, matches the stored charms and pins, and is unspent. Spending it is what makes a second submission revert.
- The caller may spend the inputs, by the rules below.
- On the proved path, each ref is live and stays live.
- The encoded spell is the spell whose outputs the contract writes.
- Supply, balance, and vault collateral move by the amounts the contract computed from `head` and `body`.

The proof establishes:

- Each app wasm returned true, including versioned-app signatures and version changes.
- A beam-in's source transaction is `proven_final`, and `beamed_outs` on that source hashes to this placeholder's `UtxoId` with the declared nonce.
- Version continuity when the app version changes. A native spell keeps the pins it loaded.

The contract authorizes the spend. The owner is the address in `coins[i].dest` from when the UTXO was created. One of these holds:

- `msg.sender` is the owner.
- The owner signed EIP-712 `Spend(bytes32 txId)`, verified as ECDSA or as ERC-1271 through `staticcall`.
- `msg.sender` is the CREATE2 token for this app, the spell is native, every input belongs to `from`, other `t` or `n` charms are copied onto `from`'s change output, and the spell leaves custom-tag charms on their current UTXOs.

`txId` covers every input, output, owner, and beam hash.

A proved spell spends at least one input. The proof commits to the spell bytes and those inputs. It does not commit to `anchor`, so a zero-input proved spell could be resubmitted under a new salt. `hosting_chain_is_bitcoin` reads the creator of `ins[0]`.

`tokenTransfer` builds the native spell. Inputs come off the front of `utxos[from][app]`. Outputs are `{app: amount}` to `to` and, when change remains, `{app: change, plus every other t or n charm from the inputs}` back to `from`. `_apply` then checks that the result is native.

The call reverts, or the transaction is mined once. Submitting the same spell again reverts with `InputSpent` or `AnchorUsed`. `wrap` pulls the underlying token in the same call. `unwrap` sends it in the same call. A revert undoes both. Proving the same spell again off-chain yields the same id, because the proof bytes are outside the preimage.

One lock covers `transact`, `wrap`, `unwrap`, and `tokenTransfer`. ERC-1271 runs as a `staticcall` during the checks. `unwrap` sends the underlying asset after supply and `locked` have moved. `receive()` reverts.

## Balances and bundles

`balanceOf(owner)` for a charm token is the total of that token on the owner's unspent, non-beamed UTXOs, including UTXOs that carry other charms. `totalSupply` is that sum over all owners. `_apply` writes both from the same `u64` values it writes into `head` and `body`. The UTXO records are the source. An invariant test recomputes the sum from `utxos[owner]`.

`transfer` of the full `balanceOf` can take more than one call. A UTXO that carries a custom-tag charm, any tag other than `t` or `n`, stays put during a native spell. `is_simple_transfer` is false for that tag even when the data bytes are copied. Those units remain inside `balanceOf`. `transfer` skips those UTXOs. If the requested amount is larger than the sum `transfer` can select, and the shortfall sits on custom-tag bundles, it reverts with `RequiresProvedSpell`. Otherwise it reverts with `InsufficientBalance`. The owner spends or splits that bundle with `transact` and a proof.

A UTXO that mixes several `t` charms, or `t` with `n`, is selectable. The change output returns the other charms to the same owner. That is a simple transfer. The NFT moves to the recipient only when the transferred token is the UTXO's only charm.

The contract spends each input UTXO whole. The remainder is a new output.

`ensure_no_zero_amounts` rejects a charm amount of 0. `transfer(to, 0)` emits an ERC-20 `Transfer` and creates no UTXO. Ethereum spells have no dust minimum. Omit a change output whose amount is 0. `to` of `address(0)` or of `Charms` reverts. An amount above `type(uint64).max` reverts.

For each `t` app that `_apply` touches, net the balance change per owner and emit `Transfer` through the token. A facade transfer emits one `Transfer(from, to, amount)`. A beam-in or a wrap emits `Transfer(0, to, amount)`. A beam-out, a burn, or an unwrap emits `Transfer(from, 0, amount)`. Supply on Ethereum changes on those mint and burn events.

## Vault

Locking an ERC-20 or ETH mints a tag-`t` charm. Burning that charm unlocks the underlying asset. The rules live in `Charms`, which holds the tokens.

```
VAULT_VK     = SHA-256("charms/ethereum/vault/v1")
identity     = SHA-256("charms/ethereum/vault/v1" ‖ chainId_be_u256 ‖ Charms_20 ‖ token_20 ‖ scale_u8)
app          = t / identity / VAULT_VK
```

`token_20` is 20 zero bytes for ETH. `scale` is 0 when the token has no `decimals()` or when `decimals <= 8`. Otherwise `scale` is `decimals - 8`. ETH is treated as 18 decimals, so `scale` is 10 and one charm unit is 10^10 wei. Charm amounts are `u64`, because `sum_token_amount` adds `u64`. Eight decimal digits keeps one output inside that cap. An 18-decimal token's sub-unit dust stays unwrapped.

`VAULT_VK` is the hash of that 24-byte string. The string is neither wasm nor a BIP-340 key. On Bitcoin and Cardano the vault charm transfers and beams. A mint or burn there has no binary that can return true.

`wrap` reads the balance the contract received. For an ERC-20 that is `balanceAfter - balanceBefore`. For ETH it is `msg.value`. The received amount equals `amount * 10^scale`. A fee-on-transfer token reverts. A rebasing token is out of scope. `wrap` then applies a zero-input spell whose only output is `{vaultApp: amount}` owned by `owner`, passes that positive `vaultDelta`, and adds the underlying amount to `locked`.

`unwrap` selects the caller's vault-app UTXOs the same way `tokenTransfer` does. It applies a spell whose outputs are the optional change, with a negative `vaultDelta`, subtracts from `locked`, and then sends the underlying asset. If the recipient reverts, the burn reverts with it.

Every `_apply` that touches the vault app keeps these true:

- `locked` equals `10^scale` times the net units wrapped and not yet unwrapped, on every chain.
- The underlying token's `balanceOf(Charms)` is at least `locked`. For ETH, the contract's balance is at least `locked`.
- `supply[vaultApp] * 10^scale <= locked`. A beam-in can mint only as many vault units as the collateral still held here.

External `transact` passes `vaultDelta = 0`. A proved spell includes the vault app when the guest accepts it as a simple transfer, which covers a beam and an ordinary move. The v16 guest rejects a simple-transfer spell unless every public input is null. Solidity moves the underlying asset from `vaultDelta`.

## Supply

`supply[app]` is the amount of that charm resident on Ethereum.

| Event | `supply` on Ethereum | Underlying `locked` |
|---|---|---|
| `wrap` | +amount of the vault app | +amount × 10^scale |
| `unwrap` | −amount of the vault app | −amount × 10^scale, then the tokens are sent |
| beam-out | −amount, and the beamed output is excluded from supply | unchanged |
| beam-in | +amount. The placeholder input was empty | unchanged, then the vault cap |
| proved mint or burn of a non-vault app | ±amount | unchanged |
| transfer, or moving units between bundles | unchanged | unchanged |

`wrap` and beam-in are different transitions. `unwrap` and beam-out are different transitions. A beam-in of the vault charm leaves `locked` unchanged. `unwrap` is the transition that sends the underlying asset out.

## Beaming and finality

**Into Ethereum.** Create the placeholder first. It is a native spell with zero inputs, one empty output, and a salt anchor. Its `UtxoId` is known before submission. The Bitcoin or Cardano source spell sets `beamed_outs[i]` to the beam hash of that id. The claim spends the placeholder, lists the source in `tx_ins_beamed_source_utxos`, and carries a v16 proof. The guest checks that the source is `proven_final`, that the placeholder exists and is empty or itself beamed, and that the hash matches, including the optional nonce. The contract applies the supply increase from that proof. For a vault app it also applies the cap.

Spending the placeholder as an ordinary input before the claim consumes the id. The source chain has already beamed to that hash, so the charms can no longer be claimed. The CLI warns on a native spend of an empty UTXO.

**Out of Ethereum.** The Ethereum spell lists `beamed_outs`. When token sums still balance, the spell is native. Another app can still make the same spell require a proof. A beamed output has no owner and creates no UTXO. `beamSourceAt[ethTxId]` stores `block.number`. After the execution block reaches the `finalized` tag, about two epochs later, `scrolls_ethereum` attests the id. The destination spell's prev tx is `EthereumTx::WithFinalityProof`. The guest checks that signature in `proven_final`, then runs the same beam checks it runs for Bitcoin and Cardano.

The canister is a new member of `scrolls/`. Deploy it, then blackhole it, as with the other Scrolls canisters.

```candid
service : {
  certify_final : (eth_tx_id : blob) -> (variant { Ok : blob; Err : text });
  finality_public_key : () -> (blob) query;
}
```

`certify_final` calls `Charms.beamSourceAt(ethTxId)` through the ICP EVM RPC canister at block tag `finalized`. At least three providers must return the same answer. When the stored block number is non-zero, the canister signs with `sign_with_schnorr` (Ed25519) under the derivation path `["scrolls", "ethereum", "finality"]`.

The message is `SHA-256("charms/ethereum/finality/v1" ‖ chainId_be_u256 ‖ Charms_20 ‖ ethTxId)`. The signature is 64 bytes. The spell bytes stay in the `EthereumTx` record. `ethTxId` is the hash of those bytes. The signature means the canonical contract accepted that id after finality.

`EthereumTx::proven_final` is true when `chain_id` is 1, `charms` equals the deployed mainnet address, and the signature verifies under `ETHEREUM_FINALITY_VKEY`. A testnet guest build uses its own constants. A mainnet proof uses the mainnet constants.

Inbound finality stays in the guest, which already implements `proven_final`. Outbound finality uses the Scrolls signature so a beacon consensus change does not rebuild the spell-checker. `proven_final` trusts `ETHEREUM_FINALITY_VKEY` and the three-provider check inside `certify_final`.

## Proofs

On the proved path, `Charms` calls `ISP1Verifier.verifyProof(programVKey, publicValues, proof)`.

- `programVKey` is the registry key for `spell.version`. For v16 that is the proof-wrapper verifying key. `charms spell vk` prints those 32 bytes. The same bytes are the first public value.
- `publicValues` are the bytes from [The committed spell](#the-committed-spell).
- `proof` is the `Proof` byte string the prover returns. Pass those bytes to the verifier. The layout is the one `verify_gnark_v6` accepts. A 4-byte SHA-256 prefix of the Groth16 verifying key, then exit code, vk root, and proof nonce as 32-byte words, then the gnark proof. v15 checks that prefix against `groth16_vk`, requires exit code 0, and requires vk root `SP1_V6_2_VK_ROOT` (`002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`).

Phase 0 runs this against a real v15 mainnet proof on a fork, using the stock verifier. If that verifier accepts the proof, v16 uses the same verifier contract. If it rejects the proof, the registry stores the verifier address for that version.

When the guest later reads an Ethereum prev tx, `extract_and_verify_spell` decodes the committed spell. It checks the id hash. For a beam source it checks the finality signature. Acceptance by the pinned `Charms` address is the earlier check. The guest does not verify that Groth16 proof again.

## Rust, prover, CLI

```rust
// charms-client/src/tx.rs. Chain gains ethereum from the strum discriminant.
pub enum Tx {
    Bitcoin(BitcoinTx),
    Cardano(CardanoTx),
    Ethereum(EthereumTx),
}
```

`TryFrom<&str>` for raw hex tries an Ethereum envelope first, then Bitcoin, then Cardano. The envelope is CBOR of `EthereumTx` prefixed with the four bytes `CHET` (`0x43 0x48 0x45 0x54`). If the Ethereum parse fails, return the error. Bitcoin's empty virtual spell is for a transaction that has no `OP_RETURN`, and an Ethereum envelope must not take that path. JSON prev txs use the existing externally tagged form, `{"ethereum": ...}`.

```rust
pub enum EthereumTx {
    Simple(EthTransact),
    WithFinalityProof { tx: EthTransact, signature: [u8; 64] },
}

pub struct EthTransact {
    pub chain_id: u64,
    pub charms: [u8; 20],
    pub anchor: Option<[u8; 32]>, // present only for zero-input transactions
    pub spell: Vec<u8>,           // committed CBOR, the exact preimage bytes
    pub proof: Vec<u8>,           // empty on the native path; not part of the id
}
```

`EnchantedTx` for `EthereumTx`:

- `tx_id` reverses `eth_tx_id()` into `TxId`.
- `extract_and_verify_spell` decodes `spell`, requires `ins` to be `Some` and `coins.len() == outs.len()`, and requires `mock` to match the caller. It stops there.
- `virtual_spell` is that decode. An Ethereum record with no spell is an error.
- `proven_final` is the Ed25519 check above. `Simple` is not final.
- `all_coin_outs` returns the committed `coins`.
- `spell_ins` returns the committed `ins`.

Add one guard in `is_correct`, next to `beaming_txs_have_finality_proofs`. Every `Tx::Ethereum` prev tx is `proven_final`, or the spell being proved is itself hosted on Ethereum and this prev tx created one of its inputs or refs. Hosted on Ethereum means the creator of `ins[0]` is `Tx::Ethereum`. In the same rebuild, a spell with no app binaries has null public inputs for every app. The simple-transfer branch otherwise ignores those inputs.

For an Ethereum host, `hosting_chain_is_bitcoin` is false. Tag `s` is an ordinary non-token app, as on Cardano. A scroll output stores the owner address in `dest`.

`ProveRequest` keeps its current fields. `chain = "ethereum"` sets their meaning:

| Field | Ethereum |
|---|---|
| `spell` | Committed form, including `ins` and `coins`. |
| `prev_txs` | An `EthereumTx` for every input and ref creator, plus beam sources with their finality witnesses. |
| `tx_ins_beamed_source_utxos`, binaries, signatures, private inputs | Same as Bitcoin and Cardano. |
| `change_address` | Empty. Charm change is an output of the spell. |
| `fee_rate` | Ignored. `spell prove --chain ethereum` accepts 0. The existing `fee_rate >= 1` check stays on Bitcoin. The wallet prices gas. |
| `collateral_utxo` | Absent. |

The response is `vec![Tx::Ethereum(Simple(...))]`. The proof field is filled when the spell requires a proof. The CLI chooses the native path. If every app is `t` or `n`, sums and NFT sets match, public inputs are null, `--beamed-from` is absent, and pins are unchanged, the CLI builds the record locally and leaves `proof` empty. Otherwise it calls `POST /spells/prove`.

Quote the prover's cycle fee in wei to `fee_addresses[ethereum][network]`. Pay it as a separate transfer when the operator wants it. `transact` does not read that fee. Bitcoin leaves the same fee outside the spell.

CLI:

| Command | Behavior |
|---|---|
| `spell prove --chain ethereum` | Prints JSON `{tx, tx_id, utxo_ids, call: {to, data, value}}`. `--caller` and `--salt` are required when `ins` is empty. `--change-address` stays required on Bitcoin and Cardano. |
| `spell check --chain ethereum` | Runs `is_correct` once the guest accepts Ethereum prev txs. Before that rebuild, it runs the native predicate and rejects a spell that needs a proof. |
| `tx show-spell --chain ethereum` | Decodes an envelope or a `Transacted` log. |
| `tx fetch --chain ethereum --tx-id <id> [--finality]` | Rebuilds the record from `Transacted`. `--finality` calls the canister. |
| `util dest --chain ethereum --addr 0x…` | Raw 20 bytes. Accepts EIP-55. Stores the lowercase bytes. |
| `util eth-token <APP>` | CREATE2 token address. |
| `util eth-vault --token <addr\|eth> --decimals <d>` | Prints the vault `App`. |

`app_contract` sees `coin_outs[i].amount == 0` and a 20-byte `dest`. An app that moves ETH moves the vault charm. Leave `charms-sdk` and the app runner as they are. In the v16 bump, `charms-lib`'s `extractAndVerifySpell` decodes the Ethereum envelope. A decoded spell is authenticated by its bytes. Acceptance is `utxo()` or `beamSourceAt` on the contract.

## Protocol version

| Phase | Spell version | Guest | Keys |
|---|---|---|---|
| Ethereum-local | Records are version 15. The registry entry has no verifier. The contract rejects proofs and `beamed_outs`. | The current guest. `Tx` has no Ethereum arm. Other chains do not read these records. | v15 verifying keys stay. |
| Beaming and proved spells | Version 16. `CURRENT_VERSION = 16`. | Rebuild. `SpellProverInput.prev_txs` deserializes `Tx`. A new arm is a new spell-checker ELF, a new `SPELL_CHECKER_VK` in `charms-proof-wrapper`, and a new wrapper verifying key. | Publish `spell_vk` for v16 from `charms spell vk` on the reproducible build. Register that `programVKey`. |

v15's `groth16_vk.bin` aliases v14's, because that bump left the wrapper binary in place. v16 rebuilds the wrapper. If the new `groth16_vk.bin` matches v15 byte for byte, alias it and keep the stock verifier. If the bytes differ, publish them. The proof's 4-byte prefix follows those bytes. The wrapper verifying key changes in either case, because the wrapper hardcodes the spell-checker key. `to_serialized_pv` stays on the v15 arm, CBOR of `([u8; 32], NormalizedSpell)`. Bitcoin and Cardano transaction layouts stay as they are.

The version registry is append-only. A proposed entry becomes active after 14 days. The entry sets the verifier address and `programVKey` for a new version. `_apply` stays in the immutable bytecode. Retiring a version is one-way and takes effect immediately, so a bad key can be turned off. Name the admin multisig at deploy time. Token addresses stay put across a version bump because CREATE2 uses the same `Charms` address. A new `Charms` deployment is a new contract. It changes every token address and the `ETHEREUM_CHARMS` constant in the next guest.

Also bump Cardano's protocol-version NFT, `scrolls_bitcoin` delegation, `scrolls_cardano`, and `charms-lib`'s `SPELL_VK`. `CHARMS_PROVE_API_URL` becomes `https://v16.charms.dev/spells/prove`.

## Edge cases

- **ETH and WETH.** ETH is the vault at `address(0)`. WETH is a separate vault. Each vault has its own supply.
- **Allowances.** Charm allowances live on `CharmToken`. `approve` on the underlying token is for `wrap`, and the spender is `Charms`. `tokenTransfer` checks that `msg.sender` is the token at the CREATE2 address it recomputes for that `App`.
- **Several charms on one UTXO.** One `head` record, one list entry per `t` app, and one balance contribution per `t` app. A facade spend copies the other `t` or `n` charms onto the change output. A custom-tag bundle uses `transact`.
- **Empty UTXOs.** These are the beam targets. Index them in `emptyUtxos` and `head`. Creating one leaves supply unchanged.
- **u64.** One output amount, and the sum of one app's inputs in a spell, fit in `u64`. The guest adds them as `u64`. Stored balances are `uint256`, so many UTXOs can sum past `u64`. The facade then uses more than one call, each under the cap.
- **Fee-on-transfer, rebasing, and blocklists.** A fee-on-transfer token reverts in `wrap`. A rebasing token is out of scope. A token that blocklists `Charms` freezes that vault. `decimals()` is read once, when the vault is created.
- **Mixed pins.** After a versioned app changes version, one owner can hold UTXOs pinned to different versions. The facade reverts with `MixedVersions` when the inputs it would select disagree on the pin. A proved `transact` runs the new binary, which is what `authorize_version_changes` requires.
- **Reorgs.** A native transfer follows the Ethereum reorg, as any other contract write does. A beam waits for `finalized`.
- **History.** `Transacted` carries the spell CBOR. `wrap`, `unwrap`, and the facade build that CBOR inside the contract, and the log is the copy a later proof reads. A later proof that spends a bundle needs the log. A native spend of a plain UTXO reads the amount from `head`. Indexers archive the logs. Under EIP-4444 that archive is an operator's copy of the logs.

## Build order

**Phase 0. Codec and verifier.** Add `SpellCodec` and `CborWellFormed`. Generate golden vectors with `util::write` over generated spells. On a fork, pass a real v15 Bitcoin proof to the deployed SP1 verifier with public values the codec built. Phase 0 is done when the vectors match and that proof verifies. The protocol version stays 15.

**Phase 1. Ethereum-local, on v15.** Build `Charms` and `CharmToken`. That is native `transact`, the deque, EIP-712 and ERC-1271, the vault, events, and a registry whose only entry is native v15. Add host-side Rust for the record type and `tx_id`, in a module the spell-checker binary does not link. Add CLI support for native spells, `util dest`, `util eth-token`, and `util eth-vault`. Add invariant tests for supply, balance, and `locked`. Audit, then deploy with CREATE2 so `ETHEREUM_CHARMS` is fixed.

**Phase 2. v16.** Deploy and blackhole `scrolls_ethereum` before the guest build. The guest hardcodes `ETHEREUM_FINALITY_VKEY`. Add `Tx::Ethereum` and the `is_correct` guards. Rebuild the spell-checker and the wrapper. Publish `programVKey`. Add the prover's Ethereum arm. Bump the other chains as in [Protocol version](#protocol-version). Propose the v16 registry entry and wait 14 days. On testnets, with a dev guest, run Bitcoin to Ethereum and back, Cardano to Ethereum and back, a USDC vault round trip, and an ERC-20 `transfer` that splits a UTXO which also holds an NFT.

**Phase 3.** Read CHIP-0420 metadata onto the facade once, from the reference NFT `n/<identity>/<vk>`, when that NFT is live on Ethereum. Add a TypeScript helper for EIP-712 and calldata. Add an ERC-721 facade for tag `n`. An L2 uses its own `chain_id` and its own guest constants.

## Rejected shapes

| Shape | Constraint that rejected it |
|---|---|
| Ethereum transaction hash as `TxId` | The EVM does not expose that hash during execution. One Ethereum transaction can contain several Charms transactions. |
| A contract nonce as `TxId` | The id would depend on earlier transactions in the block, so a published placeholder could miss. |
| Verify proofs in the guest, and have a canister attest them on Ethereum | `Charms` calls the Groth16 verifier. The canister would be an extra signer. |
| A Solidity port of `verify_gnark_v6` | Phase 0 uses the stock SP1 verifier. A second implementation can disagree on the same bytes. |
| A new public-value encoding for Ethereum | `to_serialized_pv` stays the v15 encoding, so one spell verifies on every chain. |
| Parse caller CBOR in the contract | `SpellCodec` encodes from typed calldata. A parsed blob can swallow the next field. |
| Vault policy as app wasm | The wasm cannot observe the ERC-20 transfer. A wasm that allows a mint allows it on Bitcoin. A beam-in that the guest treats as a simple transfer would skip that wasm. |
| A Groth16 proof on every ERC-20 `transfer` | The contract checks a simple transfer in `_apply`. |
| `balanceOf` over single-token UTXOs only, with bundles attributed to `address(Charms)` | `balanceOf` is the total on that address's UTXOs. Custom-tag bundles stay in the balance and out of `transfer`'s selection. |
| A beacon light client in the guest | A beacon consensus change would rebuild the spell-checker. Outbound finality uses the Scrolls signature, as Cardano does. |
| Bitcoin or Cardano header checks in Solidity | `proven_final` inside the v16 proof is that check. |
| A new `Charms` deployment for each protocol version | CREATE2 token addresses and the vault identity depend on the contract address. |
| An upgradeable proxy | The registry sets the next `programVKey`. `_apply` stays in the deployed bytecode. |
| Wei in `NativeOutput.amount` | A `u64` overflows near 18 ETH. The vault charm is the ETH balance that beams. |
| A Groth16 proof stored beside each Ethereum spell, rechecked for every ancestor | The id hashes the committed spell. The contract already checked that spell. The ancestor proof is outside the id. |

## Risks

A forged beam can unwrap real collateral. A private Bitcoin fork that passes `FINALITY_TARGET_BITS`, or a stolen `scrolls_ethereum` or Cardano finality key, can beam vault units onto Ethereum and unwrap them. The cap `supply * 10^scale <= locked` limits the loss to vault units currently outside Ethereum. v16 leaves `FINALITY_TARGET_BITS` at its current value. Raising it is a guest constant in that same rebuild, and it slows every Bitcoin beam.

If `SpellCodec` disagrees with `util::write`, proofs fail and ids disagree. That is a liveness failure. If the encoding is not injective, the proof and the accounting can describe different spells. That is a safety failure. Phase 0 covers both, including a blob that tries to swallow the next amount.

If the EVM RPC providers disagree, or the canister is out of cycles, `certify_final` fails and the beam waits. Call it again after the inputs are spent. The call does not move the UTXO back.

A registry entry can make the proved path accept a different `programVKey` after 14 days. Native rules and vault rules stay in the contract. During those 14 days, holders can unwrap or beam out. The registered `programVKey` equals the `charms spell vk` output of the reproducible build.

## Open choices

Name the registry admin addresses at deploy time.

Leave `FINALITY_TARGET_BITS` at its current value, and rely on the vault cap. Raise the Bitcoin work target before the v16 guest is built only if that cap is not enough.
