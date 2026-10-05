---
CHIP: "0020"
Title: Charms on Ethereum
Status: Draft
Created: 2026-10-04
---

# CHIP-0020. Charms on Ethereum

Ethereum becomes a third host for the existing spell, UTXO, and beaming protocol. It does not get a second asset protocol.

Charm tokens already defined by an `App` are held as UTXOs inside one `Charms` contract and projected as ERC-20s. Existing ERC-20s and ETH are locked in that contract and minted as vault charms, which beam to Bitcoin and Cardano and unlock only by burning the charm back on Ethereum.

The contract is the consensus for Ethereum Charms transactions, in the same role Bitcoin consensus has for a Bitcoin transaction. The spell-checker guest is not rebuilt until a spell on some chain has to read an Ethereum transaction. That rebuild is protocol v16, and it is required before any beam crosses Ethereum. Local UTXOs, ERC-20 transfers, and the vault ship on v15 with no guest change.

## Decisions

| Question | Decision |
|---|---|
| UTXO model | One `Charms.transact` creates every output of one Charms transaction. Each output is its own `UtxoId` and is spent on its own later. |
| UTXO id | Content-addressed. Not the Ethereum transaction hash and not a counter. `TxId.0` is the reverse of that id, matching `UtxoId::to_bytes` and Cardano's `tx_id`. |
| Simple transfer | The contract checks it. The proof is empty. A proof on a spell the contract can check itself is rejected. |
| Anything else | Groth16 is verified on Ethereum, against the same public values Bitcoin and Cardano already use: CBOR of `([u8; 32] spell_vk, NormalizedSpell)` with `ins` and `coins` filled. |
| ERC-20 facade | One `CharmToken` per `t` app. It is a minimal-proxy clone of a shared implementation, deployed with CREATE2. `balanceOf` is the sum of that token across all of the address's unspent, non-beamed UTXOs. `transfer` spends whole UTXOs through the same apply path as `transact`. |
| ETH and foreign ERC-20s | Contract policy, not an app wasm. Vault `vk` is a constant with no wasm and no BIP-340 preimage, so other chains can only transfer and beam it. |
| Finality into Ethereum | Inside the v16 proof, via the existing `proven_final` (Bitcoin work, Cardano Scrolls signature). Solidity does not grow a light client. |
| Finality out of Ethereum | A new `scrolls_ethereum` canister signs the Charms tx id after the execution block is beacon-finalized. Same pattern as Cardano's `FINALITY_VKEY`. |
| Guest | Unchanged for Ethereum-local use. Rebuilt once, as v16, when `Tx` gains an `Ethereum` arm. |
| Upgrade | UUPS (EIP-1822). Callers use a proxy that delegatecalls every call. Upgrade logic lives in the implementation, so `transact` and `transfer` do not pay an admin check. The proxy address is the stable `Charms` address. |

## What a caller does

### A contract treats a charm as an ERC-20

```solidity
ICharmsTypes.App memory app = ICharmsTypes.App({tag: 0x74, identity: ID, vk: VK});
IERC20 token = IERC20(charms.tokenAddress(app)); // CREATE2, known before deploy
token.transferFrom(msg.sender, address(this), amount);
token.transfer(msg.sender, amount);
```

`tokenAddress` is a pure function of the `App` and the `Charms` address. `transfer` spends the sender's UTXOs of that app, creates one output to the recipient and one change output, and preserves every other `t` or `n` charm on the change output. Custom-tag bundles are part of `balanceOf` but are not selected by `transfer`; spending them is a `transact` with a proof. See [Balances and bundles](#balances-and-bundles).

### A wallet locks USDC, beams it, and unlocks it

```solidity
usdc.approve(address(charms), 1_000_000);
bytes32 txId = charms.wrap(address(usdc), 1_000_000, alice, salt);
// later, after the charm has come back
charms.unwrap(address(usdc), 400_000, alice);
```

`wrap` of ETH is `charms.wrap{value: amount * 10^scale}(address(0), amount, alice, salt)`. The charm amount is an integer count of the vault's unit, not wei. ETH uses `scale = 10` (1 unit = 10 gwei). A token with `decimals <= 8` uses `scale = 0` and keeps its own smallest unit. See [Vault](#vault).

### A spell file is still a spell file

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

`coins[i].amount` is always 0. `coins[i].dest` is the raw 20-byte owner. `charms util dest --chain ethereum --addr 0x…` prints those 20 bytes. ETH held as a charm is the vault token, not `NativeOutput.amount`.

Beaming uses the fields that already exist.

```bash
# Placeholder on Ethereum. No proof. The id is known before the transaction is sent.
charms spell prove --chain ethereum --spell placeholder.yaml --caller 0xAlice --salt 0x… > ph.json
cast send "$CHARMS" "$(jq -r .call.data ph.json)"

# Bitcoin beams to sha256(UtxoId::to_bytes() of that id), as it does today.
# After Bitcoin finality, claim on Ethereum. A claim is not a local simple transfer, so it has a proof.
charms spell prove --chain ethereum --spell claim.yaml \
  --beamed-from '{0: ["<btc-txid>:<vout>"]}' \
  --prev-txs "$(jq -c .tx ph.json)" --prev-txs btc-with-block-proof.json > claim.json
```

The other direction marks `beamed_outs` on an Ethereum spell whose token sums still balance (the beamed output counts). That spell is native: no proof. After beacon finality, `charms tx fetch --chain ethereum --tx-id <id> --finality` returns `EthereumTx::WithFinalityProof`, and the Bitcoin or Cardano claim is an ordinary spell.

## Contracts

Deploy a proxy and an implementation. CharmToken contracts and the external Groth16 verifier sit beside them. Everything else is internal to the implementation.

- `CharmsProxy` is the address wallets, tokens, and the guest call `Charms`. Its `fallback` and `receive` always `delegatecall` the implementation in the ERC-1967 slot. It has no other functions and no admin branch. That is the UUPS shape from EIP-1822: every call is delegated, and the upgrade function is not on this bytecode, so a transfer does not pay for an admin check the way a transparent proxy does.
- `Charms` is the implementation. It owns UTXOs, supply, balances, the vault, and anchors, in the proxy's storage. It deploys each `CharmToken`. It also exposes `upgradeToAndCall`. The admin is a single address set at initialization. That address is the only account that can upgrade. There is no timelock and no second role.
- `CharmToken` is the ERC-20 for one `t` app. It is a clone: a minimal proxy (EIP-1167 with immutable arguments) that `delegatecall`s one shared `CharmToken` implementation. The per-token bytecode is that proxy, not a separately compiled contract. It owns allowances, EIP-2612 nonces, and metadata. It owns no balances.
- `SP1VerifierGroth16` is Succinct's immutable verifier. `Charms` calls it directly. Succinct's gateway is not on the path.

`CharmToken.transfer` and `transferFrom` are the ERC-20 entry points. They call `Charms.tokenTransfer`, which builds a simple-transfer spell and runs it through the same internal apply path as `transact`. They do not call the external `transact` (that would take the caller's identity from the token). The rules of the spell are still the rules of `transact`.

`Charms` implements `ICharms`, `ICharmsLedger`, and `IUpgradeable` as three interfaces. `ICharms` does not extend `ICharmsLedger`. Wallets and the CLI call `ICharms`. The token calls `ICharmsLedger`. The admin calls `IUpgradeable`. A caller of one does not need the methods of the others. `CharmToken` implements `ICharmToken` and `ICharmTokenHooks`. The structs live once, on `ICharmsTypes`, and the other interfaces use them.

```solidity
/// @notice Shared structs. No functions. The other interfaces use these so `App` is defined once.
/// @dev Wallets, CharmToken, and the CLI all pass `App` through. 't' = 0x74, 'n' = 0x6e, 's' = 0x73.
interface ICharmsTypes {
    /// @notice Unicode scalar tag plus the 32-byte identity and vk. Same triple as `charms_data::App`.
    struct App { uint32 tag; bytes32 identity; bytes32 vk; }

    /// @notice One `NormalizedSpell.versioned_apps` entry.
    struct Pin { bytes32 vk; uint32 version; bytes32 wasmHash; }

    /// @notice One charm on an input or output. `app` indexes `Spell.apps`.
    /// @dev Tag `t`: `amount > 0` and `data` empty. The contract writes the CBOR uint.
    ///      Any other tag: `amount == 0` and `data` is exactly one CBOR item.
    struct Charm { uint32 app; uint64 amount; bytes data; }

    /// @notice An Ethereum UTXO. `txId` is `ethTxId` in keccak byte order.
    struct UtxoRef { bytes32 txId; uint32 index; }

    /// @notice A spent UTXO plus the opening of what the contract stored for it.
    struct Input { UtxoRef utxo; Charm[] charms; Pin[] pins; }

    /// @notice A created output. `owner == address(0)` iff its index is in `beamedOuts`.
    struct Output { address owner; Charm[] charms; }

    struct BeamedOut { uint32 index; bytes32 destHash; }

    /// @notice Typed mirror of `NormalizedSpell`. The contract fills `tx.ins` and `tx.coins`.
    struct Spell {
        uint32 version;
        App[] apps;             // app_public_inputs keys, strictly increasing
        bytes[] publicInputs;  // one CBOR data item each; hex"f6" is null
        Pin[] versionedApps;    // strictly increasing by vk
        Input[] ins;
        UtxoRef[] refs;
        Output[] outs;
        BeamedOut[] beamedOuts;
        uint32[] scrolls;
    }
}

/// @notice Ledger calls from a `CharmToken`. The token stores this address (the Charms proxy) and nothing wider.
/// @dev `CharmToken.transfer` and `transferFrom` are the only callers of `tokenTransfer`.
///      `balanceOf` and `totalSupply` on the token read the two views. DeFi calls the token, not this interface.
interface ICharmsLedger {
    /// @notice Move `amount` of `app` from `from` to `to` by spending whole UTXOs and creating change.
    /// @dev Only the CREATE2 `CharmToken` for `app` may call this. The token has already checked `msg.sender` and the allowance.
    function tokenTransfer(ICharmsTypes.App calldata app, address from, address to, uint256 amount) external;

    /// @notice Ethereum-resident supply of one charm. The token's `totalSupply` returns this.
    function totalSupply(bytes32 appKey) external view returns (uint256);

    /// @notice Sum of this charm on `owner`'s unspent, non-beamed UTXOs. The token's `balanceOf` returns this.
    function balanceOf(bytes32 appKey, address owner) external view returns (uint256);
}

/// @notice Spell and vault API. Wallets, the CLI, and contracts that build spells call this on the proxy.
/// @dev Does not include `ICharmsLedger`. Those callers use the ERC-20 for balances and do not call `tokenTransfer`.
interface ICharms {
    /// @notice A Charms transaction was applied. Indexers and `tx fetch` read `txId` and `spell` from this log.
    /// @dev `spell` is the committed CBOR. `anchor` is zero when the spell spent inputs.
    event Transaction(bytes32 indexed txId, bytes32 anchor, bytes spell);

    /// @notice Spend `spell.ins` and create `spell.outs`. Returns the new `ethTxId`.
    /// @dev Wallets and the CLI call this for any spell that is not an ERC-20 `transfer` or a vault lock or unlock.
    ///      `proof` is empty when the contract can check the spell itself, and required otherwise.
    ///      `salt` is used when `ins` is empty (a placeholder). Otherwise `salt` is 0.
    ///      `signatures` has one entry per input owner other than `msg.sender`, in order of first appearance,
    ///      over EIP-712 `Spend(bytes32 txId)`. ECDSA or ERC-1271 `staticcall`.
    function transact(
        ICharmsTypes.Spell calldata spell,
        bytes32 salt,
        bytes calldata proof,
        bytes[] calldata signatures
    ) external returns (bytes32 txId);

    /// @notice Lock the underlying ERC-20, or ETH when `token` is `address(0)`, and mint that vault charm to `owner`.
    /// @dev The holder calls this after `approve` on the underlying token. `amount` is in vault units. `salt` names this zero-input creation.
    function wrap(address token, uint64 amount, address owner, bytes32 salt)
        external payable returns (bytes32 txId);

    /// @notice Burn `amount` of `msg.sender`'s vault charm and send the underlying asset to `to`.
    /// @dev The holder calls this. The underlying token is the one recorded for that vault.
    function unwrap(address token, uint64 amount, address to) external returns (bytes32 txId);

    /// @notice CREATE2 address of the `CharmToken` for `app`. Wallets use this to find the token. Valid before that token is deployed.
    function tokenAddress(ICharmsTypes.App calldata app) external view returns (address);

    /// @notice Page through `owner`'s UTXOs for one app. Wallets and the CLI use this to build a spell. `transfer` does not.
    function utxosOf(bytes32 appKey, address owner, uint256 cursor, uint256 limit)
        external view returns (ICharmsTypes.UtxoRef[] memory page, uint256 nextCursor);

    /// @notice Vault `App`, decimal `scale`, and locked underlying balance. Holders and indexers use this before `wrap` or `unwrap`.
    function vaultOf(address token) external view returns (ICharmsTypes.App memory app, uint8 scale, uint256 locked);

    /// @notice Block number of a beam-out, or 0 if that id did not beam. `scrolls_ethereum` reads this at the `finalized` tag.
    function beamSourceAt(bytes32 txId) external view returns (uint256 blockNumber);
}

/// @notice UUPS upgrade API (EIP-1822). The admin is the only caller. Spell clients and CharmToken contracts do not use this.
/// @dev `Charms` implements this beside `ICharms` and `ICharmsLedger`. The proxy itself has no upgrade function. It only `delegatecall`s.
interface IUpgradeable {
    /// @notice Point the proxy at `newImplementation`.
    /// @dev The admin calls this on the proxy. `msg.sender` must be the admin and `address(this)` must be the proxy.
    ///      `data` is calldata the admin chooses. After the ERC-1967 slot is written, a non-empty `data` is `delegatecall`ed on the new implementation, so the selector inside `data` is whatever method the admin encoded.
    ///      This design always passes empty `data` (`""`). No second method runs. Accepted spell versions and `programVKey`s are compiled into the new implementation, so the upgrade has nothing further to call.
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;

    /// @notice The ERC-1967 implementation slot. The new implementation must return the same value or the upgrade reverts.
    function proxiableUUID() external view returns (bytes32);
}

/// @notice What `Charms` calls on a `CharmToken`. The token implements this. Holders do not.
interface ICharmTokenHooks {
    /// @notice Emit ERC-20 `Transfer` from the token address. `Charms` is the only caller.
    /// @dev `_apply` nets each holder's balance change and calls this so wallets see the event on the token, not on the proxy.
    function emitTransfer(address from, address to, uint256 amount) external;
}

/// @notice User-facing charm token. Wallets, routers, and DeFi call this. One per `t` app.
/// @dev The deployed bytecode is an EIP-1167 minimal proxy with the `App` as immutable args. It `delegatecall`s a shared implementation.
///      Implements IERC-20, IERC-20 metadata, and EIP-2612. Allowances and permit nonces live here.
///      An infinite allowance is not decremented. The token also implements `ICharmTokenHooks`.
interface ICharmToken {
    /// @notice `Transfer` and `Approval` are the ERC-20 events. `Charms` causes `Transfer` by calling `emitTransfer`. Holders cause `Approval` by calling `approve` or `permit`.
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    /// @notice The Charms proxy this token reads and calls.
    function charms() external view returns (ICharmsLedger);

    /// @notice The `App` in this token's immutable args.
    function app() external view returns (ICharmsTypes.App memory);

    /// @notice Ethereum-resident supply. Forwards to `ICharmsLedger.totalSupply`. Wallets and routers read this.
    function totalSupply() external view returns (uint256);

    /// @notice This charm's total on `owner`'s UTXOs. Forwards to `ICharmsLedger.balanceOf`. Wallets and routers read this.
    function balanceOf(address owner) external view returns (uint256);

    /// @notice Spend the caller's UTXOs and create one output for `to`. Calls `tokenTransfer`.
    function transfer(address to, uint256 amount) external returns (bool);

    /// @notice Remaining amount `spender` may move from `owner`. Stored on this token. Routers read this.
    function allowance(address owner, address spender) external view returns (uint256);

    /// @notice Let `spender` move up to `amount` of the caller's balance. The caller is the holder.
    function approve(address spender, uint256 amount) external returns (bool);

    /// @notice `spender` moves `amount` from `from` to `to`. This token decrements the allowance, then calls `tokenTransfer`.
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    /// @notice Display name. A vault token takes it from the underlying token. Any other token uses the CHIP-0420 defaults until metadata is published.
    function name() external view returns (string memory);

    /// @notice Ticker. Same source as `name`.
    function symbol() external view returns (string memory);

    /// @notice Decimal places for display. A vault token uses `min(underlying decimals, 8)`. Any other token uses 0 until CHIP-0420 metadata is set.
    function decimals() external view returns (uint8);

    /// @notice EIP-2612. The holder signs an allowance off-chain. A router submits it and then calls `transferFrom`.
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;

    /// @notice Next EIP-2612 nonce for `owner`. The signing wallet reads this.
    function nonces(address owner) external view returns (uint256);

    /// @notice EIP-712 domain separator for `permit`. The signing wallet reads this.
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
```

`Charms` deploys a `CharmToken` with CREATE2 the first time that app's Ethereum-resident supply becomes non-zero. The caller of that `transact` pays for it. The salt is `appKey = keccak256(abi.encode(uint32 tag, bytes32 identity, bytes32 vk))`. The deployed bytecode is the EIP-1167 proxy, and the packed `App` is appended as immutable args. `tokenAddress(app)` is that CREATE2 address and is valid before the deploy. The CREATE2 deployer is the Charms proxy, so an upgrade does not move token addresses.

### Upgrade

Deploy the implementation first. Its constructor calls `_disableInitializers()`, so nobody can initialize the implementation contract itself and then `selfdestruct` it out from under the proxy. Deploy the proxy second, with CREATE2 salt `keccak256("charms-proxy-v1")`. The proxy constructor writes the implementation into the ERC-1967 slot and `delegatecall`s `initialize(admin)`. That call is not part of `ICharms`. It runs once and stores the admin. The proxy address is `ETHEREUM_CHARMS`. It is the `address(Charms)` mixed into `ethTxId`, the vault identity, and `tokenAddress`. Replacing the implementation does not change those ids.

The admin calls `upgradeToAndCall(newImplementation, "")` on the proxy. `msg.sender` must be the admin, and `address(this)` must be the proxy. The new implementation must return the same `proxiableUUID` (the ERC-1967 implementation slot). Empty `data` means the upgrade writes the slot and returns. It does not `delegatecall` a method on the new implementation. A new spell version is carried by that new code: the implementation accepts the spell versions it was built for, and it contains their `programVKey`s. A mutable version registry is not needed. A fix that preserves `SpellCodec` output and the `ethTxId` preimage does not need a guest rebuild. A fix that changes those bytes is a protocol bump, with a new `programVKey` compiled into the implementation.

## State

`_apply` is the only writer of UTXO, supply, balance, and vault state. `upgradeToAndCall` writes the ERC-1967 implementation slot. `initialize` writes the admin once. The charm-token maps are supply, per-owner balance, and the per-owner UTXO index. Spend-by-id needs one more record, because a spell names UTXOs and a multi-charm UTXO sits in more than one per-app list. Empty UTXOs have no app, so they cannot live in `address → app → UTXOs`.

| Store | Key | Value | Role |
|---|---|---|---|
| `supply` | `appKey` | `uint256` | Ethereum-resident supply. Beamed outputs are excluded. This is `totalSupply`. |
| `balance` | `owner`, `appKey` | `uint256` | Sum of this token on the owner's unspent, non-beamed UTXOs. This is `balanceOf`. |
| `utxos` | `owner`, `appKey` | deque of `utxoKey` | Selection index. A multi-charm UTXO is listed under every `t` app it carries. |
| `emptyUtxos` | `owner` | list of `utxoKey` | Placeholders. No app to index them by. |
| `head` | `utxoKey` | owner, kind, token amount or body hash, deque slot | The UTXO. Spend starts here. |
| `body` | `utxoKey` | charms CBOR, pins | Present when the UTXO is not a single unversioned `t` charm and is not empty. |
| `usedAnchors` | `anchor` | `bool` | Zero-input ids are single-use. |
| `beamSourceAt` | `ethTxId` | block number, or 0 | Written only when the spell has `beamed_outs`. The canister reads this. |
| `vaults` | token address | `appKey`, `scale`, `locked` | Underlying custody. `address(0)` is ETH. |
| `admin` | one address | `address` | Set once by `initialize`. The only account that may call `upgradeToAndCall`. |

`utxoKey = keccak256(abi.encodePacked(ethTxId, uint32 index))` is internal. It is not the `UtxoId`.

Those variables live in the proxy's storage, because every call delegatecalls. The ERC-1967 implementation slot is `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`, above the sequential layout, so it does not collide with `supply` or `head`. The v1 layout ends with `uint256[50] private __gap`. An upgrade may take slots from that gap or append new variables after it. It must not reorder, insert, or retype an existing variable. The proxy bytecode itself is not upgraded.

Kind is one function of the output's charms:

| Charms on the output | Kind | Stored |
|---|---|---|
| none | Empty | `head` only, plus `emptyUtxos[owner]` |
| one charm, tag `t`, no pin | Plain | amount in `head`. The deque slot names the app. |
| anything else | Bundle | `body` holds the charm map and pins. Listed in `utxos` for each `t` app it contains. |

A beamed output is not a UTXO. It still occupies an index, so `tx_outs_len` and `beamed_out_to_hash` see it. It is absent from `head`, from `balance`, and from `supply`.

The deque puts change (an output whose owner also owned an input of this transact) at the front and every other receipt at the back. `tokenTransfer` pops from the front. When the selected inputs already cover the amount and another front UTXO exists, it spends that extra UTXO too, so a passive holder's UTXO count does not grow without bound. It skips the extra input when adding it would overflow a `u64` sum.

## Identity

One `transact`, `wrap`, `unwrap`, or `tokenTransfer` is one Charms transaction. An Ethereum transaction may contain several, because a smart account can batch calls. The Ethereum transaction hash is not an id: the EVM cannot read it, and an internal call does not have one of its own.

`ethTxId = keccak256(preimage)` with this concatenation:

| Offset | Bytes | Field |
|---|---|---|
| 0 | 21 | ASCII `charms/ethereum/tx/v1` |
| 21 | 32 | `block.chainid` as a big-endian uint256 |
| 53 | 20 | `address(Charms)` |
| 73 | 32 | `anchor` |
| 105 | n | committed spell CBOR |

`anchor` is `keccak256(abi.encode(msg.sender, salt))` when `ins` is empty, and `bytes32(0)` otherwise. The salt is chosen by the caller. It is not a nonce. A nonce that an unrelated call can bump would make a placeholder id that was already published impossible to create, and any charm already beamed at that id would be stuck.

Charms byte order, which Cardano already follows in `cardano_tx::tx_id`:

| Value | Bytes |
|---|---|
| `TxId.0` | `reverse(ethTxId)` |
| `UtxoId::to_bytes()` | `TxId.0 \|\| index` as `u32` little-endian. 36 bytes. Unchanged. |
| Display / `FromStr` | `hex(ethTxId):index`, because `Display` reverses `TxId.0` again. |
| Beam hash | `SHA256(to_bytes() \|\| optional nonce as u64 little-endian)`. Unchanged. `beamed_outs[i]` is that hash. `BeamSource` is unchanged. |

`Transaction.txId` is the id once the creating transaction is mined. The source chain puts the beam hash of that id into `beamed_outs`. Signers of a multi-party spell hash this same preimage locally and sign EIP-712 `Spend(txId)`. `transact` recomputes the id and checks those signatures against it.

Uniqueness is an invariant of `_apply`, not a property of keccak. A zero-input transact consumes its anchor. Every other transact consumes its inputs. A placeholder id cannot be created twice, so a beam cannot be claimed twice.

## The committed spell

The bytes inside the id are `util::write(&NormalizedSpell)` after the same fill Bitcoin does in `spell_with_committed_ins_and_coins`:

- `tx.ins` is the input `UtxoId`s, in order. `Some`, and empty only for a zero-input transact.
- `tx.coins[i] = NativeOutput { amount: 0, dest: owner_i, content: None }`. A beamed output has `dest` of 20 zero bytes.
- `refs`, `beamed_outs`, `scrolls`, `versioned_apps` are omitted when empty (`None` / empty map), never encoded as an empty container.
- `mock` is omitted when false.

`SpellCodec` in Solidity encodes those bytes from the typed `Spell`. It does not parse CBOR. The only bytes it copies from the caller are `Data` blobs (NFT data, custom-app data, app public inputs). On the proved path each blob must be exactly one definite-length CBOR item, depth at most 16, with no trailing bytes. A skip-only `CborWellFormed` check enforces that. Without it a blob can swallow the next field, the proof attests one spell, and the contract accounts another. The native path does not accept fresh blobs: bundle data is copied from the input `body` the contract stored when that UTXO was created.

Calldata order is the CBOR order. The contract checks it and does not sort:

- `apps` by `(tag, identity, vk)`, which is `App`'s `Ord`
- charms in an output by app index
- `beamedOuts` and `scrolls` by index
- `versionedApps` by `vk`

The CBOR shapes `SpellCodec` has to match, from ciborium's non-human-readable serde:

| Rust value | CBOR |
|---|---|
| `NormalizedSpell` | map, text keys in struct order: `version`, `tx`, `app_public_inputs`, then `versioned_apps` and `mock` only when present |
| `NormalizedTransaction` | map: `ins`, optional `refs`, `outs`, optional `beamed_outs`, `coins`, optional `scrolls` |
| `UtxoId` | byte string of 36 bytes |
| `[u8; 32]` and `B32` | array of 32 uints, not a byte string. `0x98 0x20`, then each byte as a uint |
| `App` | array of 3: text of the tag (UTF-8), identity, vk |
| `NativeOutput.dest` | array of uints. `Vec<u8>` is a sequence in this serde, not a byte string. 20 bytes means 20 uints |
| token `Data` | the CBOR uint of the `u64`, shortest form |
| `Data::empty()` | null, `0xf6` |
| public values | array of 2: the spell vk as an array of 32 uints, then the spell map |

Public values are `0x82 ‖ encode([u8; 32] of programVKey) ‖ spellCbor`, which is `to_serialized_pv` for v15 and later. One byte string is both the id preimage and the proof input. Golden vectors generated by `charms_data::util::write` are the test that the two encoders are the same function.

Limits, so a spell cannot be a gas bomb: at most 64 inputs, 64 outputs, 64 apps, and 96 KiB of public values.

## transact

```
_apply(spell, anchor, proof, signatures, vaultDelta):
    require this implementation accepts spell.version
    require canonical shape, counts, and owner == 0 iff beamed
    if ins is empty: require the anchor is unused, and the spell is a placeholder or a wrap
    for each ref: require it is live
    for each input: require it is live and the opening matches head/body
    cbor = SpellCodec.encode(...)
    txId = keccak256(tag ‖ chainid ‖ this ‖ anchor ‖ cbor)
    require every input owner is msg.sender or signed Spend(txId)
    if native(spell, openings, vaultDelta): require proof is empty
    else: require ins is non-empty, blobs are well-formed, and the verifier accepts
    if beamedOuts is non-empty: require this implementation verifies proofs
    write outputs, delete inputs, update supply, balance, deques, vault, pins
    if ins is empty: mark the anchor used
    emit Transaction(txId, anchor, cbor)
    emit ERC-20 Transfer events from the per-holder deltas
```

`native` is the guest's simple-transfer path (`is_correct` with no app binaries), plus what this contract can see:

1. Every app is tag `t` or `n`. Every public input is null. No refs. No scrolls. No beam-in. A beam-in is an input whose stored charms are empty (or itself beamed) while the outputs gain charms; the contract has no `tx_ins_beamed_source_utxos` of its own, so it cannot justify that increase.
2. For each `t` app, the `u64` sum of inputs equals the sum of outputs. Beamed outputs count. Sums use checked arithmetic.
3. For each `n` app, the multiset of data bytes is unchanged.
4. Pins do not change. `versionedApps` equals the pins on the inputs and nothing else.
5. `vaultDelta` is 0, except when `_apply` was entered from `wrap` or `unwrap`. Then the vault app's output sum may differ from its input sum by exactly that delta, and no other app's sum may change.
6. Zero inputs are allowed only for a placeholder (every output empty) or for `wrap`.

A spell the native rules accept must carry an empty proof (`ProofNotRequired`). Any other spell must carry a proof (`ProofRequired`). There are not two ways to apply one spell.

What the contract checks itself, on both paths:

- The inputs exist, match the stored charms and pins, and are unspent. Spending them is the replay lock.
- The caller is allowed to spend them. See below.
- Refs, if the proof path allows them, are live and stay live.
- The encoded spell is the spell whose outputs it is about to write.
- Supply, balance, and vault collateral move by the amounts it computed, not by amounts read out of a public input.

What only the proof establishes:

- App wasm returned true, including versioned-app signatures and version changes.
- A beam-in's source transaction is `proven_final`, and `beamed_outs` on that source hashes to this placeholder's `UtxoId` with the declared nonce.
- Version continuity for a version change. The native path refuses version changes outright.

The proof does not establish spend authorization. On Bitcoin the owner signs the transaction. Here the owner is the Ethereum address in `coins[i].dest`, and authorization is:

- `msg.sender` equals the owner, or
- the owner signed EIP-712 `Spend(bytes32 txId)` (ECDSA or ERC-1271 via `staticcall`), or
- `msg.sender` is the CREATE2 token for this app, the spell is native, every input is a UTXO of `from`, other `t`/`n` charms on those inputs are copied onto `from`'s change output, and no custom-tag charm is touched.

`txId` commits to every input, output, owner, and beam hash. That is the Ethereum analogue of `SIGHASH_ALL`.

A proved spell must spend at least one input. The proof does not commit to the anchor, so a zero-input proved spell could be replayed under a fresh salt. Bitcoin and Cardano transactions have an input. `hosting_chain_is_bitcoin` looks at the creator of `ins[0]`; an empty input list would make that undefined.

`tokenTransfer` builds the native spell. Inputs come off the front of `utxos[from][app]`. Outputs are `{app: amount}` to `to` and, if there is a remainder, `{app: change, plus every other t/n charm from the inputs}` back to `from`. The contract then runs `_apply` and checks the result is native. A bug in the token cannot move a charm the rules would refuse.

Idempotency is the EVM's. The call reverts or it is mined once. Submitting it again reverts with `InputSpent` or `AnchorUsed`. `wrap`'s token pull and `unwrap`'s token push are inside the same call. A revert undoes both. Re-proving a spell off-chain yields the same id, because the proof bytes are not in the preimage.

Reentrancy: one lock around `transact`, `wrap`, `unwrap`, and `tokenTransfer`. ERC-1271 is a `staticcall` during checks. `unwrap` sends the underlying last, after supply and `locked` have moved. `receive()` reverts, so stray ETH cannot land in the contract.

## Balances and bundles

`balanceOf(owner)` for a charm token is the total of that token on the owner's unspent, non-beamed UTXOs, including UTXOs that also carry other charms. `totalSupply` is the same sum over all owners. Both are caches written in `_apply` from the same `u64` values written into `head` and `body`. The UTXO records are the source. A view that recomputes the sum from `utxos[owner]` exists for the invariant tests.

`transfer(balanceOf)` is not always possible in one call. A UTXO that carries a custom-tag charm (anything other than `t` or `n`) cannot move in a native spell, because `is_simple_transfer` is false for those tags even when the data is copied unchanged. Those units stay inside `balanceOf`. `transfer` skips those UTXOs. If the requested amount is larger than the sum of the UTXOs it is allowed to select, it reverts with `RequiresProvedSpell` when the shortfall sits on custom-tag bundles, and with `InsufficientBalance` otherwise. The owner spends the bundle with `transact` and a proof, or splits the token off the bundle that way first.

UTXOs that mix several `t` charms, or `t` with `n`, are selectable. The change output carries the other charms back to the same owner, which is a simple transfer. NFTs are not dropped and are not sent to the recipient unless the whole UTXO's charms are exactly the transferred token.

Partial spends do not exist. The input UTXO is spent whole. The remainder is a new output. That is the Charms rule, and it is the ERC-20 implementation.

Zero is not a charm amount (`ensure_no_zero_amounts`). `transfer(to, 0)` emits an ERC-20 `Transfer` and creates no UTXO. There is no Bitcoin dust limit. Change of zero is omitted. `to` of `address(0)` or of `Charms` reverts. An amount above `type(uint64).max` reverts.

For each `t` app touched by `_apply`, net the plain balance change per owner and emit `Transfer` events through the token. A facade transfer emits one `Transfer(from, to, amount)`. A beam-in or a wrap emits `Transfer(0, to, amount)`. A beam-out, a burn, or an unwrap emits `Transfer(from, 0, amount)`. Supply on Ethereum changes only in those mint and burn cases.

## Vault

Locking an ERC-20 or ETH mints a tag-`t` charm. Burning that charm unlocks the underlying. The policy lives in `Charms`, because the contract is the thing that holds the tokens. An app wasm cannot see an ERC-20 transfer, and a wasm that allowed a mint would allow it on Bitcoin too.

```
VAULT_VK     = SHA-256("charms/ethereum/vault/v1")
identity     = SHA-256("charms/ethereum/vault/v1" ‖ chainId_be_u256 ‖ Charms_20 ‖ token_20 ‖ scale_u8)
app          = t / identity / VAULT_VK
```

`token_20` is 20 zero bytes for ETH. `scale = 0` when the token has no `decimals()` or `decimals <= 8`. Otherwise `scale = decimals - 8`. ETH is treated as 18 decimals, so `scale = 10` and one charm unit is 10^10 wei. Charm amounts are `u64` because `sum_token_amount` is `u64`. Eight decimal digits keeps a single output under that cap for any supply this protocol can represent; sub-unit dust of an 18-decimal token cannot be wrapped and is not rounded.

`VAULT_VK` is the hash of a 24-byte string. That string is not wasm and not a BIP-340 key. No guest can run a contract for it or turn it into a versioned app. On Bitcoin and Cardano the vault charm is transfer-only and beam-only. Minting or burning it there is not a simple transfer and there is no binary that can authorize it.

`wrap` measures the balance the contract actually received (`balanceAfter - balanceBefore`, or `msg.value` for ETH) and requires it to equal `amount * 10^scale`. Fee-on-transfer tokens revert. Rebasing tokens are unsupported. It then applies a zero-input spell whose only output is `{vaultApp: amount}` to `owner`, with that `vaultDelta`, and adds the underlying amount to `locked`.

`unwrap` selects the caller's UTXOs of the vault app the same way `tokenTransfer` does, applies a spell whose outputs are the optional change, with a negative `vaultDelta`, subtracts from `locked`, and only then sends the underlying. A recipient that reverts undoes the burn.

Invariants, checked on every apply that touches the vault app:

- `locked` equals `10^scale` times (wrapped minus unwrapped). That counts charm units on every chain, not only Ethereum.
- `underlying.balanceOf(Charms) >= locked` (for ETH, the contract's balance).
- `supply[vaultApp] * 10^scale <= locked`. A beam-in cannot mint more of the vault charm on Ethereum than the collateral that is still here. A forged Bitcoin finality proof can steal collateral, but only up to the vault units currently living outside Ethereum.

`wrap` and `unwrap` are not a back door on `transact`. External `transact` always passes `vaultDelta = 0`. A proved spell may carry the vault app only when the guest sees a simple transfer, which is the beam and the ordinary move. The v16 guest additionally rejects a simple-transfer spell whose public inputs are not all null, so a beam claim cannot smuggle an unlock instruction in `app_public_inputs`. Solidity never reads `app_public_inputs` to decide a transfer of the underlying.

## Supply

`supply[app]` is the amount of that charm on Ethereum right now. It is not the global amount.

| Event | `supply` on Ethereum | Underlying `locked` |
|---|---|---|
| `wrap` | +amount of the vault app | +amount × 10^scale |
| `unwrap` | −amount of the vault app | −amount × 10^scale, then sent |
| beam-out | −amount. The beamed output is not resident | unchanged |
| beam-in | +amount. The placeholder input was empty | unchanged, then the vault cap |
| app mint or burn of a non-vault app, proved | ±amount | none |
| transfer, or moving units between bundles | unchanged | unchanged |

A beam-in of an ordinary charm mints the ERC-20 representation and does not touch any vault. A beam-out burns the representation and leaves the underlying where it is. Locking and unlocking are the only operations that move the underlying. Those two pairs must not be implemented as the same branch: a beam-in of USDC-the-charm is not a wrap of USDC, and a beam-out is not an unwrap.

## Beaming and finality

**Into Ethereum.** The placeholder is created first, native, zero inputs, one empty output, salt-anchored. Its `UtxoId` is known before submission. The source spell on Bitcoin or Cardano sets `beamed_outs[i]` to the beam hash of that id. The claim spends the placeholder, lists the source in `tx_ins_beamed_source_utxos`, and carries a v16 proof. The guest runs the existing checks: the source is `proven_final`, the placeholder exists and is empty or itself beamed, and the hash matches, including the optional nonce. Solidity sees a supply increase authorized by a proof, and for a vault app it also applies the cap. No Bitcoin header parser and no Cardano signature check live in the contract.

Spending a placeholder as an ordinary input before the claim consumes the id. The source chain has already beamed to that hash. The charms are not claimable anymore. The CLI warns on a native spend of an empty UTXO.

**Out of Ethereum.** The Ethereum spell lists `beamed_outs`. Token sums still balance, so the spell is native unless some other app makes it non-simple. Beamed outputs have no owner and create no UTXO. `beamSourceAt[ethTxId] = block.number`. After the execution block is beacon-finalized (the `finalized` tag, about two epochs), `scrolls_ethereum` attests it. The destination spell's prev tx is `EthereumTx::WithFinalityProof`. The guest checks that signature in `proven_final` and then runs the same beam checks it runs for Bitcoin and Cardano.

The canister is a new member of `scrolls/`, deployed and then blackholed, like its siblings.

```candid
service : {
  certify_final : (eth_tx_id : blob) -> (variant { Ok : blob; Err : text });
  finality_public_key : () -> (blob) query;
}
```

`certify_final` calls `Charms.beamSourceAt(ethTxId)` through the ICP EVM RPC canister at block tag `finalized`, requiring the same answer from at least three providers. If the stored block number is non-zero, it signs with `sign_with_schnorr` (Ed25519) under the derivation path `["scrolls", "ethereum", "finality"]`.

The message is `SHA-256("charms/ethereum/finality/v1" ‖ chainId_be_u256 ‖ Charms_20 ‖ ethTxId)`. The signature is 64 bytes. The guest does not receive the spell from the canister. It already has the spell bytes in the `EthereumTx` record, and `ethTxId` is the hash of those bytes. The signature says the canonical contract accepted that id after finality.

`EthereumTx::proven_final` is true only when `chain_id` is 1, `charms` equals the deployed mainnet address, and the signature verifies under `ETHEREUM_FINALITY_VKEY`. A testnet guest build uses different constants and is not a mainnet proof.

This split is deliberate. Inbound finality stays in the guest, which already knows how to check it. Outbound finality follows Cardano, because a beacon light client inside the spell-checker would have to be rebuilt on sync-committee and generalized-index changes. The trust added is the same class as Cardano's `FINALITY_VKEY`: the canister's key, plus the EVM RPC providers it requires to agree.

## Proofs

Verification runs inside `Charms`, on the proved path only, via `ISP1Verifier.verifyProof(programVKey, publicValues, proof)`.

- `programVKey` is the proof-wrapper verifying key compiled into this implementation for `spell.version`. For the v16 implementation that is the 32 bytes `charms spell vk` prints, and the same bytes committed as the first public value.
- `publicValues` are the bytes from [The committed spell](#the-committed-spell).
- `proof` is the `Proof` byte string the prover already returns. The contract does not re-layout it. The verifier is the one `verify_gnark_v6` corresponds to: 4-byte SHA-256 prefix of the Groth16 verifying key, then exit code, vk root, and proof nonce as 32-byte words, then the gnark proof. v15 checks that prefix against `groth16_vk`, requires exit code 0, and requires vk root `SP1_V6_2_VK_ROOT` (`002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`).

Phase 0 proves this against a real v15 mainnet proof on a fork, using the stock verifier. If that verifier accepts Charms proofs unchanged, the v16 implementation calls the same verifier contract. If it does not, the v16 implementation names the verifier address in its code. It does not carry a Solidity port of `verify_gnark_v6`.

The guest, when it later sees an Ethereum prev tx, does not verify the Groth16 proof again. Acceptance by the pinned `Charms` address is the check, authenticated by the id hash and, for a beam source, by the finality signature. Cardano already trusts on-ledger minting that the guest does not re-derive from a script. Re-verifying every ancestor proof inside the guest would be a second implementation of the same statement.

## Rust, prover, CLI

```rust
// charms-client/src/tx.rs. Chain gains ethereum from the strum discriminant.
pub enum Tx {
    Bitcoin(BitcoinTx),
    Cardano(CardanoTx),
    Ethereum(EthereumTx),
}
```

`TryFrom<&str>` for raw hex tries an Ethereum envelope first, and only then Bitcoin and Cardano. The envelope is CBOR of `EthereumTx` prefixed with the four bytes `CHET` (`0x43 0x48 0x45 0x54`). A failed Ethereum parse must not fall through into the empty virtual spell Bitcoin builds for a transaction that simply has no OP_RETURN. JSON prev txs use the existing externally tagged form, `{"ethereum": ...}`.

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
- `extract_and_verify_spell` decodes `spell`, requires `ins` to be `Some` and `coins.len() == outs.len()`, and requires `mock` to match. It does not run the Groth16 verifier.
- `virtual_spell` is that decode. An Ethereum record with no spell is an error, never an empty spell.
- `proven_final` is the Ed25519 check above. `Simple` is not final.
- `all_coin_outs` returns the committed `coins`.
- `spell_ins` returns the committed `ins`.

One new guard in `is_correct`, beside `beaming_txs_have_finality_proofs`. Every `Tx::Ethereum` prev tx must be `proven_final`, or the spell being proved must itself be hosted on Ethereum (the creator of `ins[0]` is `Tx::Ethereum`) and this prev tx must have created one of its inputs or refs. The guest also rejects a no-binary spell whose public inputs are not all null. That last check is a one-line change in the same rebuild; it closes a hole where the simple-transfer branch ignores public inputs.

`hosting_chain_is_bitcoin` is false for an Ethereum host. Tag `s` is an ordinary non-token app here, as it is on Cardano. Scroll outputs are not given Bitcoin scriptPubKeys.

`ProveRequest` does not gain fields. `chain = "ethereum"` changes the meaning of the ones that exist:

| Field | Ethereum |
|---|---|
| `spell` | Committed form, including `ins` and `coins`. |
| `prev_txs` | An `EthereumTx` for every input and ref creator, plus beam sources with their finality witnesses. |
| `tx_ins_beamed_source_utxos`, binaries, signatures, private inputs | Unchanged. |
| `change_address` | Empty. Charm change is an output. There is no fee output. |
| `fee_rate` | Ignored. The wallet prices gas. |
| `collateral_utxo` | Absent. |

The response is `vec![Tx::Ethereum(Simple(...))]` with the proof filled in when the spell is not native. The CLI, not the server, decides the native path: if the spell is `t`/`n` only, sums and NFT sets match, public inputs are null, there is no `--beamed-from`, and pins are unchanged, it builds the record locally and leaves `proof` empty. Otherwise it calls `POST /spells/prove` as it does today.

The prover's cycle fee is quoted and is not enforced inside `transact`. Bitcoin does not commit that fee in the spell either. The quote is denominated in wei at `fee_addresses[ethereum][network]` and paid as a separate transfer when the operator wants it.

CLI:

| Command | Behavior |
|---|---|
| `spell prove --chain ethereum` | Prints JSON `{tx, tx_id, utxo_ids, call: {to, data, value}}`. `--caller` and `--salt` are required when `ins` is empty. `--change-address` stays required for Bitcoin and Cardano only. |
| `spell check --chain ethereum` | Runs `is_correct` once the guest knows Ethereum prev txs. Before that, it runs the native predicate and refuses a spell that would need a proof. |
| `tx show-spell --chain ethereum` | Decodes an envelope or a `Transaction` log. |
| `tx fetch --chain ethereum --tx-id <id> [--finality]` | Rebuilds the record from `Transaction`. `--finality` calls the canister. |
| `util dest --chain ethereum --addr 0x…` | Raw 20 bytes. Accepts EIP-55, stores the lowercase bytes. |
| `util eth-token <APP>` | CREATE2 token address. |
| `util eth-vault --token <addr\|eth> --decimals <d>` | Prints the vault `App`. |

App contracts are unchanged. `app_contract` sees `coin_outs[i].amount == 0` and a 20-byte `dest`. An app that wants to move ETH moves the vault charm. `charms-sdk` and the app runner do not change. `charms-lib`'s `extractAndVerifySpell` learns the Ethereum envelope in the v16 bump, and the binding documents that a decoded spell is content-authenticated: acceptance is `utxo()` or `beamSourceAt` on the contract.

## Protocol version

| Phase | Spell version | Guest | Keys |
|---|---|---|---|
| Ethereum-local | Records are version 15. The phase-1 implementation accepts that version and rejects proofs and `beamed_outs`. | No rebuild. `Tx` has no Ethereum arm, and nothing outside Ethereum reads these records. | v15 verifying keys stay. |
| Beaming and proved spells | Version 16. `CURRENT_VERSION = 16`. | Rebuild. `SpellProverInput.prev_txs` deserializes `Tx`. A new arm is a new spell-checker ELF, a new `SPELL_CHECKER_VK` in `charms-proof-wrapper`, and a new wrapper verifying key. | Publish `spell_vk` for v16 from `charms spell vk` on the reproducible build. Compile that `programVKey` into the new implementation. The admin upgrades the proxy to it. |

The Groth16 circuit key is not assumed to change and is not assumed to stay. v15's `groth16_vk.bin` aliases v14's because that bump did not rebuild the wrapper. v16 rebuilds the wrapper. If the new `groth16_vk.bin` is byte-identical, alias it and keep the stock verifier. If it is not, publish the new bytes; the proof's 4-byte prefix follows them. Either way the value that changes for certain is the wrapper's `programVKey`, because the wrapper hardcodes the spell-checker key. `to_serialized_pv` stays on the v15 arm (`([u8; 32], NormalizedSpell)`). Bitcoin and Cardano transaction layouts do not change.

Which spell versions an implementation accepts, and the `programVKey` for each, are part of that implementation's code. A protocol bump is a new implementation plus `upgradeToAndCall(newImplementation, "")` from the admin. Token addresses and `ETHEREUM_CHARMS` stay on the proxy. A new proxy would change every token address and the guest constant. That is a new deployment, not an upgrade.

The usual v16 chores ride along: Cardano's protocol-version NFT, `scrolls_bitcoin` delegation, `scrolls_cardano`, and `charms-lib`'s `SPELL_VK`. `CHARMS_PROVE_API_URL` becomes `https://v16.charms.dev/spells/prove`.

## Edge cases

- **ETH versus a wrapped ERC-20.** ETH is the vault at `address(0)`. WETH is a different vault. They do not share supply.
- **Allowances.** Charm allowances live on `CharmToken`. The underlying token's `approve` is only for `wrap`, and it names `Charms`, not the facade. `tokenTransfer` checks `msg.sender` is the token whose CREATE2 address it just recomputed.
- **Several charms on one UTXO.** One `head` record, one list entry per `t` app, one balance contribution per `t` app. Spending via the facade preserves the other `t`/`n` charms on the change output. Spending a custom-tag bundle requires `transact`.
- **Empty UTXOs.** Allowed, required as beam targets, indexed only in `emptyUtxos` and `head`. They do not affect supply.
- **u64.** A single output amount and the sum of a spell's inputs of one app must fit in `u64`, because the guest adds them as `u64`. Balances in storage are `uint256` so many UTXOs can sum past `u64`; the facade then needs more than one call, each under the cap.
- **Weird tokens.** Fee-on-transfer reverts. Rebasing is unsupported. A token that blocklists `Charms` can freeze that vault and no other. `decimals()` is read once, at vault creation.
- **Mixed pins.** After a versioned app bumps its version, one owner can hold UTXOs pinned to different versions. The facade reverts with `MixedVersions` when the inputs it would select do not share a pin. A proved `transact` runs the new binary, which is what `authorize_version_changes` already requires.
- **Reorgs.** A native transfer reorgs with Ethereum, like any ERC-20. A beam waits for `finalized`.
- **History.** `Transaction` carries the spell CBOR because `wrap`, `unwrap`, and the facade build it inside the contract, where it is not in calldata. Proving a later spend of a bundle needs that record. Native spends of plain UTXOs do not: `head` has the amount. Indexers archive the logs; EIP-4444 makes that an operator concern, not a consensus one.

## Build order

**Phase 0. Codec and verifier, no protocol change.** `SpellCodec` and `CborWellFormed`, golden vectors from `util::write` over generated spells, and a fork test that feeds a real v15 Bitcoin proof to the deployed SP1 verifier with public values the codec built. This is the gate for the id preimage and the proof statement. Done when the vectors match and that proof verifies.

**Phase 1. Ethereum-local, still v15.** `CharmsProxy`, `Charms`, the shared `CharmToken` implementation, and the per-app clones: native `transact`, the deque, EIP-712 and ERC-1271, the vault, events, and UUPS upgrade under the admin. The phase-1 implementation accepts spell version 15 and rejects proofs and `beamed_outs`. Host-side Rust for the record type and `tx_id`, behind a feature the guest does not compile. CLI for native spells, `util dest`, `util eth-token`, `util eth-vault`. Invariant tests for the supply, balance, and `locked` tables, plus a test that an upgrade keeps token addresses and existing `UtxoId`s. Audit, then the CREATE2 proxy deployment that fixes `ETHEREUM_CHARMS`. No beaming and no proofs.

**Phase 2. v16.** Deploy and blackhole `scrolls_ethereum` before the guest build, because the guest hardcodes `ETHEREUM_FINALITY_VKEY`. Add `Tx::Ethereum` and the `is_correct` guards. Rebuild the spell-checker and the wrapper. Publish `programVKey` and compile it into a new `Charms` implementation. The admin calls `upgradeToAndCall` with empty `data`. Wire the prover's Ethereum arm. Do the usual cross-chain version bump. End-to-end on testnets with a dev guest: Bitcoin to Ethereum and back, Cardano to Ethereum and back, a USDC vault round trip, and an ERC-20 `transfer` that splits a UTXO which also holds an NFT.

**Phase 3. Can wait.** CHIP-0420 metadata on the facade, read once from the reference NFT `n/<identity>/<vk>` if that NFT is live on Ethereum. A TypeScript helper for EIP-712 and calldata. An ERC-721 facade for tag `n`. Any L2 deployment, which is a different `chain_id` and a different guest constant, not a flag on this contract.

## Alternatives

| Shape | Why it lost |
|---|---|
| Ethereum transaction hash as `TxId` | The EVM cannot read the hash of the executing transaction. One Ethereum transaction can contain several Charms transactions. |
| A contract nonce as `TxId` | The id is not known until mined, it changes across a reorg, and an unrelated call burns a placeholder that a source chain has already beamed to. |
| Verify proofs only inside the guest, and let a canister attest them on Ethereum | Ethereum can verify the Groth16 proof. A canister on this path would be a trusted party Cardano needs only because Plutus cannot do this cheaply. |
| A Solidity port of `verify_gnark_v6` | A second verifier. The stock SP1 verifier is the one the phase 0 fork test has to accept. |
| A new public-value encoding for Ethereum | Two commitment formats. The same spell would verify differently per chain. `to_serialized_pv` stays as it is. |
| Parse untrusted CBOR in the contract | The contract encodes from typed calldata. Parsing is a larger, leakier surface, and the proof already pins the bytes. |
| Vault policy as an app wasm | Every wrap needs a prover. The wasm cannot see the ERC-20 transfer. A wasm that permits a mint permits it on Bitcoin. A beam-in that the guest treats as a simple transfer would skip that wasm and still look like an unlock if Solidity obeyed the public input. |
| Prove every ERC-20 transfer | Matches Bitcoin, and makes `transfer` cost a Groth16 verification plus a prover round trip. The contract can check a simple transfer itself. That is the point of doing this on Ethereum. |
| `balanceOf` counts only single-token UTXOs, and attributes bundles to `address(Charms)` | `balanceOf` would not be the total on that address's UTXOs. The requirement is the total. Custom-tag bundles stay in the balance and out of automatic selection instead. |
| Beacon light client inside the guest | Finality would be trustless, and every beacon consensus change would be a guest rebuild. Cardano already chose a Scrolls signature for the same reason. |
| Bitcoin and Cardano light clients in Solidity | A second copy of `proven_final`. The proof is already that check. |
| A new `Charms` deployment per protocol version | CREATE2 token addresses and the vault identity are functions of the proxy address. A new proxy splits liquidity and changes `ETHEREUM_CHARMS` in the guest. |
| A transparent proxy | Every call would check `msg.sender` against an admin before delegating. UUPS keeps that check on `upgradeToAndCall` only, so `transact` and `transfer` pay one `delegatecall`. |
| A beacon proxy | One `Charms` proxy does not need a second contract read on every call to find the implementation. |
| Wei on `NativeOutput.amount` | `u64` overflows near 18 ETH, native coins are not beamable, and ETH would have two representations. The vault charm is the one representation. |
| Store the Groth16 proof beside the spell and require the guest to verify it for every Ethereum ancestor | The contract has already verified it, or the spell was native and the contract checked the sums. The ancestor proof is not part of the id. Carrying it as a sidecar means an id that does not commit to the statement the next chain trusts. |

## Risks

The vault makes a forged beam worth real tokens. A private Bitcoin fork deep enough to pass `FINALITY_TARGET_BITS`, or a stolen `scrolls_ethereum` or Cardano finality key, can beam vault units onto Ethereum and unwrap them. The cap `supply * 10^scale <= locked` limits the loss to vault units that are currently outside Ethereum. This design does not raise `FINALITY_TARGET_BITS`. Raising it would be a guest constant in the same v16 rebuild, and it would slow every Bitcoin beam, not only vault beams.

A `SpellCodec` that diverges from `util::write` is a liveness failure: proofs do not verify and ids do not match. A codec that is not injective is a safety failure. The phase 0 vectors, including a blob that tries to swallow the next amount, are the mitigation.

Outbound beams stall if the EVM RPC providers disagree or the canister is out of cycles. The attestation can be retried. The UTXO is already spent; the funds are not returned and not lost.

The admin can call `upgradeToAndCall` immediately. That call can change the native path, the vault, and which proofs the contract accepts. There is no delay. The `programVKey` in the new implementation has to equal the reproducible `charms spell vk` output for that spell version. Watch the ERC-1967 implementation slot. An upgrade that changes `SpellCodec` or the `ethTxId` preimage without a protocol bump desynchronizes new spells from the guest.

## What is not decided here

The admin address is chosen at deploy time. The design does not name it.

v16 keeps `FINALITY_TARGET_BITS` at its current value. The vault cap is the bound on a forged beam.
