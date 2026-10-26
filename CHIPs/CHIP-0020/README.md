---
CHIP: "0020"
Title: Charms on Ethereum
Status: Draft
Created: 2026-10-04
---

# CHIP-0020. Charms on Ethereum

Ethereum becomes a third host for the existing spell, UTXO, and beaming protocol. It does not get a second asset protocol.

Only a fungible charm, tag `t`, is an ERC-20. NFT (`n`), Scroll (`s`), custom-tag, and empty UTXOs stay UTXOs inside `Charms`. A caller moves those with `transact`, not with `transfer` or `transferFrom`. Charm tokens already defined by a tag-`t` `App` are held as UTXOs inside one `Charms` contract and projected as ERC-20s. Existing ERC-20s and ETH are locked in that contract and minted as vault charms, which beam to Bitcoin and Cardano and unlock only by burning the charm back on Ethereum. A vault charm is not a second token. Its ERC-20 face is the underlying asset, and ETH's face is `address(0)`. The charm moves as a UTXO through `transact`.

The contract is the consensus for Ethereum Charms transactions, in the same role Bitcoin consensus has for a Bitcoin transaction. The spell-checker guest verifies a spell carried in `Tx::Ethereum`, including its proof, with the same public values and Groth16 check Bitcoin and Cardano use. That guest is protocol version 16. Beaming still waits on `proven_final`. Local UTXOs, ERC-20 transfers, and the vault do not need that proof.

## Decisions

| Question | Decision |
|---|---|
| UTXO model | One `Charms.transact` creates every output of one Charms transaction. Each output is its own `UtxoId` and is spent on its own later. |
| UTXO id | Content-addressed. Not the Ethereum transaction hash and not a counter. `TxId.0` is the reverse of that id, matching `UtxoId::to_bytes` and Cardano's `tx_id`. |
| Simple transfer | The contract checks it. The proof is empty. A proof on a spell the contract can check itself is rejected. |
| Anything else | Groth16 is verified on Ethereum, against the same public values Bitcoin and Cardano already use: CBOR of `([u8; 32] spell_vk, NormalizedSpell)` with `ins` and `coins` filled. |
| Token metadata | `setMetadata` on the proxy, checked against `metadataSigner()`. That signer is an immutable in the `Charms` implementation. Fields follow CHIP-0420. `decimals` freezes on the first accepted call. `name`, `symbol`, and `image` may change later. The clone's `contractURI()` reads the proxy. `charms_metadata` signs a digest of the app key, the Bitcoin block time, and `metadataHash`. The same signature is valid on every chain. |
| ERC-20 facade | One `CharmToken` per non-vault tag-`t` app. A vault app has no `CharmToken`, and neither does any other tag. For a non-vault app, `tokenAddress` is the CREATE2 address and does not deploy, and `ensureToken` deploys the minimal-proxy clone. That clone `delegatecall`s `CharmTokenProxy`. For a vault app, both return the underlying ERC-20 recorded for that vault, or `address(0)` for ETH, and `ensureToken` does not deploy. `balanceOf`, `transfer`, and `transferFrom` apply only to a non-vault clone. `balanceOf` is the sum of that token across all of the address's unspent, non-beamed UTXOs. `transfer` spends whole UTXOs through the same apply path as `transact`. A vault charm moves through `transact`. The underlying token's `transfer` is unchanged. `_apply` does not deploy a clone. |
| ETH and foreign ERC-20s | Contract policy, not an app wasm. Vault `vk` is a constant with no wasm and no BIP-340 preimage, so other chains can only transfer and beam it. |
| Finality into Ethereum | Inside the v16 proof, via the existing `proven_final` (Bitcoin work, Cardano Scrolls signature). Solidity does not grow a light client. |
| Finality out of Ethereum | `scrolls_ethereum` verifies a beacon light-client proof that the execution block is finalized, then signs the Charms tx id. The guest still checks that one Ed25519 signature, as it does for Cardano's `FINALITY_VKEY`. |
| Guest | The host checker and the spell-checker guest both verify a non-empty proof on an Ethereum record. The guest accepts that record in `prev_txs` when it created an input or reference of a spell on the same chain and contract. This guest is protocol version 16. `ETHEREUM_FINALITY_VKEY` is the `scrolls_ethereum` key. Later beacon forks do not change that constant. |
| `scrolls_ethereum` lifetime | Upgradeable, with one controller. Not blackholed. A beacon fork that changes a light-client index is a wasm upgrade of this canister. Bitcoin and Cardano Scrolls stay blackholed. |
| Upgrade | ERC-1967 proxy for `Charms`. Every call `delegatecall`s. The upgrade function lives on the implementation (OpenZeppelin UUPS), so `transact` and `transfer` do not pay an admin check. The proxy address is the stable `Charms` address. `CharmToken` logic and the metadata signer are immutables in the `Charms` implementation. The admin replaces them by upgrading that implementation. Token addresses stay. |

## What a caller does

### A contract treats a tag-`t` charm as an ERC-20

```solidity
ICharmsTypes.App memory app = ICharmsTypes.App({
    tag: 0x74, identity: ID, vk: VK
}); // 0x74 is tag t
address predicted = charms.tokenAddress(app); // pure CREATE2, no deploy
IERC20 token = IERC20(charms.ensureToken(app));
// deploys the clone if it is not there yet
token.transferFrom(msg.sender, address(this), amount);
token.transfer(msg.sender, amount);
```

For a non-vault tag-`t` app, `tokenAddress` is a pure function of the `App` and the `Charms` address. It reverts for any other tag and does not deploy. A wallet or integration that needs on-chain `transfer` or `balanceOf` calls `ensureToken` once. Until then the address is knowable off-chain from `tokenAddress`. `transfer` spends the sender's UTXOs of that `t` app and creates one output of that token to the recipient. When any other `t` or `n` charm remains, or this token's remainder is nonzero, it also creates one sender-owned change output. That output carries the remainder when it is nonzero and every other `t` or `n` charm. A zero remainder of this token is not written there. NFT, Scroll, custom-tag, and empty UTXOs have no ERC-20. The caller spends them with `transact`. Units of a `t` token that sit on a UTXO next to one of those charms still count in that token's `balanceOf`. `transfer` does not select those UTXOs. Spending them is `transact` with a proof. See [Balances and bundles](#balances-and-bundles).

### A wallet locks USDC, beams it, and unlocks it

```solidity
usdc.approve(address(charms), 1_000_000);
bytes32 txId = charms.wrap(address(usdc), 1_000_000, alice, salt);
// later, after the charm has come back
charms.unwrap(address(usdc), 400_000, alice);
```

`wrap` of ETH is `charms.wrap{value: amount * 10^scale}(address(0), amount, alice, salt)`. The charm amount is an integer count of the vault's unit, not wei. ETH is fixed at 18 decimals, so `scale = 10` (1 unit = 10 gwei). A token with `decimals <= 8` uses `scale = 0` and keeps its own smallest unit. Scale is not part of the vault `App`. See [Vault](#vault).

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

This example is an ethereum-local simple transfer. The spell version is 16. The first deployment accepts that version. A native transfer needs no proof. A beam is still a later change. `coins[i].amount` is always 0. `coins[i].dest` is the raw 20-byte owner. `charms util dest --chain ethereum --addr 0x…` prints those 20 bytes. ETH held as a charm is the ETH vault charm. Its ERC-20 face is `address(0)`, not a `CharmToken` and not `NativeOutput.amount`.

A vault app does not follow the clone path above. `tokenAddress` and `ensureToken` return the underlying ERC-20 recorded for that vault, or `address(0)` when the asset is ETH. Neither call deploys a clone. The first `wrap` writes the record. The vault identity is a hash of that token, so before the record exists both calls revert and deploy nothing. Moving the charm is `transact`. `transfer` on the underlying token moves that token. It does not move the charm.

Beaming uses the fields that already exist.

```bash
charms spell prove --chain ethereum --spell placeholder.yaml \
  --caller 0xAlice --salt 0x… > ph.json
charms tx build --chain ethereum --tx "$(jq -r '.[0]' ph.json)"

# Bitcoin beams to sha256(UtxoId::to_bytes() of that id), as it does today.
# After Bitcoin finality, claim on Ethereum.
# A claim is not a local simple transfer, so it has a proof.
charms spell prove --chain ethereum --spell claim.yaml \
  --beamed-from '{0: ["<btc-txid>:<vout>"]}' \
  --prev-txs "$(jq -r '.[0]' ph.json)" \
  --prev-txs btc-with-block-proof.json > claim.json
```

`ph.json` is a JSON array of one hex string. The hex is the Charms record for an empty UTXO. The bytes are the `CHET` envelope. They are not a signable Ethereum transaction. `spell prove` takes no `--prev-txs`. The spell mints nothing and burns nothing, so the command does not call the prover.

The record carries `chain_id`, `charms`, `anchor`, `spell`, and `proof`. It also carries `caller` and `salt`, the preimage of `anchor`. `eth_tx_id` does not hash `caller` or `salt`. A wallet cannot sign the record.

`charms tx build --chain ethereum` takes that hex and no other spell input. It encodes the committed spell inside that record as `transact` calldata. It prints one JSON object with `from`, `to`, `data`, and `value`. `data` is the calldata. `from` is the caller that must send the call. `to` is the Charms proxy. `value` is `0`. That call is what gets executed. The wallet adds the account nonce, the gas fields, and the signature.

The other direction marks `beamed_outs` on an Ethereum spell whose token sums still balance (the beamed output counts). That spell is native: no proof. After beacon finality, `charms tx fetch --chain ethereum --tx-id <id> --finality` returns the record with `signature` set, and the Bitcoin or Cardano claim is an ordinary spell.

## Contracts

Deploy a proxy and an implementation. CharmToken contracts and the external Groth16 verifier sit beside them. Everything else is internal to the implementation.

- `CharmsProxy` is the address wallets, tokens, and the guest call `Charms`. Its `fallback` and `receive` always `delegatecall` the implementation in the ERC-1967 slot. It has no other functions and no admin branch. The storage slot is ERC-1967 (`keccak256("eip1967.proxy.implementation") - 1`), the slot OpenZeppelin's UUPS implementation uses. This is not the EIP-1822 `PROXIABLE` slot. Every call is delegated, and the upgrade function is not on the proxy bytecode, so a transfer does not pay for an admin check the way a transparent proxy does.
- `Charms` is the implementation. It owns UTXOs, supply, balances, the vault, anchors, and token metadata in the proxy's storage. `tokenImplementation` and `metadataSigner` are immutables in this bytecode. `ensureToken` deploys a `CharmToken` clone only for a non-vault tag-`t` app. For a vault app it returns the underlying address and deploys nothing. It exposes `upgradeToAndCall`. The admin is a single address set at initialization. That address is the only account that can upgrade `Charms`. A new implementation carries the next token implementation and the next metadata signer. There is no timelock and no second role.
- `CharmTokenProxy` is one shared forwarder. Every non-vault clone `delegatecall`s it. On each call it reads `Charms.tokenImplementation()` with an external call, then `delegatecall`s that implementation. It has no ERC-1967 slot and no `upgradeTo`. Its address is fixed in the clone runtime.
- `CharmToken` is the ERC-20 logic for one non-vault tag-`t` app. The per-app contract is still a clone: a minimal proxy with immutable arguments. Its fallback appends the packed `App` and a `uint16` length to calldata, then `delegatecall`s `CharmTokenProxy`. The per-token bytecode is that clone, not a separately compiled contract. It owns allowances and EIP-2612 nonces. It owns no balances and no metadata. Metadata lives on the Charms proxy, and the clone reads it. There is no `CharmToken` for a vault app, tag `n`, tag `s`, a custom tag, or an empty UTXO.
- `SP1VerifierGroth16` is Succinct's immutable verifier. `Charms` calls it directly. Succinct's gateway is not on the path.

`CharmToken.transfer` and `transferFrom` are the ERC-20 entry points for a non-vault tag-`t` app. They call `Charms.tokenTransfer`, which builds a simple-transfer spell and runs it through the same internal apply path as `transact`. They do not call the external `transact` (that would take the caller's identity from the token). The rules of the spell are still the rules of `transact`. A vault charm has no `CharmToken`. The caller moves it with `transact`. The underlying token's `transfer` stays that token's own transfer. A non-`t` charm has no `transfer` or `transferFrom`. The caller uses `transact`.

`Charms` implements `ICharms`, `ICharmsLedger`, and `IUpgradeable` as three interfaces. `ICharms` does not extend `ICharmsLedger`. Wallets and the CLI call `ICharms`. The token calls `ICharmsLedger`. The admin calls `IUpgradeable`. A caller of one does not need the methods of the others. `CharmToken` implements `ICharmToken` and `ICharmTokenHooks`. The structs live once, on `ICharmsTypes`, and the other interfaces use them.

```solidity
/// @notice Shared structs. No functions. The other interfaces use these so `App` is
/// defined once.
/// @dev Wallets, CharmToken, and the CLI all pass `App` through. 't' = 0x74, 'n' = 0x6e,
/// 's' = 0x73.
interface ICharmsTypes {
    /// @notice Unicode scalar tag plus the 32-byte identity and vk. Same triple as
    /// `charms_data::App`.
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

    /// @notice Typed mirror of `NormalizedSpell`. The contract fills `tx.ins` and
    /// `tx.coins`.
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

    /// @notice CHIP-0420 display fields. `symbol` is that CHIP's `ticker`.
    struct Metadata {
        string name;
        string symbol;
        uint8 decimals;
        string description;
        string url;
        string image;
        bytes32 imageHash;
    }
}

/// @notice Ledger calls from a tag-`t` `CharmToken`. The token stores this address (the
/// Charms proxy) and nothing wider.
/// @dev Only tag `t` has this surface. `CharmToken.transfer` and `transferFrom` are the
/// only callers of `tokenTransfer`.
/// `balanceOf` and `totalSupply` on that token read the two views. DeFi calls the token,
/// not this interface.
///      `tokenTransfer` does not deploy a `CharmToken`.
interface ICharmsLedger {
    /// @notice Move `amount` of `app` from `from` to `to` by spending whole UTXOs and
    /// creating change.
    /// @dev `app.tag` must be `t`, and `app` must not be a vault. Only the CREATE2
    /// `CharmToken` for that app may call this. The token has already checked
    /// `msg.sender` and the allowance. A vault charm moves through `transact`.
    function tokenTransfer(
        ICharmsTypes.App calldata app,
        address from,
        address to,
        uint256 amount
    ) external;

    /// @notice Ethereum-resident supply of one charm. The token's `totalSupply` returns
    /// this.
    function totalSupply(bytes32 appKey) external view returns (uint256);

    /// @notice Sum of this charm on `owner`'s unspent, non-beamed UTXOs. The token's
    /// `balanceOf` returns this.
    function balanceOf(bytes32 appKey, address owner) external view returns (uint256);

    /// @notice Display name. `"Charm"` until `setMetadata` stores a name.
    function name(ICharmsTypes.App calldata app)
        external
        view
        returns (string memory);

    /// @notice Display symbol. CHIP-0420 `ticker`. `"CHARM"` until published.
    function symbol(ICharmsTypes.App calldata app)
        external
        view
        returns (string memory);

    /// @notice Display decimals. `0` until published, then the frozen value.
    function decimals(ICharmsTypes.App calldata app)
        external
        view
        returns (uint8);

    /// @notice ERC-7572 document for `app`, as a `data:application/json` URI.
    function contractURI(ICharmsTypes.App calldata app)
        external
        view
        returns (string memory);
}

/// @notice Spell and vault API. Wallets, the CLI, and contracts that build spells call
/// this on the proxy.
/// @dev Does not include `ICharmsLedger`. Those callers use the ERC-20 for balances and
/// do not call `tokenTransfer`.
interface ICharms {
    /// @notice A Charms transaction was applied. Indexers and `tx fetch` read `txId` and
    /// `spell` from this log.
    /// @dev `spell` is the committed CBOR. `anchor` is zero when the spell spent inputs.
    event Transaction(bytes32 indexed txId, bytes32 anchor, bytes spell);

    /// @notice Spend `spell.ins` and create `spell.outs`. Returns the new `ethTxId`.
    /// @dev Wallets and the CLI call this for any spell that is not an ERC-20 `transfer`
    /// or a vault lock or unlock.
    /// `proof` is empty when the contract can check the spell itself, and required
    /// otherwise.
    ///      `salt` is used when `ins` is empty (a placeholder). Otherwise `salt` is 0.
    /// `signatures` has one entry per input owner other than `msg.sender`, in order of
    /// first appearance,
    ///      over EIP-712 `Spend(bytes32 txId)`. ECDSA or ERC-1271 `staticcall`.
    function transact(
        ICharmsTypes.Spell calldata spell,
        bytes32 salt,
        bytes calldata proof,
        bytes[] calldata signatures
    ) external returns (bytes32 txId);

    /// @notice Lock the underlying ERC-20, or ETH when `token` is `address(0)`, and mint
    /// that vault charm to `owner`.
    /// @dev The holder calls this after `approve` on the underlying token. `amount` is in
    /// vault units. `salt` names this zero-input creation.
    function wrap(address token, uint64 amount, address owner, bytes32 salt)
        external payable returns (bytes32 txId);

    /// @notice Burn `amount` of `msg.sender`'s vault charm and send the underlying asset
    /// to `to`.
    /// @dev The holder calls this. The underlying token is the one recorded for that
    /// vault. The contract sends `amount * 10^scale` and does not require `to`'s
    /// balance to increase by that amount. A fee taken out of the amount sent does
    /// not revert the unwrap. A fee charged on top of that amount is unsupported.
    function unwrap(address token, uint64 amount, address to)
        external
        returns (bytes32 txId);

    /// @notice ERC-20 face of a tag-`t` `app`. Does not deploy.
    /// @dev A non-vault app returns the CREATE2 address of its `CharmToken`. A vault app
    /// returns the underlying ERC-20 recorded on the first `wrap`, or `address(0)` for
    /// ETH. Before that record exists the call reverts. Any other tag reverts.
    function tokenAddress(ICharmsTypes.App calldata app) external view returns (address);

    /// @notice ERC-20 face of a tag-`t` `app`. A non-vault app deploys its `CharmToken`
    /// clone when no code is at `tokenAddress(app)`. A vault app does not deploy.
    /// @dev A vault app returns the same address as `tokenAddress`. Any tag other than
    /// `t` reverts. `_apply` and `tokenTransfer` do not call this.
    function ensureToken(ICharmsTypes.App calldata app) external returns (address token);

    /// @notice `CharmToken` implementation the forwarder delegatecalls.
    /// @dev Immutable in the `Charms` bytecode. Not a proxy slot and not
    /// ERC-1967. A clone does not store this.
    function tokenImplementation() external view returns (address);

    /// @notice Signer `setMetadata` accepts.
    /// @dev Immutable in the `Charms` bytecode. Not a proxy slot.
    function metadataSigner() external view returns (address);

    /// @notice Accepted publication. Indexers read `appKey`, `version`, and the hash.
    event MetadataSet(bytes32 indexed appKey, uint64 version, bytes32 metadataHash);

    /// @notice Publish CHIP-0420 display fields for a non-vault tag-`t` app.
    /// @dev Anyone may call. `version` is the Bitcoin block time `sign_metadata`
    /// returned. It must exceed the stored version. The first success freezes
    /// `decimals`.
    function setMetadata(
        ICharmsTypes.App calldata app,
        ICharmsTypes.Metadata calldata metadata,
        uint64 version,
        bytes calldata sig
    ) external;

    /// @notice Stored metadata version for `app`. `0` means unpublished.
    function metadataVersion(ICharmsTypes.App calldata app)
        external
        view
        returns (uint64);

    /// @notice Page through `owner`'s UTXOs for one app. Wallets and the CLI use this to
    /// build a spell. `transfer` does not.
    function utxosOf(bytes32 appKey, address owner, uint256 cursor, uint256 limit)
        external view returns (ICharmsTypes.UtxoRef[] memory page, uint256 nextCursor);

    /// @notice The stored record for one UTXO. `charms-lib` and an indexer call this to
    /// see that the contract accepted the output.
    /// @dev Returns `owner` and `body` only. `body` is empty for a missing or spent id,
    /// for an Empty UTXO, and for an unpinned Plain token. A missing or spent id is
    /// `owner == address(0)` with that empty `body`. Kind and the Plain amount stay in
    /// `head` and are not returned, so an owned Empty UTXO and an unpinned Plain token
    /// both read as that owner plus an empty `body`.
    function utxo(ICharmsTypes.UtxoRef calldata u)
        external
        view
        returns (address owner, bytes memory body);

    /// @notice The one vault `App` for `token` and its canonical `scale`. Holders and
    /// indexers use this before `wrap` or `unwrap`.
    /// @dev `app` does not depend on `scale`. ETH (`token == address(0)`) is always
    /// `scale` 10. An ERC-20's `scale` is derived from `decimals()` by the rule in Vault.
    /// `token.balanceOf(charms)`, or the ETH balance of `charms` for the ETH vault, is
    /// what `charms` holds, not the committed vault backing. A direct transfer raises it
    /// without raising `locked`, so it can exceed `locked`. `locked` is not returned; it
    /// stays an internal check in `_checkVaults`.
    function vaultOf(address token)
        external
        view
        returns (ICharmsTypes.App memory app, uint8 scale);

    /// @notice Block number of a beam-out, or 0 if that id did not beam.
    function beamSourceAt(bytes32 txId) external view returns (uint256 blockNumber);
}

/// @notice Upgrade API on the implementation. The admin is the only caller. Spell clients
/// and CharmToken contracts do not use this. The slot is ERC-1967, as in OpenZeppelin
/// UUPS.
/// @dev `Charms` implements this beside `ICharms` and `ICharmsLedger`. The proxy itself
/// has no upgrade function. It only `delegatecall`s.
interface IUpgradeable {
    /// @notice Point the proxy at `newImplementation`.
    /// @dev The admin calls this on the proxy. `msg.sender` must be the admin and
    /// `address(this)` must be the proxy.
    /// `data` is calldata the admin chooses. After the ERC-1967 slot is written, a
    /// non-empty `data` is `delegatecall`ed on the new implementation, so the selector
    /// inside `data` is whatever method the admin encoded.
    /// This design always passes empty `data` (`""`). No second method runs. Accepted
    /// spell versions, `programVKey`s, `tokenImplementation`, and `metadataSigner`
    /// are compiled into the new implementation, so the upgrade has nothing further
    /// to call.
    /// `_authorizeUpgrade` requires `msg.sender` to be the admin. It reverts when
    /// `tokenImplementation()` on the new implementation has no code, when
    /// `CharmToken` at that address returns a `charms()` other than this proxy, or
    /// when `metadataSigner()` is `address(0)`.
    function upgradeToAndCall(address newImplementation, bytes calldata data)
        external
        payable;

    /// @notice The ERC-1967 implementation slot. The new implementation must return the
    /// same value or the upgrade reverts.
    function proxiableUUID() external view returns (bytes32);
}

/// @notice What `Charms` calls on a `CharmToken`. The token implements this. Holders do
/// not.
interface ICharmTokenHooks {
    /// @notice Emit ERC-20 `Transfer` from the token address. `Charms` is the only
    /// caller.
    /// @dev A spell emits `Transfer(sender, Charms, decrease)` and
    /// `Transfer(Charms, receiver, increase)` when this clone is already deployed.
    /// `Charms` is the proxy. A facade `transfer` emits `Transfer(from, to, amount)`.
    /// `_apply` does not deploy the clone in order to emit.
    function emitTransfer(address from, address to, uint256 amount) external;

    /// @notice Emit `ContractURIUpdated` from this clone. Only `Charms` may call.
    function emitContractURIUpdated() external;
}

/// @notice User-facing ERC-20 for one non-vault fungible charm, tag `t`.
/// Wallets, routers, and DeFi call this. One per such app. A vault app has
/// no clone. NFT, Scroll, custom-tag, and empty UTXOs are not this interface.
/// @dev The deployed bytecode forwards calldata plus the packed `App` and a `uint16`
/// length, then `delegatecall`s `CharmTokenProxy`. That forwarder `delegatecall`s
/// the current implementation.
/// Implements IERC-20, IERC-20 metadata, and EIP-2612. Allowances and permit nonces live
/// here.
/// An infinite allowance is not decremented. The token also implements
/// `ICharmTokenHooks`.
interface ICharmToken {
    /// @notice `Transfer` and `Approval` are the ERC-20 events. `Charms` causes
    /// `Transfer` by calling `emitTransfer` when this clone is already deployed.
    /// A facade move is `Transfer(from, to, amount)`. A spell move uses the Charms
    /// proxy as the counterparty. Holders cause `Approval` by calling `approve` or
    /// `permit`.
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    /// @notice ERC-7572. The proxy causes this via `emitContractURIUpdated`.
    event ContractURIUpdated();

    /// @notice The Charms proxy this token reads and calls.
    function charms() external view returns (ICharmsLedger);

    /// @notice The `App` in this token's immutable args.
    function app() external view returns (ICharmsTypes.App memory);

    /// @notice Ethereum-resident supply. Forwards to `ICharmsLedger.totalSupply`. Wallets
    /// and routers read this.
    function totalSupply() external view returns (uint256);

    /// @notice This charm's total on `owner`'s UTXOs. Forwards to
    /// `ICharmsLedger.balanceOf`. Wallets and routers read this.
    function balanceOf(address owner) external view returns (uint256);

    /// @notice Spend the caller's UTXOs and create one output for `to`. Calls
    /// `tokenTransfer`.
    function transfer(address to, uint256 amount) external returns (bool);

    /// @notice Remaining amount `spender` may move from `owner`. Stored on this token.
    /// Routers read this.
    function allowance(address owner, address spender) external view returns (uint256);

    /// @notice Let `spender` move up to `amount` of the caller's balance. The caller is
    /// the holder.
    function approve(address spender, uint256 amount) external returns (bool);

    /// @notice `spender` moves `amount` from `from` to `to`. This token decrements the
    /// allowance, then calls `tokenTransfer`.
    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool);

    /// @notice ERC-20 name. Published CHIP-0420 `name`, or `"Charm"` until then.
    /// Forwards to `ICharmsLedger.name`. A vault app has no clone.
    function name() external view returns (string memory);

    /// @notice ERC-20 symbol. CHIP-0420 `ticker`, or `"CHARM"` until published.
    /// Forwards to `ICharmsLedger.symbol`. A vault app has no clone.
    function symbol() external view returns (string memory);

    /// @notice Display decimals. The published value, or `0` until the first publish.
    /// Forwards to `ICharmsLedger.decimals`. Frozen after that publish.
    function decimals() external view returns (uint8);

    /// @notice ERC-7572 URI for this clone. Forwards to `ICharmsLedger.contractURI`.
    /// A `data:application/json` document built from the stored fields.
    function contractURI() external view returns (string memory);

    /// @notice EIP-2612. The holder signs an allowance off-chain. A router submits it and
    /// then calls `transferFrom`.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /// @notice Next EIP-2612 nonce for `owner`. The signing wallet reads this.
    function nonces(address owner) external view returns (uint256);

    /// @notice EIP-712 separator for `permit`. The domain name is the constant
    /// `"Charm"`, not the published display name. The signing wallet reads this.
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
```

For a non-vault tag-`t` app, `tokenAddress(app)` only computes the CREATE2 address. It does not deploy. `ensureToken(app)` deploys the clone when `extcodesize` at that address is 0, and returns the address. If the clone is already deployed, it returns the same address and does not revert. For a vault app, both return the underlying asset recorded on the first `wrap` (`address(0)` for ETH) and deploy nothing. `app.tag` must be `t`. Any other tag reverts. The caller of `ensureToken` pays for a non-vault deploy. A native spell does not. `_apply` and `tokenTransfer` do not deploy.

The salt is `appKey = keccak256(abi.encode(uint32 tag, bytes32 identity, bytes32 vk))`. The CREATE2 deployer is the Charms proxy, so an upgrade of Charms does not move non-vault token addresses. For those apps, `tokenAddress(app)` is that address before and after `ensureToken`. A vault app has no CREATE2 address.

The clone bytecode is clones-with-immutable-args (the wighawag scheme). `appData` is `abi.encodePacked(uint32 tag, bytes32 identity, bytes32 vk)`. `uint32 tag` is big-endian, so `appData` is 68 bytes. `extraLength` is `appData.length + 2`, which is 70 (`0x0046`): the `App` plus the trailing length. `runSize` is `55 + extraLength`, which is 125 (`0x007d`).

The creation code is 10 bytes and returns the runtime:

```text
hex"61007d3d81600a3d39f3"
```

The runtime is 55 bytes of forwarding logic, then `appData`, then `uint16(appData.length)` (`0x0044`):

```text
hex"3d3d3d3d363d3d376100466037363936610046013d73"
  ‖ charmTokenProxy
  ‖ hex"5af43d3d93803e603557fd5bf3"
  ‖ appData
  ‖ hex"0044"
```

`charmTokenProxy` is 20 bytes. It is the address of `CharmTokenProxy`, `CREATE` of the Charms proxy at nonce 1. The clone fallback copies caller calldata to memory, `CODECOPY`s `extraLength` bytes from runtime offset `0x37` onto the end of that copy, and `delegatecall`s `charmTokenProxy` with args length `calldatasize + extraLength`. The copied bytes are the 68-byte `App` and the trailing `uint16` length. `CharmTokenProxy` forwards that same calldata. The `CharmToken` implementation reads `appData` as the 68 bytes immediately before that `uint16` on `msg.data`. `charmTokenProxy` is fixed before the first clone and is part of this init code, so it is part of `tokenAddress`. The `CharmToken` implementation address is not in this init code. `tokenAddress = CREATE2(CharmsProxy, appKey, creation ‖ runtime)`. Replacing the implementation does not change `tokenAddress`.

### Upgrade

`tokenImplementation` and `metadataSigner` are immutables in the `Charms` bytecode. The constructor sets them. They are not proxy storage slots. A call through the proxy runs that bytecode, so both view functions return those immutables. They change when the admin upgrades to a new `Charms` implementation whose constructor received new arguments.

```solidity
address public immutable tokenImplementation;
address public immutable metadataSigner;

constructor(
    CharmsApply applier,
    address tokenImplementation_,
    address metadataSigner_
) {
    if (tokenImplementation_ == address(0)) revert();
    if (metadataSigner_ == address(0)) revert();
    APPLY = applier;
    SPELL_VERSION = applier.SPELL_VERSION();
    tokenImplementation = tokenImplementation_;
    metadataSigner = metadataSigner_;
    _disableInitializers();
}
```

The constructor reverts when `tokenImplementation_` or `metadataSigner_` is `address(0)`. `_disableInitializers()` runs on the implementation contract, so `initialize` cannot be called there.

Three creation codes form a cycle. The proxy creation code contains the address of the implementation it first calls. The `Charms` creation code contains the `CharmToken` address. The `CharmToken` creation code contains the proxy address. The proxy therefore cannot first point at that `Charms` implementation.

`CharmsInitializer` is the implementation the proxy calls first. Its creation code contains neither address. It inherits `CharmsStorage`, so `admin` is slot 9, the same slot `Charms` reads. Its constructor calls `_disableInitializers()`, so `initialize` on the `CharmsInitializer` contract reverts. `initialize(address admin)` stores `admin` and executes `new CharmTokenProxy()`. It does not take a metadata signer and it does not create a `CharmToken`. It implements UUPS `upgradeToAndCall` and the same `_authorizeUpgrade` checks as `Charms`. The OpenZeppelin initializer flag is a namespaced slot, not one of the sequential slots. The proxy constructor's `delegatecall` sets that flag on the proxy. `Charms` does not run `initialize`.

The deploy script CREATE2-deploys in this order. `deployer`, `admin`, and `metadataSigner` are deploy-time parameters. The CHIP does not name those accounts.

1. `CharmsInitializer` at `CREATE2(deployer, keccak256("charms-initializer"), type(CharmsInitializer).creationCode)`. Call this address `B`. That creation code has no constructor argument.
2. The proxy address is known before the proxy exists. `P = CREATE2(deployer, keccak256("charms-proxy-v1"), abi.encodePacked(type(CharmsProxy).creationCode, abi.encode(B, abi.encodeCall(CharmsInitializer.initialize, (admin)))))`. The proxy constructor writes `B` into the ERC-1967 slot and `delegatecall`s `initialize(admin)`.
3. `CharmToken` at `CREATE2(deployer, keccak256("charms-token"), abi.encodePacked(type(CharmToken).creationCode, abi.encode(ICharmsLedger(P))))`. Call this address `T`. `T` can be deployed before `P` exists. This implementation includes `contractURI`.
4. The stock Groth16 verifier, then `CharmsApply` at spell version 16 with `charms-lib`'s `SPELL_VK` and that verifier, then `Charms` with `constructor(applier, T, metadataSigner)`.
5. `CharmsProxy` at `P`. The constructor `delegatecall`s `CharmsInitializer.initialize(admin)`. That call stores `admin` at slot 9 and creates `CharmTokenProxy` as the proxy's first contract, nonce 1. The forwarder's `charms` immutable is `P`, because `msg.sender` in that constructor is the proxy.
6. The admin calls `upgradeToAndCall` on `P` with the `Charms` address and empty `data`. The script does not deploy per-app clones.

A plain `CREATE` of `CharmsInitializer` makes `B` depend on the deployer nonce. `B` is an argument of the proxy creation code, so `P` follows that nonce. The proxy salt stays `keccak256("charms-proxy-v1")`. `P` is `ETHEREUM_CHARMS`. It is the `address(Charms)` mixed into `ethTxId`, the vault identity, and `tokenAddress`. Replacing the `Charms` implementation does not change those ids.

`_authorizeUpgrade` runs on the current implementation, `CharmsInitializer` for the first upgrade and `Charms` after that. `msg.sender` must be the admin, and `address(this)` must be the proxy. The new implementation must return the same `proxiableUUID` (the ERC-1967 implementation slot). The check calls `tokenImplementation()` and `metadataSigner()` on the new implementation. `tokenImplementation()` must have code. `CharmToken(tokenImplementation()).charms()` must equal the proxy. `metadataSigner()` must not be `address(0)`. Empty `data` writes the ERC-1967 slot and returns. It does not `delegatecall` a method on the new implementation. The constructor already set the immutables.

A later `CharmToken` that adds or changes `contractURI` is deployed with `constructor(ICharmsLedger(P))`. A new `Charms` implementation is deployed with that address and a metadata signer. The admin calls `upgradeToAndCall`. The clone runtime still holds `CharmTokenProxy`, so the token address does not change. `SPELL_VK` changes only when that new `Charms` was built with a new `CharmsApply`.

A new spell version is carried by the new `Charms` code. The implementation accepts the spell versions it was built for, and it contains their `programVKey`s. A mutable version registry is not needed. A fix that preserves `SpellCodec` output and the `ethTxId` preimage does not need a guest rebuild. A fix that changes those bytes is a protocol bump, with a new `programVKey` compiled into the implementation.

### CharmToken upgrades

The per-app clones stay the clones-with-immutable-args proxies above. The runtime stays 125 bytes. That runtime is not the plain EIP-1167 proxy. EIP-1167 does not append the `App`. The 20 bytes inside the runtime are `CharmTokenProxy`.

`CharmTokenProxy` is a forwarder. The clone `delegatecall`s it, so `address(this)` in the forwarder is the clone, and `msg.sender` is the original caller. The forwarder does not read storage. It calls `Charms.tokenImplementation()` and `delegatecall`s the address that call returns, with the calldata it received, including the appended `App`.

```solidity
contract CharmTokenProxy {
    ICharms public immutable charms;

    constructor() {
        charms = ICharms(msg.sender);
    }

    fallback() external {
        address impl = charms.tokenImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(
                gas(), impl, 0, calldatasize(), 0, 0
            )
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

`charms` is an immutable in the forwarder's bytecode. `initialize` creates the forwarder with `new CharmTokenProxy()`, so that immutable is the Charms proxy. An immutable is code, and `delegatecall` runs that code, so the forwarder still sees the proxy address while it executes inside the clone.

A storage read in the forwarder would not see the forwarder's storage. The clone's `delegatecall` makes `SLOAD` and `SSTORE` use the clone. A UUPS proxy in the middle would read the ERC-1967 implementation slot and would write it from `upgradeTo`. Both opcodes hit the clone. `initialize` does not write that slot on the clone, so the read is zero. `upgradeTo` on one token would store an implementation only on that token. The forwarder has no `upgradeTo` and does not read an ERC-1967 slot. The implementation address is an immutable in the `Charms` bytecode. The forwarder's external call runs `tokenImplementation` on the proxy. The proxy `delegatecall`s `Charms`, and that function returns the immutable. The load is from the implementation code, not from a proxy slot.

`CharmToken` behavior stays the behavior already specified for allowances, permit nonces, and the ledger calls. Execution is still a `delegatecall` whose `address(this)` is the clone, so those slots stay on the clone. `Transfer` and `Approval` are logged on the clone.

Each token call pays for one extra `CALL` and one extra `DELEGATECALL`. The clone still `delegatecall`s once, and that target is `CharmTokenProxy`. The forwarder then `CALL`s `tokenImplementation()` and `delegatecall`s the current implementation. This is an opcode-price estimate from EIP-2929, not a measured transaction. A zero-value `CALL` or `DELEGATECALL` costs the account-access price of its target, 2600 gas when that account is cold and 100 gas when it is warm, plus memory expansion. Unused gas returned by the callee is not an extra cost. The lookup can make a later call from the implementation into the Charms proxy warm. The implementation account is cold on the first token call of a transaction. Cold and warm access change the total, so these prices stay unadded.

`tokenImplementation()` does not check `msg.sender`. The forwarder's call comes from the clone.

The `CharmToken` implementation takes the predicted proxy address in its constructor.

```solidity
constructor(ICharmsLedger charms_) {
    charms = charms_;
}
```

The deploy script passes `ICharmsLedger(P)`. `initialize` does not create this contract. A replacement is deployed the same way, from any account, with the same proxy address. `upgradeToAndCall` accepts the `Charms` implementation that names it, when `charms()` equals the proxy. The upgrade stores nothing about the token. The new bytecode carries the address.

Clone storage, under that second `delegatecall`:

| Slot | Variable | Type |
|---|---|---|
| 0 | `allowance` | `mapping(address => mapping(address => uint256))` |
| 1 | `nonces` | `mapping(address => uint256)` |

`charms` on the implementation is an immutable in that implementation's bytecode. It is not a clone slot. A new implementation keeps `allowance` at slot 0 and `nonces` at slot 1. It does not reorder them, insert a variable ahead of them, or retype them. A new variable appends at slot 2 or after. It still reads the `App` from the last 70 bytes of calldata. It does not read or write an ERC-1967 slot.

`CharmTokenProxy` is not upgraded. Replacing it would change the address in every clone and would change every `tokenAddress`.

## State

`_apply` is the only writer of UTXO, supply, balance, and vault state. `setMetadata` is the only writer of `meta`. `upgradeToAndCall` writes the ERC-1967 implementation slot. `initialize` writes `admin` once and creates `CharmTokenProxy`. `tokenImplementation` and `metadataSigner` are not storage. Each `Charms` constructor writes them into that implementation's bytecode. The charm-token maps are supply, per-owner balance, and the per-owner UTXO index. Spend-by-id needs one more record, because a spell names UTXOs and a multi-charm UTXO sits in more than one per-app list. Empty UTXOs have no app, so they cannot live in `address → app → UTXOs`.

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
| `admin` | one address | `address` | Set once by `initialize`. The only account that may call `upgradeToAndCall`. Slot 9. |
| `vaultTokens` | vault `appKey` | `address` | Underlying token recorded on the first `wrap`. Slot 10. |
| `meta` | `appKey` | version, decimals, strings, image hash | CHIP-0420 display fields. Version 0 means unpublished. Slot 11. |

`utxoKey = keccak256(abi.encodePacked(ethTxId, uint32 index))` is internal. It is not the `UtxoId`.

Those variables live in the proxy's storage, because every call delegatecalls. The ERC-1967 implementation slot is `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`, above the sequential layout, so it does not collide with `supply` or `head`. Sequential slots follow declaration order in `CharmsStorage`. `supply` is slot 0. `beamSources` is slot 7. `admin` is slot 9. `vaultTokens` is slot 10. `meta` is slot 11. The gap becomes `uint256[49]` and still ends at slot 60. Slots 12 through 60 inclusive are those 49 words. The next variable appends at slot 12. `tokenImplementation` and `metadataSigner` are immutables in the `Charms` bytecode and have no row in this table. An upgrade must not reorder, insert ahead of, or retype an existing variable. `beamSources` stays at slot 7. The proxy bytecode itself is not upgraded.

Kind is one function of the output's charms:

| Charms on the output | Kind | Stored |
|---|---|---|
| none | Empty | `head` only, plus `emptyUtxos[owner]` |
| one charm, tag `t`, no pin | Plain | amount in `head`. The deque slot names the app. |
| anything else | Bundle | `body` holds the charm map and pins. Listed in `utxos` for each `t` app it contains. |

`utxo(UtxoRef)` returns `(owner, body)` only. Kind and the Plain amount stay in `head`; they are not on that return. `body` is empty unless the UTXO is a Bundle. A missing or spent id has no `head` and returns `owner == address(0)` with an empty `body`. An owned Empty UTXO and an unpinned Plain token are not distinguishable from that return.

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

`ethTxId` is fixed once the spell CBOR, the caller, the salt, the chain id, and the proxy address are fixed. That is before the Ethereum transaction is mined. Signers hash that preimage locally. `Transaction.txId` in the log is the same `ethTxId`, published when the transaction is mined. The source chain puts the beam hash of that id into `beamed_outs`. `transact` recomputes the id and checks EIP-712 `Spend` signatures against it.

`Spend` uses its own EIP-712 domain. It is not the token's `permit` domain, and `CharmToken.DOMAIN_SEPARATOR` is only for `permit`.

| Field | Value |
|---|---|
| `name` | `"Charms"` |
| `version` | `"1"` |
| `chainId` | `block.chainid` |
| `verifyingContract` | the Charms proxy |

The type is `Spend(bytes32 txId)`. `txId` is `ethTxId`, the `keccak256` digest of the id preimage, the same `bytes32` `transact` returns and `Transaction` logs. It is not `TxId.0`. `TxId.0` is `reverse(ethTxId)`. That reversed form is the first 32 bytes of `UtxoId::to_bytes`, which the beam hash uses.

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

`spellCbor` is `util::write(&NormalizedSpell)` in the committed form above. Two consumers use it, and they do not hash the same preimage.

- The id preimage is `ASCII "charms/ethereum/tx/v1" ‖ chainid as uint256 BE ‖ proxy (20 bytes) ‖ anchor (32 bytes) ‖ spellCbor`. `ethTxId = keccak256` of that preimage.
- Proof public values are `to_serialized_pv` for v15 and later: CBOR of `([u8; 32] programVKey, NormalizedSpell)`, which is `0x82 ‖ encode([u8; 32] of programVKey) ‖ spellCbor`. `encode([u8; 32])` is the 32-uint array (`0x98 0x20`, then each byte). The Groth16 verifier commits to those public-value bytes. It does not commit to the id prefix.

Golden vectors from `charms_data::util::write` check `spellCbor` and `to_serialized_pv`. They do not include the id-preimage prefix. A separate vector checks `keccak256` of that prefix concatenated with `spellCbor`. A vault-identity vector checks SHA-256 of `"charms/ethereum/vault/v1" ‖ chainId_be_u256 ‖ Charms_20 ‖ token_20`, with no scale byte.

Limits, so a spell cannot be a gas bomb: at most 64 inputs, 64 outputs, 64 apps, and 96 KiB of public values.

## transact

```
_apply(spell, anchor, proof, signatures, vaultDelta):
    require this implementation accepts spell.version
    require canonical shape, counts, and owner == 0 iff beamed
    if ins is empty:
        require the anchor is unused, and the spell is a placeholder or a wrap
    for each ref: require it is live
    for each input: require it is live and the opening matches head/body
    cbor = SpellCodec.encode(...)
    txId = keccak256(tag ‖ chainid ‖ this ‖ anchor ‖ cbor)
    require every input owner is msg.sender or signed Spend(txId)
    if native(spell, openings, vaultDelta): require proof is empty
    else: require ins is non-empty, blobs are well-formed, and the verifier accepts
    if beamedOuts is non-empty: require this build is beaming-capable (v16+)
    write outputs, delete inputs, update supply, balance, deques, vault, pins
    if ins is empty: mark the anchor used
    emit Transaction(txId, anchor, cbor)
    unless this apply is a facade transfer or transferFrom:
        for each non-vault tag-t app whose plain balance changed:
            token = CREATE2 CharmToken address
            if extcodesize(token) == 0: skip emitTransfer
            else:
                for each owner whose balance fell: emitTransfer(owner, Charms, decrease)
                for each owner whose balance rose: emitTransfer(Charms, owner, increase)
    a facade transfer emits Transfer(from, to, amount), including a self-transfer
    a vault app emits no CharmToken Transfer and does not call the underlying token
```

`native` is the guest's simple-transfer path (`is_correct` with no app binaries), plus what this contract can see:

1. Every app is tag `t` or `n`. Every public input is null. No refs. No scrolls. No beam-in. A beam-in is an input whose stored charms are empty (or itself beamed) while the outputs gain charms; the contract has no `tx_ins_beamed_source_utxos` of its own, so it cannot justify that increase.
2. For each `t` app, the `u64` sum of inputs equals the sum of outputs. Beamed outputs count. Sums use checked arithmetic.
3. For each `n` app, the multiset of data bytes is unchanged.
4. Pins do not change. `versionedApps` equals the pins on the inputs and nothing else. The spell has one `versioned_apps` entry per vk, not one per output. On each new output, store the subset of those entries whose vk is the vk of an app on that output. An app with no `versioned_apps` entry stores no pin. A multi-app UTXO stores one pin per versioned vk it carries, in `body`, and no pins for apps it does not carry. A single tag-`t` charm with no pin is Plain and leaves `body` empty. The same charm with a pin is a Bundle, and `body` holds that pin. `tokenTransfer` reverts with `MixedVersions` when the selected inputs do not all store the same pin for that app's vk. A native spell copies that shared pin into its one `versioned_apps` entry. A proved spell may change the version only when the new wasm runs, which is the guest's `authorize_version_changes` rule.
5. `vaultDelta` is 0, except when `_apply` was entered from `wrap` or `unwrap`. Then the vault app's output sum may differ from its input sum by exactly that delta, and no other app's sum may change.
6. Zero inputs are allowed only for a placeholder (every output empty) or for `wrap`.

A spell the native rules accept must carry an empty proof (`ProofNotRequired`). Any other spell must carry a proof (`ProofRequired`). There are not two ways to apply one spell.

A balanced beam-out is native: the beamed output counts in the token sum, and the proof is empty. A beam-in is not native, because the placeholder input is empty and the outputs gain charms, so it carries a proof. A version-15 implementation with a zero verifier is not beaming-capable. It rejects any spell with `beamedOuts`, and it rejects proofs. The deployed version-16 implementation is beaming-capable. A non-empty `beamedOuts` on that implementation does not by itself require Groth16.

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
- the owner signed EIP-712 `Spend(bytes32 txId)` under the Charms domain above (ECDSA or ERC-1271 via `staticcall`), with `txId` equal to `ethTxId`, or
- `msg.sender` is the CREATE2 token for this app, the spell is native, every input is a UTXO of `from`, any other `t`/`n` charm on those inputs is copied onto a change output owned by `from` (including when this token's remainder is zero), and no custom-tag charm is touched.

`txId` commits to every input, output, owner, and beam hash. That is the Ethereum analogue of `SIGHASH_ALL`.

A proved spell must spend at least one input. The proof does not commit to the anchor, so a zero-input proved spell could be replayed under a fresh salt. Bitcoin and Cardano transactions have an input. `hosting_chain_is_bitcoin` looks at the creator of `ins[0]`; an empty input list would make that undefined. The host rejects a proved record whose effective anchor is not zero. `transact` writes `bytes32(0)` when `ins` is non-empty, and a different anchor would be a different `ethTxId` for the same proof.

`tokenTransfer` builds the native spell. Inputs come off the front of `utxos[from][app]`. The recipient output is `{app: amount}` to `to`. When the selected inputs still hold any other `t` or `n` charm, or this token's remainder is nonzero, one more output goes to `from`. That output carries the remainder of this token when the remainder is nonzero, plus every other `t` or `n` charm from the inputs. A zero remainder of this token is not written on it (`ensure_no_zero_amounts`). The change output is omitted only when the selected inputs contain nothing except the transferred amount of this token. The contract then runs `_apply` and checks the result is native. A bug in the token cannot move a charm the rules would refuse.

Idempotency is the EVM's. The call reverts or it is mined once. Submitting it again reverts with `InputSpent` or `AnchorUsed`. `wrap`'s token pull and `unwrap`'s token push are inside the same call. A revert undoes both. Re-proving a spell off-chain yields the same id, because the proof bytes are not in the preimage.

Reentrancy: one lock around `transact`, `wrap`, `unwrap`, and `tokenTransfer`. ERC-1271 is a `staticcall` during checks. `unwrap` sends the underlying last, after supply and `locked` have moved. `receive()` reverts, so stray ETH cannot land in the contract.

## Balances and bundles

`balanceOf`, `transfer`, and `transferFrom` exist only on a tag-`t` `CharmToken`. `balanceOf(owner)` is the total of that token on the owner's unspent, non-beamed UTXOs, including UTXOs that also carry other charms. An NFT, a Scroll, a custom-tag charm, and an empty UTXO are not ERC-20s. They stay UTXOs in `Charms`. The caller moves them with `transact`. `totalSupply` is the same sum over all owners. Both are caches written in `_apply` from the same `u64` values written into `head` and `body`. The UTXO records are the source. A view that recomputes the sum from `utxos[owner]` exists for the invariant tests.

`transfer(balanceOf)` is not always possible in one call. A UTXO that carries a custom-tag charm (anything other than `t` or `n`) cannot move in a native spell, because `is_simple_transfer` is false for those tags even when the data is copied unchanged. Those units stay inside `balanceOf`. `transfer` skips those UTXOs. If the requested amount is larger than the sum of the UTXOs it is allowed to select, it reverts with `RequiresProvedSpell` when the shortfall sits on custom-tag bundles, and with `InsufficientBalance` otherwise. The owner spends the bundle with `transact` and a proof, or splits the token off the bundle that way first.

UTXOs that mix several `t` charms, or `t` with `n`, are selectable. The sender-owned change output carries the other charms back, including when this token's remainder is zero, which is a simple transfer. NFTs are not dropped and are not sent to the recipient unless the whole UTXO's charms are exactly the transferred token.

Partial spends do not exist. The input UTXO is spent whole. Every charm not placed on the recipient output is a new output, even when the transferred token's own remainder is zero. That is the Charms rule, and it is the ERC-20 implementation.

Zero is not a charm amount (`ensure_no_zero_amounts`). `transfer(to, 0)` emits an ERC-20 `Transfer` and creates no UTXO. There is no Bitcoin dust limit. A zero remainder of the transferred token is not written on the change output. That output is still required when any other charm remains, and it is omitted only when the selected inputs contain nothing except the transferred amount of this token. `to` of `address(0)` or of `Charms` reverts. An amount above `type(uint64).max` reverts.

For each non-vault tag-`t` app whose plain balance changed in a spell (`transact` or any other `_apply` that is not a facade `transfer` or `transferFrom`), set `token` to that app's CREATE2 address. If `extcodesize(token) == 0`, skip `emitTransfer` and do not deploy. If code is present, emit through that clone with the Charms proxy as the counterparty. Each owner whose plain balance decreased emits `Transfer(owner, Charms, decrease)`. Each owner whose plain balance increased emits `Transfer(Charms, owner, increase)`. Senders are emitted first, then receivers. Owners are not paired with each other, so a spell does not emit `Transfer(Alice, Carol)`. This replaces `Transfer(from, 0)` and `Transfer(0, to)` on the spell path. The hub is the Charms proxy. A facade `transfer` or `transferFrom` emits one `Transfer(from, to, amount)`, including a transfer to the holder and a zero amount, and does not use the hub. A vault app has no clone, so `_apply` does not emit a `CharmToken` `Transfer` for it and does not call the underlying token. Supply on Ethereum changes in mint and burn cases whether or not a non-vault clone exists. Indexers read the `Transaction` log for a vault charm and for a charm whose clone is not deployed yet.

## Vault

Locking an ERC-20 or ETH mints a tag-`t` charm. Burning that charm unlocks the underlying. The policy lives in `Charms`, because the contract is the thing that holds the tokens. An app wasm cannot see an ERC-20 transfer, and a wasm that allowed a mint would allow it on Bitcoin too.

One underlying asset has one vault charm. The asset is the pair `(chain, Charms proxy, token)`.

```
VAULT_VK     = SHA-256("charms/ethereum/vault/v1")
identity     = SHA-256(
                 "charms/ethereum/vault/v1"
                 ‖ chainId_be_u256
                 ‖ Charms_20
                 ‖ token_20)
app          = t / identity / VAULT_VK
```

`token_20` is 20 zero bytes for ETH. That is the sentinel `tokenAddress` and `ensureToken` return for the ETH vault. `scale` is not in that preimage. `appKey = keccak256(abi.encode(uint32 tag, bytes32 identity, bytes32 vk))` therefore does not include `scale`. A different scale cannot mint a second `App` for the same token. There is no `CharmToken` for this app. The ERC-20 face is `token` itself: the underlying contract, or `address(0)` for ETH. The first `wrap` stores `token` under `appKey`. Until that record exists, `tokenAddress` and `ensureToken` revert, because the identity hash does not yield the address, and they deploy nothing.

`wrap` and `unwrap` derive `scale`. The caller does not pass it. ETH is fixed: 18 decimals, so `scale = 10` and one charm unit is 10^10 wei. For an ERC-20, `scale = 0` when the token has no `decimals()` or `decimals <= 8`. Otherwise `scale = decimals - 8`. The contract stores that value on `vaults[token]` at the first `wrap` and uses it on every later `wrap` and `unwrap`. A later `decimals()` that would derive a different `scale` reverts. Charm amounts are `u64` because `sum_token_amount` is `u64`. Eight decimal digits keeps a single output under that cap for any supply this protocol can represent. Sub-unit dust of an 18-decimal token cannot be wrapped and is not rounded.

`VAULT_VK` is the hash of a 24-byte string. That string is not wasm and not a BIP-340 key. No guest can run a contract for it or turn it into a versioned app. On Bitcoin and Cardano the vault charm is transfer-only and beam-only. Minting or burning it there is not a simple transfer and there is no binary that can authorize it.

`wrap` measures the balance the contract actually received (`balanceAfter - balanceBefore`, or `msg.value` for ETH) and requires it to equal `amount * 10^scale`. Fee-on-transfer tokens revert. Rebasing tokens are unsupported. It then applies a zero-input spell whose only output is `{vaultApp: amount}` to `owner`, with that `vaultDelta`, and adds the underlying amount to `locked`.

`unwrap` selects the caller's UTXOs of the vault app the same way `tokenTransfer` does, applies a spell whose outputs are the optional change, with a negative `vaultDelta`, subtracts from `locked`, and only then sends `amount * 10^scale` of the underlying. It does not read the recipient's balance. A token that takes its fee out of the amount sent delivers less than that amount; the unwrap still completes, and the recipient accepts the shortfall. The contract's balance drops by the amount it sent, so `locked` still matches what the contract holds, and other holders are unaffected. A fee charged on top of that amount is unsupported. The vault normally holds exactly `locked`, so the extra debit reverts the transfer. Surplus, including another holder's collateral, can let that transfer succeed and leave the contract holding less than `locked`. The next apply that touches the vault then fails `_checkVaults`. A recipient that reverts undoes the burn.

Invariants, checked on every apply that touches the vault app:

- `locked` equals `10^scale` times (wrapped minus unwrapped). That counts charm units on every chain, not only Ethereum.
- `underlying.balanceOf(Charms) >= locked` (for ETH, the contract's balance).
- `supply[vaultApp] * 10^scale <= locked`. A beam-in cannot mint more of the vault charm on Ethereum than the collateral that is still here. A forged Bitcoin finality proof can steal collateral, but only up to the vault units currently living outside Ethereum.

`wrap` and `unwrap` are not a back door on `transact`. External `transact` always passes `vaultDelta = 0`. A proved spell may carry the vault app only when the guest sees a simple transfer, which is the beam and the ordinary move. The v16 guest additionally rejects a simple-transfer spell whose public inputs are not all null, so a beam claim cannot smuggle an unlock instruction in `app_public_inputs`. Solidity never reads `app_public_inputs` to decide a transfer of the underlying.

## Token metadata

A non-vault tag-`t` charm is an ERC-20. Its display fields are the CHIP-0420 fields. `symbol` is that CHIP's `ticker`. The Charms proxy stores the record. The clone does not. `name`, `symbol`, `decimals`, and `contractURI` on the clone read the proxy by `appKey`.

`contractURI` is a method on the `CharmToken` implementation. The first implementation is the `CharmToken` deployed with `constructor(ICharmsLedger(P))`, and it includes `contractURI`. A later implementation that adds or changes `contractURI` is named by a new `Charms` constructor, then installed with `upgradeToAndCall`. `initialize` creates `CharmTokenProxy` as the proxy's first contract. Clones bake that forwarder, so `tokenAddress` does not change.

### What is stored

`meta[appKey]` holds one record. Lengths below are UTF-8 byte lengths. Storage order is `version` and `decimals` packed in one slot, then `imageHash`, then `name`, `symbol`, `description`, `url`, and `image`. The calldata struct `Metadata` does not include `version`.

| Field | CHIP-0420 | Rule |
|---|---|---|
| `name` | `name` | 0 to 64 bytes. Empty means `name()` returns `Charm`. |
| `symbol` | `ticker` | 1 to 32 bytes. Required on every accepted call. |
| `decimals` | `decimals` | A `uint8`. The first accepted call freezes it. |
| `description` | `description` | 0 to 256 bytes. |
| `url` | `url` | 0 to 128 bytes. |
| `image` | `image` | A URI. The contract does not store image bytes. |
| `imageHash` | `image_hash` | SHA-256 of a remote image, or zero. |
| `version` | none | A `uint64`. Zero means the app is unpublished. |

Until the first accepted `setMetadata`, `name()` returns `Charm`, `symbol()` returns `CHARM`, and `decimals()` returns `0`.

`image` is empty, a remote URI, or a tiny SVG.

- An empty image requires `imageHash` to be zero.
- A remote image starts with `https://`, `ipfs://`, or `ar://`, is at most 128 bytes, and requires a nonzero `imageHash`.
- An SVG starts with `data:image/svg+xml`, is at most 256 bytes, and requires `imageHash` to be zero.

CHIP-0420 asks that a remote image be `image/png`, `image/jpeg`, or `image/svg+xml`. The contract does not fetch the URI, so it does not check that media type.

A nonempty `url` starts with `https://`, `ipfs://`, `ar://`, or `data:`. The contract does not fetch either URI.

`setMetadata` reverts when `app.tag` is not `t` or when `app.vk` is `VAULT_VK`. A vault has no clone. Wallets keep the underlying token's `name`, `symbol`, `decimals`, and icon. ETH has no ERC-20 metadata here.

### Signing

Anyone may submit `setMetadata`. The contract accepts it only when `ecrecover` of the digest below equals `metadataSigner()`.

`metadataSigner` is one secp256k1 address, an immutable set by the `Charms` constructor, and never the zero address. It is not a proxy slot. Replacing it is a new `Charms` implementation and `upgradeToAndCall`. The key is the ICP threshold ECDSA key from `sign_with_ecdsa`, key name `key_1`, derivation path `["scrolls", "metadata"]`. That key is separate from `ETHEREUM_FINALITY_VKEY`. The Ethereum address of the key is fixed when `charms_metadata` is created. The contract checks the signature, the version, and the decimals rule.

`charms_metadata` holds that key. `sign_metadata` takes a tag-`t` app and one Bitcoin transaction. It rejects every other tag and every other chain. For `{tag: t, identity, vk}` the metadata charm is `{tag: n, identity, vk}`, with the same identity and the same vk. That pair is the CHIP-0420 reference NFT. The transaction must be final under its proof, and exactly one output must carry that charm. The canister checks only the transaction passed into the call. It does not read earlier transactions, and it does not follow a `ref` field. Charms does not read or store an NFT UTXO.

The charm data is the metadata. `ticker` maps to `symbol`. The other CHIP-0420 names are the names in the table above. `metadataHash` is `_metadataHash` below. The canister signs `_metadataDigest`. There is no EIP-191 prefix. `sign_with_ecdsa` returns `r || s`. The method returns the metadata charm, the version, and 65 bytes, `r || s || v`, with `v` equal to 27 or 28. `ecrecover` of `_metadataDigest` and that signature is the Ethereum address of the canister public key. The caller attaches the cycle cost of `sign_with_ecdsa`.

`version` is the `time` field of the Bitcoin block header that contains the transaction, as a `uint64`. `setMetadata` takes that `version` because `ecrecover` returns an address and the caller rebuilds the digest. The caller passes the version `sign_metadata` returned. A different version fails the signature check.

A Bitcoin header has no height. The merkle block in the finality proof lists transaction ids. `proven_final` checks that the metadata transaction is in the block, that every header meets the target in its own `nBits`, and that the sum of that work reaches the finality target. A header that misses its target rejects the proof. The proof does not include the coinbase, and BIP34 writes the height in the coinbase. The canister reads `time` from the block that contains the transaction.

A private chain that actually mines the finality work can still put any timestamp in that block. That is the same work bound as a forged Bitcoin beam. The canister does not keep a Bitcoin checkpoint.

Two transactions in one block share that timestamp. Bitcoin requires the timestamp to be greater than the median of the previous 11 blocks. A later block can carry an earlier timestamp. `version` must be strictly greater than the stored version. The stored version starts at 0. The canister rejects a block time of 0, so the first accepted version is at least 1. A gap is allowed. An equal version reverts even when the hash matches, so a mined call cannot be replayed. A call that was not mined can be submitted again at that same version. A later update whose block time is not greater than the stored version reverts, and the stored record stays.

```solidity
bytes32 constant METADATA_TYPEHASH = keccak256(
    "CharmsMetadata(bytes32 appKey,uint64 version,bytes32 metadataHash)"
);

function _metadataHash(Metadata calldata m)
    internal
    pure
    returns (bytes32)
{
    return keccak256(abi.encode(
        m.name,
        m.symbol,
        m.decimals,
        m.description,
        m.url,
        m.image,
        m.imageHash
    ));
}

function _metadataDigest(
    bytes32 appKey,
    uint64 version,
    bytes32 metadataHash
) internal pure returns (bytes32) {
    return keccak256(abi.encode(
        METADATA_TYPEHASH,
        appKey,
        version,
        metadataHash
    ));
}
```

`appKey` is `keccak256(abi.encode(uint32 tag, bytes32 identity, bytes32 vk))`, the same key `tokenAddress` uses.

The first accepted call stores `decimals` and freezes it. A later call with a different `decimals` reverts and leaves the stored record as it was. `name`, `symbol`, `description`, `url`, `image`, and `imageHash` may change on a higher version.

`setMetadata` does not deploy a clone. `ensureToken` does not take a signature. Call `setMetadata` before `ensureToken` when the clone should not appear under the defaults.

### Events and the clone

Every accepted `setMetadata` emits `MetadataSet(appKey, version, metadataHash)` from the proxy.

`ContractURIUpdated()` has no arguments. The clone emits it. The clone's address is the ERC-20 address. When `setMetadata` succeeds and the clone's code size is nonzero, the proxy calls `emitContractURIUpdated` on that clone. The clone requires `msg.sender` to be the proxy, then emits `ContractURIUpdated`. When the clone is not deployed, the proxy skips that call.

When `ensureToken` deploys a clone and the stored version is already nonzero, it calls `emitContractURIUpdated` on the new clone in that transaction. When the app is still unpublished, `ensureToken` does not emit `ContractURIUpdated`.

`DOMAIN_SEPARATOR` hashes the constant name `Charm` and the constant version `1`. It does not hash the published display name. A later rename does not invalidate `permit`.

### contractURI

The clone implements ERC-7572 `contractURI()` and forwards to the proxy. The return value is a `data:application/json` URI. The JSON is UTF-8. The URI is the prefix `data:application/json,` followed by that JSON percent-encoded under RFC 3986, leaving only unreserved bytes unescaped.

The keys are `name`, `symbol`, and `decimals`, then `description`, `image`, and `external_link` when the stored string is nonempty. `name`, `symbol`, and `decimals` match the ERC-20 methods, including the defaults before publication. `external_link` is the stored `url`. `decimals` is a JSON number.

```json
{
  "name": "Example",
  "symbol": "EX",
  "decimals": 8,
  "description": "One fungible charm.",
  "image": "ipfs://bafyexample",
  "external_link": "https://example.com"
}
```

Charms does not implement ERC-1046 `tokenURI()`. That method would describe one unit. A fungible charm has one document, and `contractURI()` returns it.

### Icons outside the token

ERC-20 defines no logo method. Wallets that do not call `contractURI` still need an icon.

The Charms token list uses the tokenlists.org schema. Chain id 1 is published at `https://charms.dev/tokens/ethereum.json`. Another chain id is published at `https://charms.dev/tokens/<chainId>.json`. An off-chain generator rebuilds each file from `MetadataSet` logs. An app is listed only after both of these are true: `setMetadata` has been accepted, and `ensureToken` has deployed the clone. An unpublished clone is not on the list. Its `name`, `symbol`, and `decimals` still return the defaults. `name`, `symbol`, and `decimals` on the list are the published values. `logoURI` is the stored `image` when the image is nonempty, and the field is omitted when the image is empty.

A dapp adds the token with EIP-747 `wallet_watchAsset`. `address` is the clone. `symbol`, `decimals`, and `image` are the published fields. Omit `image` when the stored image is empty.

```javascript
ethereum.request({
  method: "wallet_watchAsset",
  params: {
    type: "ERC20",
    options: {
      address: token,
      symbol: symbol,
      decimals: decimals,
      image: image
    }
  }
});
```

CoinGecko and the Trust Wallet asset list are manual submissions for a major token. The submission uses the clone address and the published symbol, decimals, and image. The contract does not call either directory.

### Gas

The figures below add opcode prices. They are not measured transaction costs. A zero-to-nonzero `SSTORE` is 20000 gas. `ecrecover` is 3000 gas. The record occupies seven slots when every string is at most 31 bytes. One slot packs `version` and `decimals`, one holds `imageHash`, and five hold the strings. That first call is 7 times 20000 gas plus 3000 gas, and then the log and the calldata. A 256-byte `description` adds eight slots. A 256-byte SVG adds eight more. Those sixteen slots add 16 times 20000 gas. A later rewrite of one short string is one dirty `SSTORE` at 2900 gas, plus `ecrecover` and the log. `ContractURIUpdated` adds one external call from the proxy to the clone.

### Trust and edge cases

The signer freezes `decimals` on the first accepted call and can change `name`, `symbol`, `description`, `url`, and `image` later. A stolen metadata key can change the ticker and the icon wallets show. It cannot move balances, change allowances, or sign beam finality.

Two signatures at the same version are ordered by inclusion. The first mined call is stored. The second reverts. A higher version mined first rejects every lower version after it. One signer means both payloads came from that key.

When no call has been accepted, the defaults remain. When the off-chain source is burned or otherwise gone, the last accepted record remains. The contract has no delete. A later version can change the mutable fields and cannot change `decimals`.

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

**Out of Ethereum.** The Ethereum spell lists `beamed_outs`. Token sums still balance, so the spell is native unless some other app makes it non-simple. Beamed outputs have no owner and create no UTXO. `beamSourceAt[ethTxId] = block.number`. After that execution block is beacon-finalized, `scrolls_ethereum` attests the id. The destination spell's prev tx is the same `EthereumTx` with `signature` set. The guest checks that signature in `proven_final` and then runs the same beam checks it runs for Bitcoin and Cardano.

The guest does not grow a beacon light client. `signature` is an optional 64-byte field on the record. It is omitted when absent, so an envelope written before the field still decodes. A nested `{ tx, signature }` variant does not, because this CBOR decoder cannot retry an untagged enum. `proven_final` is still one Ed25519 check. It is false when `signature` is absent, when `ETHEREUM_FINALITY` is unset, or when the signature does not verify.

`scrolls_ethereum` is a new canister under `scrolls/`. It is not blackholed. It has one controller, chosen at deploy and not named here. `scrolls_bitcoin` and `scrolls_cardano` stay blackholed. This canister is the exception because a beacon fork can change a generalized index or the execution payload's SSZ layout, and the verifier has to change with it. A wasm upgrade keeps the canister id. `sign_with_schnorr` with key `key_1` and derivation path `["scrolls", "ethereum", "finality"]` keeps the same public key, so `ETHEREUM_FINALITY_VKEY` does not change. A new canister at each fork would be a new id, a new key, and another guest build. That is rejected.

```candid
type StorageProofArg = record {
  key : blob;
  proof : vec blob;
};
type CertifyProofs = record {
  updates : vec blob;
  finality : blob;
  account_proof : vec blob;
  storage_proofs : vec StorageProofArg;
};
type DeployConfig = record {
  beacon_api : text;
  execution_api : text;
  charms : blob;
  implementation : blob;
  proxy_code_hash : blob;
  beam_source_slot : nat64;
  ws_period_epochs : nat64;
};

service : (DeployConfig) -> {
  certify_final : (blob, opt CertifyProofs) ->
    (variant { Ok : blob; Err : text });
  finality_public_key : () -> (blob) query;
  finality_status : () -> (record {
    finalized_slot : nat64;
    finalized_epoch : nat64;
    current_period : nat64;
    implementation : blob;
  }) query;
  reset_checkpoint : (blob) -> (variant { Ok; Err : text });
  set_ws_period : (nat64) -> (variant { Ok; Err : text });
}
```

`updates` and `finality` are Electra SSZ. A caller passes those bytes raw. A fetched beacon response is a sequence of chunks: a little-endian length, a 4-byte fork digest, and the SSZ payload. The canister strips that framing and then runs the same checks. `updates` holds at most one `LightClientUpdate`. `account_proof` is the Merkle-Patricia nodes for the Charms proxy. Each storage proof opens one slot. `finality_public_key` is the query. Cardano's Rust constant for the same kind of key is `FINALITY_VKEY`. The canister method keeps its own name. `reset_checkpoint` and `set_ws_period` accept a call only from the controller.

`DeployConfig` is the install argument. `beacon_api` and `execution_api` are https URLs with no userinfo. `charms` and `implementation` are 20 bytes. `proxy_code_hash` is 32 bytes. `ws_period_epochs` is non-zero. The upgrade argument is `opt DeployConfig`. `null` keeps the stored config. A record replaces it, which is how a new implementation and a new `beamSourceAt` slot are recorded. v1 stores `beamSources` at slot 7.

### The light-client store

The canister stores a trusted bootstrap checkpoint, the current sync committee, the next sync committee, and the latest verified finalized beacon header with its execution payload header. The execution payload header is where the execution `state_root` and the execution block number come from.

A sync-committee period is 256 epochs. An epoch is 32 slots of 12 seconds, so a period is 98,304 seconds (27.3 hours). The canister verifies at most one `LightClientUpdate` in a message. The stored period is the period of the latest verified finalized header.

The daily timer does not request that stored period on every tick. An update for period P names the committee for period P+1, and its finalized header stays in period P. In `helios-consensus-core` 0.11.1, `apply_update_no_quorum_check` rotates the current committee only when the update's finalized header is in the next period. Fetching period P again never supplies that header, so the store would sit on P until the weak-subjectivity window expired.

When `next_sync_committee` is missing, the timer fetches `GET /eth/v1/beacon/light_client/updates?start_period=<stored period>&count=1` with `Accept: application/octet-stream`. Applying that update records the next committee and does not rotate. When the next committee is already stored, the timer fetches `start_period` equal to the stored period plus one. The next committee signs that object. The canister applies it when its finalized header is in that next period, which rotates the current committee and stores the committee after that. If the beacon API has no such update yet, the tick leaves the store unchanged.

A tick applies at most one update. After several missed periods, each later tick that finds a finalized header in the next period advances one period. `certify_final` uses this same choice when it fetches an update.

Those responses are untrusted input. The canister verifies them. The beacon API is not a source of truth.

The current slot is ICP time converted to seconds, minus mainnet beacon genesis `1606824023`, divided by 12. The canister does not ask a beacon node for the time.

### Stable records

Chain config, the Schnorr public key, each light-client record, and the signatures for the current finalized beacon header are written to stable memory during ordinary calls. A wasm upgrade reads those records. `post_upgrade` loads them, applies `opt DeployConfig` when the argument is present, and starts the daily timer again. An empty public-key record starts another key fetch. A canister whose stable memory is still the older length-prefixed JSON blob is loaded once and rewritten as records.

The light-client records are the finalized header, the optimistic header, the current sync committee, the next sync committee, the participant counters, and the best update. A call writes a record when that record's bytes changed. A signature cache hit writes nothing. A new signature rewrites the current-header signature record. A finality update writes the header records and the participant counters that changed. The committee records stay in place until a period update changes one of them.

For one fixture state, the older length-prefixed JSON snapshot is 108,542 bytes. That state holds two sync committees, two Electra light-client headers, the chain config, the public key, and one signature. Later calls write the records below. The counts are bytes copied into stable memory, including a 24-byte slot header for each record that changed. `certify_writes_changed_records_not_the_snapshot` locks the write counts. `electra_header_json_is_much_smaller_than_one_committee` locks the JSON sizes. Both are one deterministic serde run. A committee is 51,845 bytes because its 512 public keys are hex strings. A header is 1,935 bytes of JSON. A shorter encoding would be a different byte count. The snapshot stays large because it contains both committees.

| Change | Stable bytes |
|---|---|
| No record changed, including a signature cache hit | 0 |
| One new signature on an empty cache | 156 |
| Finalized header | 1,959 |
| Optimistic header | 1,959 |
| Participant counters | 40 |
| Both headers and the participant counters | 3,958 |
| Next sync committee | 51,869 |
| Older length-prefixed JSON snapshot | 108,542 |

156 is a 132-byte signature record plus the 24-byte slot header. The record is the 32-byte header root, a 4-byte count, a 32-byte transaction id, and a 64-byte signature. 1,959 is the 1,935-byte header JSON plus the slot header. 40 is 16 counter bytes plus the slot header. 51,869 is the 51,845-byte committee JSON plus the slot header. When the finalized header changes and the cache already holds signatures, those signature bytes are overwritten with zeros. A signature returned for the retired header is left out of the new record.

### certify_final

`certify_final(ethTxId, proofs)` signs only after the checks below succeed. When `proofs` is absent, the canister fetches the same bytes with HTTPS outcalls and runs the same checks. A fetched byte string is not trusted because it arrived from the network. Caller-supplied bytes and fetched bytes are one kind of input.

A public call that omits `proofs` makes the canister pay for those outcalls. The canister checks the stored checkpoint before any request. The checkpoint must already be set and inside the weak-subjectivity window. The caller then attaches cycles for three pricing-version-2 outcalls, each capped at 128 KiB: the finality update, one light-client update, and `eth_getProof`. The quote prices the update URL with `start_period` set to the largest `u64`, which is at least as long as the period it will fetch. The canister accepts that amount and only then fetches. Attached cycles above the quote are not accepted. Cycles the outcalls do not spend stay in the canister. Supplying `proofs` does not fetch and does not require that payment. The daily timer is not a public call; it spends the canister's own cycles.

One message verifies at most one `LightClientUpdate` and one `LightClientFinalityUpdate`. If the stored committee cannot verify the finality update, the canister applies one update. If that is still not enough, it returns an error and does not sign. The caller retries. A message does not walk an open-ended backlog.

The checks run in this order.

1. The `LightClientFinalityUpdate` has a sync-committee aggregate signature whose participation satisfies `bits * 3 >= 512 * 2` (at least 342 of 512). The signature is BLS12-381 under the stored committee for that signature period, over the signing root the light-client spec defines for the attested header.
2. The finality branch connects `hash_tree_root(finalized_header.beacon)` to the attested beacon state's `state_root`, at the finalized-checkpoint index. The attested header can be newer than that checkpoint. The branch covers the finalized beacon header. It does not cover the execution payload.
3. `finalized_header` carries its own execution payload header and its own execution branch. That branch connects the payload to `finalized_header.beacon.body_root`. The canister reads `state_root` and `block_number` from this finalized payload. The attested header has an execution payload too, and the canister checks that branch as well, because the sync committee signed that beacon header. The attested execution state is not the state the storage proofs use. A beam that exists only in a block after the finalized checkpoint does not pass.
4. An account proof for the Charms proxy, against the finalized execution `state_root`. The canister recovers the account from the proof nodes. The code hash equals the deployed proxy bytecode. The proved account is the proxy. Delegatecall keeps the implementation's storage there. The implementation contract's own account is the wrong account.
5. A storage proof of `beamSourceAt[ethTxId]`. The slot index is that mapping's place in the implementation layout. v1 stores `beamSources` at slot 7, and `DeployConfig.beam_source_slot` records that index. The storage slot is `keccak256(abi.encode(ethTxId, uint256(slot)))`. That 32-byte value is the EIP-1186 logical key, and the proof's `key` is those bytes. The canister recomputes the slot from `ethTxId` and the recorded index and requires the key to equal it. The secure-trie path is `keccak256(storage_proof.key)`. The canister walks the proof along that path. It does not accept a caller-supplied path hash in place of the slot. The value `v` opened by the proof satisfies `0 < v` and `v <= block_number`, where `block_number` is the finalized execution block number from step 3.
6. A storage proof that the ERC-1967 implementation slot equals the implementation address the canister expects. The logical key is the 32-byte ERC-1967 slot. The trie path is `keccak256` of that slot, same as step 5. A `Charms` upgrade that moves the mapping fails this check until a canister upgrade records the new implementation and the new slot.

The canister then signs with `sign_with_schnorr` (Ed25519) under the derivation path above, unless it already stored a signature for this `ethTxId` and the current finalized beacon header. That pair is the cache key. A hit returns the stored 64 bytes and does not sign. A miss prices `sign_with_schnorr` and accepts that amount from the caller before signing, including when the caller supplied the proofs. The accepted cycles fund the management-canister signature call. When the finalized header changes, the pair is new and the caller pays again. A repeat while the header is unchanged does not. The cache holds signatures only for the current finalized beacon header. The canister writes that set to stable memory when the set changes. When the header changes, including when a signature call returns after the change, signatures for the previous header are dropped and left out of the stable record.

The message is `SHA-256("charms/ethereum/finality/v1" ‖ chainId_be_u256 ‖ Charms_20 ‖ ethTxId)`. The signature is 64 bytes. The guest does not receive the spell from the canister. It already has the spell bytes in the `EthereumTx` record, and `ethTxId` is the hash of those bytes. The signature says the canonical contract accepted that id in a beacon-finalized execution state.

`EthereumTx::proven_final` is true only when `chain_id` is 1, `charms` equals the deployed mainnet address, and the signature verifies under `ETHEREUM_FINALITY_VKEY`. A testnet guest build uses different constants and is not a mainnet proof.

Agreement among EVM RPC providers at block tag `finalized` is not a check on this path. The state root comes from the verified finality update, and the storage proof is checked against that root. Providers cannot repair a bad proof, and a requirement that they agree can reject a proof the canister has already checked. That is a stall, which is the failure this design is removing. Operators can compare `finality_status` with a beacon node they run. That comparison does not gate the signature.

### Beacon forks and the guest key

Generalized indices and the execution payload's SSZ type change at forks. Electra is the change the consensus specs already describe. The finalized-checkpoint root moves from generalized index 105 to 169, the current sync committee from 54 to 86, and the next sync committee from 55 to 87. Capella and Deneb also extended the execution payload header, which changes its tree hash. Capella adds `withdrawals_root`. Deneb adds `blob_gas_used` and `excess_blob_gas`. Electra keeps that Deneb header. The fork table (epochs, indices, and payload type) lives in the wasm. A fork that changes any of them needs a wasm upgrade before the fork epoch. If the upgrade is late, `certify_final` fails closed and does not accept an update it cannot verify.

Blackholing would freeze that table. The next incompatible fork would stop certification, and the only recovery would be a new canister. A new canister rotates `ETHEREUM_FINALITY_VKEY` and forces a spell-checker rebuild. Keeping one upgradeable canister is how the guest constant survives a fork. The cost is the controller. A wasm upgrade can sign a header that did not finalize. That is the same capability as the finality key. The controller is a governance principal, not an individual's day-to-day key.

### Weak subjectivity

A light client that is too far behind cannot tell the canonical chain from a conflicting history. Electra computes that window with `compute_weak_subjectivity_period` in the [weak subjectivity guide](https://ethereum.github.io/consensus-specs/electra/weak-subjectivity/). The spec's worked example caps the period at 3,532 epochs once total active balance is at least 16,777,216 ETH. 3,532 epochs is 3,532 * 32 * 12 = 1,356,288 seconds, which is 15.7 days. The canister does not hold a full beacon state, so it cannot recompute that function. It stores `ws_period_epochs`, which the controller sets with `set_ws_period`. The initial value follows the spec period for stake at deploy. If the published period shrinks, the controller lowers the stored value. A stored period longer than the spec period would keep a checkpoint that is already too old.

When the current epoch is past the stored finalized epoch plus `ws_period_epochs`, the canister rejects updates and refuses to sign. Recovery is `reset_checkpoint` with an SSZ `LightClientBootstrap` (header, current sync committee, and branch). The canister checks the branch against the header's `state_root`. The header being canonical is the controller's assertion. That is weak subjectivity, not a proof the canister can rerun. After the reset, the timer and `certify_final` catch up one period at a time. The Ed25519 key does not change. A dishonest reset can authorize a false beam. `finality_status` changes when it happens, and the call is on chain.

### Trust

The guest trusts one Ed25519 key, `ETHEREUM_FINALITY_VKEY`. That key is the canister's ICP threshold Schnorr key. The canister does not hold the seed. This is the same class of assumption as Cardano's `FINALITY_VKEY`.

The canister trusts a supermajority of each sync committee it applies, using `bits * 3 >= 512 * 2`. The protocol does not slash a committee member for a light-client signature. A committee that signs a false finality update is not punished for that signature. Members are sampled from the active set and the sample rotates every 27.3 hours. The signature itself has no slashing condition.

The canister also trusts its controller. An upgrade or a checkpoint reset changes what can be signed, and the guest key stays put.

EVM RPC providers and beacon API hosts are not in that set. They supply bytes. The checks above accept or reject the bytes.

Inbound finality stays in the guest. The guest already checks Bitcoin work and the Cardano finality signature. A beacon light client in the spell-checker would be rebuilt whenever an index changes, and that rebuild is a new guest. The light client lives in the canister so `ETHEREUM_FINALITY_VKEY` can stay.

## Cost

Cycle prices below are from the [Internet Computer cycle-cost reference](https://docs.internetcomputer.org/references/cycle-costs/). One trillion cycles is 1 XDR. The dollar figures use 1 XDR = $1.366430, the rate that page dated 22 May 2026. The signature price does not depend on the calling subnet. Instruction and outcall prices below are the 13-node application-subnet column. A 34-node subnet charges about 2.6 times as many cycles for those two.

| Step | Cycles | About |
|---|---|---|
| `sign_with_schnorr`, Ed25519, key `key_1` | 26,153,846,153 | $0.036 |
| One quorum aggregate verification | about 2.3 billion, if one wasm operator is one instruction | $0.003 |
| One light-client HTTPS outcall, pricing version 2, response of a few tens of kilobytes | a few hundred million | under $0.001 |
| Update-message base fee | 5,000,000 | negligible |

The signature is the certificate. It costs more than ten times the aggregate verification, and the outcall is smaller than either. A certificate that also applies one `LightClientUpdate` verifies two aggregates, about 4.6 billion wasm operators in the measurement below. The [resource limits](https://docs.internetcomputer.org/references/resource-limits/) put 40 billion instructions on one update message and 4 billion on one round of one execution thread. A message may continue on a later round. Two aggregates sit near that round boundary and under the message cap.

The daily timer pays for at most one aggregate verification and one outcall. That is under one cent a day on a 13-node subnet at the rate above. The timer does not call `sign_with_schnorr`. A new `certify_final` signature is charged to the caller, not to the canister balance. The caller attaches the `sign_with_schnorr` quote in addition to the fetch quote when proofs are omitted. A cached signature does not require the signature payment. When proofs are omitted, the fetch quote is still required.

HTTPS outcalls must use pricing version 2. Version 1 is still the default and prices the reserved response size. If `max_response_bytes` is left at its 2,000,000-byte default, version 1 costs 20.8 billion cycles on a 13-node subnet for the response term alone (`800 * 2,000,000 * 13`), which is the same order as the signature. The canister also sets `max_response_bytes` to a cap that fits a sync committee (24,576 bytes of pubkeys, plus the header and the branches). 128 KiB is enough. The outcall dollar figure applies the version 2 formula to that cap. This spike did not time a live outcall.

A later option, not part of v16, is to sign one Merkle root of many `ethTxId`s and let the guest check a membership proof. That amortizes the 26 billion cycles. It also changes the guest, because `proven_final` today verifies one signature over one id. It earns a design only if certificate volume makes that signature the budget.

## Light client library

Use `helios-consensus-core` 0.11.1 from [a16z/helios](https://github.com/a16z/helios/tree/0.11.1/ethereum/consensus-core). [sp1-helios](https://github.com/succinctlabs/sp1-helios) pins that tag and verifies light-client updates with this crate inside SP1. The wasm32 build below is the check that matters for a canister. The BLS backend is `bls12_381` 0.8 with the `experimental` feature, the pure Rust zkcrypto implementation.

The canister build is `wasm32-unknown-unknown`. This revision does not compile for that target unchanged. Its wasm32-only dependencies are `getrandom` with the `js` feature and `wasmtimer`. A dev build with Rust 1.96.1 does link, and the resulting module imports five wasm-bindgen symbols (`__wbindgen_placeholder__` and `__wbindgen_externref_xform__`). An ICP canister cannot provide those imports.

Drop those two dependencies and use `std::time::SystemTime` for the slot helper. The canister passes ICP time in. It does not call `SystemTime::now`. `bls12_381` 0.8 still pulls `getrandom` 0.2 through `rand_core` 0.6, and that crate refuses `wasm32-unknown-unknown` unless `js` or `custom` is enabled. Enable `custom` and register a function that returns an error, as `scrolls_cardano` already does. Verification does not draw random bytes. The benchmark below returned success, so this path did not call the stub.

The same patch, the cdylib, and the Wasmtime runner are in `CHIPs/CHIP-0020/bench/`. `reproduce.sh` clones tag 0.11.1, applies `helios-0.11.1-wasm32.patch`, and runs them. After that patch, `cargo build --release --target wasm32-unknown-unknown` of the cdylib produces a module of 600,341 bytes with no import section. `reproduce.sh` printed that size, and it printed the fuel counts in the table. That file includes the benchmark exports, so a canister that only verifies updates is smaller. Rustc was 1.96.1. Wasmtime was 34.0.2. The release profile was opt-level 3, codegen-units 16, and no LTO.

The measurement is one minimum-quorum check. 342 of 512 committee keys participate, which is the smallest bit count that satisfies `bits * 3 >= 512 * 2`. Helios then starts from the committee aggregate and subtracts the other 170 keys. Each subtraction decompresses a compressed G1 pubkey. The signature check is `Signature::verify` from the same crate (hash to G2, the crate's scalar-multiplication subgroup check, and one pairing).

The host was a 4-vCPU Xeon under KVM. The run was single-threaded. Wasmtime was 34.0.2 with Cranelift speed optimization. Fuel counts wasm operators at one each, except `nop`, `drop`, and some control-flow operators, which cost nothing. The ICP instruction counter weights operators differently. The cycle row above treats one fuel unit as one instruction. A run under `ic0.performance_counter` on a replica can move that row. Wall times are the median of five calls after one warmup call. Every call returned success, including a reject of a signature over a different message during setup.

| Piece | Wasmtime fuel | Median wall time |
|---|---|---|
| Decompress the 170 subtracted keys | 1,899,084,026 | 99.8 ms (99.4 to 101.0) |
| Add those 170 points, already decompressed | 17,878,101 | 0.92 ms (0.91 to 1.01) |
| Helios participating-key aggregate | 1,928,184,021 | 100.5 ms (100.5 to 101.2) |
| `Signature::verify` | 367,867,991 | 18.8 ms (18.7 to 18.8) |
| Aggregate and verify, the quorum check | 2,296,052,001 | 119.6 ms (119.2 to 120.4) |

Decompression is 98.5 percent of the aggregate and 83 percent of the quorum check. Point addition is not the budget. The check cannot get twice as cheap without decoding fewer keys or a faster field square root. A committee with every bit set subtracts nothing, so the minimum legal quorum is the expensive case. The naive subgroup check inside `Signature::verify` is 117 million fuel. `G2Affine::is_torsion_free` on the same point is 12.6 million. The difference is about 100 million fuel, 4.5 percent of the quorum check. Swapping that check does not move a certificate whose large terms are the signature and the key decompression.

A published SP1 measurement of Helios without BLS precompiles is 3.36 billion RISC-V cycles for a finality update and 3.37 billion for a period update, 6.73 billion combined ([Succinct Ships: Optimized bn254 & bls12-381 Precompiles in SP1](https://blog.succinct.xyz/succinctshipsprecompiles/), Uma Roy, 7 October 2024). Those counts are RISC-V cycles on SP1. The table above counts wasm operators. Both sit in the 1 to 10 billion band. ICP has no BLS12-381 precompile, so the column that applies is the one without precompiles. The precompile column is about 50 million cycles.

`helios-consensus-core` 0.11.1 already switches proof indices at `forks.electra.epoch`. Finality is generalized index 105 before Electra and 169 after. The code stores `(index, depth)` as `(41, 6)` and then `(41, 7)`. The current sync committee is 54 and then 86. The next committee is 55 and then 87. Those generalized indices are the ones in the [Electra light-client sync protocol](https://ethereum.github.io/consensus-specs/electra/light-client/sync-protocol/). The execution payload branch is hardcoded at depth 4, index 9, against the beacon body root. A later fork that moves that field is a wasm change. `Forks` has a `fulu` version for the signing domain, and the proof functions in this revision do not branch on it.

Two calls in this crate do not mean what the canister needs. `verify_finality_update` accepts any non-zero participation whose aggregate signature matches. The 2/3 check is in `apply_finality_update`, which returns `None` when the quorum fails instead of returning an error. `force_update` can apply an update that missed the quorum. The canister requires `bits * 3 >= 512 * 2` itself. It does not call `force_update`, and it does not call `apply_update_no_quorum_check`.

`ethereum-consensus` (ralexstokes, commit `5031d31`, 18 July 2025) is not the crate to start from. A fresh resolve fails because `multihash` 0.16 depends on yanked `core2` 0.4.0, and that checkout has no `Cargo.lock`. Its BLS backend is `blst`, and the crate also depends on `c-kzg`. `blst` 0.3.17 by itself does compile and link for `wasm32-unknown-unknown` (a one-function crate, `cargo build --target wasm32-unknown-unknown`, Rust 1.96.1). A faster C backend is possible later. It does not include the light-client proofs or the fork indices. Lighthouse's `consensus/types` on the stable branch depends on `bls` (blst), `rayon`, `parking_lot`, `regex`, `tempfile`, and `rand`. That is a beacon-node crate. It was not built. The manifest is enough to reject it for a canister.

## Proofs

Verification runs inside `Charms`, on the proved path only, via `ISP1Verifier.verifyProof(programVKey, publicValues, proof)`.

- `programVKey` is the proof-wrapper verifying key compiled into this implementation for `spell.version`. For the v16 implementation that is the 32 bytes `charms spell vk` prints, and the same bytes committed as the first public value.
- `publicValues` are the bytes from [The committed spell](#the-committed-spell).
- `proof` is the `Proof` byte string the prover already returns. The contract does not re-layout it. The verifier is the one `verify_gnark_v6` corresponds to: 4-byte SHA-256 prefix of the Groth16 verifying key, then exit code, vk root, and proof nonce as 32-byte words, then the gnark proof. v15 checks that prefix against `groth16_vk`, requires exit code 0, and requires vk root `SP1_V6_2_VK_ROOT` (`002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`).

A v15 Groth16 proof still verifies under the pinned v15 program key. A version-16 proof commits the key `charms spell vk` prints. The contract does not carry a Solidity port of `verify_gnark_v6`.

`extract_and_verify_spell` checks a non-empty `proof` with `verify_snark_proof` against `to_serialized_pv`. The public values are CBOR of `([u8; 32] spell_vk, NormalizedSpell)`. A proof that does not verify is rejected. An empty proof is the native path, and Groth16 is not run. A proved record is also rejected when its effective anchor is not zero, because `transact` writes a zero anchor once the spell spends inputs and the id hashes that anchor. The id still does not hash the proof. The contract on Ethereum still verifies Groth16 on the proved path. A later spell reads the same record, so the host check and the contract check are the same statement.

The spell-checker ELF verifies an Ethereum record in `prev_txs`, including a non-empty proof, and then the wrapper commits the spell being proved. An Ethereum-hosted spell whose output coin has a nonzero amount, a destination that is not 20 bytes, or nonempty content is rejected before proving and inside the guest. A request whose chain is not the chain that created the first input is rejected before the prover runs. The spell version is 16. An empty UTXO committed at version 15 stays that version. Its bytes are not rewritten, so the transaction id does not change, and a version-16 spell can spend it. `SPELL_VK` and `SPELL_CHECKER_VK` are the keys of this guest. Version 15 keeps its pinned program key. The Cardano reference NFT and `scrolls_bitcoin_v15` stay on their v15 deployments. The first Ethereum deployment is spell version 16. This guest checks `signature` against `ETHEREUM_FINALITY`. That constant is the `scrolls_ethereum` Ed25519 key, chain 1, and the mainnet Charms proxy `0x02177ffA1d7FBB35F2c444eE89B1f9De7B270B4f`. `proven_final` is that check.

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
pub struct EthereumTx {
    pub chain_id: u64,
    pub charms: [u8; 20],
    pub anchor: Option<[u8; 32]>,    // set only when ins is empty
    pub spell: Vec<u8>,              // committed CBOR, the id preimage
    pub proof: Vec<u8>,              // empty on the native path; not in the id
    pub caller: Option<[u8; 20]>,    // anchor preimage; not in the id
    pub salt: Option<[u8; 32]>,      // anchor preimage; not in the id
    pub signature: Option<[u8; 64]>, // scrolls_ethereum; omitted when absent
}
```

`EnchantedTx` for `EthereumTx`:

- `tx_id` reverses `eth_tx_id()` into `TxId`.
- `extract_and_verify_spell` decodes `spell` and requires `mock` to match. A placeholder keeps an anchor, an empty proof, and canonical CBOR. Any other spell carries a proof. The function then requires a zero effective anchor (`None`, or 32 zero bytes), a non-empty `ins`, `coins.len() == outs.len()`, amount 0, empty content, and a 20-byte `dest`, and it runs `verify_snark_proof`. Any other anchor is rejected. The proof does not commit to the anchor, and `transact` writes `bytes32(0)` when `ins` is non-empty, so a nonzero anchor would name an output id the contract never creates.
- `virtual_spell` is that decode. An Ethereum record with no spell is an error, never an empty spell.
- `proven_final` is the Ed25519 check above. A record with no `signature` is not final. The check uses `ETHEREUM_FINALITY` (`vkey`, `chain_id`, `charms`). That constant is the `scrolls_ethereum` key, chain 1, and the mainnet proxy.
- `all_coin_outs` returns the committed `coins`.
- `spell_ins` returns the committed `ins`.

One new guard in `is_correct`, beside `beaming_txs_have_finality_proofs`. Every `Tx::Ethereum` prev tx must be `proven_final`, or the spell being proved must itself be hosted on Ethereum (the creator of `ins[0]` is `Tx::Ethereum`), this prev tx must have created one of its inputs or refs, and its `chain_id` and `charms` must equal that hosting record. The host implements that guard. `proven_final` is false until the finality signature exists, so an Ethereum previous transaction is accepted only when it created an input or reference of a spell hosted by the same chain and contract. A non-final record from another network or another `charms` contract is rejected. The guest runs that guard and checks the record's proof. A no-binary spell whose public inputs are not all null is still accepted on the simple-transfer path. That check is not part of this rebuild.

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

An empty UTXO has no apps. It mints nothing and burns nothing. `spell prove` builds that record locally, takes no `--prev-txs`, and does not call the prover. `proof` stays empty. The printed hex is the only spell input `tx build` needs. `tx build` constructs the signable `transact` call, and that call is what gets executed.

An empty UTXO is the local path. Any other Ethereum spell is proved. The prover returns one `Tx::Ethereum` whose `spell` is the committed CBOR, including `ins` and `coins`, and whose `proof` is the Groth16 proof. `chain_id` and `charms` are copied from the Ethereum record that created the first input. A native `t`/`n` spell that the contract can check without a proof is still a later local path.

`CharmsFee.fee_rate` and `fee_base` stay in sats, as in `charms-client/src/request.rs`. Ethereum does not reuse those fields as wei, and this design does not add a wei field to `CharmsFee`. `transact` does not charge a Charms fee. The wallet pays Ethereum gas. `ProveRequest.fee_rate` is ignored for `chain = ethereum`.

CLI:

| Command | Behavior |
|---|---|
| `spell prove --chain ethereum` | For an empty UTXO, prints a JSON array of one hex string. The hex is the Charms record. No `--prev-txs`. Nothing is minted or burned, so the prover is not called. `tx build` reads that hex. `--caller` and `--salt` are required when `ins` is empty. Any other spell is proved. It takes `--prev-txs` and does not take `--caller`, `--salt`, `--chain-id`, `--charms`, or `--change-address`. The printed hex is the proved record. `--change-address` stays required for Bitcoin and Cardano only. |
| `tx build --chain ethereum` | Takes that hex and prints `{from, to, data, value}`. `data` is `transact` calldata for the spell inside the record. That call is what gets executed. The hex is not a signable Ethereum transaction. |
| `spell check --chain ethereum` | Runs `is_correct` on the host. An Ethereum previous transaction is admissible when it is final, or when it created an input or reference of a spell hosted by the same chain and contract. A non-empty proof is checked, and a proved record whose anchor is not zero is rejected. `spell prove` for that spell runs the same check inside the guest. |
| `tx show-spell --chain ethereum` | Decodes an envelope or a `Transaction` log. |
| `tx fetch --chain ethereum --tx-id <id> [--finality]` | Rebuilds the record from `Transaction`. `--finality` calls the canister and sets `signature`. |
| `util dest --chain ethereum --addr 0x…` | Raw 20 bytes. Accepts EIP-55, stores the lowercase bytes. |
| `util eth-token <APP>` | For a non-vault app, the CREATE2 address from the same formula as `tokenAddress`. For a vault app, the underlying address, `address(0)` for ETH. Does not deploy. |
| `util eth-vault --token <addr\|eth>` | Prints the vault `App`. The `App` does not take a decimals argument. ETH's scale is 10. An ERC-20's scale is derived from `decimals()` and printed beside the `App`. |

App contracts are unchanged. `app_contract` sees `coin_outs[i].amount == 0` and a 20-byte `dest`. An app that wants to move ETH moves the vault charm. `charms-sdk` and the app runner do not change. `charms-lib`'s `extractAndVerifySpell` already decodes an Ethereum envelope and checks its proof. This rebuild changes the `SPELL_VK` that check uses for a current-version spell. The binding documents that a decoded spell is content-authenticated: acceptance of a created output is `utxo(UtxoRef)` on the contract. Acceptance of a beam-out is `beamSourceAt(ethTxId) != 0`.

## Protocol version

| Record | Spell version | Guest | Keys |
|---|---|---|---|
| First deployment | Spell version 16. A native spell needs no proof. | An empty UTXO does not run the guest. The CLI writes that record at version 16. | The empty-UTXO path does not use `SPELL_VK`. The contract accepts version 16. |
| Proved Ethereum spell | Version 16. | The guest verifies a spell in `Tx::Ethereum`, including its proof. | `SPELL_VK` is `0x00da533974a87fa489f6f9831c9ea2447b456b38ef3a5c6dc9e421af52831f8d`. Version 15 keeps `0x00425796f4c4fa050043eee14d801b4f935244e44aad6a28de0cd5cb3de0ae52`. Older Bitcoin and Cardano proofs verify under their pinned keys. |
| Beaming | The guest checks the `scrolls_ethereum` signature. | `ETHEREUM_FINALITY` names that key, chain 1, and the mainnet proxy. | `programVKey` is this guest's `SPELL_VK`. |

An empty UTXO committed at version 15 stays that version. The bytes are not rewritten, and a version-16 spell can spend it.

This rebuild compiles a new wrapper because the wrapper hardcodes `SPELL_CHECKER_VK`. Version 16 reuses v15's Groth16 verifying key when the rebuilt `groth16_vk.bin` is the same bytes. Those bytes are v14's, prefix `4388a21c`, and the stock verifier still matches that prefix. The value that changes is the wrapper's `programVKey`. `to_serialized_pv` for version 15 and 16 is CBOR of `([u8; 32], NormalizedSpell)`. Bitcoin and Cardano transaction layouts do not change.

Which spell versions an implementation accepts, and the `programVKey` for each, are part of that implementation's code. The first deployment accepts new spells of version 16 only. There is no version-15 deployment on mainnet. Its `programVKey` is `charms-lib`'s `SPELL_VK`. Its verifier is the stock Groth16 verifier. It still spends UTXOs created by version-15 spells, because that state is in `head` and `body`. It rejects a new spell whose version is 15. A later protocol bump is a new implementation plus `upgradeToAndCall(newImplementation, "")` from the admin. Token addresses and `ETHEREUM_CHARMS` stay on the proxy. A new proxy would change every token address and the guest constant. That is a new deployment, not an upgrade.

`charms-lib`'s `SPELL_VK` is the version-16 wrapper key. `CHARMS_PROVE_API_URL` is `https://v16.charms.dev/spells/prove`. The Cardano reference input is still the v15 protocol NFT, and the host still calls `scrolls_bitcoin_v15`. A version-16 Cardano spell's redeemer says `v16` against that NFT. Minting the v16 NFT and delegating the canister are later.

## Edge cases

- **ETH versus a wrapped ERC-20.** ETH is the vault at `address(0)`. WETH is a different vault. They do not share supply.
- **Allowances.** Non-vault charm allowances live on `CharmToken`. A vault charm has no allowance surface. The underlying token's `approve` is only for `wrap`, and it names `Charms`. `tokenTransfer` rejects a vault app. For a non-vault app it checks `msg.sender` is the token whose CREATE2 address it just recomputed. The underlying token's `transfer` does not move the vault charm.
- **Several charms on one UTXO.** One `head` record, one list entry per `t` app, one balance contribution per `t` app. Spending via the tag-`t` token preserves the other `t` or `n` charms on a sender-owned change output, including when this token's remainder is zero. An `n` charm, an `s` charm, a custom-tag charm, or an empty UTXO is spent with `transact`.
- **Empty UTXOs.** Allowed, required as beam targets, indexed only in `emptyUtxos` and `head`. They do not affect supply.
- **u64.** A single output amount and the sum of a spell's inputs of one app must fit in `u64`, because the guest adds them as `u64`. Balances in storage are `uint256` so many UTXOs can sum past `u64`; the facade then needs more than one call, each under the cap.
- **Weird tokens.** Fee-on-transfer reverts on `wrap`. On `unwrap`, only a fee taken out of the amount sent is accepted: the recipient's balance may end below what it was plus the amount unwrapped, and that shortfall does not revert. A fee charged on top of the amount is unsupported. It reverts when the vault holds exactly `locked`, and with surplus it can leave `held < locked` so later vault operations fail. Rebasing is unsupported. A token that blocklists `Charms` can freeze that vault and no other. The first `wrap` stores the canonical `scale`. A later `decimals()` that would change it reverts. The `App` stays the one identity above.
- **Mixed pins.** After a versioned app bumps its version, one owner can hold UTXOs pinned to different versions. The facade reverts with `MixedVersions` when the inputs it would select do not share a pin. A proved `transact` runs the new binary, which is what `authorize_version_changes` already requires.
- **Reorgs.** A native transfer reorgs with Ethereum, like any ERC-20. A beam waits until the canister's finalized execution header covers the block in `beamSourceAt`.
- **Unpublished metadata.** `name` is `Charm`, `symbol` is `CHARM`, and `decimals` is 0. `contractURI` returns a document that contains those three fields.
- **Stale metadata signature.** A bad signature, an equal or lower version, or a changed `decimals` reverts. The last accepted record stays. The contract does not delete it.
- **Clone not deployed yet.** `setMetadata` stores the record and emits `MetadataSet` from the proxy. It does not emit `ContractURIUpdated`. `ensureToken` emits that event from the clone when it deploys one for an app that is already published.
- **History.** `Transaction` carries the spell CBOR because `wrap`, `unwrap`, and the facade build it inside the contract, where it is not in calldata. Proving a later spend of a bundle needs that record. Native spends of plain UTXOs do not: `head` has the amount. Indexers archive the logs; EIP-4444 makes that an operator concern, not a consensus one.


## Alternatives

| Shape | Why it lost |
|---|---|
| Ethereum transaction hash as `TxId` | The EVM cannot read the hash of the executing transaction. One Ethereum transaction can contain several Charms transactions. |
| A contract nonce as `TxId` | The id is not known until mined, it changes across a reorg, and an unrelated call burns a placeholder that a source chain has already beamed to. |
| Verify proofs only inside the guest, and let a canister attest them on Ethereum | Ethereum can verify the Groth16 proof. A canister on this path would be a trusted party Cardano needs only because Plutus cannot do this cheaply. |
| A Solidity port of `verify_gnark_v6` | A second verifier. The stock SP1 verifier is the one the fork test has to accept. |
| A new public-value encoding for Ethereum | Two commitment formats. The same spell would verify differently per chain. `to_serialized_pv` stays as it is. |
| Parse untrusted CBOR in the contract | The contract encodes from typed calldata. Parsing is a larger, leakier surface, and the proof already pins the bytes. |
| Vault policy as an app wasm | Every wrap needs a prover. The wasm cannot see the ERC-20 transfer. A wasm that permits a mint permits it on Bitcoin. A beam-in that the guest treats as a simple transfer would skip that wasm and still look like an unlock if Solidity obeyed the public input. |
| Prove every ERC-20 transfer | Matches Bitcoin, and makes `transfer` cost a Groth16 verification plus a prover round trip. The contract can check a simple transfer itself. That is the point of doing this on Ethereum. |
| `balanceOf` counts only single-token UTXOs, and attributes bundles to `address(Charms)` | `balanceOf` would not be the total on that address's UTXOs. The requirement is the total. Custom-tag bundles stay in the balance and out of automatic selection instead. |
| Beacon light client inside the guest | An index change would rebuild the spell-checker. The light client sits in `scrolls_ethereum`, so `ETHEREUM_FINALITY_VKEY` stays across those forks. |
| `eth_call` of `beamSourceAt` at tag `finalized`, from at least three EVM RPC providers | The previous check. Those providers are not the beacon chain. They can agree on a wrong block, or disagree and stall a beam whose output is already spent. |
| The same provider agreement, plus the light client | The storage proof is checked against the light client's execution state root. The extra vote can only reject a proof that already verified. |
| Blackhole `scrolls_ethereum` | The next fork that changes a generalized index or the execution payload SSZ stops certification. A new canister is the recovery, and it rotates `ETHEREUM_FINALITY_VKEY`. |
| A new canister and key at each beacon fork | `sign_with_schnorr` follows the canister id. A new id is a new guest constant at every consensus fork. |
| Bitcoin and Cardano light clients in Solidity | A second copy of `proven_final`. The proof is already that check. |
| A new `Charms` deployment per protocol version | CREATE2 token addresses and the vault identity are functions of the proxy address. A new proxy splits liquidity and changes `ETHEREUM_CHARMS` in the guest. |
| A transparent proxy | Every call would check `msg.sender` against an admin before delegating. UUPS keeps that check on `upgradeToAndCall` only, so `transact` and `transfer` pay one `delegatecall`. |
| A beacon proxy | One `Charms` proxy does not need a second contract read on every call to find the implementation. |
| A standard beacon in front of `CharmToken` | A beacon proxy reads the beacon from an ERC-1967 slot. Under the clone's `delegatecall` that slot is the clone's storage, and `initialize` does not write it there. A beacon address stored as an immutable in `CharmTokenProxy` would be a second contract on the path `Charms.tokenImplementation()` already provides. |
| A forwarder that calls `Charms` and returns logs | A normal call runs `CharmToken` with `address(this)` equal to the implementation. Allowances would be stored on that shared contract, and `Transfer` would be logged there. Copying the logs back onto the clone repeats every event. `delegatecall` keeps the slots and the logs on the clone. |
| A UUPS proxy between the clone and `CharmToken` | `upgradeTo` and the ERC-1967 read would run under the clone's `delegatecall`, so each clone would store its own implementation. `CharmTokenProxy` does not read that slot and has no `upgradeTo`. |
| Wei on `NativeOutput.amount` | `u64` overflows near 18 ETH, native coins are not beamable, and ETH would have two representations. The vault charm is the one representation. |
| Store the Groth16 proof beside the spell and require only the guest to verify it | The proof is already a field of the record and is not part of the id. The host checks a non-empty proof in `extract_and_verify_spell`. The guest checks the same proof when the record is in `prev_txs`. The contract checks it on Ethereum. |
| Read display fields from a reference NFT | The NFT may not be on Ethereum. `setMetadata` takes a signature instead, and the contract does not track an NFT UTXO. `charms_metadata` checks that NFT in the transaction it is given. |
| Bind the metadata signature to the chain id and the Charms proxy | The same charm is published on every chain. A digest that names one proxy fails `ecrecover` on the next chain. The signed version is what stops an old signature from replacing a newer name. |
| Use the block height as the metadata version | A Bitcoin header has no height. The merkle proof `proven_final` checks does not include the coinbase, where BIP34 writes the height. The header `time` is the clock that proof checks, and only after every header meets its own target. |
| Let the caller choose the metadata version | The caller could submit an old `metadataHash` under a higher version. The canister reads the version from the block it verified. |
| Store the image bytes in the proxy | A remote image does not fit in contract state. The contract stores a URI and `imageHash`. |
| ERC-1046 `tokenURI()` | That method describes one unit. A fungible charm has one document, returned by `contractURI()`. |
| Put `contractURI` in the clone bytecode | A new implementation address in that bytecode changes `tokenAddress`. `contractURI` is a method on the `CharmToken` implementation named by the `Charms` constructor. `upgradeToAndCall` installs a later `Charms`. The clone keeps `CharmTokenProxy`. |
| `ensureToken` takes the first signature | The clone reads storage, so publication does not require deployment. `setMetadata` stays the only write. |
| Ed25519 signatures for metadata | The finality key is Ed25519. `ecrecover` is the check `Spend` already uses, and it avoids a second verifier. |
| Use `ETHEREUM_FINALITY_VKEY` as the metadata signer | A stolen display key would then be a stolen finality key. The keys stay separate. |

## Risks

The vault makes a forged beam worth real tokens. A private Bitcoin fork deep enough to pass `FINALITY_TARGET_BITS`, or a stolen `scrolls_ethereum` or Cardano finality key, can beam vault units onto Ethereum and unwrap them. The cap `supply * 10^scale <= locked` limits the loss to vault units that are currently outside Ethereum. This design does not raise `FINALITY_TARGET_BITS`. Raising it would be a guest constant in the same v16 rebuild, and it would slow every Bitcoin beam, not only vault beams.

A `SpellCodec` that diverges from `util::write` is a liveness failure: proofs do not verify and ids do not match. A codec that is not injective is a safety failure. The codec vectors, including a blob that tries to swallow the next amount, are the mitigation.

Outbound beams stall when the light client is past its weak-subjectivity window, when a beacon fork lands before the wasm upgrade, or when the canister is out of cycles. `certify_final` can be retried after catch-up, after `reset_checkpoint`, or after the fork upgrade. The Ethereum output is already spent. The funds are not returned, and they are not lost.

A sync committee that signs a false finality update for one period can cause a false beam. The protocol does not slash that signature. The vault cap bounds the loss, which is the same bound as a stolen finality key. A controller who upgrades the wasm or calls `reset_checkpoint` can do the same thing, and the guest key does not rotate to take that power away.

The admin who calls `upgradeToAndCall` chooses the next `Charms` implementation, and that bytecode chooses `tokenImplementation`. A `CharmToken` implementation runs as the clone, and `tokenTransfer` trusts that clone. A hostile implementation can move balances without an allowance check. That is the same admin authority as a hostile `Charms` implementation. There is no separate key for token logic.

The admin can call `upgradeToAndCall` immediately. That call can change the native path, the vault, and which proofs the contract accepts. There is no delay. The `programVKey` in the new implementation has to equal the reproducible `charms spell vk` output for that spell version. Watch the ERC-1967 implementation slot. An upgrade that changes `SpellCodec` or the `ethTxId` preimage without a protocol bump desynchronizes new spells from the guest.

A stolen metadata key can rename a charm and can freeze a wrong `decimals` on the first `setMetadata`. It cannot move balances or authorize a beam. The metadata key is not the Ethereum finality key.

## What is not decided here

The admin address, the `scrolls_ethereum` controller, the beacon API URL, and the execution API URL are chosen at deploy. The design does not name them.

The Ethereum address of the metadata key is fixed when `charms_metadata` is deployed. The design names the canister, the derivation path, and the signed digest. It does not name that address.

The bootstrap checkpoint, the `beamSourceAt` slot index, and the expected `Charms` implementation address are fixed when that implementation is deployed. `ws_period_epochs` starts from the Electra spec period for the stake at that time.

v16 keeps `FINALITY_TARGET_BITS` at its current value. The vault cap is the bound on a forged beam.
