---
CHIP: "0020"
Title: Charms on Ethereum
Status: Draft
Created: 2026-10-04
---

# CHIP-0020. Charms on Ethereum

Ethereum becomes a third host for the existing spell, UTXO, and beaming protocol. It does not get a second asset protocol.

Only a fungible charm, tag `t`, is an ERC-20. NFT (`n`), Scroll (`s`), custom-tag, and empty UTXOs stay UTXOs inside `Charms`. A caller moves those with `transact`, not with `transfer` or `transferFrom`. Charm tokens already defined by a tag-`t` `App` are held as UTXOs inside one `Charms` contract and projected as ERC-20s. Existing ERC-20s and ETH are locked in that contract and minted as vault charms, which beam to Bitcoin and Cardano and unlock only by burning the charm back on Ethereum. A vault charm is not a second token. Its ERC-20 face is the underlying asset, and ETH's face is `address(0)`. The charm moves as a UTXO through `transact`.

The contract is the consensus for Ethereum Charms transactions, in the same role Bitcoin consensus has for a Bitcoin transaction. The spell-checker guest is not rebuilt until a spell on some chain has to read an Ethereum transaction. That rebuild is protocol v16, and it is required before any beam crosses Ethereum. Local UTXOs, ERC-20 transfers, and the vault ship on v15 with no guest change.

## Decisions

| Question | Decision |
|---|---|
| UTXO model | One `Charms.transact` creates every output of one Charms transaction. Each output is its own `UtxoId` and is spent on its own later. |
| UTXO id | Content-addressed. Not the Ethereum transaction hash and not a counter. `TxId.0` is the reverse of that id, matching `UtxoId::to_bytes` and Cardano's `tx_id`. |
| Simple transfer | The contract checks it. The proof is empty. A proof on a spell the contract can check itself is rejected. |
| Anything else | Groth16 is verified on Ethereum, against the same public values Bitcoin and Cardano already use: CBOR of `([u8; 32] spell_vk, NormalizedSpell)` with `ins` and `coins` filled. |
| ERC-20 facade | One `CharmToken` per non-vault tag-`t` app. A vault app has no `CharmToken`, and neither does any other tag. For a non-vault app, `tokenAddress` is the CREATE2 address and does not deploy, and `ensureToken` deploys the minimal-proxy clone. For a vault app, both return the underlying ERC-20 recorded for that vault, or `address(0)` for ETH, and `ensureToken` does not deploy. `balanceOf`, `transfer`, and `transferFrom` apply only to a non-vault clone. `balanceOf` is the sum of that token across all of the address's unspent, non-beamed UTXOs. `transfer` spends whole UTXOs through the same apply path as `transact`. A vault charm moves through `transact`. The underlying token's `transfer` is unchanged. `_apply` does not deploy a clone. |
| ETH and foreign ERC-20s | Contract policy, not an app wasm. Vault `vk` is a constant with no wasm and no BIP-340 preimage, so other chains can only transfer and beam it. |
| Finality into Ethereum | Inside the v16 proof, via the existing `proven_final` (Bitcoin work, Cardano Scrolls signature). Solidity does not grow a light client. |
| Finality out of Ethereum | A new `scrolls_ethereum` canister signs the Charms tx id after the execution block is beacon-finalized. Same pattern as Cardano's `FINALITY_VKEY`. |
| Guest | Unchanged for Ethereum-local use. Rebuilt once, as v16, when `Tx` gains an `Ethereum` arm. |
| Upgrade | ERC-1967 proxy. Every call `delegatecall`s. The upgrade function lives on the implementation (OpenZeppelin UUPS), so `transact` and `transfer` do not pay an admin check. The proxy address is the stable `Charms` address. |

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
version: 15
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

This example is an ethereum-local simple transfer. Its spell version is 15. A beam, or any proved spell, uses version 16 and the v16 implementation. `coins[i].amount` is always 0. `coins[i].dest` is the raw 20-byte owner. `charms util dest --chain ethereum --addr 0x…` prints those 20 bytes. ETH held as a charm is the ETH vault charm. Its ERC-20 face is `address(0)`, not a `CharmToken` and not `NativeOutput.amount`.

A vault app does not follow the clone path above. `tokenAddress` and `ensureToken` return the underlying ERC-20 recorded for that vault, or `address(0)` when the asset is ETH. Neither call deploys a clone. The first `wrap` writes the record. The vault identity is a hash of that token, so before the record exists both calls revert and deploy nothing. Moving the charm is `transact`. `transfer` on the underlying token moves that token. It does not move the charm.

Beaming uses the fields that already exist.

```bash
# Placeholder on Ethereum. No proof. The id is known before submission.
charms spell prove --chain ethereum --spell placeholder.yaml \
  --caller 0xAlice --salt 0x… > ph.json
charms tx build --chain ethereum --tx "$(jq -c .tx ph.json)"

# Bitcoin beams to sha256(UtxoId::to_bytes() of that id), as it does today.
# After Bitcoin finality, claim on Ethereum.
# A claim is not a local simple transfer, so it has a proof.
charms spell prove --chain ethereum --spell claim.yaml \
  --beamed-from '{0: ["<btc-txid>:<vout>"]}' \
  --prev-txs "$(jq -c .tx ph.json)" \
  --prev-txs btc-with-block-proof.json > claim.json
```

`ph.json` has one field, `tx`. That value is the Charms record for an empty UTXO. `spell prove` takes no `--prev-txs`. The spell mints nothing and burns nothing, so the command does not call the prover.

The record carries `chain_id`, `charms`, `anchor`, `spell`, and `proof`. It also carries `caller` and `salt`, the preimage of `anchor`. `eth_tx_id` does not hash `caller` or `salt`. A wallet cannot sign the record.

`charms tx build --chain ethereum` takes that `tx` and no other spell input. It constructs the signable `transact` call. That call is what gets executed. The wallet adds the account nonce, the gas fields, and the signature.

The other direction marks `beamed_outs` on an Ethereum spell whose token sums still balance (the beamed output counts). That spell is native: no proof. After beacon finality, `charms tx fetch --chain ethereum --tx-id <id> --finality` returns `EthereumTx::WithFinalityProof`, and the Bitcoin or Cardano claim is an ordinary spell.

## Contracts

Deploy a proxy and an implementation. CharmToken contracts and the external Groth16 verifier sit beside them. Everything else is internal to the implementation.

- `CharmsProxy` is the address wallets, tokens, and the guest call `Charms`. Its `fallback` and `receive` always `delegatecall` the implementation in the ERC-1967 slot. It has no other functions and no admin branch. The storage slot is ERC-1967 (`keccak256("eip1967.proxy.implementation") - 1`), the slot OpenZeppelin's UUPS implementation uses. This is not the EIP-1822 `PROXIABLE` slot. Every call is delegated, and the upgrade function is not on the proxy bytecode, so a transfer does not pay for an admin check the way a transparent proxy does.
- `Charms` is the implementation. It owns UTXOs, supply, balances, the vault, and anchors, in the proxy's storage. `ensureToken` deploys a `CharmToken` only for a non-vault tag-`t` app. For a vault app it returns the underlying address and deploys nothing. It also exposes `upgradeToAndCall`. The admin is a single address set at initialization. That address is the only account that can upgrade. There is no timelock and no second role.
- `CharmToken` is the ERC-20 for one non-vault tag-`t` app. It is a clone: a minimal proxy with immutable arguments. Its fallback appends the packed `App` and a `uint16` length to calldata, then `delegatecall`s one shared `CharmToken` implementation. The per-token bytecode is that proxy, not a separately compiled contract. It owns allowances, EIP-2612 nonces, and metadata. It owns no balances. There is no `CharmToken` for a vault app, tag `n`, tag `s`, a custom tag, or an empty UTXO.
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
    /// `scrolls_ethereum` reads this at the `finalized` tag.
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
    /// spell versions and `programVKey`s are compiled into the new implementation, so the
    /// upgrade has nothing further to call.
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
}

/// @notice User-facing ERC-20 for one non-vault fungible charm, tag `t`.
/// Wallets, routers, and DeFi call this. One per such app. A vault app has
/// no clone. NFT, Scroll, custom-tag, and empty UTXOs are not this interface.
/// @dev The deployed bytecode forwards calldata plus the packed `App` and a `uint16`
/// length, then `delegatecall`s a shared implementation.
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

    /// @notice ERC-20 name. CHIP-0420 `name` once published, and `"Charm"` until then.
    /// A vault app has no clone and does not copy the underlying token's name.
    function name() external view returns (string memory);

    /// @notice ERC-20 symbol. This is CHIP-0420 `ticker`, not a separate field. `"CHARM"`
    /// until `ticker` is published. A vault app does not copy the underlying symbol.
    function symbol() external view returns (string memory);

    /// @notice Display decimals. CHIP-0420 `decimals`, default 0. A vault app has no
    /// clone decimals. Scale is not part of the vault `App`.
    function decimals() external view returns (uint8);

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

    /// @notice EIP-712 domain separator for `permit`. The signing wallet reads this.
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
  ‖ charmTokenImplementation
  ‖ hex"5af43d3d93803e603557fd5bf3"
  ‖ appData
  ‖ hex"0044"
```

`charmTokenImplementation` is 20 bytes. The fallback copies caller calldata to memory, `CODECOPY`s `extraLength` bytes from runtime offset `0x37` onto the end of that copy, and `delegatecall`s `charmTokenImplementation` with args length `calldatasize + extraLength`. The copied bytes are the 68-byte `App` and the trailing `uint16` length. The implementation reads `appData` as the 68 bytes immediately before that `uint16` on `msg.data`. `charmTokenImplementation` is fixed before the first clone and is part of this init code, so it is part of `tokenAddress`. `tokenAddress = CREATE2(CharmsProxy, appKey, creation ‖ runtime)`.

### Upgrade

Deploy the implementation first. Its constructor calls `_disableInitializers()`, so `initialize` cannot be called on the implementation contract. Only the proxy's `delegatecall` can run it, and the initializer rejects a second call. Deploy the proxy second. Its address is `CREATE2(deployer, salt, initCode)` with `salt = keccak256("charms-proxy-v1")`. `deployer` is a deploy-time parameter. The CHIP does not name that account. `initCode` is the proxy creation code that writes `implementation` into the ERC-1967 slot and `delegatecall`s `initialize(admin)`. `admin` is also a deploy-time parameter. That call is not part of `ICharms`. It runs once and stores the admin. The resulting proxy address is `ETHEREUM_CHARMS`. It is the `address(Charms)` mixed into `ethTxId`, the vault identity, and `tokenAddress`. Replacing the implementation does not change those ids.

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

A balanced beam-out is native: the beamed output counts in the token sum, and the proof is empty. A beam-in is not native, because the placeholder input is empty and the outputs gain charms, so it carries a proof. The phase-1 implementation is not beaming-capable. It rejects any spell with `beamedOuts`, and it rejects proofs. The v16 implementation is beaming-capable. A non-empty `beamedOuts` on that implementation does not by itself require Groth16.

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

A proved spell must spend at least one input. The proof does not commit to the anchor, so a zero-input proved spell could be replayed under a fresh salt. Bitcoin and Cardano transactions have an input. `hosting_chain_is_bitcoin` looks at the creator of `ins[0]`; an empty input list would make that undefined.

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

The query is `finality_public_key`. Cardano's Rust constant for the same kind of key is `FINALITY_VKEY`. The canister method keeps its own name. `certify_final` calls `Charms.beamSourceAt(ethTxId)` through the ICP EVM RPC canister at block tag `finalized`, requiring the same answer from at least three providers. If the stored block number is non-zero, it signs with `sign_with_schnorr` (Ed25519) under the derivation path `["scrolls", "ethereum", "finality"]`.

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
    pub anchor: Option<[u8; 32]>, // set only when ins is empty
    pub spell: Vec<u8>,           // committed CBOR, the id preimage
    pub proof: Vec<u8>,           // empty on the native path; not in the id
    pub caller: Option<[u8; 20]>, // anchor preimage; not in the id
    pub salt: Option<[u8; 32]>,   // anchor preimage; not in the id
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

An empty UTXO has no apps. It mints nothing and burns nothing. `spell prove` builds that record locally, takes no `--prev-txs`, and does not call the prover. `proof` stays empty. The printed `tx` is the only spell input `tx build` needs. `tx build` constructs the signable `transact` call, and that call is what gets executed.

The CLI decides the native path for any other spell too. If the spell is `t` and `n` only, sums and NFT sets match, public inputs are null, there is no `--beamed-from`, and pins are unchanged, it builds the record locally and leaves `proof` empty. Otherwise it calls `POST /spells/prove`. The response is `vec![Tx::Ethereum(Simple(...))]`, with the proof filled in when the spell is not native.

`CharmsFee.fee_rate` and `fee_base` stay in sats, as in `charms-client/src/request.rs`. Ethereum does not reuse those fields as wei, and this design does not add a wei field to `CharmsFee`. `transact` does not charge a Charms fee. The wallet pays Ethereum gas. `ProveRequest.fee_rate` is ignored for `chain = ethereum`.

CLI:

| Command | Behavior |
|---|---|
| `spell prove --chain ethereum` | For an empty UTXO, prints JSON whose only field is `tx`. No `--prev-txs`. Nothing is minted or burned, so the prover is not called. `tx` is the Charms record. It is enough for `tx build` to construct the signable `transact` call. `--caller` and `--salt` are required when `ins` is empty. `--change-address` stays required for Bitcoin and Cardano only. |
| `tx build --chain ethereum` | Takes that `tx` and constructs the signable `transact` call. That call is what gets executed. |
| `spell check --chain ethereum` | Runs `is_correct` once the guest knows Ethereum prev txs. Before that, it runs the native predicate and refuses a spell that would need a proof. |
| `tx show-spell --chain ethereum` | Decodes an envelope or a `Transaction` log. |
| `tx fetch --chain ethereum --tx-id <id> [--finality]` | Rebuilds the record from `Transaction`. `--finality` calls the canister. |
| `util dest --chain ethereum --addr 0x…` | Raw 20 bytes. Accepts EIP-55, stores the lowercase bytes. |
| `util eth-token <APP>` | For a non-vault app, the CREATE2 address from the same formula as `tokenAddress`. For a vault app, the underlying address, `address(0)` for ETH. Does not deploy. |
| `util eth-vault --token <addr\|eth>` | Prints the vault `App`. The `App` does not take a decimals argument. ETH's scale is 10. An ERC-20's scale is derived from `decimals()` and printed beside the `App`. |

App contracts are unchanged. `app_contract` sees `coin_outs[i].amount == 0` and a 20-byte `dest`. An app that wants to move ETH moves the vault charm. `charms-sdk` and the app runner do not change. `charms-lib`'s `extractAndVerifySpell` learns the Ethereum envelope in the v16 bump, and the binding documents that a decoded spell is content-authenticated: acceptance of a created output is `utxo(UtxoRef)` on the contract. Acceptance of a beam-out is `beamSourceAt(ethTxId) != 0`.

## Protocol version

| Phase | Spell version | Guest | Keys |
|---|---|---|---|
| Ethereum-local | Records are version 15. The phase-1 implementation accepts that version and rejects proofs and `beamed_outs`. | No rebuild. `Tx` has no Ethereum arm, and nothing outside Ethereum reads these records. | v15 verifying keys stay. |
| Beaming and proved spells | Version 16. `CURRENT_VERSION = 16`. | Rebuild. `SpellProverInput.prev_txs` deserializes `Tx`. A new arm is a new spell-checker ELF, a new `SPELL_CHECKER_VK` in `charms-proof-wrapper`, and a new wrapper verifying key. | Publish `spell_vk` for v16 from `charms spell vk` on the reproducible build. Compile that `programVKey` into the new implementation. The admin upgrades the proxy to it. |

The Groth16 circuit key is not assumed to change and is not assumed to stay. v15's `groth16_vk.bin` aliases v14's because that bump did not rebuild the wrapper. v16 rebuilds the wrapper. If the new `groth16_vk.bin` is byte-identical, alias it and keep the stock verifier. If it is not, publish the new bytes; the proof's 4-byte prefix follows them. Either way the value that changes for certain is the wrapper's `programVKey`, because the wrapper hardcodes the spell-checker key. `to_serialized_pv` stays on the v15 arm (`([u8; 32], NormalizedSpell)`). Bitcoin and Cardano transaction layouts do not change.

Which spell versions an implementation accepts, and the `programVKey` for each, are part of that implementation's code. The phase-1 implementation accepts new spells of version 15 only. The v16 implementation accepts new spells of version 16 only. It still spends UTXOs created by version-15 spells, because that state is in `head` and `body`. It rejects a new spell whose version is 15. A protocol bump is a new implementation plus `upgradeToAndCall(newImplementation, "")` from the admin. Token addresses and `ETHEREUM_CHARMS` stay on the proxy. A new proxy would change every token address and the guest constant. That is a new deployment, not an upgrade.

The usual v16 chores ride along: Cardano's protocol-version NFT, `scrolls_bitcoin` delegation, `scrolls_cardano`, and `charms-lib`'s `SPELL_VK`. `CHARMS_PROVE_API_URL` becomes `https://v16.charms.dev/spells/prove`.

## Edge cases

- **ETH versus a wrapped ERC-20.** ETH is the vault at `address(0)`. WETH is a different vault. They do not share supply.
- **Allowances.** Non-vault charm allowances live on `CharmToken`. A vault charm has no allowance surface. The underlying token's `approve` is only for `wrap`, and it names `Charms`. `tokenTransfer` rejects a vault app. For a non-vault app it checks `msg.sender` is the token whose CREATE2 address it just recomputed. The underlying token's `transfer` does not move the vault charm.
- **Several charms on one UTXO.** One `head` record, one list entry per `t` app, one balance contribution per `t` app. Spending via the tag-`t` token preserves the other `t` or `n` charms on a sender-owned change output, including when this token's remainder is zero. An `n` charm, an `s` charm, a custom-tag charm, or an empty UTXO is spent with `transact`.
- **Empty UTXOs.** Allowed, required as beam targets, indexed only in `emptyUtxos` and `head`. They do not affect supply.
- **u64.** A single output amount and the sum of a spell's inputs of one app must fit in `u64`, because the guest adds them as `u64`. Balances in storage are `uint256` so many UTXOs can sum past `u64`; the facade then needs more than one call, each under the cap.
- **Weird tokens.** Fee-on-transfer reverts on `wrap`. On `unwrap`, only a fee taken out of the amount sent is accepted: the recipient's balance may end below what it was plus the amount unwrapped, and that shortfall does not revert. A fee charged on top of the amount is unsupported. It reverts when the vault holds exactly `locked`, and with surplus it can leave `held < locked` so later vault operations fail. Rebasing is unsupported. A token that blocklists `Charms` can freeze that vault and no other. The first `wrap` stores the canonical `scale`. A later `decimals()` that would change it reverts. The `App` stays the one identity above.
- **Mixed pins.** After a versioned app bumps its version, one owner can hold UTXOs pinned to different versions. The facade reverts with `MixedVersions` when the inputs it would select do not share a pin. A proved `transact` runs the new binary, which is what `authorize_version_changes` already requires.
- **Reorgs.** A native transfer reorgs with Ethereum, like any ERC-20. A beam waits for `finalized`.
- **History.** `Transaction` carries the spell CBOR because `wrap`, `unwrap`, and the facade build it inside the contract, where it is not in calldata. Proving a later spend of a bundle needs that record. Native spends of plain UTXOs do not: `head` has the amount. Indexers archive the logs; EIP-4444 makes that an operator concern, not a consensus one.

## Build order

**Phase 0. Codec and verifier, no protocol change.** `SpellCodec` and `CborWellFormed`. Golden vectors from `util::write` cover `spellCbor` and `to_serialized_pv`. They do not cover the `ethTxId` prefix. A second vector checks `keccak256(prefix ‖ spellCbor)`. The fork test calls `ISP1Verifier.verifyProof(programVKey, publicValues, proofBytes)` with `publicValues = to_serialized_pv` and `proofBytes` the Charms `Proof` that `verify_gnark_v6` accepts for v15 (`SP1_V6_2_VK_ROOT`). The verifier address is an input to the test and, later, a constant in the v16 implementation. The CHIP does not hardcode a chain address. Done when the CBOR vectors match, the id-preimage vector matches, the vault-identity vector matches with no scale byte, and that proof verifies.

**Phase 1. Ethereum-local, still v15.** `CharmsProxy`, `Charms`, the shared `CharmToken` implementation, and the per-app clones: native `transact`, the deque, EIP-712 and ERC-1271, the vault, events, and ERC-1967 upgrade under the admin. The phase-1 implementation accepts spell version 15 and rejects proofs and `beamed_outs`. Host-side Rust for the record type and `tx_id`, behind a feature the guest does not compile. CLI for native spells, `util dest`, `util eth-token`, `util eth-vault`. Invariant tests for the supply, balance, and `locked` tables, plus a test that an upgrade keeps token addresses and existing `UtxoId`s. Audit, then the CREATE2 proxy deployment that fixes `ETHEREUM_CHARMS`. No beaming and no proofs.

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
