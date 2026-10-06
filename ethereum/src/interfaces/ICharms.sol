// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";

/// @notice Shared structs. No functions. The other interfaces use these so `App` is defined once.
/// @dev Wallets, CharmToken, and the CLI all pass `App` through. 't' = 0x74, 'n' = 0x6e,
/// 's' = 0x73.
interface ICharmsTypes {
    /// @notice Unicode scalar tag plus the 32-byte identity and vk. Same triple as
    /// `charms_data::App`.
    struct App {
        uint32 tag;
        bytes32 identity;
        bytes32 vk;
    }

    /// @notice One `NormalizedSpell.versioned_apps` entry.
    struct Pin {
        bytes32 vk;
        uint32 version;
        bytes32 wasmHash;
    }

    /// @notice One charm on an input or output. `app` indexes `Spell.apps`.
    /// @dev Tag `t`: `amount > 0` and `data` empty. The contract writes the CBOR uint.
    ///      Any other tag: `amount == 0` and `data` is exactly one CBOR item.
    struct Charm {
        uint32 app;
        uint64 amount;
        bytes data;
    }

    /// @notice An Ethereum UTXO. `txId` is `ethTxId` in keccak byte order.
    struct UtxoRef {
        bytes32 txId;
        uint32 index;
    }

    /// @notice A spent UTXO plus the opening of what the contract stored for it.
    struct Input {
        UtxoRef utxo;
        Charm[] charms;
        Pin[] pins;
    }

    /// @notice A created output. `owner == address(0)` iff its index is in `beamedOuts`.
    struct Output {
        address owner;
        Charm[] charms;
    }

    struct BeamedOut {
        uint32 index;
        bytes32 destHash;
    }

    /// @notice Typed mirror of `NormalizedSpell`. The contract fills `tx.ins` and `tx.coins`.
    struct Spell {
        uint32 version;
        App[] apps; // app_public_inputs keys, strictly increasing
        bytes[] publicInputs; // one CBOR data item each; hex"f6" is null
        Pin[] versionedApps; // strictly increasing by vk
        Input[] ins;
        UtxoRef[] refs;
        Output[] outs;
        BeamedOut[] beamedOuts;
        uint32[] scrolls;
    }
}

/// @notice Ledger calls from a tag-`t` `CharmToken`. The token stores this address (the Charms
/// proxy) and nothing wider.
/// @dev Only tag `t` has this surface. `CharmToken.transfer` and `transferFrom` are the only
/// callers of `tokenTransfer`. `balanceOf` and `totalSupply` on that token read the two views.
/// DeFi calls the token, not this interface. `tokenTransfer` does not deploy a `CharmToken`.
interface ICharmsLedger {
    /// @notice Move `amount` of `app` from `from` to `to` by spending whole UTXOs and creating
    /// change.
    /// @dev `app.tag` must be `t`, and `app` must not be a vault. Only the CREATE2 `CharmToken`
    /// for that app may call this. The token has already checked `msg.sender` and the allowance.
    /// A vault charm moves through `transact`.
    function tokenTransfer(ICharmsTypes.App calldata app, address from, address to, uint256 amount)
        external;

    /// @notice Ethereum-resident supply of one charm. The token's `totalSupply` returns this.
    function totalSupply(bytes32 appKey) external view returns (uint256);

    /// @notice Sum of this charm on `owner`'s unspent, non-beamed UTXOs. The token's `balanceOf`
    /// returns this.
    function balanceOf(bytes32 appKey, address owner) external view returns (uint256);

    /// @notice The token's ERC-20 `name`. A non-vault clone forwards here because its
    /// implementation is part of `tokenAddress` and cannot change, while this policy can.
    /// @dev `"Charm"` until CHIP-0420 metadata is published. A vault app has no clone and no
    /// second name.
    function name(ICharmsTypes.App calldata app) external view returns (string memory);

    /// @notice The token's ERC-20 `symbol`. Forwarded for the same reason as `name`.
    /// @dev `"CHARM"` until CHIP-0420 `ticker` is published.
    function symbol(ICharmsTypes.App calldata app) external view returns (string memory);

    /// @notice The token's ERC-20 `decimals`. Forwarded for the same reason as `name`.
    /// @dev `0` until CHIP-0420 `decimals` is published.
    function decimals(ICharmsTypes.App calldata app) external view returns (uint8);
}

/// @notice The `Transaction` log and every revert reason of the Charms proxy.
interface ICharmsErrors {
    /// @notice A Charms transaction was applied. Indexers and `tx fetch` read `txId` and `spell`
    /// from this log.
    /// @dev `spell` is the committed CBOR. `anchor` is zero when the spell spent inputs.
    event Transaction(bytes32 indexed txId, bytes32 anchor, bytes spell);

    error UnsupportedVersion(uint32 version);
    error NotCanonical();
    error LimitExceeded();
    error InvalidTag();
    error InputSpent();
    error OpeningMismatch();
    error RefNotLive();
    error AnchorUsed();
    error SaltNotZero();
    error NotPlaceholderOrWrap();
    error BadSignatureCount();
    error BadSignature(address owner);
    error ProofNotRequired();
    error ProofRequired();
    error ProofsUnsupported();
    error BeamingUnsupported();
    error ProvedSpellWithoutInputs();
    error MalformedBlob();
    error NotTokenTag();
    error NotToken();
    error InvalidRecipient();
    error ZeroAmount();
    error AmountTooLarge();
    error InsufficientBalance();
    error RequiresProvedSpell();
    error MixedVersions();
    error ScaleChanged();
    error InvalidDecimals();
    error UnderlyingAmountMismatch();
    error EthTransferFailed();
    error VaultUndercollateralized();
    error MetadataUnspecified();
    error EthRejected();
    error NotAdmin();
    error ZeroAdmin();
    error InvalidCursor();
    error ZeroLimit();
    error NotDelegated();
}

/// @notice Spell and vault API. Wallets, the CLI, and contracts that build spells call this on
/// the proxy.
/// @dev Does not include `ICharmsLedger`. Those callers use the ERC-20 for balances and do not
/// call `tokenTransfer`.
interface ICharms is ICharmsErrors {
    /// @notice Spend `spell.ins` and create `spell.outs`. Returns the new `ethTxId`.
    /// @dev Wallets and the CLI call this for any spell that is not an ERC-20 `transfer` or a
    /// vault lock or unlock. `proof` is empty when the contract can check the spell itself, and
    /// required otherwise. `salt` is used when `ins` is empty (a placeholder). Otherwise `salt`
    /// is 0. `signatures` has one entry per input owner other than `msg.sender`, in order of first
    /// appearance, over EIP-712 `Spend(bytes32 txId)`. ECDSA or ERC-1271 `staticcall`.
    function transact(
        ICharmsTypes.Spell calldata spell,
        bytes32 salt,
        bytes calldata proof,
        bytes[] calldata signatures
    ) external returns (bytes32 txId);

    /// @notice Lock the underlying ERC-20, or ETH when `token` is `address(0)`, and mint that
    /// vault charm to `owner`.
    /// @dev The holder calls this after `approve` on the underlying token. `amount` is in vault
    /// units. `salt` names this zero-input creation.
    function wrap(address token, uint64 amount, address owner, bytes32 salt)
        external
        payable
        returns (bytes32 txId);

    /// @notice Burn `amount` of `msg.sender`'s vault charm and send the underlying asset to `to`.
    /// @dev The holder calls this. The underlying token is the one recorded for that vault.
    function unwrap(address token, uint64 amount, address to) external returns (bytes32 txId);

    /// @notice ERC-20 face of a tag-`t` `app`. Does not deploy.
    /// @dev A non-vault app returns the CREATE2 address of its `CharmToken`. That address
    /// depends only on `app` and this contract. A vault app returns the underlying ERC-20
    /// recorded for that vault on the first `wrap`, or `address(0)` for ETH. The identity is a
    /// hash, so before that record exists the call reverts and no clone is deployed. Any tag
    /// other than `t` reverts.
    function tokenAddress(ICharmsTypes.App calldata app) external view returns (address);

    /// @notice ERC-20 face of a tag-`t` `app`. A non-vault app deploys its `CharmToken` clone
    /// when no code is at `tokenAddress(app)`. A vault app does not deploy.
    /// @dev A vault app returns the same address as `tokenAddress`. If the non-vault clone is
    /// already there, return that address. Any tag other than `t` reverts. `_apply` and
    /// `tokenTransfer` do not call this.
    function ensureToken(ICharmsTypes.App calldata app) external returns (address token);

    /// @notice Page through `owner`'s UTXOs for one app. Wallets and the CLI use this to build a
    /// spell. `transfer` does not.
    /// @dev `appKey == 0` pages `owner`'s empty UTXOs. Pass `cursor` 0 for the first page and
    /// then the `nextCursor` the previous page returned, which is 0 when the list is exhausted.
    /// A cursor names a live UTXO of this list, not a position. Any other cursor, including one
    /// whose UTXO was spent after it was returned, reverts with `InvalidCursor`. Read every page
    /// at one block (`eth_call` with a fixed block tag) to collect every UTXO live at that block.
    /// A wallet that reads at the latest block restarts from 0 on `InvalidCursor`. `limit` must
    /// not be 0.
    function utxosOf(bytes32 appKey, address owner, uint256 cursor, uint256 limit)
        external
        view
        returns (ICharmsTypes.UtxoRef[] memory page, uint256 nextCursor);

    /// @notice The stored record for one UTXO. `charms-lib` and an indexer call this to see that
    /// the contract accepted the output.
    /// @dev `kind` is 0 Empty, 1 Plain, 2 Bundle. `body` is empty for Empty and for an unpinned
    /// Plain token. A missing id returns kind 0 and `owner == address(0)`.
    function utxo(ICharmsTypes.UtxoRef calldata u)
        external
        view
        returns (uint8 kind, address owner, uint64 amount, bytes memory body);

    /// @notice The one vault `App` for `token` and its canonical `scale`. Holders and indexers use
    /// this before `wrap` or `unwrap`.
    /// @dev `app` does not depend on `scale`. ETH (`token == address(0)`) is always `scale` 10.
    /// An ERC-20's `scale` is derived from `decimals()` by the rule in Vault.
    /// `token.balanceOf(charms)`, or the ETH balance of `charms` for the ETH vault, is what
    /// `charms` holds, not the committed vault backing. A direct transfer raises it without
    /// raising `locked`, so it can exceed `locked`. `locked` is not returned; it stays an internal
    /// check in `_checkVaults`.
    function vaultOf(address token) external view returns (ICharmsTypes.App memory app, uint8 scale);

    /// @notice Block number of a beam-out, or 0 if that id did not beam. `scrolls_ethereum` reads
    /// this at the `finalized` tag.
    function beamSourceAt(bytes32 txId) external view returns (uint256 blockNumber);
}

/// @notice Upgrade API on the implementation. The admin is the only caller. Spell clients and
/// CharmToken contracts do not use this. The slot is ERC-1967, as in OpenZeppelin UUPS.
/// @dev `Charms` implements this beside `ICharms` and `ICharmsLedger`. The proxy itself has no
/// upgrade function. It only `delegatecall`s. `proxiableUUID` comes from `IERC1822Proxiable`:
/// the ERC-1967 implementation slot, which the new implementation must return or the upgrade
/// reverts.
interface IUpgradeable is IERC1822Proxiable {
    /// @notice Point the proxy at `newImplementation`.
    /// @dev The admin calls this on the proxy. `msg.sender` must be the admin and
    /// `address(this)` must be the proxy. A non-empty `data` is `delegatecall`ed on the new
    /// implementation after the ERC-1967 slot is written. This design always passes empty `data`.
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
}

/// @notice What `Charms` calls on a `CharmToken`. The token implements this. Holders do not.
interface ICharmTokenHooks {
    /// @notice Emit ERC-20 `Transfer` from the token address. `Charms` is the only caller.
    /// @dev A spell emits `Transfer(sender, Charms, decrease)` and `Transfer(Charms, receiver,
    /// increase)` on a deployed non-vault clone. `Charms` is the proxy. A facade `transfer` or
    /// `transferFrom` emits `Transfer(from, to, amount)` instead, including a self-transfer.
    /// `_apply` does not deploy the clone in order to emit.
    function emitTransfer(address from, address to, uint256 amount) external;
}

/// @notice User-facing ERC-20 for one non-vault fungible charm, tag `t`. Wallets, routers, and
/// DeFi call this. One per such app. A vault app has no clone: its ERC-20 face is the underlying
/// token, or `address(0)` for ETH, and the charm moves through `transact`. NFT, Scroll,
/// custom-tag, and empty UTXOs are not this interface.
/// @dev The deployed bytecode forwards calldata plus the packed `App` and a `uint16` length, then
/// `delegatecall`s a shared implementation. Implements IERC-20, IERC-20 metadata, and EIP-2612.
/// Allowances and permit nonces live here. An infinite allowance is not decremented. The token
/// also implements `ICharmTokenHooks`.
interface ICharmToken {
    /// @notice `Transfer` and `Approval` are the ERC-20 events. `Charms` causes `Transfer` by
    /// calling `emitTransfer` when this clone is already deployed. A facade move is
    /// `Transfer(from, to, amount)`. A spell move uses the Charms proxy as the counterparty.
    /// Holders cause `Approval` by calling `approve` or `permit`.
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    error NotCharms();
    error InsufficientAllowance();
    error PermitExpired();
    error InvalidSigner();

    /// @notice The Charms proxy this token reads and calls.
    function charms() external view returns (ICharmsLedger);

    /// @notice The `App` in this token's immutable args.
    function app() external view returns (ICharmsTypes.App memory);

    /// @notice Ethereum-resident supply. Forwards to `ICharmsLedger.totalSupply`.
    function totalSupply() external view returns (uint256);

    /// @notice This charm's total on `owner`'s UTXOs. Forwards to `ICharmsLedger.balanceOf`.
    function balanceOf(address owner) external view returns (uint256);

    /// @notice Spend the caller's UTXOs and create one output for `to`. Calls `tokenTransfer`.
    function transfer(address to, uint256 amount) external returns (bool);

    /// @notice Remaining amount `spender` may move from `owner`. Stored on this token.
    function allowance(address owner, address spender) external view returns (uint256);

    /// @notice Let `spender` move up to `amount` of the caller's balance.
    function approve(address spender, uint256 amount) external returns (bool);

    /// @notice `spender` moves `amount` from `from` to `to`. This token decrements the allowance,
    /// then calls `tokenTransfer`.
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    /// @notice ERC-20 name. Forwards to `ICharmsLedger.name`. `"Charm"` until CHIP-0420 metadata
    /// is published.
    function name() external view returns (string memory);

    /// @notice ERC-20 symbol. Forwards to `ICharmsLedger.symbol`. `"CHARM"` until CHIP-0420
    /// `ticker` is published.
    function symbol() external view returns (string memory);

    /// @notice Display decimals. Forwards to `ICharmsLedger.decimals`. `0` until CHIP-0420
    /// `decimals` is published.
    function decimals() external view returns (uint8);

    /// @notice EIP-2612. The holder signs an allowance off-chain. A router submits it and then
    /// calls `transferFrom`.
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
