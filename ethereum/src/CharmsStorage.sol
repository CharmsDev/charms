// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharmsErrors, ICharmsTypes} from "./interfaces/ICharms.sol";
import {CharmTokenClone} from "./libraries/CharmTokenClone.sol";
import {UtxoList} from "./libraries/UtxoList.sol";

/// @notice The v1 storage layout of the Charms proxy, and the types and keys that `Charms` and
/// `CharmsApply` share. Both run in the proxy's storage: `Charms` behind the proxy and
/// `CharmsApply` through `Charms`'s `delegatecall`.
abstract contract CharmsStorage is ICharmsTypes, ICharmsErrors {
    uint32 internal constant TAG_T = 0x74;
    uint32 internal constant TAG_N = 0x6e;
    /// @dev SHA-256("charms/ethereum/vault/v1"). No wasm and no BIP-340 key hashes to this.
    bytes32 internal constant VAULT_VK =
        0xb5db9f943cfb299964f85a136ddbfe0f58363ee9e7b4ca7606b7bebde0c6f274;
    uint256 internal constant MAX_ITEMS = 64;
    bytes internal constant CBOR_NULL = hex"f6";

    enum Kind {
        Empty,
        Plain,
        Bundle
    }

    /// @dev `link` is the app key of a Plain UTXO and the hash of `body` for a Bundle.
    struct Head {
        address owner;
        Kind kind;
        uint8 index;
        uint64 amount;
        bytes32 txId;
        bytes32 link;
    }

    struct Vault {
        bytes32 appKey;
        uint8 scale;
        uint256 locked;
    }

    /// @dev Set only by `wrap` (positive) and `unwrap` (negative). `delta` is in vault units.
    struct VaultMove {
        address token;
        bytes32 appKey;
        uint8 scale;
        int256 delta;
    }

    /// @dev Inputs owned by `authorized` need no signature. `anchor` is zero unless the spell has
    /// no inputs.
    struct Context {
        bytes32 anchor;
        address authorized;
        VaultMove move;
        bytes proof;
        bytes[] signatures;
    }

    // v1 storage layout. Append only; never reorder, insert, or retype.
    mapping(bytes32 appKey => uint256) internal supply;
    mapping(address owner => mapping(bytes32 appKey => uint256)) internal balance;
    mapping(address owner => mapping(bytes32 appKey => UtxoList.List)) internal utxos;
    mapping(address owner => UtxoList.List) internal emptyUtxos;
    mapping(bytes32 utxoKey => Head) internal head;
    mapping(bytes32 utxoKey => bytes) internal body;
    mapping(bytes32 anchor => bool) internal usedAnchors;
    mapping(bytes32 txId => uint256 blockNumber) internal beamSources;
    mapping(address token => Vault) internal vaults;
    address public admin;
    mapping(bytes32 appKey => address token) internal vaultTokens;
    uint256[50] private __gap;

    function _appEq(App memory a, App memory b) internal pure returns (bool) {
        return a.tag == b.tag && a.identity == b.identity && a.vk == b.vk;
    }

    /// @dev `App`'s `Ord`: tag, then identity, then vk.
    function _appLess(App memory a, App memory b) internal pure returns (bool) {
        if (a.tag != b.tag) return a.tag < b.tag;
        if (a.identity != b.identity) return a.identity < b.identity;
        return a.vk < b.vk;
    }

    function _utxoKey(bytes32 txId, uint32 index) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(txId, index));
    }

    function _tokenAddress(App memory app) internal view returns (address) {
        return CharmTokenClone.predict(address(this), _charmTokenImplementation(), app);
    }

    /// @dev `CREATE(proxy, nonce 1)`, which `initialize` checks.
    function _charmTokenImplementation() internal view returns (address) {
        return
            address(
                uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), hex"01"))))
            );
    }
}
