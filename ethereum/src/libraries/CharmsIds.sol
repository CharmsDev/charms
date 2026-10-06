// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Content-addressed ids that other chains recompute: the Charms transaction id and the
/// vault identity.
library CharmsIds {
    /// @notice `ethTxId = keccak256("charms/ethereum/tx/v1" ‖ chainid as uint256 ‖ Charms proxy
    /// ‖ anchor ‖ committed spell CBOR)`. `UtxoId`'s `TxId.0` is this value reversed.
    function ethTxId(uint256 chainId, address charms, bytes32 anchor, bytes memory spellCbor)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(abi.encodePacked("charms/ethereum/tx/v1", chainId, charms, anchor, spellCbor));
    }

    /// @notice `SHA-256("charms/ethereum/vault/v1" ‖ chainid as uint256 ‖ Charms proxy ‖ token)`,
    /// with 20 zero bytes for ETH. No scale byte, so one asset has one vault `App`.
    function vaultIdentity(uint256 chainId, address charms, address token)
        internal
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked("charms/ethereum/vault/v1", chainId, charms, token));
    }
}
