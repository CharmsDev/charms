// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICharmsTypes} from "../interfaces/ICharms.sol";

/// @notice The stored record of a Bundle UTXO: its charms with their full `App`s, then the pins
/// stored for it. Big-endian and packed:
/// `uint8 n ‖ n × (uint32 tag ‖ bytes32 identity ‖ bytes32 vk ‖ uint64 amount ‖ uint32 len ‖ data)
///  ‖ uint8 m ‖ m × (bytes32 vk ‖ uint32 version ‖ bytes32 wasmHash)`.
/// @dev Only the contract writes these bytes, so `decode` trusts them.
library UtxoBody {
    struct Held {
        ICharmsTypes.App app;
        uint64 amount;
        bytes data;
    }

    function encode(
        ICharmsTypes.App[] memory apps,
        ICharmsTypes.Charm[] memory charms,
        ICharmsTypes.Pin[] memory pins
    ) internal pure returns (bytes memory b) {
        uint256 len = 2 + pins.length * 68;
        for (uint256 i; i < charms.length; ++i) {
            len += 80 + charms[i].data.length;
        }
        b = new bytes(len + 32);
        uint256 p;
        assembly ("memory-safe") {
            p := add(b, 32)
        }
        p = _put(p, charms.length, 1);
        for (uint256 i; i < charms.length; ++i) {
            ICharmsTypes.Charm memory c = charms[i];
            ICharmsTypes.App memory a = apps[c.app];
            p = _put(p, a.tag, 4);
            p = _put(p, uint256(a.identity), 32);
            p = _put(p, uint256(a.vk), 32);
            p = _put(p, c.amount, 8);
            p = _put(p, c.data.length, 4);
            p = _copy(p, c.data);
        }
        p = _put(p, pins.length, 1);
        for (uint256 i; i < pins.length; ++i) {
            p = _put(p, uint256(pins[i].vk), 32);
            p = _put(p, pins[i].version, 4);
            p = _put(p, uint256(pins[i].wasmHash), 32);
        }
        assembly ("memory-safe") {
            mstore(b, len)
        }
    }

    function decode(bytes memory b)
        internal
        pure
        returns (Held[] memory held, ICharmsTypes.Pin[] memory pins)
    {
        uint256 p;
        assembly ("memory-safe") {
            p := add(b, 32)
        }
        uint256 v;
        (v, p) = _take(p, 1);
        held = new Held[](v);
        for (uint256 i; i < held.length; ++i) {
            Held memory h = held[i];
            (v, p) = _take(p, 4);
            h.app.tag = uint32(v);
            (v, p) = _take(p, 32);
            h.app.identity = bytes32(v);
            (v, p) = _take(p, 32);
            h.app.vk = bytes32(v);
            (v, p) = _take(p, 8);
            h.amount = uint64(v);
            (v, p) = _take(p, 4);
            bytes memory data = new bytes(v);
            assembly ("memory-safe") {
                mcopy(add(data, 32), p, v)
            }
            h.data = data;
            p += v;
        }
        (v, p) = _take(p, 1);
        pins = new ICharmsTypes.Pin[](v);
        for (uint256 i; i < pins.length; ++i) {
            (v, p) = _take(p, 32);
            pins[i].vk = bytes32(v);
            (v, p) = _take(p, 4);
            pins[i].version = uint32(v);
            (v, p) = _take(p, 32);
            pins[i].wasmHash = bytes32(v);
        }
    }

    function _put(uint256 p, uint256 v, uint256 size) private pure returns (uint256) {
        assembly ("memory-safe") {
            mstore(p, shl(sub(256, mul(8, size)), v))
        }
        return p + size;
    }

    function _take(uint256 p, uint256 size) private pure returns (uint256 v, uint256) {
        assembly ("memory-safe") {
            v := shr(sub(256, mul(8, size)), mload(p))
        }
        return (v, p + size);
    }

    function _copy(uint256 p, bytes memory data) private pure returns (uint256) {
        assembly ("memory-safe") {
            mcopy(p, add(data, 32), mload(data))
        }
        return p + data.length;
    }
}
