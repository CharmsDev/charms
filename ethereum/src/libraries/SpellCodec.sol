// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICharmsTypes} from "../interfaces/ICharms.sol";

/// @notice Writes `charms_data::util::write(&NormalizedSpell)` for a typed `Spell` after the fill
/// Bitcoin does in `spell_with_committed_ins_and_coins`: `tx.ins` from `ins` and one
/// `NativeOutput { amount: 0, dest: owner }` per output.
/// @dev Encodes, never parses. The input must already be canonical: sorted apps, charms, pins,
/// beamed outs and scrolls, valid tags, and token charms with empty `data`. Every byte not copied
/// from a caller blob comes from this file.
library SpellCodec {
    uint32 internal constant TOKEN = 0x74;

    bytes32 private constant K_VERSION = "\x67version";
    bytes32 private constant K_TX = "\x62tx";
    bytes32 private constant K_APP_PUBLIC_INPUTS = "\x71app_public_inputs";
    bytes32 private constant K_VERSIONED_APPS = "\x6eversioned_apps";
    bytes32 private constant K_INS = "\x63ins";
    bytes32 private constant K_REFS = "\x64refs";
    bytes32 private constant K_OUTS = "\x64outs";
    bytes32 private constant K_BEAMED_OUTS = "\x6bbeamed_outs";
    bytes32 private constant K_COINS = "\x65coins";
    bytes32 private constant K_SCROLLS = "\x67scrolls";
    bytes32 private constant COIN_PREFIX = "\xa2\x66amount\x00\x64dest\x94";
    bytes32 private constant PIN_PREFIX = "\xa2\x67version";
    bytes32 private constant K_WASM_HASH = "\x69wasm_hash";

    uint256 private constant MAJOR_UINT = 0;
    uint256 private constant MAJOR_ARRAY = 4;
    uint256 private constant MAJOR_MAP = 5;

    /// @notice The committed spell CBOR.
    function encode(ICharmsTypes.Spell memory s) internal pure returns (bytes memory out) {
        out = new bytes(_bound(s) + 32);
        uint256 start;
        assembly ("memory-safe") {
            start := add(out, 32)
        }
        uint256 p = start;
        bool pinned = s.versionedApps.length != 0;
        p = _head(p, MAJOR_MAP, pinned ? 4 : 3);
        p = _raw(p, K_VERSION, 8);
        p = _head(p, MAJOR_UINT, s.version);
        p = _raw(p, K_TX, 3);
        p = _tx(p, s);
        p = _raw(p, K_APP_PUBLIC_INPUTS, 18);
        p = _publicInputs(p, s);
        if (pinned) {
            p = _raw(p, K_VERSIONED_APPS, 15);
            p = _pins(p, s.versionedApps);
        }
        assembly ("memory-safe") {
            mstore(out, sub(p, start))
        }
    }

    /// @notice `to_serialized_pv` for v15 and later: CBOR of `([u8; 32] programVKey, spell)`.
    function publicValues(bytes32 programVKey, bytes memory spellCbor)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(spellCbor.length + 67 + 32);
        uint256 start;
        assembly ("memory-safe") {
            start := add(out, 32)
            mstore8(start, 0x82)
        }
        uint256 p = _b32(start + 1, programVKey);
        p = _copy(p, spellCbor);
        assembly ("memory-safe") {
            mstore(out, sub(p, start))
        }
    }

    /// @notice Byte length of `publicValues(programVKey, spellCbor)` without building it.
    function publicValuesLength(bytes32 programVKey, uint256 spellCborLength)
        internal
        pure
        returns (uint256 n)
    {
        n = 3 + spellCborLength;
        for (uint256 i; i < 32; ++i) {
            n += uint8(programVKey[i]) < 24 ? 1 : 2;
        }
    }

    /// @notice `UtxoId::to_bytes()`: the id reversed into `TxId` order, then the index as `u32`
    /// little-endian.
    function utxoIdBytes(bytes32 txId, uint32 index) internal pure returns (bytes memory b) {
        b = new bytes(36 + 32);
        uint256 p;
        assembly ("memory-safe") {
            p := add(b, 32)
        }
        _utxoIdBody(p, txId, index);
        assembly ("memory-safe") {
            mstore(b, 36)
        }
    }

    function _tx(uint256 p, ICharmsTypes.Spell memory s) private pure returns (uint256) {
        uint256 fields = 3;
        if (s.refs.length != 0) ++fields;
        if (s.beamedOuts.length != 0) ++fields;
        if (s.scrolls.length != 0) ++fields;
        p = _head(p, MAJOR_MAP, fields);

        p = _raw(p, K_INS, 4);
        p = _head(p, MAJOR_ARRAY, s.ins.length);
        for (uint256 i; i < s.ins.length; ++i) {
            p = _utxoId(p, s.ins[i].utxo.txId, s.ins[i].utxo.index);
        }
        if (s.refs.length != 0) {
            p = _raw(p, K_REFS, 5);
            p = _head(p, MAJOR_ARRAY, s.refs.length);
            for (uint256 i; i < s.refs.length; ++i) {
                p = _utxoId(p, s.refs[i].txId, s.refs[i].index);
            }
        }
        p = _raw(p, K_OUTS, 5);
        p = _head(p, MAJOR_ARRAY, s.outs.length);
        for (uint256 i; i < s.outs.length; ++i) {
            p = _charms(p, s.apps, s.outs[i].charms);
        }
        if (s.beamedOuts.length != 0) {
            p = _raw(p, K_BEAMED_OUTS, 12);
            p = _head(p, MAJOR_MAP, s.beamedOuts.length);
            for (uint256 i; i < s.beamedOuts.length; ++i) {
                p = _head(p, MAJOR_UINT, s.beamedOuts[i].index);
                p = _b32(p, s.beamedOuts[i].destHash);
            }
        }
        p = _raw(p, K_COINS, 6);
        p = _head(p, MAJOR_ARRAY, s.outs.length);
        for (uint256 i; i < s.outs.length; ++i) {
            p = _raw(p, COIN_PREFIX, 15);
            p = _dest(p, s.outs[i].owner);
        }
        if (s.scrolls.length != 0) {
            p = _raw(p, K_SCROLLS, 8);
            p = _head(p, MAJOR_ARRAY, s.scrolls.length);
            for (uint256 i; i < s.scrolls.length; ++i) {
                p = _head(p, MAJOR_UINT, s.scrolls[i]);
            }
        }
        return p;
    }

    function _charms(uint256 p, ICharmsTypes.App[] memory apps, ICharmsTypes.Charm[] memory charms)
        private
        pure
        returns (uint256)
    {
        p = _head(p, MAJOR_MAP, charms.length);
        for (uint256 j; j < charms.length; ++j) {
            ICharmsTypes.Charm memory c = charms[j];
            p = _head(p, MAJOR_UINT, c.app);
            p = apps[c.app].tag == TOKEN ? _head(p, MAJOR_UINT, c.amount) : _copy(p, c.data);
        }
        return p;
    }

    function _publicInputs(uint256 p, ICharmsTypes.Spell memory s) private pure returns (uint256) {
        p = _head(p, MAJOR_MAP, s.apps.length);
        for (uint256 i; i < s.apps.length; ++i) {
            ICharmsTypes.App memory app = s.apps[i];
            assembly ("memory-safe") {
                mstore8(p, 0x83)
            }
            p = _tag(p + 1, app.tag);
            p = _b32(p, app.identity);
            p = _b32(p, app.vk);
            p = _copy(p, s.publicInputs[i]);
        }
        return p;
    }

    function _pins(uint256 p, ICharmsTypes.Pin[] memory pins) private pure returns (uint256) {
        p = _head(p, MAJOR_MAP, pins.length);
        for (uint256 i; i < pins.length; ++i) {
            p = _b32(p, pins[i].vk);
            p = _raw(p, PIN_PREFIX, 9);
            p = _head(p, MAJOR_UINT, pins[i].version);
            p = _raw(p, K_WASM_HASH, 10);
            p = _b32(p, pins[i].wasmHash);
        }
        return p;
    }

    /// @dev Shortest-form CBOR head, as ciborium writes it.
    function _head(uint256 p, uint256 major, uint256 v) private pure returns (uint256) {
        uint256 m = major << 5;
        assembly ("memory-safe") {
            switch lt(v, 24)
            case 1 {
                mstore8(p, or(m, v))
                p := add(p, 1)
            }
            default {
                switch lt(v, 0x100)
                case 1 {
                    mstore8(p, or(m, 24))
                    mstore8(add(p, 1), v)
                    p := add(p, 2)
                }
                default {
                    switch lt(v, 0x10000)
                    case 1 {
                        mstore8(p, or(m, 25))
                        mstore(add(p, 1), shl(240, v))
                        p := add(p, 3)
                    }
                    default {
                        switch lt(v, 0x100000000)
                        case 1 {
                            mstore8(p, or(m, 26))
                            mstore(add(p, 1), shl(224, v))
                            p := add(p, 5)
                        }
                        default {
                            mstore8(p, or(m, 27))
                            mstore(add(p, 1), shl(192, v))
                            p := add(p, 9)
                        }
                    }
                }
            }
        }
        return p;
    }

    /// @dev `[u8; 32]` and `B32` serialize as a 32-element array of uints, not a byte string.
    function _b32(uint256 p, bytes32 b) private pure returns (uint256) {
        assembly ("memory-safe") {
            mstore8(p, 0x98)
            mstore8(add(p, 1), 0x20)
            p := add(p, 2)
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                let x := byte(i, b)
                switch lt(x, 24)
                case 1 {
                    mstore8(p, x)
                    p := add(p, 1)
                }
                default {
                    mstore8(p, 0x18)
                    mstore8(add(p, 1), x)
                    p := add(p, 2)
                }
            }
        }
        return p;
    }

    /// @dev `NativeOutput.dest` is a `Vec<u8>`, which this serde writes as an array of uints. The
    /// array head (0x94, 20 elements) is the last byte of `COIN_PREFIX`.
    function _dest(uint256 p, address owner) private pure returns (uint256) {
        assembly ("memory-safe") {
            let a := shl(96, owner)
            for { let i := 0 } lt(i, 20) { i := add(i, 1) } {
                let x := byte(i, a)
                switch lt(x, 24)
                case 1 {
                    mstore8(p, x)
                    p := add(p, 1)
                }
                default {
                    mstore8(p, 0x18)
                    mstore8(add(p, 1), x)
                    p := add(p, 2)
                }
            }
        }
        return p;
    }

    /// @dev A `char` tag is a text string of its UTF-8 encoding.
    function _tag(uint256 p, uint32 c) private pure returns (uint256) {
        assembly ("memory-safe") {
            switch lt(c, 0x80)
            case 1 {
                mstore8(p, 0x61)
                mstore8(add(p, 1), c)
                p := add(p, 2)
            }
            default {
                switch lt(c, 0x800)
                case 1 {
                    mstore8(p, 0x62)
                    mstore8(add(p, 1), or(0xc0, shr(6, c)))
                    mstore8(add(p, 2), or(0x80, and(c, 0x3f)))
                    p := add(p, 3)
                }
                default {
                    switch lt(c, 0x10000)
                    case 1 {
                        mstore8(p, 0x63)
                        mstore8(add(p, 1), or(0xe0, shr(12, c)))
                        mstore8(add(p, 2), or(0x80, and(shr(6, c), 0x3f)))
                        mstore8(add(p, 3), or(0x80, and(c, 0x3f)))
                        p := add(p, 4)
                    }
                    default {
                        mstore8(p, 0x64)
                        mstore8(add(p, 1), or(0xf0, shr(18, c)))
                        mstore8(add(p, 2), or(0x80, and(shr(12, c), 0x3f)))
                        mstore8(add(p, 3), or(0x80, and(shr(6, c), 0x3f)))
                        mstore8(add(p, 4), or(0x80, and(c, 0x3f)))
                        p := add(p, 5)
                    }
                }
            }
        }
        return p;
    }

    /// @dev `UtxoId` is a 36-byte byte string.
    function _utxoId(uint256 p, bytes32 txId, uint32 index) private pure returns (uint256) {
        assembly ("memory-safe") {
            mstore8(p, 0x58)
            mstore8(add(p, 1), 36)
        }
        _utxoIdBody(p + 2, txId, index);
        return p + 38;
    }

    function _utxoIdBody(uint256 p, bytes32 txId, uint32 index) private pure {
        bytes32 reversed = _reverse(txId);
        assembly ("memory-safe") {
            mstore(p, reversed)
            mstore8(add(p, 32), and(index, 0xff))
            mstore8(add(p, 33), and(shr(8, index), 0xff))
            mstore8(add(p, 34), and(shr(16, index), 0xff))
            mstore8(add(p, 35), shr(24, index))
        }
    }

    function _reverse(bytes32 x) private pure returns (bytes32) {
        uint256 v = uint256(x);
        v = ((v >> 8) & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
            | ((v & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8);
        v = ((v >> 16) & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
            | ((v & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16);
        v = ((v >> 32) & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
            | ((v & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32);
        v = ((v >> 64) & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff)
            | ((v & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff) << 64);
        v = (v >> 128) | (v << 128);
        return bytes32(v);
    }

    /// @dev Writes 32 bytes at `p` and advances by `len`. The next write or the final length
    /// overwrites the tail, and `encode` allocates 32 bytes of slack for the last word.
    function _raw(uint256 p, bytes32 word, uint256 len) private pure returns (uint256) {
        assembly ("memory-safe") {
            mstore(p, word)
        }
        return p + len;
    }

    function _copy(uint256 p, bytes memory b) private pure returns (uint256) {
        assembly ("memory-safe") {
            let n := mload(b)
            mcopy(p, add(b, 32), n)
            p := add(p, n)
        }
        return p;
    }

    /// @dev An upper bound on the encoded length. Array and map counts are at most 64, so every
    /// head fits in 3 bytes and every uint in 9.
    function _bound(ICharmsTypes.Spell memory s) private pure returns (uint256 n) {
        n = 128 + (s.ins.length + s.refs.length) * 38 + s.beamedOuts.length * 71
            + s.scrolls.length * 5 + s.versionedApps.length * 156;
        for (uint256 i; i < s.outs.length; ++i) {
            ICharmsTypes.Charm[] memory charms = s.outs[i].charms;
            n += 58;
            for (uint256 j; j < charms.length; ++j) {
                n += 14 + charms[j].data.length;
            }
        }
        for (uint256 i; i < s.apps.length; ++i) {
            n += 138 + s.publicInputs[i].length;
        }
    }
}
