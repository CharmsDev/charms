// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharmsErrors, ICharmsTypes} from "../interfaces/ICharms.sol";

/// @notice CHIP-0020 metadata digest, field rules, and ERC-7572 `contractURI`.
library CharmsMetadata {
    bytes32 internal constant TYPEHASH =
        keccak256("CharmsMetadata(bytes32 appKey,uint64 version,bytes32 metadataHash)");
    uint256 private constant IMAGE_SVG_MAX = 256;
    uint256 private constant IMAGE_REMOTE_MAX = 128;

    function digest(bytes32 key, uint64 version, bytes32 metadataHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(TYPEHASH, key, version, metadataHash));
    }

    function check(ICharmsTypes.Metadata calldata metadata) internal pure {
        if (bytes(metadata.name).length > 64) revert ICharmsErrors.InvalidMetadata();
        uint256 symbolLen = bytes(metadata.symbol).length;
        if (symbolLen == 0 || symbolLen > 32) revert ICharmsErrors.InvalidMetadata();
        if (bytes(metadata.description).length > 256) revert ICharmsErrors.InvalidMetadata();
        _checkUrl(bytes(metadata.url));
        _checkImage(bytes(metadata.image), metadata.imageHash);
    }

    /// @dev Keys are `name`, `symbol`, `decimals`, then nonempty `description`, `image`, and
    /// `external_link` (`url`). The JSON is percent-encoded. Unreserved bytes stay raw.
    function uri(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        string memory description,
        string memory image,
        string memory url
    ) internal pure returns (string memory) {
        string memory json = string.concat(
            '{"name":', _quote(name_), ',"symbol":', _quote(symbol_), ',"decimals":', _u8(decimals_)
        );
        if (bytes(description).length != 0) {
            json = string.concat(json, ',"description":', _quote(description));
        }
        if (bytes(image).length != 0) json = string.concat(json, ',"image":', _quote(image));
        if (bytes(url).length != 0) json = string.concat(json, ',"external_link":', _quote(url));
        return
            string.concat("data:application/json,", _percentEncode(bytes(string.concat(json, "}"))));
    }

    function _checkUrl(bytes memory url) private pure {
        if (url.length == 0) return;
        if (url.length > 128 || !_allowedUrl(url)) revert ICharmsErrors.InvalidMetadata();
    }

    function _allowedUrl(bytes memory url) private pure returns (bool) {
        return _hasPrefix(url, "https://") || _hasPrefix(url, "ipfs://") || _hasPrefix(url, "ar://")
            || _hasPrefix(url, "data:");
    }

    function _checkImage(bytes memory image, bytes32 imageHash) private pure {
        if (image.length == 0) {
            if (imageHash != bytes32(0)) revert ICharmsErrors.InvalidMetadata();
            return;
        }
        if (_hasPrefix(image, "data:image/svg+xml")) {
            if (image.length > IMAGE_SVG_MAX || imageHash != bytes32(0)) {
                revert ICharmsErrors.InvalidMetadata();
            }
            return;
        }
        if (imageHash == bytes32(0)) {
            if (image.length <= IMAGE_REMOTE_MAX && _ipfsContentCommitment(image)) return;
            revert ICharmsErrors.InvalidMetadata();
        }
        if (
            image.length <= IMAGE_REMOTE_MAX
                && (_hasPrefix(image, "https://")
                    || _hasPrefix(image, "ipfs://")
                    || _hasPrefix(image, "ar://"))
        ) return;
        revert ICharmsErrors.InvalidMetadata();
    }

    function _ipfsContentCommitment(bytes memory image) private pure returns (bool ok) {
        assembly ("memory-safe") {
            ok := committed(image)

            function loadByte(data, i) -> b {
                b := byte(and(i, 31), mload(add(data, and(i, not(31)))))
            }

            // Base58btc, with 0, I, O, and l removed. Indices match the 58-character alphabet.
            function b58(c) -> found, v {
                if and(lt(0x30, c), lt(c, 0x3a)) {
                    found := 1
                    v := sub(c, 0x31)
                    leave
                }
                if and(lt(0x40, c), lt(c, 0x49)) {
                    found := 1
                    v := add(sub(c, 0x41), 9)
                    leave
                }
                if and(lt(0x49, c), lt(c, 0x4f)) {
                    found := 1
                    v := add(sub(c, 0x4a), 17)
                    leave
                }
                if and(lt(0x4f, c), lt(c, 0x5b)) {
                    found := 1
                    v := add(sub(c, 0x50), 22)
                    leave
                }
                if and(lt(0x60, c), lt(c, 0x6c)) {
                    found := 1
                    v := add(sub(c, 0x61), 33)
                    leave
                }
                if and(lt(0x6c, c), lt(c, 0x7b)) {
                    found := 1
                    v := add(sub(c, 0x6d), 44)
                }
            }

            // Lowercase RFC 4648 base32, no padding characters.
            function b32(c) -> found, v {
                if and(lt(0x60, c), lt(c, 0x7b)) {
                    found := 1
                    v := sub(c, 0x61)
                    leave
                }
                if and(lt(0x31, c), lt(c, 0x38)) {
                    found := 1
                    v := add(sub(c, 0x32), 26)
                }
            }

            function accByte(buf, j) -> b {
                b := byte(and(j, 31), mload(add(buf, and(j, not(31)))))
            }

            function cidV0(data, base) -> good {
                let acc := mload(0x40)
                mstore(0x40, add(acc, 96))
                mstore(acc, 0)
                mstore(add(acc, 32), 0)
                mstore(add(acc, 64), 0)
                for { let k := 0 } lt(k, 46) { k := add(k, 1) } {
                    let found, carry := b58(loadByte(data, add(base, k)))
                    if iszero(found) { leave }
                    for { let i := 34 } gt(i, 0) { i := sub(i, 1) } {
                        let j := sub(i, 1)
                        carry := add(carry, mul(58, accByte(acc, j)))
                        mstore8(add(acc, j), and(carry, 0xff))
                        carry := shr(8, carry)
                    }
                    if carry { leave }
                }
                let word := mload(acc)
                if and(eq(byte(0, word), 0x12), eq(byte(1, word), 0x20)) { good := 1 }
            }

            function cidV1(data, base) -> good {
                if iszero(eq(loadByte(data, base), 0x62)) { leave }
                let out := mload(0x40)
                mstore(0x40, add(out, 96))
                mstore(out, 0)
                mstore(add(out, 32), 0)
                mstore(add(out, 64), 0)
                let acc := 0
                let bits := 0
                let n := 0
                for { let i := 1 } lt(i, 59) { i := add(i, 1) } {
                    let found, v := b32(loadByte(data, add(base, i)))
                    if iszero(found) { leave }
                    acc := add(shl(5, acc), v)
                    bits := add(bits, 5)
                    if iszero(lt(bits, 8)) {
                        bits := sub(bits, 8)
                        mstore8(add(out, n), and(shr(bits, acc), 0xff))
                        n := add(n, 1)
                        acc := and(acc, sub(shl(1, bits), 1))
                    }
                }
                if iszero(and(eq(bits, 2), and(iszero(and(acc, 3)), eq(n, 36)))) { leave }
                let word := mload(out)
                let codec := byte(1, word)
                if and(
                    and(eq(byte(0, word), 0x01), and(gt(codec, 0), lt(codec, 0x80))),
                    and(eq(byte(2, word), 0x12), eq(byte(3, word), 0x20))
                ) { good := 1 }
            }

            function committed(imagePtr) -> good {
                let len := mload(imagePtr)
                if lt(len, 7) { leave }
                let data := add(imagePtr, 32)
                if iszero(eq(shr(200, mload(data)), 0x697066733a2f2f)) { leave }
                switch sub(len, 7)
                case 46 { good := cidV0(data, 7) }
                case 59 { good := cidV1(data, 7) }
            }
        }
    }

    function _hasPrefix(bytes memory value, bytes memory prefix) private pure returns (bool) {
        if (value.length < prefix.length) return false;
        for (uint256 i; i < prefix.length; ++i) {
            if (value[i] != prefix[i]) return false;
        }
        return true;
    }

    function _quote(string memory value) internal pure returns (string memory) {
        bytes memory raw = bytes(value);
        uint256 n = 2;
        for (uint256 i; i < raw.length; ++i) {
            bytes1 c = raw[i];
            if (c == 0x22 || c == 0x5c || c == 0x0a || c == 0x0d || c == 0x09) n += 2;
            else if (uint8(c) < 0x20) n += 6;
            else n += 1;
        }
        bytes memory out = new bytes(n);
        out[0] = 0x22;
        uint256 j = 1;
        for (uint256 i; i < raw.length; ++i) {
            bytes1 c = raw[i];
            if (c == 0x22 || c == 0x5c) {
                out[j++] = 0x5c;
                out[j++] = c;
            } else if (c == 0x0a) {
                out[j++] = 0x5c;
                out[j++] = 0x6e;
            } else if (c == 0x0d) {
                out[j++] = 0x5c;
                out[j++] = 0x72;
            } else if (c == 0x09) {
                out[j++] = 0x5c;
                out[j++] = 0x74;
            } else if (uint8(c) < 0x20) {
                out[j++] = 0x5c;
                out[j++] = 0x75;
                out[j++] = 0x30;
                out[j++] = 0x30;
                out[j++] = _hexLower(uint8(c) >> 4);
                out[j++] = _hexLower(uint8(c) & 0x0f);
            } else {
                out[j++] = c;
            }
        }
        out[j] = 0x22;
        return string(out);
    }

    function _percentEncode(bytes memory data) private pure returns (string memory) {
        uint256 extra;
        for (uint256 i; i < data.length; ++i) {
            if (!_unreserved(data[i])) extra += 2;
        }
        bytes memory out = new bytes(data.length + extra);
        uint256 j;
        for (uint256 i; i < data.length; ++i) {
            bytes1 c = data[i];
            if (_unreserved(c)) {
                out[j++] = c;
            } else {
                out[j++] = 0x25;
                out[j++] = _hexUpper(uint8(c) >> 4);
                out[j++] = _hexUpper(uint8(c) & 0x0f);
            }
        }
        return string(out);
    }

    function _unreserved(bytes1 c) private pure returns (bool) {
        return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
            || c == 0x2d || c == 0x2e || c == 0x5f || c == 0x7e;
    }

    function _u8(uint8 n) private pure returns (string memory) {
        if (n < 10) return string(abi.encodePacked(bytes1(uint8(0x30 + n))));
        if (n < 100) {
            return
                string(abi.encodePacked(bytes1(uint8(0x30 + n / 10)), bytes1(uint8(0x30 + n % 10))));
        }
        return string(
            abi.encodePacked(
                bytes1(uint8(0x30 + n / 100)),
                bytes1(uint8(0x30 + (n / 10) % 10)),
                bytes1(uint8(0x30 + n % 10))
            )
        );
    }

    function _hexUpper(uint8 n) private pure returns (bytes1) {
        return bytes1(n < 10 ? 0x30 + n : 0x37 + n);
    }

    function _hexLower(uint8 n) private pure returns (bytes1) {
        return bytes1(n < 10 ? 0x30 + n : 0x57 + n);
    }
}
