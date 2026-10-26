// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharmsErrors, ICharmsTypes} from "../interfaces/ICharms.sol";

/// @notice CHIP-0020 metadata digest, field rules, and ERC-7572 `contractURI`.
library CharmsMetadata {
    bytes32 internal constant TYPEHASH =
        keccak256("CharmsMetadata(bytes32 appKey,uint64 version,bytes32 metadataHash)");
    uint256 private constant IMAGE_SVG_MAX = 256;
    uint256 private constant IMAGE_REMOTE_MAX = 128;
    string private constant BASE58_ALPHABET =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    string private constant BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

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

    function _ipfsContentCommitment(bytes memory image) private pure returns (bool) {
        if (image.length < 7 || !_hasPrefix(image, "ipfs://")) return false;
        bytes memory rest = new bytes(image.length - 7);
        for (uint256 i; i < rest.length; ++i) {
            rest[i] = image[i + 7];
        }
        return _cidV0(rest) || _cidV1(rest);
    }

    function _cidV0(bytes memory rest) private pure returns (bool) {
        if (rest.length != 46) return false;
        bytes memory acc = new bytes(34);
        for (uint256 k; k < rest.length; ++k) {
            (bool ok, uint256 carry) = _alphabetIndex(rest[k], bytes(BASE58_ALPHABET));
            if (!ok) return false;
            for (uint256 i = 34; i > 0; --i) {
                uint256 j = i - 1;
                carry = carry + 58 * uint256(uint8(acc[j]));
                acc[j] = bytes1(uint8(carry % 256));
                carry = carry / 256;
            }
            if (carry != 0) return false;
        }
        return acc[0] == 0x12 && acc[1] == 0x20;
    }

    function _cidV1(bytes memory rest) private pure returns (bool) {
        if (rest.length != 59 || rest[0] != 0x62) return false;
        uint256 acc;
        uint256 bits;
        uint256 n;
        bytes memory out = new bytes(36);
        for (uint256 i = 1; i < rest.length; ++i) {
            (bool ok, uint256 v) = _alphabetIndex(rest[i], bytes(BASE32_ALPHABET));
            if (!ok) return false;
            acc = (acc << 5) + v;
            bits = bits + 5;
            if (bits >= 8) {
                bits = bits - 8;
                out[n] = bytes1(uint8((acc >> bits) & 0xff));
                n = n + 1;
                acc = acc & ((1 << bits) - 1);
            }
        }
        if (bits != 2 || (acc & 3) != 0 || n != 36) return false;
        uint8 codec = uint8(out[1]);
        return out[0] == 0x01 && codec >= 0x01 && codec <= 0x7f && out[2] == 0x12 && out[3] == 0x20;
    }

    function _alphabetIndex(bytes1 c, bytes memory alphabet)
        private
        pure
        returns (bool ok, uint256 index)
    {
        for (uint256 i; i < alphabet.length; ++i) {
            if (alphabet[i] == c) return (true, i);
        }
        return (false, 0);
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
