// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharmsErrors, ICharmsTypes} from "../interfaces/ICharms.sol";

/// @notice CHIP-0020 metadata digest, field rules, and ERC-7572 `contractURI`.
library CharmsMetadata {
    bytes32 internal constant TYPEHASH = keccak256(
        "CharmsMetadata(uint256 chainId,address charms,bytes32 appKey,uint64 version,bytes32 metadataHash)"
    );

    /// @dev `address(this)` is the proxy. The signed message is this digest, with no EIP-191 prefix.
    /// `metadataHash` is `MetadataHash.digest`. This wrapper binds that hash to the chain, the
    /// proxy, the app key, and the version. `charms_metadata` does not sign this digest.
    function digest(bytes32 key, uint64 version, bytes32 metadataHash)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(TYPEHASH, block.chainid, address(this), key, version, metadataHash)
        );
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
            if (image.length > 256 || imageHash != bytes32(0)) {
                revert ICharmsErrors.InvalidMetadata();
            }
            return;
        }
        if (
            _hasPrefix(image, "https://") || _hasPrefix(image, "ipfs://")
                || _hasPrefix(image, "ar://")
        ) {
            if (image.length > 128 || imageHash == bytes32(0)) {
                revert ICharmsErrors.InvalidMetadata();
            }
            return;
        }
        revert ICharmsErrors.InvalidMetadata();
    }

    function _hasPrefix(bytes memory value, bytes memory prefix) private pure returns (bool) {
        if (value.length < prefix.length) return false;
        for (uint256 i; i < prefix.length; ++i) {
            if (value[i] != prefix[i]) return false;
        }
        return true;
    }

    function _quote(string memory value) private pure returns (string memory) {
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
