// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Checks that a caller blob is exactly one definite-length, well-formed CBOR item
/// nested at most 16 deep, with no trailing bytes. Depth counts every item on a path, the
/// outermost item and the innermost scalar included, so 15 nested arrays around a scalar pass
/// and 16 do not.
/// @dev Without this a blob could end early and swallow the next field of the spell, so the proof
/// would attest one spell while the contract accounts for another.
library CborWellFormed {
    uint256 internal constant MAX_DEPTH = 16;

    function isSingleItem(bytes memory b) internal pure returns (bool) {
        (bool ok, uint256 end) = _skip(b, 0, 1);
        return ok && end == b.length;
    }

    function _skip(bytes memory b, uint256 i, uint256 depth)
        private
        pure
        returns (bool ok, uint256 next)
    {
        if (depth > MAX_DEPTH || i >= b.length) return (false, 0);
        uint256 initial = uint8(b[i]);
        uint256 major = initial >> 5;
        uint256 info = initial & 31;
        ++i;

        uint256 arg = info;
        if (info >= 24) {
            if (info > 27) return (false, 0);
            uint256 size = 1 << (info - 24);
            if (b.length - i < size) return (false, 0);
            arg = 0;
            for (uint256 k; k < size; ++k) {
                arg = (arg << 8) | uint8(b[i + k]);
            }
            i += size;
            if (major == 7 && info == 24 && arg < 32) return (false, 0);
        }

        if (major <= 1 || major == 7) return (true, i);
        if (major <= 3) {
            if (b.length - i < arg) return (false, 0);
            return (true, i + arg);
        }
        if (major == 6) return _skip(b, i, depth + 1);

        uint256 items = major == 4 ? arg : arg * 2;
        for (uint256 k; k < items; ++k) {
            (ok, i) = _skip(b, i, depth + 1);
            if (!ok) return (false, 0);
        }
        return (true, i);
    }
}
