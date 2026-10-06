// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {CborWellFormed} from "../src/libraries/CborWellFormed.sol";

/// @notice Caller blobs on the proved path must be exactly one definite-length item nested at
/// most 16 deep. Anything else could end early or late and take bytes from the next spell field.
contract CborWellFormedTest is Test {
    function test_rejectsBlobsThatAreNotOneItem() public pure {
        bytes[] memory bad = new bytes[](10);
        bad[0] = hex"";
        bad[1] = hex"8201";
        bad[2] = hex"a101";
        bad[3] = hex"0101";
        bad[4] = hex"f6f6";
        bad[5] = hex"4201";
        bad[6] = hex"6261";
        bad[7] = hex"5900ff00";
        bad[8] = hex"c1";
        bad[9] = hex"820102ff";
        _assertAll(bad, false);
    }

    function test_rejectsHeadsCutShortAtEveryArgumentWidth() public pure {
        bytes[] memory bad = new bytes[](8);
        bad[0] = hex"18";
        bad[1] = hex"1901";
        bad[2] = hex"1a000000";
        bad[3] = hex"1b00000000000000";
        bad[4] = hex"98";
        bad[5] = hex"b901";
        bad[6] = hex"5a000000";
        bad[7] = hex"fb3ff00000000000";
        _assertAll(bad, false);
    }

    function test_rejectsIndefiniteLengthsBreaksAndReservedHeads() public pure {
        bytes[] memory bad = new bytes[](10);
        bad[0] = hex"5f40ff";
        bad[1] = hex"7f60ff";
        bad[2] = hex"9f01ff";
        bad[3] = hex"bf0101ff";
        bad[4] = hex"ff";
        bad[5] = hex"1c";
        bad[6] = hex"1d";
        bad[7] = hex"1e";
        bad[8] = hex"fc";
        bad[9] = hex"f810";
        _assertAll(bad, false);
    }

    function test_acceptsOneDefiniteItemOfEveryMajorType() public pure {
        bytes[] memory good = new bytes[](20);
        good[0] = hex"00";
        good[1] = hex"1800";
        good[2] = hex"1b0000000100000000";
        good[3] = hex"3818";
        good[4] = hex"40";
        good[5] = hex"4101";
        good[6] = hex"6161";
        good[7] = hex"80";
        good[8] = hex"820102";
        good[9] = hex"a0";
        good[10] = hex"a10102";
        good[11] = hex"c101";
        good[12] = hex"c249010000000000000000";
        good[13] = hex"f4";
        good[14] = hex"f6";
        good[15] = hex"f7";
        good[16] = hex"f820";
        good[17] = hex"f93c00";
        good[18] = hex"fa3f800000";
        good[19] = hex"fb3ff0000000000000";
        _assertAll(good, true);
    }

    function test_nestingDepthStopsAtSixteen() public pure {
        assertTrue(CborWellFormed.isSingleItem(_nested(hex"81", 15)), "16 levels");
        assertFalse(CborWellFormed.isSingleItem(_nested(hex"81", 16)), "17 levels of arrays");
        assertFalse(CborWellFormed.isSingleItem(_nested(hex"a100", 16)), "17 levels of maps");
        assertFalse(CborWellFormed.isSingleItem(_nested(hex"c1", 16)), "17 levels of tags");
    }

    /// @dev `levels` copies of `head` wrapped around the uint 0.
    function _nested(bytes memory head, uint256 levels) internal pure returns (bytes memory b) {
        for (uint256 i; i < levels; ++i) {
            b = bytes.concat(b, head);
        }
        b = bytes.concat(b, hex"00");
    }

    function _assertAll(bytes[] memory blobs, bool expected) internal pure {
        for (uint256 i; i < blobs.length; ++i) {
            assertEq(CborWellFormed.isSingleItem(blobs[i]), expected, vm.toString(blobs[i]));
        }
    }
}
