// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {MetadataHash} from "../src/libraries/MetadataHash.sol";

contract MetadataHashTest is Test {
    function test_recovers_canister_key() public pure {
        bytes memory signature =
            hex"1f66ab9438e8121d7bb37dd6c29539ecdd39f3d18cdad958511badef90a19fe00180d9c3429a499d5bbfd95bae57517f684d0ee6a200f8a7c11b47dddd2720d31b";
        address signer = MetadataHash.recover(
            "Example",
            "EX",
            8,
            "One fungible charm.",
            "https://example.com",
            "ipfs://bafyexample",
            bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111)),
            signature
        );
        assertEq(signer, 0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A);
    }
}
