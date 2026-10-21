// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library MetadataHash {
    function digest(
        string memory name,
        string memory symbol,
        uint8 decimals,
        string memory description,
        string memory url,
        string memory image,
        bytes32 imageHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(name, symbol, decimals, description, url, image, imageHash));
    }

    function recover(
        string memory name,
        string memory symbol,
        uint8 decimals,
        string memory description,
        string memory url,
        string memory image,
        bytes32 imageHash,
        bytes memory signature
    ) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := shr(248, mload(add(signature, 96)))
        }
        return
            ecrecover(digest(name, symbol, decimals, description, url, image, imageHash), v, r, s);
    }
}
