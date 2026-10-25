// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {stdJson} from "forge-std/StdJson.sol";

import {Charms} from "../src/Charms.sol";
import {appKey} from "../src/libraries/CharmTokenClone.sol";
import {CharmsMetadata} from "../src/libraries/CharmsMetadata.sol";
import {MetadataHash} from "../src/libraries/MetadataHash.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract MetadataDigestTest is CharmsTestBase {
    using stdJson for string;

    uint256 internal metadataKey;
    string internal constant VECTOR = "test/vectors/metadata-digest.json";

    function setUp() public override {
        (metadataSigner, metadataKey) = makeAddrAndKey("metadata");
        super.setUp();
    }

    function test_sharedVectorIsTheSignedDigest() public {
        string memory json = vm.readFile(VECTOR);
        App memory app = App({
            tag: uint32(uint8(bytes(json.readString(".tag"))[0])),
            identity: json.readBytes32(".identity"),
            vk: json.readBytes32(".vk")
        });
        Metadata memory metadata = _metadata(json);
        uint64 version = uint64(json.readUint(".version"));
        bytes32 metadataHash = MetadataHash.digest(
            metadata.name,
            metadata.symbol,
            metadata.decimals,
            metadata.description,
            metadata.url,
            metadata.image,
            metadata.imageHash
        );
        assertEq(metadataHash, json.readBytes32(".metadataHash"));
        assertEq(appKey(app), json.readBytes32(".appKey"));

        bytes32 digest = json.readBytes32(".digest");
        assertEq(CharmsMetadata.digest(appKey(app), version, metadataHash), digest);
        assertEq(_recover(digest, json.readBytes(".signature")), json.readAddress(".address"));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(metadataKey, digest);
        charms.setMetadata(app, metadata, version, abi.encodePacked(r, s, v));
        assertEq(charms.metadataVersion(app), version);

        vm.chainId(block.chainid + 1);
        Charms other = _deploy(16, PROGRAM_VKEY, verifier);
        other.setMetadata(app, metadata, version, abi.encodePacked(r, s, v));
        assertEq(other.metadataVersion(app), version);
    }

    function _recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "signature");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := shr(248, mload(add(signature, 96)))
        }
        return ecrecover(digest, v, r, s);
    }

    function _metadata(string memory json) internal pure returns (Metadata memory) {
        return Metadata({
            name: json.readString(".name"),
            symbol: json.readString(".symbol"),
            decimals: uint8(json.readUint(".decimals")),
            description: json.readString(".description"),
            url: json.readString(".url"),
            image: json.readString(".image"),
            imageHash: json.readBytes32(".imageHash")
        });
    }
}
