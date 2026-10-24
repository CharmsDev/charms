// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {Charms} from "../src/Charms.sol";
import {ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {appKey} from "../src/libraries/CharmTokenClone.sol";
import {CharmsMetadata} from "../src/libraries/CharmsMetadata.sol";
import {MetadataHash} from "../src/libraries/MetadataHash.sol";

/// @notice Publish tag-`t` metadata. The signature is an argument. This file holds no key.
/// @dev forge script script/SetMetadata.s.sol --sig "digest(uint256,address,uint64)" <chainId> <charms> <version>
///      prints the eBTC digest. Sign that digest with no EIP-191 prefix, then
///      forge script script/SetMetadata.s.sol --sig "run(address,uint64,bytes)" <charms> <version> <sig>
///      --rpc-url <url> --private-key <broadcaster>
contract SetMetadata is Script, ICharmsTypes {
    using stdJson for string;

    string internal constant EBTC_FILE = "metadata/ebtc.json";

    function ebtc() public view returns (App memory app, Metadata memory metadata) {
        string memory json = vm.readFile(EBTC_FILE);
        bytes memory tag = bytes(json.readString(".tag"));
        require(tag.length == 1, "tag is one character");
        app = App({
            tag: uint32(uint8(tag[0])),
            identity: json.readBytes32(".identity"),
            vk: json.readBytes32(".vk")
        });
        metadata = Metadata({
            name: json.readString(".name"),
            symbol: json.readString(".symbol"),
            decimals: uint8(json.readUint(".decimals")),
            description: json.readString(".description"),
            url: json.readString(".url"),
            image: json.readString(".image"),
            imageHash: json.readBytes32(".imageHash")
        });
    }

    /// @notice Digest for the eBTC file at `version` on `charms`. No key.
    function digest(uint256 chainId, address charms, uint64 version)
        external
        view
        returns (bytes32)
    {
        (App memory app, Metadata memory metadata) = ebtc();
        bytes32 hashed = _hash(metadata);
        bytes32 message = CharmsMetadata.digestFor(chainId, charms, appKey(app), version, hashed);
        console.logBytes32(message);
        return message;
    }

    /// @notice Publish the eBTC file. `signature` is 65 bytes, `r ‖ s ‖ v`, over `digest`.
    function run(address charms, uint64 version, bytes memory signature) external {
        (App memory app, Metadata memory metadata) = ebtc();
        vm.startBroadcast();
        Charms(payable(charms)).setMetadata(app, metadata, version, signature);
        vm.stopBroadcast();
    }

    function tokenList(
        uint256 chainId,
        address token,
        Metadata memory metadata,
        string memory timestamp
    ) public pure returns (string memory) {
        string memory head = string.concat(
            '{"name":"Charms","timestamp":',
            _quote(timestamp),
            ',"version":{"major":1,"minor":0,"patch":0},"tokens":['
        );
        if (token == address(0)) return string.concat(head, "]}");
        return string.concat(head, _token(chainId, token, metadata), "]}");
    }

    function watchAsset(address token, Metadata memory metadata)
        public
        pure
        returns (string memory)
    {
        string memory image = bytes(metadata.image).length == 0
            ? ""
            : string.concat(',"image":', _quote(metadata.image));
        return string.concat(
            '{"type":"ERC20","options":{"address":',
            _quote(Strings.toHexString(uint160(token), 20)),
            ',"symbol":',
            _quote(metadata.symbol),
            ',"decimals":',
            Strings.toString(metadata.decimals),
            image,
            "}}"
        );
    }

    function _token(uint256 chainId, address token, Metadata memory metadata)
        private
        pure
        returns (string memory)
    {
        string memory logo = bytes(metadata.image).length == 0
            ? ""
            : string.concat(',"logoURI":', _quote(metadata.image));
        return string.concat(
            '{"chainId":',
            Strings.toString(chainId),
            ',"address":',
            _quote(Strings.toHexString(uint160(token), 20)),
            ',"name":',
            _quote(metadata.name),
            ',"symbol":',
            _quote(metadata.symbol),
            ',"decimals":',
            Strings.toString(metadata.decimals),
            logo,
            "}"
        );
    }

    function _hash(Metadata memory metadata) private pure returns (bytes32) {
        return MetadataHash.digest(
            metadata.name,
            metadata.symbol,
            metadata.decimals,
            metadata.description,
            metadata.url,
            metadata.image,
            metadata.imageHash
        );
    }

    function _quote(string memory value) private pure returns (string memory) {
        bytes memory raw = bytes(value);
        uint256 extra;
        for (uint256 i; i < raw.length; ++i) {
            if (raw[i] == '"' || raw[i] == "\\") extra += 1;
        }
        bytes memory out = new bytes(raw.length + extra + 2);
        out[0] = '"';
        uint256 n = 1;
        for (uint256 i; i < raw.length; ++i) {
            if (raw[i] == '"' || raw[i] == "\\") out[n++] = "\\";
            out[n++] = raw[i];
        }
        out[n] = '"';
        return string(out);
    }
}
