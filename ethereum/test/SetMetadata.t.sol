// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {stdJson} from "forge-std/StdJson.sol";

import {SetMetadata} from "../script/SetMetadata.s.sol";
import {CharmToken} from "../src/CharmToken.sol";
import {ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract SetMetadataScriptTest is CharmsTestBase {
    using stdJson for string;

    uint256 internal signerKey;
    SetMetadata internal tool;
    string internal constant FIXTURE = "test/fixtures/metadata.json";

    function setUp() public override {
        (metadataSigner, signerKey) = makeAddrAndKey("metadataSigner");
        super.setUp();
        tool = new SetMetadata();
    }

    function test_filePublishesSymbolDecimalsAndLogo() public {
        string memory json = vm.readFile(FIXTURE);
        (ICharmsTypes.App memory app, ICharmsTypes.Metadata memory metadata) = tool.load(FIXTURE);
        assertEq(app.tag, T);
        assertEq(app.identity, json.readBytes32(".identity"));
        assertEq(app.vk, json.readBytes32(".vk"));
        assertEq(metadata.name, json.readString(".name"));
        assertEq(metadata.symbol, json.readString(".symbol"));
        assertEq(metadata.decimals, uint8(json.readUint(".decimals")));
        assertEq(metadata.name, "Example");
        assertEq(metadata.symbol, "EX");
        assertEq(metadata.decimals, 6);
        assertEq(metadata.image, json.readString(".image"));

        bytes32 message = tool.digest(FIXTURE, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, message);
        charms.setMetadata(app, metadata, 1, abi.encodePacked(r, s, v));
        address token = charms.ensureToken(app);

        assertEq(CharmToken(token).name(), "Example");
        assertEq(CharmToken(token).symbol(), "EX");
        assertEq(CharmToken(token).decimals(), 6);
        assertTrue(_has(CharmToken(token).contractURI(), "Example"));

        string memory list =
            tool.tokenList(block.chainid, token, metadata, "2026-10-24T00:00:00.000Z");
        assertTrue(_has(list, "Example"));
        assertTrue(_has(list, "\"decimals\":6"));
        assertTrue(_has(list, metadata.image));
        assertTrue(_has(list, _lower(token)));
        assertEq(tool.tokenList(1, address(0), metadata, "2026-10-24T00:00:00.000Z"), _emptyList());

        string memory watch = tool.watchAsset(token, metadata);
        assertTrue(_has(watch, "\"type\":\"ERC20\""));
        assertTrue(_has(watch, "\"symbol\":\"EX\""));
        assertTrue(_has(watch, "\"decimals\":6"));
        assertTrue(_has(watch, metadata.image));

        metadata.image = "";
        metadata.imageHash = bytes32(0);
        assertFalse(_has(tool.watchAsset(token, metadata), "image"));
        assertFalse(_has(tool.tokenList(1, token, metadata, "2026-10-24T00:00:00.000Z"), "logoURI"));
    }

    function test_digestPublishesAfterTheChainIdChanges() public {
        (ICharmsTypes.App memory app, ICharmsTypes.Metadata memory metadata) = tool.load(FIXTURE);
        bytes32 message = tool.digest(FIXTURE, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, message);
        vm.chainId(block.chainid + 1);
        charms.setMetadata(app, metadata, 1, abi.encodePacked(r, s, v));
        assertEq(charms.metadataVersion(app), 1);
    }

    function test_tokenListEscapesQuotes() public view {
        ICharmsTypes.Metadata memory metadata;
        metadata.name = "a\"b\\c";
        metadata.symbol = "AB";
        metadata.decimals = 6;
        string memory list =
            tool.tokenList(1, address(0x1111111111111111111111111111111111111111), metadata, "t");
        assertTrue(_has(list, "\"a\\\"b\\\\c\""));
    }

    function test_exportsEscapeControlCharacters() public view {
        ICharmsTypes.Metadata memory metadata;
        metadata.name = "a\nb\tc";
        metadata.symbol = string(abi.encodePacked("A\rB", bytes1(0x01)));
        metadata.decimals = 6;
        metadata.image = "https://example.com/x\n";
        address token = address(0x1111111111111111111111111111111111111111);
        string memory list = tool.tokenList(1, token, metadata, "t\n");
        string memory watch = tool.watchAsset(token, metadata);
        vm.parseJson(list);
        vm.parseJson(watch);
        assertTrue(_has(list, "\"a\\nb\\tc\""));
        assertTrue(_has(list, "\"A\\rB\\u0001\""));
        assertTrue(_has(list, "\"https://example.com/x\\n\""));
        assertTrue(_has(list, "\"t\\n\""));
        assertTrue(_has(watch, "\"A\\rB\\u0001\""));
        assertTrue(_has(watch, "\"https://example.com/x\\n\""));
    }

    function _emptyList() internal pure returns (string memory) {
        return "{\"name\":\"Charms\",\"timestamp\":\"2026-10-24T00:00:00.000Z\",\"version\":{\"major\":1,\"minor\":0,\"patch\":0},\"tokens\":[]}";
    }

    function _has(string memory hay, string memory needle) internal pure returns (bool) {
        bytes memory h = bytes(hay);
        bytes memory n = bytes(needle);
        if (n.length == 0 || n.length > h.length) return false;
        for (uint256 i; i + n.length <= h.length; ++i) {
            bool match_ = true;
            for (uint256 j; j < n.length; ++j) {
                if (h[i + j] != n[j]) {
                    match_ = false;
                    break;
                }
            }
            if (match_) return true;
        }
        return false;
    }

    function _lower(address token) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        uint160 v = uint160(token);
        for (uint256 i; i < 20; ++i) {
            uint8 b = uint8(v >> (8 * (19 - i)));
            out[2 + i * 2] = hexChars[b >> 4];
            out[3 + i * 2] = hexChars[b & 0x0f];
        }
        return string(out);
    }
}
