// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {SetMetadata} from "../script/SetMetadata.s.sol";
import {CharmToken} from "../src/CharmToken.sol";
import {ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract EbtcMetadataTest is CharmsTestBase {
    uint256 internal signerKey;
    SetMetadata internal tool;

    function setUp() public override {
        (metadataSigner, signerKey) = makeAddrAndKey("ebtcMetadataSigner");
        super.setUp();
        tool = new SetMetadata();
    }

    function test_ebtcFilePublishesSymbolDecimalsAndLogo() public {
        (ICharmsTypes.App memory app, ICharmsTypes.Metadata memory metadata) = tool.ebtc();
        assertEq(app.tag, T);
        assertEq(
            app.identity, hex"0796f63ed48144b4ec69fb794fbc2290ae63acf945fb035d5474648b50ee43b6"
        );
        assertEq(app.vk, hex"fd0cac892e457454be0212fa7d9a0e1517d5bd6a33aa7c66a1f10f55e375c290");
        assertEq(metadata.name, "eBTC");
        assertEq(metadata.symbol, "eBTC");
        assertEq(metadata.decimals, 8);
        assertEq(
            metadata.image, "ipfs://bafkreiamp6ocmalh4uu77jhcr2yh3i5ea4knet53qnmfuupmg45326u4wa"
        );
        assertEq(
            metadata.imageHash,
            hex"0c7f9c260167e529ffa4e28eb07da3a40714d24fbb83585a51ec373bbd7a9cb0"
        );

        bytes32 message = tool.digest(block.chainid, address(charms), 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, message);
        charms.setMetadata(app, metadata, 1, abi.encodePacked(r, s, v));
        address token = charms.ensureToken(app);

        assertEq(CharmToken(token).name(), "eBTC");
        assertEq(CharmToken(token).symbol(), "eBTC");
        assertEq(CharmToken(token).decimals(), 8);
        assertTrue(_has(CharmToken(token).contractURI(), "eBTC"));

        string memory list =
            tool.tokenList(block.chainid, token, metadata, "2026-10-24T00:00:00.000Z");
        assertTrue(_has(list, "eBTC"));
        assertTrue(_has(list, "\"decimals\":8"));
        assertTrue(_has(list, metadata.image));
        assertTrue(_has(list, _lower(token)));
        assertEq(tool.tokenList(1, address(0), metadata, "2026-10-24T00:00:00.000Z"), _emptyList());

        string memory watch = tool.watchAsset(token, metadata);
        assertTrue(_has(watch, "\"type\":\"ERC20\""));
        assertTrue(_has(watch, "\"symbol\":\"eBTC\""));
        assertTrue(_has(watch, "\"decimals\":8"));
        assertTrue(_has(watch, metadata.image));

        metadata.image = "";
        metadata.imageHash = bytes32(0);
        assertFalse(_has(tool.watchAsset(token, metadata), "image"));
        assertFalse(_has(tool.tokenList(1, token, metadata, "2026-10-24T00:00:00.000Z"), "logoURI"));
    }

    function test_digestForAnotherChainIsRejected() public {
        (ICharmsTypes.App memory app, ICharmsTypes.Metadata memory metadata) = tool.ebtc();
        bytes32 message = tool.digest(block.chainid + 1, address(charms), 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, message);
        vm.expectRevert();
        charms.setMetadata(app, metadata, 1, abi.encodePacked(r, s, v));
    }

    function test_tokenListEscapesQuotes() public view {
        ICharmsTypes.Metadata memory metadata;
        metadata.name = "a\"b\\c";
        metadata.symbol = "AB";
        metadata.decimals = 8;
        string memory list =
            tool.tokenList(1, address(0x1111111111111111111111111111111111111111), metadata, "t");
        assertTrue(_has(list, "\"a\\\"b\\\\c\""));
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
