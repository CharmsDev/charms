// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";

import {CharmToken} from "../src/CharmToken.sol";
import {Charms} from "../src/Charms.sol";
import {ICharmToken, ICharms, ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract MetadataTest is CharmsTestBase {
    uint256 internal metadataKey;

    bytes32 internal constant IMAGE_HASH = bytes32(uint256(1));

    string internal constant DEFAULT_URI =
        "data:application/json,%7B%22name%22%3A%22Charm%22%2C%22symbol%22%3A%22CHARM%22%2C%22decimals%22%3A0%7D";
    string internal constant EXAMPLE_URI =
        "data:application/json,%7B%22name%22%3A%22Example%22%2C%22symbol%22%3A%22EX%22%2C%22decimals%22%3A8%2C%22description%22%3A%22One%20fungible%20charm.%22%2C%22image%22%3A%22ipfs%3A%2F%2Fbafyexample%22%2C%22external_link%22%3A%22https%3A%2F%2Fexample.com%22%7D";

    function setUp() public override {
        (metadataSigner, metadataKey) = makeAddrAndKey("metadata");
        super.setUp();
    }

    function test_unpublishedCloneUsesTheDefaults() public {
        CharmToken token = CharmToken(charms.ensureToken(_app(T, "coin")));

        assertEq(token.name(), "Charm");
        assertEq(token.symbol(), "CHARM");
        assertEq(token.decimals(), 0);
        assertEq(token.contractURI(), DEFAULT_URI);
        assertEq(charms.metadataVersion(_app(T, "coin")), 0);
    }

    function test_setMetadataPublishesFieldsAndContractUri() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        bytes32 hash = _hash(metadata);
        CharmToken token = CharmToken(charms.ensureToken(coin));

        vm.expectEmit(true, false, false, true, address(charms));
        emit ICharms.MetadataSet(_key(coin), 1, hash);
        vm.expectEmit(false, false, false, false, address(token));
        emit ICharmToken.ContractURIUpdated();
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));

        assertEq(token.name(), "Example");
        assertEq(token.symbol(), "EX");
        assertEq(token.decimals(), 8);
        assertEq(token.contractURI(), EXAMPLE_URI);
        assertEq(charms.metadataVersion(coin), 1);
        assertEq(charms.name(coin), "Example");
        assertEq(charms.symbol(coin), "EX");
        assertEq(charms.decimals(coin), 8);
        assertEq(charms.contractURI(coin), EXAMPLE_URI);
    }

    function test_laterCallChangesMutableFieldsAndKeepsDecimals() public {
        App memory coin = _app(T, "coin");
        CharmToken token = CharmToken(charms.ensureToken(coin));
        Metadata memory metadata = _example();
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));

        Metadata memory next = metadata;
        next.name = "Renamed";
        next.symbol = "RN";
        next.description = "Updated.";
        next.url = "https://renamed.example";
        next.image = "ar://renamed";
        next.imageHash = bytes32(uint256(2));
        next.decimals = 6;
        vm.expectRevert(ICharmsErrors.DecimalsFrozen.selector);
        charms.setMetadata(coin, next, 2, _sign(coin, next, 2));
        assertEq(token.name(), "Example");
        assertEq(token.decimals(), 8);
        assertEq(charms.metadataVersion(coin), 1);

        next.decimals = 8;
        charms.setMetadata(coin, next, 2, _sign(coin, next, 2));

        assertEq(token.name(), "Renamed");
        assertEq(token.symbol(), "RN");
        assertEq(token.decimals(), 8);
        assertEq(charms.metadataVersion(coin), 2);
        assertEq(
            token.contractURI(),
            "data:application/json,%7B%22name%22%3A%22Renamed%22%2C%22symbol%22%3A%22RN%22%2C%22decimals%22%3A8%2C%22description%22%3A%22Updated.%22%2C%22image%22%3A%22ar%3A%2F%2Frenamed%22%2C%22external_link%22%3A%22https%3A%2F%2Frenamed.example%22%7D"
        );
    }

    function test_badSignatureIsRejectedAndLeavesTheRecord() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        bytes memory sig = _sign(coin, metadata, 1);
        sig[0] = bytes1(uint8(sig[0]) ^ 1);

        vm.expectRevert(ICharmsErrors.InvalidMetadataSignature.selector);
        charms.setMetadata(coin, metadata, 1, sig);

        assertEq(charms.metadataVersion(coin), 0);
        assertEq(CharmToken(charms.ensureToken(coin)).name(), "Charm");
        assertEq(CharmToken(charms.ensureToken(coin)).contractURI(), DEFAULT_URI);
    }

    function test_sameVersionCannotBeReplayed() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        bytes memory sig = _sign(coin, metadata, 1);
        charms.setMetadata(coin, metadata, 1, sig);

        vm.expectRevert(ICharmsErrors.StaleMetadataVersion.selector);
        charms.setMetadata(coin, metadata, 1, sig);
        assertEq(charms.metadataVersion(coin), 1);
    }

    function test_setMetadataBeforeEnsureTokenEmitsOnDeploy() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));
        assertEq(charms.tokenAddress(coin).code.length, 0);

        address token = charms.ensureToken(coin);
        assertEq(CharmToken(token).name(), "Example");
        assertEq(CharmToken(token).contractURI(), EXAMPLE_URI);
    }

    function test_ensureTokenEmitsContractUriWhenAlreadyPublished() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));
        address token = charms.tokenAddress(coin);

        vm.expectEmit(false, false, false, false, token);
        emit ICharmToken.ContractURIUpdated();
        assertEq(charms.ensureToken(coin), token);
    }

    function test_unpublishedEnsureTokenDoesNotEmitContractUri() public {
        App memory coin = _app(T, "coin");
        vm.recordLogs();
        charms.ensureToken(coin);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("ContractURIUpdated()");
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != topic);
        }
    }

    function test_vaultAndOtherTagsHaveNoMetadataSurface() public {
        Metadata memory metadata = _example();
        App memory vault = App(T, keccak256("vault"), VAULT_VK);
        vm.expectRevert(ICharmsErrors.NotToken.selector);
        charms.setMetadata(vault, metadata, 1, "");
        vm.expectRevert(ICharmsErrors.NotToken.selector);
        charms.name(vault);

        App memory nft = _app(N, "nft");
        vm.expectRevert(ICharmsErrors.NotTokenTag.selector);
        charms.setMetadata(nft, metadata, 1, "");
        vm.expectRevert(ICharmsErrors.NotTokenTag.selector);
        charms.contractURI(nft);
    }

    function test_invalidFieldsRevert() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        metadata.symbol = "";
        vm.expectRevert(ICharmsErrors.InvalidMetadata.selector);
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));

        metadata = _example();
        metadata.imageHash = bytes32(0);
        vm.expectRevert(ICharmsErrors.InvalidMetadata.selector);
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));

        metadata = _example();
        metadata.url = "http://example.com";
        vm.expectRevert(ICharmsErrors.InvalidMetadata.selector);
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));
        assertEq(charms.metadataVersion(coin), 0);
    }

    function test_metadataRecordUsesSlotEleven() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));

        bytes32 base = keccak256(abi.encode(_key(coin), uint256(11)));
        uint256 packed = uint256(vm.load(address(charms), base));
        assertEq(uint64(packed), 1);
        assertEq(uint8(packed >> 64), 8);
        assertEq(vm.load(address(charms), bytes32(uint256(base) + 1)), IMAGE_HASH);
    }

    function test_contractUriRoundTripsSpecialCharacters() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        metadata.name = string(bytes.concat(bytes('A"B\\C'), hex"e58583"));
        metadata.symbol = 'X"Y';
        metadata.description = string(bytes.concat(bytes('say "hi"\\path'), hex"0a09080c"));
        metadata.url = 'https://example.com/a"b';
        metadata.image = 'ipfs://bafy/"img';
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));

        CharmToken token = CharmToken(charms.ensureToken(coin));
        bytes memory json = _json(token.contractURI());
        assertEq(_stringField(json, "name"), metadata.name);
        assertEq(_stringField(json, "symbol"), metadata.symbol);
        assertEq(_stringField(json, "description"), metadata.description);
        assertEq(_stringField(json, "image"), metadata.image);
        assertEq(_stringField(json, "external_link"), metadata.url);
        assertEq(_numberField(json, "decimals"), metadata.decimals);
        assertEq(json, _json(charms.contractURI(coin)));
    }

    function test_signatureDoesNotReplayOnAnotherChain() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();

        vm.chainId(1);
        bytes memory sig = _sign(coin, metadata, 1);
        vm.chainId(11_155_111);
        vm.expectRevert(ICharmsErrors.InvalidMetadataSignature.selector);
        charms.setMetadata(coin, metadata, 1, sig);
        assertEq(charms.metadataVersion(coin), 0);

        vm.chainId(1);
        charms.setMetadata(coin, metadata, 1, sig);
        assertEq(charms.metadataVersion(coin), 1);
    }

    function test_signatureDoesNotReplayOnAnotherProxy() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        bytes memory sig = _sign(coin, metadata, 1);
        Charms other = _deploy(16, PROGRAM_VKEY, verifier);

        vm.expectRevert(ICharmsErrors.InvalidMetadataSignature.selector);
        other.setMetadata(coin, metadata, 1, sig);
        assertEq(other.metadataVersion(coin), 0);

        charms.setMetadata(coin, metadata, 1, sig);
        assertEq(charms.metadataVersion(coin), 1);
        assertEq(other.metadataVersion(coin), 0);
    }

    function test_signatureDoesNotReplayOnAnotherApp() public {
        App memory coin = _app(T, "coin");
        App memory other = _app(T, "other");
        Metadata memory metadata = _example();
        bytes memory sig = _sign(coin, metadata, 1);

        vm.expectRevert(ICharmsErrors.InvalidMetadataSignature.selector);
        charms.setMetadata(other, metadata, 1, sig);
        assertEq(charms.metadataVersion(other), 0);

        charms.setMetadata(coin, metadata, 1, sig);
        assertEq(charms.metadataVersion(coin), 1);
        assertEq(charms.metadataVersion(other), 0);
    }

    function test_signatureBindsTheMetadataHash() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        bytes memory sig = _sign(coin, metadata, 1);
        metadata.name = "Tampered";

        vm.expectRevert(ICharmsErrors.InvalidMetadataSignature.selector);
        charms.setMetadata(coin, metadata, 1, sig);
        assertEq(charms.metadataVersion(coin), 0);
    }

    function test_eip191PrefixIsRejected() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        bytes32 digest = keccak256(
            abi.encode(
                keccak256(
                    "CharmsMetadata(uint256 chainId,address charms,bytes32 appKey,uint64 version,bytes32 metadataHash)"
                ),
                block.chainid,
                address(charms),
                _key(coin),
                uint64(1),
                _hash(metadata)
            )
        );
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(metadataKey, prefixed);

        vm.expectRevert(ICharmsErrors.InvalidMetadataSignature.selector);
        charms.setMetadata(coin, metadata, 1, abi.encodePacked(r, s, v));
        assertEq(charms.metadataVersion(coin), 0);
    }

    function test_versionZeroIsRejectedAndAGapIsAllowed() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();

        vm.expectRevert(ICharmsErrors.StaleMetadataVersion.selector);
        charms.setMetadata(coin, metadata, 0, _sign(coin, metadata, 0));

        bytes memory atFour = _sign(coin, metadata, 4);
        vm.expectRevert(ICharmsErrors.InvalidMetadataSignature.selector);
        charms.setMetadata(coin, metadata, 2, atFour);

        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));
        charms.setMetadata(coin, metadata, 4, atFour);
        assertEq(charms.metadataVersion(coin), 4);

        vm.expectRevert(ICharmsErrors.StaleMetadataVersion.selector);
        charms.setMetadata(coin, metadata, 3, _sign(coin, metadata, 3));
        vm.expectRevert(ICharmsErrors.StaleMetadataVersion.selector);
        charms.setMetadata(coin, metadata, 4, atFour);
        assertEq(charms.metadataVersion(coin), 4);
        assertEq(CharmToken(charms.ensureToken(coin)).name(), "Example");
    }

    function test_publishedZeroDecimalsStaysFrozen() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        metadata.decimals = 0;
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));
        CharmToken token = CharmToken(charms.ensureToken(coin));

        assertEq(token.decimals(), 0);
        assertEq(charms.metadataVersion(coin), 1);

        metadata.decimals = 8;
        vm.expectRevert(ICharmsErrors.DecimalsFrozen.selector);
        charms.setMetadata(coin, metadata, 2, _sign(coin, metadata, 2));
        assertEq(token.decimals(), 0);
        assertEq(charms.metadataVersion(coin), 1);

        metadata.decimals = 0;
        metadata.name = "Zero";
        charms.setMetadata(coin, metadata, 2, _sign(coin, metadata, 2));
        assertEq(token.name(), "Zero");
        assertEq(token.decimals(), 0);
    }

    function test_setMetadataWithoutACloneEmitsOnlyFromTheProxy() public {
        App memory coin = _app(T, "coin");
        Metadata memory metadata = _example();
        bytes32 hash = _hash(metadata);

        vm.recordLogs();
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 metaTopic = keccak256("MetadataSet(bytes32,uint64,bytes32)");
        bytes32 uriTopic = keccak256("ContractURIUpdated()");
        uint256 metaLogs;
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != uriTopic);
            if (logs[i].topics[0] != metaTopic) continue;
            assertEq(logs[i].emitter, address(charms));
            assertEq(logs[i].topics[1], _key(coin));
            (uint64 version, bytes32 got) = abi.decode(logs[i].data, (uint64, bytes32));
            assertEq(version, 1);
            assertEq(got, hash);
            ++metaLogs;
        }
        assertEq(metaLogs, 1);
        assertEq(charms.tokenAddress(coin).code.length, 0);
    }

    function test_permitDomainStaysCharmAfterRename() public {
        App memory coin = _app(T, "coin");
        CharmToken token = CharmToken(charms.ensureToken(coin));
        Metadata memory metadata = _example();
        charms.setMetadata(coin, metadata, 1, _sign(coin, metadata, 1));
        metadata.name = "Renamed";
        charms.setMetadata(coin, metadata, 2, _sign(coin, metadata, 2));
        assertEq(token.name(), "Renamed");

        bytes32 domain = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("Charm"),
                keccak256("1"),
                block.chainid,
                address(token)
            )
        );
        assertEq(token.DOMAIN_SEPARATOR(), domain);

        (address alice, uint256 aliceKey) = makeAddrAndKey("alice");
        uint256 deadline = block.timestamp + 1000;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                ),
                alice,
                address(0xBEEF),
                uint256(1),
                uint256(0),
                deadline
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(aliceKey, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        token.permit(alice, address(0xBEEF), 1, deadline, v, r, s);
        assertEq(token.allowance(alice, address(0xBEEF)), 1);
    }

    function _example() internal pure returns (Metadata memory) {
        return Metadata({
            name: "Example",
            symbol: "EX",
            decimals: 8,
            description: "One fungible charm.",
            url: "https://example.com",
            image: "ipfs://bafyexample",
            imageHash: IMAGE_HASH
        });
    }

    function _hash(Metadata memory metadata) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                metadata.name,
                metadata.symbol,
                metadata.decimals,
                metadata.description,
                metadata.url,
                metadata.image,
                metadata.imageHash
            )
        );
    }

    function _json(string memory uri) internal pure returns (bytes memory) {
        bytes memory raw = bytes(uri);
        bytes memory prefix = bytes("data:application/json,");
        uint256 n;
        for (uint256 i = prefix.length; i < raw.length; ++i) {
            if (raw[i] == "%") i += 2;
            ++n;
        }
        bytes memory out = new bytes(n);
        uint256 j;
        for (uint256 i = prefix.length; i < raw.length; ++i) {
            if (raw[i] == "%") {
                out[j++] = bytes1(uint8(_hex(raw[i + 1]) * 16 + _hex(raw[i + 2])));
                i += 2;
            } else {
                out[j++] = raw[i];
            }
        }
        return out;
    }

    function _stringField(bytes memory json, string memory key)
        internal
        pure
        returns (string memory)
    {
        bytes memory pattern = bytes(string.concat('"', key, '":"'));
        uint256 i = _at(json, pattern) + pattern.length;
        bytes memory buf = new bytes(json.length);
        uint256 n;
        while (i < json.length) {
            bytes1 c = json[i++];
            if (c == '"') break;
            if (c != "\\") {
                buf[n++] = c;
                continue;
            }
            c = json[i++];
            if (c == "n") {
                buf[n++] = 0x0a;
            } else if (c == "r") {
                buf[n++] = 0x0d;
            } else if (c == "t") {
                buf[n++] = 0x09;
            } else if (c == "u") {
                uint16 code = (uint16(_hex(json[i])) << 12) | (uint16(_hex(json[i + 1])) << 8)
                    | (uint16(_hex(json[i + 2])) << 4) | uint16(_hex(json[i + 3]));
                i += 4;
                buf[n++] = bytes1(uint8(code));
            } else {
                buf[n++] = c;
            }
        }
        return _trim(buf, n);
    }

    function _numberField(bytes memory json, string memory key) internal pure returns (uint8) {
        bytes memory pattern = bytes(string.concat('"', key, '":'));
        uint256 i = _at(json, pattern) + pattern.length;
        uint256 value;
        while (i < json.length && json[i] >= "0" && json[i] <= "9") {
            value = value * 10 + uint8(json[i]) - 48;
            ++i;
        }
        return uint8(value);
    }

    function _at(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        for (uint256 i; i + needle.length <= hay.length; ++i) {
            bool match_ = true;
            for (uint256 j; j < needle.length; ++j) {
                if (hay[i + j] != needle[j]) {
                    match_ = false;
                    break;
                }
            }
            if (match_) return i;
        }
        revert("field missing");
    }

    function _hex(bytes1 c) internal pure returns (uint8) {
        uint8 v = uint8(c);
        if (v >= 0x30 && v <= 0x39) return v - 0x30;
        if (v >= 0x41 && v <= 0x46) return v - 0x37;
        if (v >= 0x61 && v <= 0x66) return v - 0x57;
        revert("bad hex");
    }

    function _trim(bytes memory buf, uint256 n) internal pure returns (string memory) {
        bytes memory out = new bytes(n);
        for (uint256 i; i < n; ++i) {
            out[i] = buf[i];
        }
        return string(out);
    }

    function _sign(App memory app, Metadata memory metadata, uint64 version)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = keccak256(
            abi.encode(
                keccak256(
                    "CharmsMetadata(uint256 chainId,address charms,bytes32 appKey,uint64 version,bytes32 metadataHash)"
                ),
                block.chainid,
                address(charms),
                _key(app),
                version,
                _hash(metadata)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(metadataKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
