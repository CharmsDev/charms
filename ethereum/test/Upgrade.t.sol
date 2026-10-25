// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {CharmTokenNext} from "../script/CharmTokenNext.sol";
import {CharmToken} from "../src/CharmToken.sol";
import {CharmTokenProxy} from "../src/CharmTokenProxy.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsInitializer} from "../src/CharmsInitializer.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";
import {ICharmsErrors, ICharmsLedger} from "../src/interfaces/ICharms.sol";
import {CharmsMetadata} from "../src/libraries/CharmsMetadata.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract ReportsZeroSigner {
    address public immutable tokenImplementation;
    address public immutable metadataSigner;

    constructor(address token) {
        tokenImplementation = token;
    }

    function proxiableUUID() external pure returns (bytes32) {
        return bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    }
}

contract OtherSlotImplementation {
    address public immutable tokenImplementation;
    address public immutable metadataSigner;

    constructor(address token, address signer) {
        tokenImplementation = token;
        metadataSigner = signer;
    }

    function proxiableUUID() external pure returns (bytes32) {
        return bytes32(uint256(1));
    }
}

contract UpgradeTest is CharmsTestBase {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    struct History {
        App vault;
        address token;
        UtxoRef wrapped;
        UtxoRef sent;
        UtxoRef change;
        UtxoRef placeholder;
    }

    function test_implementationCannotBeInitialized() public {
        CharmsInitializer impl = new CharmsInitializer();

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(bob);
    }

    function test_proxyCannotBeInitializedTwice() public {
        CharmsInitializer impl = new CharmsInitializer();
        CharmsProxy proxy =
            new CharmsProxy(address(impl), abi.encodeCall(CharmsInitializer.initialize, (bob)));

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        CharmsInitializer(address(proxy)).initialize(bob);
    }

    function test_adminIsTheInitializeArgument() public {
        address chosen = makeAddr("chosen admin");
        CharmsInitializer impl = new CharmsInitializer();

        CharmsProxy proxy =
            new CharmsProxy(address(impl), abi.encodeCall(CharmsInitializer.initialize, (chosen)));

        assertEq(CharmsInitializer(address(proxy)).admin(), chosen);
    }

    function test_onlyTheAdminCanUpgrade() public {
        Charms next = _implementationV16();

        vm.prank(bob);
        vm.expectRevert(ICharmsErrors.NotAdmin.selector);
        charms.upgradeToAndCall(address(next), "");
    }

    function test_upgradeOnlyRunsThroughTheProxy() public {
        Charms current = Charms(payable(_implementation()));
        Charms next = _implementationV16();

        vm.prank(admin);
        vm.expectRevert(UUPSUpgradeable.UUPSUnauthorizedCallContext.selector);
        current.upgradeToAndCall(address(next), "");
    }

    function test_upgradeToAContractWithoutProxiableUuidReverts() public {
        vm.prank(admin);
        vm.expectRevert(ICharmsErrors.NoTokenImplementation.selector);
        charms.upgradeToAndCall(address(verifier), "");
    }

    function test_upgradeToAContractWithAnotherProxiableUuidReverts() public {
        OtherSlotImplementation other =
            new OtherSlotImplementation(charms.tokenImplementation(), charms.metadataSigner());

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                UUPSUpgradeable.UUPSUnsupportedProxiableUUID.selector, bytes32(uint256(1))
            )
        );
        charms.upgradeToAndCall(address(other), "");
    }

    function test_upgradeWithEthAndEmptyDataReverts() public {
        Charms next = _implementationV16();
        vm.deal(admin, 1 ether);

        vm.prank(admin);
        vm.expectRevert(ERC1967Utils.ERC1967NonPayable.selector);
        charms.upgradeToAndCall{value: 1 ether}(address(next), "");
    }

    function test_forwarderIsTheProxysFirstCreation() public view {
        address forwarder = vm.computeCreateAddress(address(charms), 1);

        assertGt(forwarder.code.length, 0);
        assertEq(address(CharmTokenProxy(forwarder).charms()), address(charms));
        assertTrue(forwarder != charms.tokenImplementation());
        assertEq(address(CharmToken(charms.tokenImplementation()).charms()), address(charms));
    }

    function test_everyCloneDelegatesToTheForwarder() public {
        bytes memory runtime = charms.ensureToken(_app(T, "coin")).code;
        bytes memory forwarded = new bytes(20);
        for (uint256 i; i < 20; ++i) {
            forwarded[i] = runtime[22 + i];
        }

        assertEq(address(bytes20(forwarded)), vm.computeCreateAddress(address(charms), 1));
    }

    function test_upgradeWritesTheNewImplementationToTheErc1967Slot() public {
        _phase1History();
        Charms before = Charms(payable(_implementation()));

        Charms next = _upgradeToV16();

        assertEq(before.SPELL_VERSION(), 15);
        assertEq(_implementation(), address(next));
        assertEq(charms.SPELL_VERSION(), 16);
    }

    function test_upgradeKeepsTokenAddressesAndTheyStillTransfer() public {
        History memory h = _phase1History();
        App memory coin = _app(T, "coin");
        address clone = charms.ensureToken(coin);

        _upgradeToV16();

        assertEq(h.token, address(0));
        assertEq(charms.tokenAddress(h.vault), address(0));
        assertEq(charms.ensureToken(h.vault), address(0));
        assertEq(charms.tokenAddress(coin), clone);

        _mintOne(bob, _apps(coin), _charms(_token(0, 300)));
        vm.prank(bob);
        CharmToken(clone).transfer(carol, 100);
        assertEq(CharmToken(clone).balanceOf(bob), 200);
        assertEq(CharmToken(clone).balanceOf(carol), 100);

        Spell memory s = _spell(_apps(h.vault), 1, 1);
        s.ins[0] = _input(h.sent.txId, h.sent.index, _charms(_token(0, 300)));
        s.outs[0] = Output(carol, _charms(_token(0, 300)));
        _transact(bob, s);
        assertEq(_balance(h.vault, carol), 300);
        assertEq(_balance(h.vault, bob), 0);
    }

    function test_upgradeKeepsEveryUtxoRecord() public {
        History memory h = _phase1History();
        bytes[4] memory before = _records(h);

        _upgradeToV16();

        bytes[4] memory current = _records(h);
        for (uint256 i; i < 4; ++i) {
            assertEq(current[i], before[i], "a UTXO record changed");
        }
        _assertRecord(h.wrapped, 0, address(0), 0);
        _assertRecord(h.sent, 1, bob, 300);
        _assertRecord(h.change, 1, alice, 700);
        _assertRecord(h.placeholder, 0, carol, 0);
    }

    function test_upgradeKeepsSupplyBalancesAndCollateral() public {
        History memory h = _phase1History();

        _upgradeToV16();

        assertEq(charms.totalSupply(_key(h.vault)), 1000);
        assertEq(_balance(h.vault, alice), 700);
        assertEq(_balance(h.vault, bob), 300);
        uint256 locked = _locked(address(0));
        assertEq(locked, 1000e10);
        assertEq(address(charms).balance, 1000e10);
    }

    function test_v16SpellSpendsAUtxoTheV15BuildCreated() public {
        History memory h = _phase1History();
        _upgradeToV16();
        Spell memory s = _spell(_apps(h.vault), 1, 1);
        s.ins[0] = _input(h.sent.txId, h.sent.index, _charms(_token(0, 300)));
        s.outs[0] = Output(carol, _charms(_token(0, 300)));

        bytes32 txId = _transact(bob, s);

        assertEq(s.version, 16);
        _assertRecord(UtxoRef(txId, 0), 1, carol, 300);
        assertEq(_balance(h.vault, carol), 300);
        assertEq(_balance(h.vault, bob), 0);
    }

    function test_v16RefusesANewVersion15Spell() public {
        History memory h = _phase1History();
        _upgradeToV16();
        Spell memory s = _spell(_apps(h.vault), 1, 1);
        s.version = 15;
        s.ins[0] = _input(h.sent.txId, h.sent.index, _charms(_token(0, 300)));
        s.outs[0] = Output(carol, _charms(_token(0, 300)));

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(ICharmsErrors.UnsupportedVersion.selector, uint32(15))
        );
        charms.transact(s, bytes32(0), "", new bytes[](0));
    }

    function test_ethLockedBeforeTheUpgradeUnwrapsAfterIt() public {
        _phase1History();
        _upgradeToV16();

        vm.prank(alice);
        charms.unwrap(address(0), 700, alice);

        assertEq(alice.balance, 700e10);
        uint256 locked = _locked(address(0));
        assertEq(locked, 300e10);
    }

    function test_upgradeKeepsTheCloneAndRunsTheNewTokenLogic() public {
        App memory coin = _app(T, "coin");
        address clone = charms.ensureToken(coin);
        assertEq(charms.tokenAddress(coin), clone);
        assertEq(CharmToken(clone).name(), "Charm");
        vm.prank(bob);
        CharmToken(clone).approve(carol, 7);

        CharmTokenNext nextToken = new CharmTokenNext(ICharmsLedger(address(charms)));
        Charms next = new Charms(
            new CharmsApply(16, PROGRAM_VKEY, verifier), address(nextToken), charms.metadataSigner()
        );
        vm.prank(admin);
        charms.upgradeToAndCall(address(next), "");

        assertEq(charms.tokenAddress(coin), clone);
        assertEq(charms.tokenImplementation(), address(nextToken));
        assertEq(CharmToken(clone).name(), "Charm");
        assertEq(CharmToken(clone).allowance(bob, carol), 7);
        assertEq(CharmTokenNext(clone).revision(), 2);
    }

    function test_upgradeRejectsATokenBoundElsewhere() public {
        CharmToken foreign = new CharmToken(ICharmsLedger(address(0xdead)));
        Charms next = new Charms(
            new CharmsApply(16, PROGRAM_VKEY, verifier), address(foreign), metadataSigner
        );

        vm.prank(admin);
        vm.expectRevert(ICharmsErrors.TokenCharmsMismatch.selector);
        charms.upgradeToAndCall(address(next), "");
    }

    function test_upgradeSwapsTheTokenAndTheSignerAndKeepsCloneState() public {
        App memory coin = _app(T, "coin");
        CharmToken token = CharmToken(charms.ensureToken(coin));
        Metadata memory metadata = _metadata();
        (, uint256 oldKey) = makeAddrAndKey("metadataSigner");
        assertEq(vm.addr(oldKey), metadataSigner);
        charms.setMetadata(coin, metadata, 1, _signMetadata(oldKey, coin, metadata, 1));

        (address holder, uint256 holderKey) = makeAddrAndKey("permit-holder");
        uint256 deadline = block.timestamp + 1000;
        bytes32 domain = token.DOMAIN_SEPARATOR();
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                ),
                holder,
                carol,
                uint256(11),
                token.nonces(holder),
                deadline
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(holderKey, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        token.permit(holder, carol, 11, deadline, v, r, s);

        (address nextSigner, uint256 nextKey) = makeAddrAndKey("next-signer");
        CharmTokenNext nextToken = new CharmTokenNext(ICharmsLedger(address(charms)));
        Charms next =
            new Charms(new CharmsApply(16, PROGRAM_VKEY, verifier), address(nextToken), nextSigner);
        vm.prank(admin);
        charms.upgradeToAndCall(address(next), "");

        assertEq(charms.tokenAddress(coin), address(token));
        assertEq(charms.tokenImplementation(), address(nextToken));
        assertEq(charms.metadataSigner(), nextSigner);
        assertEq(CharmTokenNext(address(token)).revision(), 2);
        assertEq(token.allowance(holder, carol), 11);
        assertEq(token.nonces(holder), 1);
        assertEq(token.name(), "Example");

        metadata.name = "After";
        vm.expectRevert(ICharmsErrors.InvalidMetadataSignature.selector);
        charms.setMetadata(coin, metadata, 2, _signMetadata(oldKey, coin, metadata, 2));
        assertEq(token.name(), "Example");
        assertEq(token.nonces(holder), 1);

        charms.setMetadata(coin, metadata, 2, _signMetadata(nextKey, coin, metadata, 2));
        assertEq(token.name(), "After");
        assertEq(token.decimals(), 8);
        assertEq(charms.tokenAddress(coin), address(token));
        assertEq(token.allowance(holder, carol), 11);
        assertEq(token.nonces(holder), 1);
    }

    function test_upgradeRejectsAReportedZeroSigner() public {
        ReportsZeroSigner hostile = new ReportsZeroSigner(charms.tokenImplementation());

        vm.prank(admin);
        vm.expectRevert(ICharmsErrors.ZeroMetadataSigner.selector);
        charms.upgradeToAndCall(address(hostile), "");
    }

    function test_upgradeRejectsATokenWithNoCode() public {
        Charms next = new Charms(
            new CharmsApply(16, PROGRAM_VKEY, verifier), address(0xBEEF), metadataSigner
        );

        vm.prank(admin);
        vm.expectRevert(ICharmsErrors.NoTokenImplementation.selector);
        charms.upgradeToAndCall(address(next), "");
    }

    function test_constructorRejectsAZeroMetadataSigner() public {
        CharmsApply applier = new CharmsApply(16, PROGRAM_VKEY, verifier);
        address token = charms.tokenImplementation();

        vm.expectRevert(ICharmsErrors.ZeroMetadataSigner.selector);
        new Charms(applier, token, address(0));
    }

    function _metadata() internal pure returns (Metadata memory) {
        return Metadata({
            name: "Example",
            symbol: "EX",
            decimals: 8,
            description: "One fungible charm.",
            url: "https://example.com",
            image: "ipfs://bafyexample",
            imageHash: bytes32(uint256(1))
        });
    }

    function _signMetadata(uint256 key, App memory app, Metadata memory metadata, uint64 version)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 metadataHash = keccak256(
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
        bytes32 digest = CharmsMetadata.digest(_key(app), version, metadataHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _phase1History() internal returns (History memory h) {
        _deployPhase1();
        vm.deal(alice, 1000e10);
        vm.prank(alice);
        h.wrapped = UtxoRef(charms.wrap{value: 1000e10}(address(0), 1000, alice, bytes32(0)), 0);
        (h.vault,) = charms.vaultOf(address(0));
        h.token = charms.tokenAddress(h.vault);
        Spell memory s = _spell(_apps(h.vault), 1, 2);
        s.ins[0] = _input(h.wrapped.txId, h.wrapped.index, _charms(_token(0, 1000)));
        s.outs[0] = Output(bob, _charms(_token(0, 300)));
        s.outs[1] = Output(alice, _charms(_token(0, 700)));
        _transact(alice, s);
        h.sent = _onlyUtxo(h.vault, bob);
        h.change = _onlyUtxo(h.vault, alice);
        h.placeholder = UtxoRef(_placeholder(carol), 0);
    }

    function _implementationV16() internal returns (Charms) {
        return new Charms(
            new CharmsApply(16, PROGRAM_VKEY, verifier),
            charms.tokenImplementation(),
            charms.metadataSigner()
        );
    }

    function _upgradeToV16() internal returns (Charms next) {
        next = _implementationV16();
        vm.prank(admin);
        charms.upgradeToAndCall(address(next), "");
    }

    function _implementation() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(charms), IMPLEMENTATION_SLOT))));
    }

    function _onlyUtxo(App memory app, address owner) internal view returns (UtxoRef memory) {
        (UtxoRef[] memory page,) = charms.utxosOf(_key(app), owner, 0, 10);
        assertEq(page.length, 1);
        return page[0];
    }

    function _records(History memory h) internal view returns (bytes[4] memory r) {
        r[0] = _record(h.wrapped);
        r[1] = _record(h.sent);
        r[2] = _record(h.change);
        r[3] = _record(h.placeholder);
    }

    function _record(UtxoRef memory u) internal view returns (bytes memory) {
        (address owner, bytes memory body) = charms.utxo(u);
        return abi.encode(owner, body);
    }

    function _assertRecord(UtxoRef memory u, uint8 kind, address owner, uint64 amount)
        internal
        view
    {
        (address o, bytes memory body) = charms.utxo(u);
        (uint8 k,, uint64 a) = _storedHead(u.txId, u.index);
        assertEq(o, owner);
        assertEq(body.length, 0);
        assertEq(k, kind);
        assertEq(a, amount);
    }
}
