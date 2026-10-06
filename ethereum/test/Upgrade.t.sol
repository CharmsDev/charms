// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {CharmToken} from "../src/CharmToken.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";
import {ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract OtherSlotImplementation {
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
        Charms impl = _implementationV16();

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(bob);
    }

    function test_proxyCannotBeInitializedTwice() public {
        vm.prank(bob);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        charms.initialize(bob);
    }

    function test_adminIsTheInitializeArgument() public {
        address chosen = makeAddr("chosen admin");

        CharmsProxy proxy = new CharmsProxy(
            address(_implementationV16()), abi.encodeCall(Charms.initialize, (chosen))
        );

        assertEq(Charms(payable(address(proxy))).admin(), chosen);
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
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC1967Utils.ERC1967InvalidImplementation.selector, address(verifier)
            )
        );
        charms.upgradeToAndCall(address(verifier), "");
    }

    function test_upgradeToAContractWithAnotherProxiableUuidReverts() public {
        OtherSlotImplementation other = new OtherSlotImplementation();

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

    function test_sharedTokenImplementationIsTheProxysFirstCreation() public view {
        address impl = vm.computeCreateAddress(address(charms), 1);

        assertGt(impl.code.length, 0);
        assertEq(address(CharmToken(impl).charms()), address(charms));
    }

    function test_everyCloneDelegatesToTheSharedImplementation() public {
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

        _upgradeToV16();

        assertEq(charms.tokenAddress(h.vault), h.token);
        assertEq(charms.ensureToken(h.vault), h.token);
        vm.prank(bob);
        CharmToken(h.token).transfer(carol, 100);
        assertEq(CharmToken(h.token).balanceOf(bob), 200);
        assertEq(CharmToken(h.token).balanceOf(carol), 100);
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

    function _phase1History() internal returns (History memory h) {
        _deployPhase1();
        vm.deal(alice, 1000e10);
        vm.prank(alice);
        h.wrapped = UtxoRef(charms.wrap{value: 1000e10}(address(0), 1000, alice, bytes32(0)), 0);
        (h.vault,) = charms.vaultOf(address(0));
        h.token = charms.ensureToken(h.vault);
        vm.prank(alice);
        CharmToken(h.token).transfer(bob, 300);
        h.sent = _onlyUtxo(h.vault, bob);
        h.change = _onlyUtxo(h.vault, alice);
        h.placeholder = UtxoRef(_placeholder(carol), 0);
    }

    function _implementationV16() internal returns (Charms) {
        return new Charms(new CharmsApply(16, PROGRAM_VKEY, verifier));
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
        (uint8 kind, address owner, uint64 amount, bytes memory body) = charms.utxo(u);
        return abi.encode(kind, owner, amount, body);
    }

    function _assertRecord(UtxoRef memory u, uint8 kind, address owner, uint64 amount)
        internal
        view
    {
        (uint8 k, address o, uint64 a, bytes memory body) = charms.utxo(u);
        assertEq(k, kind);
        assertEq(o, owner);
        assertEq(a, amount);
        assertEq(body.length, 0);
    }
}
