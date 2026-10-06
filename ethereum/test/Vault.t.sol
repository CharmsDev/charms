// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {CharmTokenClone} from "../src/libraries/CharmTokenClone.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";
import {BareToken, FeeToken, MockToken, MutableDecimalsToken, RejectEth} from "./utils/Mocks.sol";

contract VaultTest is CharmsTestBase {
    address internal alice;
    address internal bob;

    function setUp() public override {
        super.setUp();
        _deployPhase1();
        alice = makeAddr("alice");
        bob = makeAddr("bob");
    }

    function test_ethWrapUsesScaleTenAndMintsToOwner() public {
        (App memory app, uint8 scale) = charms.vaultOf(address(0));
        uint256 locked = _locked(address(0));
        assertEq(scale, 10);
        assertEq(locked, 0);
        assertEq(app.tag, T);

        vm.deal(alice, 1 ether);
        vm.prank(alice);
        charms.wrap{value: 7 * 10 ** 10}(address(0), 7, bob, bytes32(uint256(1)));

        assertEq(_balance(app, bob), 7);
        assertEq(_balance(app, alice), 0);
        (app, scale) = charms.vaultOf(address(0));
        locked = _locked(address(0));
        assertEq(scale, 10);
        assertEq(locked, 7 * 10 ** 10);
        assertEq(address(charms).balance, 7 * 10 ** 10);
    }

    function test_ethWrapRevertsWhenValueMismatches() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.UnderlyingAmountMismatch.selector);
        charms.wrap{value: (7 * 10 ** 10) - 1}(address(0), 7, alice, bytes32(uint256(1)));

        assertEq(address(charms).balance, 0);
        assertEq(alice.balance, 1 ether);
        uint256 locked = _locked(address(0));
        assertEq(locked, 0);
    }

    function test_reusedAnchorReverts() public {
        bytes32 salt = bytes32(uint256(11));
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        charms.wrap{value: 10 ** 10}(address(0), 1, alice, salt);

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.AnchorUsed.selector);
        charms.wrap{value: 10 ** 10}(address(0), 1, alice, salt);

        (App memory app,) = charms.vaultOf(address(0));
        uint256 locked = _locked(address(0));
        assertEq(_balance(app, alice), 1);
        assertEq(locked, 10 ** 10);
    }

    function test_erc20WrapRevertsWhenEthIsAttached() public {
        MockToken token = new MockToken("USDC", "USDC", 6);
        token.mint(alice, 5);
        vm.deal(alice, 1 ether);
        vm.startPrank(alice);
        token.approve(address(charms), 5);
        vm.expectRevert(ICharmsErrors.UnderlyingAmountMismatch.selector);
        charms.wrap{value: 1}(address(token), 5, alice, bytes32(uint256(1)));
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 5);
        assertEq(token.balanceOf(address(charms)), 0);
        assertEq(address(charms).balance, 0);
        uint256 locked = _locked(address(token));
        assertEq(locked, 0);
    }

    function test_sixDecimalVaultScaleIsZero() public {
        _assertScale(address(new MockToken("USDC", "USDC", 6)), 0);
    }

    function test_eighteenDecimalVaultScaleIsTen() public {
        _assertScale(address(new MockToken("WETH", "WETH", 18)), 10);
    }

    function test_twentyFourDecimalVaultScaleIsSixteen() public {
        _assertScale(address(new MockToken("WIDE", "WIDE", 24)), 16);
    }

    function test_tokenWithoutDecimalsUsesScaleZero() public {
        _assertScale(address(new BareToken()), 0);
    }

    function test_feeOnTransferWrapReverts() public {
        FeeToken token = new FeeToken();
        token.mint(alice, 100);
        vm.startPrank(alice);
        token.approve(address(charms), 100);
        vm.expectRevert(ICharmsErrors.UnderlyingAmountMismatch.selector);
        charms.wrap(address(token), 100, alice, bytes32(uint256(1)));
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 100);
        assertEq(token.balanceOf(address(charms)), 0);
        uint256 locked = _locked(address(token));
        assertEq(locked, 0);
    }

    function test_decimalsChangeRevertsWrapAndUnwrap() public {
        MutableDecimalsToken token = new MutableDecimalsToken();
        assertEq(token.decimals(), 18);
        _wrap(address(token), 3, 10);
        (App memory app, uint8 scale) = charms.vaultOf(address(token));
        uint256 locked = _locked(address(token));
        assertEq(scale, 10);
        assertEq(locked, 3 * 10 ** 10);
        assertEq(_balance(app, alice), 3);

        token.setDecimals(6);
        assertEq(token.decimals(), 6);

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.ScaleChanged.selector);
        charms.wrap(address(token), 1, alice, bytes32(uint256(2)));
        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.ScaleChanged.selector);
        charms.unwrap(address(token), 1, bob);

        assertEq(_balance(app, alice), 3);
        locked = _locked(address(token));
        assertEq(locked, 3 * 10 ** 10);
        assertEq(token.balanceOf(address(charms)), 3 * 10 ** 10);
        assertEq(token.balanceOf(bob), 0);
    }

    function test_unwrapBurnsSendsUnderlyingAndLeavesChange() public {
        MockToken token = new MockToken("USDC", "USDC", 6);
        _wrap(address(token), 100, 0);

        vm.prank(alice);
        bytes32 txId = charms.unwrap(address(token), 40, bob);

        (App memory app, uint8 scale) = charms.vaultOf(address(token));
        uint256 locked = _locked(address(token));
        assertEq(scale, 0);
        assertEq(_balance(app, alice), 60);
        assertEq(charms.totalSupply(_key(app)), 60);
        assertEq(token.balanceOf(bob), 40);
        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(address(charms)), 60);
        assertEq(locked, 60);

        (uint8 kind, address owner, uint64 amount,) = charms.utxo(UtxoRef(txId, 0));
        assertEq(kind, 1);
        assertEq(owner, alice);
        assertEq(amount, 60);
        (kind, owner,,) = charms.utxo(UtxoRef(txId, 1));
        assertEq(kind, 0);
        assertEq(owner, address(0));
    }

    function test_unwrapAboveBalanceReverts() public {
        MockToken token = new MockToken("USDC", "USDC", 6);
        _wrap(address(token), 10, 0);
        (App memory app,) = charms.vaultOf(address(token));

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.InsufficientBalance.selector);
        charms.unwrap(address(token), 11, bob);

        assertEq(_balance(app, alice), 10);
        assertEq(token.balanceOf(bob), 0);
        assertEq(token.balanceOf(address(charms)), 10);
        uint256 locked = _locked(address(token));
        assertEq(locked, 10);
    }

    function test_unwrapToZeroOrToCharmsReverts() public {
        MockToken token = new MockToken("USDC", "USDC", 6);
        _wrap(address(token), 10, 0);

        vm.startPrank(alice);
        vm.expectRevert(ICharmsErrors.InvalidRecipient.selector);
        charms.unwrap(address(token), 1, address(0));
        vm.expectRevert(ICharmsErrors.InvalidRecipient.selector);
        charms.unwrap(address(token), 1, address(charms));
        vm.stopPrank();

        uint256 locked = _locked(address(token));
        assertEq(locked, 10);
        assertEq(token.balanceOf(address(charms)), 10);
    }

    function test_unwrapToARevertingRecipientLeavesTheBalance() public {
        RejectEth sink = new RejectEth();
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        charms.wrap{value: 5 * 10 ** 10}(address(0), 5, alice, bytes32(uint256(4)));
        (App memory app,) = charms.vaultOf(address(0));

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.EthTransferFailed.selector);
        charms.unwrap(address(0), 2, address(sink));

        assertEq(_balance(app, alice), 5);
        uint256 locked = _locked(address(0));
        assertEq(locked, 5 * 10 ** 10);
        assertEq(address(charms).balance, 5 * 10 ** 10);
        assertEq(address(sink).balance, 0);
    }

    function test_vaultIdentityIsTheChipPreimage() public {
        MockToken token = new MockToken("USDC", "USDC", 6);
        _assertIdentity(address(0));
        _assertIdentity(address(token));

        vm.deal(alice, 1 ether);
        vm.prank(alice);
        charms.wrap{value: 10 ** 10}(address(0), 1, alice, bytes32(uint256(1)));
        _wrap(address(token), 1, 0);

        (App memory eth,) = charms.vaultOf(address(0));
        (App memory erc,) = charms.vaultOf(address(token));
        assertEq(charms.balanceOf(_appKey(eth), alice), 1);
        assertEq(charms.balanceOf(_appKey(erc), alice), 1);
        assertTrue(_appKey(eth) != _appKey(erc));
    }

    function test_vaultAppKeyDoesNotDependOnScale() public {
        MutableDecimalsToken token = new MutableDecimalsToken();
        (App memory at18, uint8 scale18) = charms.vaultOf(address(token));
        assertEq(scale18, 10);
        assertEq(at18.identity, _vaultId(address(token)));
        assertEq(at18.vk, sha256("charms/ethereum/vault/v1"));

        token.setDecimals(6);
        (App memory at6, uint8 scale6) = charms.vaultOf(address(token));
        assertEq(scale6, 0);
        assertEq(at6.identity, at18.identity);
        assertEq(at6.vk, at18.vk);
        assertEq(at6.tag, at18.tag);
        assertEq(_appKey(at6), _appKey(at18));
        assertEq(at6.identity, _vaultId(address(token)));
    }

    function test_erc20VaultFaceIsTheUnderlyingAndDeploysNoClone() public {
        MockToken wide = new MockToken("Wide", "WIDE", 18);
        MockToken tiny = new MockToken("Tiny", "TINY", 6);
        _wrap(address(wide), 1, 10);
        _wrap(address(tiny), 1, 0);

        (App memory wideApp,) = charms.vaultOf(address(wide));
        (App memory tinyApp,) = charms.vaultOf(address(tiny));

        assertEq(charms.tokenAddress(wideApp), address(wide));
        assertEq(charms.ensureToken(wideApp), address(wide));
        assertEq(charms.ensureToken(wideApp), address(wide));
        assertEq(charms.tokenAddress(tinyApp), address(tiny));
        assertEq(charms.ensureToken(tinyApp), address(tiny));
        assertEq(_clone(wideApp).code.length, 0);
        assertEq(_clone(tinyApp).code.length, 0);

        wide.mint(bob, 5);
        vm.prank(bob);
        assertTrue(wide.transfer(alice, 5));
        assertEq(wide.balanceOf(alice), 5);
        assertEq(_balance(wideApp, alice), 1);
        assertEq(_balance(wideApp, bob), 0);
    }

    function test_ethVaultFaceIsAddressZero() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        charms.wrap{value: 10 ** 10}(address(0), 1, alice, bytes32(uint256(1)));
        (App memory app,) = charms.vaultOf(address(0));

        assertEq(charms.tokenAddress(app), address(0));
        assertEq(charms.ensureToken(app), address(0));
        assertEq(_clone(app).code.length, 0);
    }

    function test_vaultFaceRevertsBeforeTheFirstWrapAndDeploysNothing() public {
        MockToken usdc = new MockToken("USD Coin", "USDC", 6);
        (App memory app,) = charms.vaultOf(address(usdc));

        vm.expectRevert(ICharmsErrors.MetadataUnspecified.selector);
        charms.tokenAddress(app);
        vm.expectRevert(ICharmsErrors.MetadataUnspecified.selector);
        charms.ensureToken(app);
        assertEq(_clone(app).code.length, 0);
    }

    function test_underlyingCannotDriveVaultTokenTransfer() public {
        MockToken usdc = new MockToken("USDC", "USDC", 6);
        _wrap(address(usdc), 10, 0);
        (App memory app,) = charms.vaultOf(address(usdc));

        vm.prank(address(usdc));
        vm.expectRevert(ICharmsErrors.NotToken.selector);
        charms.tokenTransfer(app, alice, bob, 1);

        assertEq(_balance(app, alice), 10);
        assertEq(_balance(app, bob), 0);
        assertEq(usdc.balanceOf(address(charms)), 10);
    }

    function test_plainEthSendReverts() public {
        vm.deal(address(this), 1 ether);
        vm.expectRevert(ICharmsErrors.EthRejected.selector);
        this.pay{value: 1 ether}(address(charms));
        assertEq(address(charms).balance, 0);
    }

    function test_vaultCharmMovesThroughTransact() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        bytes32 wrapped =
            charms.wrap{value: 20 * 10 ** 10}(address(0), 20, alice, bytes32(uint256(1)));
        (App memory app,) = charms.vaultOf(address(0));
        assertEq(charms.tokenAddress(app), address(0));

        Spell memory s = _spell(_apps(app), 1, 2);
        s.ins[0] = _input(wrapped, 0, _charms(_token(0, 20)));
        s.outs[0] = Output(bob, _charms(_token(0, 8)));
        s.outs[1] = Output(alice, _charms(_token(0, 12)));
        _transact(alice, s);

        assertEq(_balance(app, alice), 12);
        assertEq(_balance(app, bob), 8);
        assertEq(charms.totalSupply(_key(app)), 20);
        assertEq(address(charms).balance, 20 * 10 ** 10);
        assertEq(bob.balance, 0);
        (UtxoRef[] memory alices,) = charms.utxosOf(_key(app), alice, 0, 10);
        (UtxoRef[] memory bobs,) = charms.utxosOf(_key(app), bob, 0, 10);
        assertEq(alices.length, 1);
        assertEq(bobs.length, 1);
        (uint8 kind, address owner, uint64 amount,) = charms.utxo(alices[0]);
        assertEq(kind, 1);
        assertEq(owner, alice);
        assertEq(amount, 12);
        (kind, owner, amount,) = charms.utxo(bobs[0]);
        assertEq(kind, 1);
        assertEq(owner, bob);
        assertEq(amount, 8);
    }

    function pay(address to) external payable {
        (bool ok, bytes memory data) = to.call{value: msg.value}("");
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(data, 32), mload(data))
            }
        }
    }

    function _assertScale(address token, uint8 expected) private {
        (App memory before, uint8 scale) = charms.vaultOf(token);
        uint256 locked = _locked(token);
        assertEq(scale, expected, "scale before the first wrap");
        assertEq(locked, 0);
        _wrap(token, 5, expected);
        App memory registered;
        (registered, scale) = charms.vaultOf(token);
        locked = _locked(token);
        assertEq(scale, expected, "scale after the first wrap");
        assertEq(locked, 5 * 10 ** uint256(expected));
        assertEq(registered.identity, before.identity);
        assertEq(registered.vk, before.vk);
        assertEq(_balance(registered, alice), 5);
    }

    function _assertIdentity(address token) private view {
        (App memory app,) = charms.vaultOf(token);
        assertEq(app.tag, T);
        assertEq(app.identity, _vaultId(token));
        assertEq(app.vk, sha256("charms/ethereum/vault/v1"));
    }

    function _clone(App memory app) private view returns (address) {
        return
            CharmTokenClone.predict(
                address(charms), vm.computeCreateAddress(address(charms), 1), app
            );
    }

    function _vaultId(address token) private view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                "charms/ethereum/vault/v1", uint256(block.chainid), address(charms), token
            )
        );
    }

    function _appKey(App memory app) private pure returns (bytes32) {
        return keccak256(abi.encode(app.tag, app.identity, app.vk));
    }

    function _wrap(address token, uint64 amount, uint8 scale) private {
        uint256 underlying = uint256(amount) * 10 ** uint256(scale);
        Mintable(token).mint(alice, underlying);
        vm.startPrank(alice);
        Mintable(token).approve(address(charms), underlying);
        charms.wrap(address(token), amount, alice, bytes32(uint256(uint160(token))));
        vm.stopPrank();
    }
}

interface Mintable {
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
}
