// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";

import {CharmToken} from "../src/CharmToken.sol";
import {ICharmToken, ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract TokenTest is CharmsTestBase {
    address internal alice;
    uint256 internal aliceKey;
    address internal bob;
    uint256 internal bobKey;
    address internal carol = makeAddr("carol");

    bytes internal constant NFT = hex"636e6674";
    bytes internal constant MARK = hex"6178";

    struct CharmRecord {
        uint32 tag;
        bytes32 identity;
        bytes32 vk;
        uint64 amount;
        bytes data;
    }

    struct StoredPin {
        bytes32 vk;
        uint32 version;
        bytes32 wasmHash;
    }

    function setUp() public override {
        super.setUp();
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");
    }

    function test_tokenAddressMatchesTheChipCreate2BeforeDeploy() public view {
        App memory coin = _app(T, "coin");
        address predicted = _create2(coin);

        assertEq(predicted.code.length, 0);
        assertEq(charms.tokenAddress(coin), predicted);
        assertEq(predicted.code.length, 0);
    }

    function test_tokenAddressRevertsUnlessTheTagIsT() public {
        vm.expectRevert(ICharmsErrors.NotTokenTag.selector);
        charms.tokenAddress(_app(N, "nft"));
        vm.expectRevert(ICharmsErrors.NotTokenTag.selector);
        charms.tokenAddress(_app(S, "scroll"));
        vm.expectRevert(ICharmsErrors.NotTokenTag.selector);
        charms.tokenAddress(_app(X, "custom"));
    }

    function test_ensureTokenDeploysTheChipRuntime() public {
        App memory coin = _app(T, "coin");
        address predicted = _create2(coin);
        assertEq(charms.tokenAddress(coin), predicted);

        address deployed = charms.ensureToken(coin);

        assertEq(deployed, predicted);
        bytes memory runtime = _runtime(coin);
        assertEq(runtime.length, 125);
        assertEq(deployed.code, runtime, "clone runtime is the CHIP's 125 bytes");
    }

    function test_ensureTokenReturnsTheExistingClone() public {
        App memory coin = _app(T, "coin");
        address first = charms.ensureToken(coin);
        address second = charms.ensureToken(coin);

        assertEq(second, first);
        assertEq(second, _create2(coin));
    }

    function test_ensureTokenRevertsUnlessTheTagIsT() public {
        vm.expectRevert(ICharmsErrors.NotTokenTag.selector);
        charms.ensureToken(_app(N, "nft"));
        vm.expectRevert(ICharmsErrors.NotTokenTag.selector);
        charms.ensureToken(_app(S, "scroll"));
        vm.expectRevert(ICharmsErrors.NotTokenTag.selector);
        charms.ensureToken(_app(X, "custom"));
    }

    function test_cloneReportsItsAppAndTheProxy() public {
        App memory coin = _app(T, "coin");
        CharmToken token = CharmToken(charms.ensureToken(coin));

        App memory reported = token.app();
        assertEq(reported.tag, coin.tag);
        assertEq(reported.identity, coin.identity);
        assertEq(reported.vk, coin.vk);
        assertEq(address(token.charms()), address(charms));
    }

    function test_nonVaultTokenMetadataIsCharm() public {
        CharmToken token = CharmToken(charms.ensureToken(_app(T, "coin")));

        assertEq(token.name(), "Charm");
        assertEq(token.symbol(), "CHARM");
        assertEq(token.decimals(), 0);
    }

    function test_balanceAndSupplyCountBundledUnits() public {
        App memory coin = _app(T, "coin");
        CharmToken token = CharmToken(charms.ensureToken(coin));
        _mintBeside(alice, coin, 4, _app(N, "art"), NFT);

        assertEq(token.balanceOf(alice), 4, "units beside an NFT");
        assertEq(token.totalSupply(), 4, "supply beside an NFT");

        _mintBeside(alice, coin, 6, _app(X, "mark"), MARK);

        assertEq(token.balanceOf(alice), 10, "units beside a custom tag");
        assertEq(token.totalSupply(), 10, "supply beside a custom tag");
    }

    function test_exactSpendLeavesNoChange() public {
        App memory coin = _app(T, "coin");
        bytes32 minted = _mintPlain(alice, coin, 100);
        CharmToken token = CharmToken(charms.ensureToken(coin));

        vm.prank(alice);
        assertTrue(token.transfer(bob, 100));

        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(bob), 100);
        assertEq(token.totalSupply(), 100);
        assertEq(_page(coin, alice).length, 0);
        (uint8 spent, address spentOwner) = _kind(minted, 0);
        assertEq(spent, 0);
        assertEq(spentOwner, address(0));

        UtxoRef[] memory bobs = _page(coin, bob);
        assertEq(bobs.length, 1);
        assertEq(bobs[0].index, 0);
        (uint8 kind, address owner, uint64 amount, bytes memory body) = charms.utxo(bobs[0]);
        assertEq(kind, 1);
        assertEq(owner, bob);
        assertEq(amount, 100);
        assertEq(body.length, 0);
        (kind, owner,,) = charms.utxo(UtxoRef(bobs[0].txId, 1));
        assertEq(kind, 0, "no change output");
        assertEq(owner, address(0));
    }

    function test_remainderGoesToAChangeOutput() public {
        App memory coin = _app(T, "coin");
        bytes32 minted = _mintPlain(alice, coin, 100);
        CharmToken token = CharmToken(charms.ensureToken(coin));

        vm.prank(alice);
        assertTrue(token.transfer(bob, 40));

        assertEq(token.balanceOf(alice), 60);
        assertEq(token.balanceOf(bob), 40);
        assertEq(token.totalSupply(), 100);
        (uint8 spent, address spentOwner) = _kind(minted, 0);
        assertEq(spent, 0);
        assertEq(spentOwner, address(0));

        UtxoRef[] memory bobs = _page(coin, bob);
        UtxoRef[] memory alices = _page(coin, alice);
        assertEq(bobs.length, 1);
        assertEq(alices.length, 1);
        assertEq(bobs[0].txId, alices[0].txId);
        assertEq(bobs[0].index, 0);
        assertEq(alices[0].index, 1);

        (uint8 kind, address owner, uint64 amount,) = charms.utxo(bobs[0]);
        assertEq(kind, 1);
        assertEq(owner, bob);
        assertEq(amount, 40);
        (kind, owner, amount,) = charms.utxo(alices[0]);
        assertEq(kind, 1);
        assertEq(owner, alice);
        assertEq(amount, 60);
    }

    function test_zeroRemainderWithAnNftStillCreatesChange() public {
        App memory coin = _app(T, "coin");
        App memory art = _app(N, "art");
        _mintBeside(alice, coin, 50, art, NFT);
        CharmToken token = CharmToken(charms.ensureToken(coin));

        vm.prank(alice);
        assertTrue(token.transfer(bob, 50));

        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(bob), 50);
        assertEq(_page(coin, alice).length, 0);

        UtxoRef[] memory bobs = _page(coin, bob);
        assertEq(bobs.length, 1);
        assertEq(bobs[0].index, 0);
        (uint8 kind, address owner, uint64 amount, bytes memory body) = charms.utxo(bobs[0]);
        assertEq(kind, 1);
        assertEq(owner, bob);
        assertEq(amount, 50);
        assertEq(body.length, 0);

        (kind, owner, amount, body) = charms.utxo(UtxoRef(bobs[0].txId, 1));
        assertEq(kind, 2);
        assertEq(owner, alice);
        (CharmRecord[] memory held, StoredPin[] memory pins) = _open(body);
        assertEq(pins.length, 0);
        assertEq(held.length, 1, "change holds the NFT and no zero token amount");
        assertEq(held[0].tag, art.tag);
        assertEq(held[0].identity, art.identity);
        assertEq(held[0].vk, art.vk);
        assertEq(held[0].data, NFT);
        (bool tokenOnChange,,) = _find(held, coin);
        assertFalse(tokenOnChange);
    }

    function test_otherTokenOnTheInputStaysOnChange() public {
        App memory coin = _app(T, "coin");
        App memory other = _app(T, "other");
        _mintTwo(alice, coin, 80, other, 7);
        CharmToken coinToken = CharmToken(charms.ensureToken(coin));
        CharmToken otherToken = CharmToken(charms.ensureToken(other));

        vm.prank(alice);
        assertTrue(coinToken.transfer(bob, 30));

        assertEq(coinToken.balanceOf(alice), 50);
        assertEq(coinToken.balanceOf(bob), 30);
        assertEq(otherToken.balanceOf(alice), 7);
        assertEq(otherToken.balanceOf(bob), 0);
        assertEq(_page(other, bob).length, 0);

        UtxoRef[] memory bobs = _page(coin, bob);
        UtxoRef[] memory alices = _page(coin, alice);
        UtxoRef[] memory others = _page(other, alice);
        assertEq(bobs.length, 1);
        assertEq(alices.length, 1);
        assertEq(others.length, 1);
        assertEq(alices[0].txId, bobs[0].txId);
        assertEq(alices[0].txId, others[0].txId);
        assertEq(alices[0].index, others[0].index);
        assertEq(bobs[0].index, 0);
        assertEq(alices[0].index, 1);

        (uint8 kind, address owner, uint64 amount,) = charms.utxo(bobs[0]);
        assertEq(kind, 1);
        assertEq(owner, bob);
        assertEq(amount, 30);
        bytes memory body;
        (kind, owner,, body) = charms.utxo(alices[0]);
        assertEq(kind, 2);
        assertEq(owner, alice);
        (CharmRecord[] memory held,) = _open(body);
        (, uint64 coinLeft,) = _find(held, coin);
        (, uint64 otherLeft,) = _find(held, other);
        assertEq(coinLeft, 50);
        assertEq(otherLeft, 7);
    }

    function test_zeroTransferEmitsAndCreatesNoUtxo() public {
        App memory coin = _app(T, "coin");
        bytes32 minted = _mintPlain(alice, coin, 5);
        CharmToken token = CharmToken(charms.ensureToken(coin));
        UtxoRef[] memory before = _page(coin, alice);

        vm.recordLogs();
        vm.prank(alice);
        assertTrue(token.transfer(bob, 0));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].emitter, address(token));
        assertEq(logs[0].topics[0], keccak256("Transfer(address,address,uint256)"));
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(alice))));
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(bob))));
        assertEq(abi.decode(logs[0].data, (uint256)), 0);

        assertEq(token.balanceOf(alice), 5);
        assertEq(token.balanceOf(bob), 0);
        UtxoRef[] memory stayed = _page(coin, alice);
        assertEq(stayed.length, 1);
        assertEq(stayed[0].txId, before[0].txId);
        assertEq(stayed[0].index, before[0].index);
        assertEq(stayed[0].txId, minted);
        (uint8 kind, address owner, uint64 amount,) = charms.utxo(stayed[0]);
        assertEq(kind, 1);
        assertEq(owner, alice);
        assertEq(amount, 5);
    }

    function test_transferToZeroReverts() public {
        CharmToken token = _funded(alice, 10);
        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.InvalidRecipient.selector);
        token.transfer(address(0), 1);
        assertEq(token.balanceOf(alice), 10);
    }

    function test_transferToTheProxyReverts() public {
        CharmToken token = _funded(alice, 10);
        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.InvalidRecipient.selector);
        token.transfer(address(charms), 1);
        assertEq(token.balanceOf(alice), 10);
    }

    function test_transferAboveUint64Reverts() public {
        CharmToken token = _funded(alice, 10);
        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.AmountTooLarge.selector);
        token.transfer(bob, uint256(type(uint64).max) + 1);
        assertEq(token.balanceOf(alice), 10);
    }

    function test_transferAboveBalanceReverts() public {
        CharmToken token = _funded(alice, 10);
        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.InsufficientBalance.selector);
        token.transfer(bob, 11);
        assertEq(token.balanceOf(alice), 10);
    }

    function test_shortfallOnACustomBundleRequiresAProvedSpell() public {
        App memory coin = _app(T, "coin");
        App memory mark = _app(X, "mark");
        _mintBeside(alice, coin, 40, mark, MARK);
        _mintPlain(alice, coin, 10);
        CharmToken token = CharmToken(charms.ensureToken(coin));

        uint256 plain;
        uint256 bundled;
        UtxoRef[] memory page = _page(coin, alice);
        assertEq(page.length, 2);
        for (uint256 i; i < page.length; ++i) {
            (uint8 kind,,, bytes memory body) = charms.utxo(page[i]);
            if (kind == 1) {
                (,, uint64 amount,) = charms.utxo(page[i]);
                plain += amount;
            } else {
                assertEq(kind, 2);
                (CharmRecord[] memory held,) = _open(body);
                (, uint64 units,) = _find(held, coin);
                bundled += units;
                (bool ok, uint64 markAmount, bytes memory data) = _find(held, mark);
                assertTrue(ok);
                assertEq(markAmount, 0);
                assertEq(data, MARK);
            }
        }
        assertEq(plain, 10);
        assertEq(bundled, 40);
        assertEq(token.balanceOf(alice), 50);
        assertEq(token.totalSupply(), 50);

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.RequiresProvedSpell.selector);
        token.transfer(bob, 30);

        assertEq(token.balanceOf(alice), 50);
        assertEq(_page(coin, alice).length, 2);
    }

    function test_mixedVersionPinsRevert() public {
        App memory coin = _app(T, "versioned");
        _mintPinned(alice, coin, 10, 1);
        _mintPinned(alice, coin, 10, 2);
        CharmToken token = CharmToken(charms.ensureToken(coin));

        UtxoRef[] memory page = _page(coin, alice);
        assertEq(page.length, 2);
        (CharmRecord[] memory heldA, StoredPin[] memory pinsA) = _open(_body(page[0]));
        (CharmRecord[] memory heldB, StoredPin[] memory pinsB) = _open(_body(page[1]));
        assertEq(heldA.length, 1);
        assertEq(heldB.length, 1);
        assertEq(heldA[0].amount, 10);
        assertEq(heldB[0].amount, 10);
        assertEq(pinsA.length, 1);
        assertEq(pinsB.length, 1);
        assertEq(pinsA[0].vk, coin.vk);
        assertEq(pinsB[0].vk, coin.vk);
        assertTrue(pinsA[0].version != pinsB[0].version);
        assertTrue(pinsA[0].wasmHash != pinsB[0].wasmHash);
        assertEq(token.balanceOf(alice), 20);

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.MixedVersions.selector);
        token.transfer(bob, 15);

        assertEq(token.balanceOf(alice), 20);
        assertEq(_page(coin, alice).length, 2);
    }

    function test_transferAlsoSpendsTheNextReceipt() public {
        App memory coin = _app(T, "coin");
        _mintPlain(bob, coin, 30);
        CharmToken token = CharmToken(charms.ensureToken(coin));
        vm.startPrank(bob);
        assertTrue(token.transfer(alice, 10));
        assertTrue(token.transfer(alice, 10));
        assertTrue(token.transfer(alice, 10));
        vm.stopPrank();

        UtxoRef[] memory receipts = _page(coin, alice);
        assertEq(receipts.length, 3);
        assertEq(_amount(receipts[0]), 10);
        assertEq(_amount(receipts[1]), 10);
        assertEq(_amount(receipts[2]), 10);
        assertEq(token.balanceOf(alice), 30);

        vm.prank(alice);
        assertTrue(token.transfer(carol, 5));

        assertEq(token.balanceOf(alice), 25);
        assertEq(token.balanceOf(carol), 5);
        assertEq(token.totalSupply(), 30);
        UtxoRef[] memory alices = _page(coin, alice);
        UtxoRef[] memory carols = _page(coin, carol);
        assertEq(alices.length, 2);
        assertEq(carols.length, 1);
        assertEq(_amount(alices[0]), 15, "change from the two front receipts");
        assertEq(_owner(alices[0]), alice);
        assertEq(alices[0].txId, carols[0].txId);
        assertEq(alices[0].index, 1);
        assertEq(carols[0].index, 0);
        assertEq(_amount(carols[0]), 5);
        assertEq(_owner(carols[0]), carol);
        assertEq(alices[1].txId, receipts[2].txId, "the back receipt stays");
        assertEq(alices[1].index, receipts[2].index);
        assertEq(_amount(alices[1]), 10);
        assertEq(_owner(alices[1]), alice);
    }

    function test_approveSetsTheAllowance() public {
        CharmToken token = CharmToken(charms.ensureToken(_app(T, "coin")));
        vm.prank(alice);
        assertTrue(token.approve(bob, 25));
        assertEq(token.allowance(alice, bob), 25);
        vm.prank(alice);
        assertTrue(token.approve(bob, 0));
        assertEq(token.allowance(alice, bob), 0);
    }

    function test_transferFromDecrementsTheAllowance() public {
        CharmToken token = _funded(alice, 100);
        vm.prank(alice);
        assertTrue(token.approve(bob, 40));

        vm.prank(bob);
        assertTrue(token.transferFrom(alice, carol, 15));

        assertEq(token.allowance(alice, bob), 25);
        assertEq(token.balanceOf(alice), 85);
        assertEq(token.balanceOf(carol), 15);
        assertEq(token.balanceOf(bob), 0);
    }

    function test_infiniteAllowanceDoesNotDecrement() public {
        CharmToken token = _funded(alice, 100);
        vm.prank(alice);
        assertTrue(token.approve(bob, type(uint256).max));

        vm.prank(bob);
        assertTrue(token.transferFrom(alice, carol, 15));

        assertEq(token.allowance(alice, bob), type(uint256).max);
        assertEq(token.balanceOf(alice), 85);
        assertEq(token.balanceOf(carol), 15);
    }

    function test_transferFromRevertsWhenTheAllowanceIsShort() public {
        CharmToken token = _funded(alice, 100);
        vm.prank(alice);
        assertTrue(token.approve(bob, 14));

        vm.prank(bob);
        vm.expectRevert(ICharmToken.InsufficientAllowance.selector);
        token.transferFrom(alice, carol, 15);

        assertEq(token.allowance(alice, bob), 14);
        assertEq(token.balanceOf(alice), 100);
        assertEq(token.balanceOf(carol), 0);
    }

    function test_permitSetsTheAllowanceAndIncrementsTheNonce() public {
        CharmToken token = CharmToken(charms.ensureToken(_app(T, "coin")));
        vm.warp(1_000_000);
        uint256 deadline = 1_000_000;
        assertEq(token.nonces(alice), 0);
        assertEq(token.DOMAIN_SEPARATOR(), _domain(address(token)));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(aliceKey, _permitDigest(address(token), alice, bob, 70, 0, deadline));
        token.permit(alice, bob, 70, deadline, v, r, s);

        assertEq(token.allowance(alice, bob), 70);
        assertEq(token.nonces(alice), 1);
    }

    function test_permitRevertsWhenExpired() public {
        CharmToken token = CharmToken(charms.ensureToken(_app(T, "coin")));
        vm.warp(1_000_000);
        uint256 deadline = 999_999;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(aliceKey, _permitDigest(address(token), alice, bob, 70, 0, deadline));

        vm.expectRevert(ICharmToken.PermitExpired.selector);
        token.permit(alice, bob, 70, deadline, v, r, s);

        assertEq(token.allowance(alice, bob), 0);
        assertEq(token.nonces(alice), 0);
    }

    function test_permitRevertsForTheWrongSigner() public {
        CharmToken token = CharmToken(charms.ensureToken(_app(T, "coin")));
        vm.warp(1_000_000);
        uint256 deadline = 1_000_000;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(bobKey, _permitDigest(address(token), alice, carol, 70, 0, deadline));

        vm.expectRevert(ICharmToken.InvalidSigner.selector);
        token.permit(alice, carol, 70, deadline, v, r, s);

        assertEq(token.allowance(alice, carol), 0);
        assertEq(token.nonces(alice), 0);
    }

    function test_domainSeparatorUsesCharmVersionOneAndTheToken() public {
        CharmToken token = CharmToken(charms.ensureToken(_app(T, "coin")));
        bytes32 expected = keccak256(
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

        assertEq(token.DOMAIN_SEPARATOR(), expected);
        assertEq(token.name(), "Charm");
    }

    function test_emitTransferRevertsUnlessCalledByCharms() public {
        CharmToken token = CharmToken(charms.ensureToken(_app(T, "coin")));
        vm.prank(alice);
        vm.expectRevert(ICharmToken.NotCharms.selector);
        token.emitTransfer(alice, bob, 1);
    }

    function test_tokenTransferRevertsUnlessCalledByTheToken() public {
        App memory coin = _app(T, "coin");
        charms.ensureToken(coin);
        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.NotToken.selector);
        charms.tokenTransfer(coin, alice, bob, 1);
    }

    function test_nativeTransactEmitsOneNettedTransfer() public {
        App memory coin = _app(T, "coin");
        bytes32 minted = _mintPlain(alice, coin, 100);
        CharmToken token = CharmToken(charms.ensureToken(coin));
        Spell memory s = _spell(_apps(coin), 1, 2);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 100)));
        s.outs[0] = Output(bob, _charms(_token(0, 40)));
        s.outs[1] = Output(alice, _charms(_token(0, 60)));

        vm.recordLogs();
        _transact(alice, s);

        (uint256 count, address from, address to, uint256 amount, address emitter) =
            _transfers(vm.getRecordedLogs());
        assertEq(count, 1);
        assertEq(emitter, address(token));
        assertEq(from, alice);
        assertEq(to, bob);
        assertEq(amount, 40);
        assertEq(token.balanceOf(alice), 60);
        assertEq(token.balanceOf(bob), 40);
        assertEq(token.totalSupply(), 100);
    }

    function test_nativeTransactEmitsNothingWhenTheCloneIsAbsent() public {
        App memory coin = _app(T, "coin");
        bytes32 minted = _mintPlain(alice, coin, 100);
        address predicted = charms.tokenAddress(coin);
        assertEq(predicted.code.length, 0);
        Spell memory s = _spell(_apps(coin), 1, 2);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 100)));
        s.outs[0] = Output(bob, _charms(_token(0, 40)));
        s.outs[1] = Output(alice, _charms(_token(0, 60)));

        vm.recordLogs();
        _transact(alice, s);

        (uint256 count,,,,) = _transfers(vm.getRecordedLogs());
        assertEq(count, 0);
        assertEq(predicted.code.length, 0);
        assertEq(_balance(coin, alice), 60);
        assertEq(_balance(coin, bob), 40);
        assertEq(charms.totalSupply(_key(coin)), 100);
    }

    function _funded(address owner, uint64 amount) private returns (CharmToken token) {
        App memory coin = _app(T, "coin");
        _mintPlain(owner, coin, amount);
        token = CharmToken(charms.ensureToken(coin));
    }

    function _mintPlain(address owner, App memory app, uint64 amount) private returns (bytes32) {
        return _mintOne(owner, _apps(app), _charms(_token(0, amount)));
    }

    function _mintBeside(
        address owner,
        App memory coin,
        uint64 amount,
        App memory other,
        bytes memory data
    ) private returns (bytes32) {
        App[] memory apps = _apps(coin, other);
        return _mintOne(
            owner, apps, _both(Charm(_at(apps, coin), amount, ""), Charm(_at(apps, other), 0, data))
        );
    }

    function _mintTwo(address owner, App memory a, uint64 amountA, App memory b, uint64 amountB)
        private
        returns (bytes32)
    {
        App[] memory apps = _apps(a, b);
        return _mintOne(
            owner, apps, _both(Charm(_at(apps, a), amountA, ""), Charm(_at(apps, b), amountB, ""))
        );
    }

    function _mintPinned(address owner, App memory app, uint64 amount, uint32 version)
        private
        returns (bytes32 txId)
    {
        bytes32 placeholder = _placeholder(owner);
        Spell memory s = _spell(_apps(app), 1, 1);
        s.ins[0] = _input(placeholder, 0, new Charm[](0));
        s.outs[0] = Output(owner, _charms(_token(0, amount)));
        s.versionedApps = new Pin[](1);
        s.versionedApps[0] = Pin(app.vk, version, keccak256(abi.encodePacked("wasm", version)));
        vm.prank(owner);
        txId = charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function _page(App memory app, address owner) private view returns (UtxoRef[] memory page) {
        (page,) = charms.utxosOf(_key(app), owner, 0, 20);
    }

    function _amount(UtxoRef memory u) private view returns (uint64 amount) {
        (,, amount,) = charms.utxo(u);
    }

    function _owner(UtxoRef memory u) private view returns (address owner) {
        (, owner,,) = charms.utxo(u);
    }

    function _body(UtxoRef memory u) private view returns (bytes memory body) {
        (,,, body) = charms.utxo(u);
    }

    function _runtime(App memory app) private view returns (bytes memory) {
        return abi.encodePacked(
            hex"3d3d3d3d363d3d376100466037363936610046013d73",
            vm.computeCreateAddress(address(charms), 1),
            hex"5af43d3d93803e603557fd5bf3",
            app.tag,
            app.identity,
            app.vk,
            hex"0044"
        );
    }

    function _create2(App memory app) private view returns (address) {
        bytes memory initCode = abi.encodePacked(hex"61007d3d81600a3d39f3", _runtime(app));
        bytes32 salt = keccak256(abi.encode(app.tag, app.identity, app.vk));
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(hex"ff", address(charms), salt, keccak256(initCode)))
                )
            )
        );
    }

    function _domain(address token) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("Charm"),
                keccak256("1"),
                block.chainid,
                token
            )
        );
    }

    function _permitDigest(
        address token,
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) private view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                ),
                owner,
                spender,
                value,
                nonce,
                deadline
            )
        );
        return keccak256(abi.encodePacked(hex"1901", _domain(token), structHash));
    }

    function _transfers(Vm.Log[] memory logs)
        private
        pure
        returns (uint256 count, address from, address to, uint256 amount, address emitter)
    {
        bytes32 topic = keccak256("Transfer(address,address,uint256)");
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics.length < 3 || logs[i].topics[0] != topic) continue;
            count++;
            if (count == 1) {
                emitter = logs[i].emitter;
                from = address(uint160(uint256(logs[i].topics[1])));
                to = address(uint160(uint256(logs[i].topics[2])));
                amount = abi.decode(logs[i].data, (uint256));
            }
        }
    }

    function _at(App[] memory apps, App memory app) private pure returns (uint32) {
        for (uint256 i; i < apps.length; ++i) {
            if (apps[i].tag == app.tag && apps[i].identity == app.identity && apps[i].vk == app.vk)
            {
                return uint32(i);
            }
        }
        revert("missing app");
    }

    function _both(Charm memory a, Charm memory b) private pure returns (Charm[] memory) {
        return a.app < b.app ? _charms(a, b) : _charms(b, a);
    }

    function _open(bytes memory body)
        private
        pure
        returns (CharmRecord[] memory held, StoredPin[] memory pins)
    {
        require(body.length != 0, "empty body");
        uint256 o = 1;
        held = new CharmRecord[](uint8(body[0]));
        for (uint256 i; i < held.length; ++i) {
            uint256 v;
            (v, o) = _take(body, o, 4);
            held[i].tag = uint32(v);
            (v, o) = _take(body, o, 32);
            held[i].identity = bytes32(v);
            (v, o) = _take(body, o, 32);
            held[i].vk = bytes32(v);
            (v, o) = _take(body, o, 8);
            held[i].amount = uint64(v);
            (v, o) = _take(body, o, 4);
            held[i].data = _slice(body, o, v);
            o += v;
        }
        require(o < body.length, "truncated body");
        pins = new StoredPin[](uint8(body[o]));
        o += 1;
        for (uint256 i; i < pins.length; ++i) {
            uint256 v;
            (v, o) = _take(body, o, 32);
            pins[i].vk = bytes32(v);
            (v, o) = _take(body, o, 4);
            pins[i].version = uint32(v);
            (v, o) = _take(body, o, 32);
            pins[i].wasmHash = bytes32(v);
        }
        require(o == body.length, "trailing body");
    }

    function _find(CharmRecord[] memory held, App memory app)
        private
        pure
        returns (bool ok, uint64 amount, bytes memory data)
    {
        for (uint256 i; i < held.length; ++i) {
            if (held[i].tag == app.tag && held[i].identity == app.identity && held[i].vk == app.vk)
            {
                return (true, held[i].amount, held[i].data);
            }
        }
        return (false, 0, "");
    }

    function _take(bytes memory body, uint256 o, uint256 n)
        private
        pure
        returns (uint256 v, uint256)
    {
        require(o + n <= body.length, "short body");
        for (uint256 i; i < n; ++i) {
            v = (v << 8) | uint8(body[o + i]);
        }
        return (v, o + n);
    }

    function _slice(bytes memory body, uint256 o, uint256 n)
        private
        pure
        returns (bytes memory out)
    {
        require(o + n <= body.length, "short data");
        out = new bytes(n);
        for (uint256 i; i < n; ++i) {
            out[i] = body[o + i];
        }
    }
}
