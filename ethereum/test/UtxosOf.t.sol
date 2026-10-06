// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

/// @notice A wallet that pages `utxosOf` from cursor 0 to the end, and starts again from 0 when the
/// UTXO its cursor names was spent, collects every UTXO that stays live while it pages.
contract UtxosOfTest is CharmsTestBase {
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    App internal coin;
    UtxoRef[] internal receipts;

    function setUp() public override {
        super.setUp();
        coin = _app(T, "coin");
        bytes32 placeholder = _placeholder(bob);
        Spell memory s = _spell(_apps(coin), 1, 5);
        s.ins[0].utxo = UtxoRef(placeholder, 0);
        for (uint256 i; i < 5; ++i) {
            s.outs[i] = Output(alice, _charms(_token(0, uint64(10 + i))));
        }
        vm.prank(bob);
        bytes32 txId = charms.transact(s, bytes32(0), PROOF, new bytes[](0));
        for (uint32 i; i < 5; ++i) {
            receipts.push(UtxoRef(txId, i));
        }
    }

    function test_aSpentCursorRevertsAndARestartCollectsTheRest() public {
        (UtxoRef[] memory page, uint256 next) = charms.utxosOf(_key(coin), alice, 0, 2);
        _assertRefs(page, 0, 2);

        _spend(2);
        vm.expectRevert(ICharmsErrors.InvalidCursor.selector);
        charms.utxosOf(_key(coin), alice, next, 10);

        (page, next) = charms.utxosOf(_key(coin), alice, 0, 10);
        assertEq(page.length, 4);
        _assertRef(page[0], 0);
        _assertRef(page[1], 1);
        _assertRef(page[2], 3);
        _assertRef(page[3], 4);
        assertEq(next, 0);
    }

    function test_aUtxoSpentAheadOfTheCursorLeavesLaterPages() public {
        (, uint256 next) = charms.utxosOf(_key(coin), alice, 0, 2);
        _spend(3);

        (UtxoRef[] memory page, uint256 last) = charms.utxosOf(_key(coin), alice, next, 10);

        assertEq(page.length, 2);
        _assertRef(page[0], 2);
        _assertRef(page[1], 4);
        assertEq(last, 0);
    }

    function test_onePerPageCollectsEveryLiveUtxoInOrder() public {
        _spend(1);
        uint256[] memory expected = new uint256[](4);
        (expected[0], expected[1], expected[2], expected[3]) = (0, 2, 3, 4);
        uint256 cursor;
        uint256 n;
        do {
            UtxoRef[] memory page;
            (page, cursor) = charms.utxosOf(_key(coin), alice, cursor, 1);
            for (uint256 i; i < page.length; ++i) {
                _assertRef(page[i], expected[n++]);
            }
        } while (cursor != 0);
        assertEq(n, 4);
    }

    function testFuzz_pagingWithRestartsReturnsEveryUtxoThatStaysLiveExactlyOnce(
        uint8 spendMask,
        uint8 pageSize,
        uint8 spendAfterPage
    ) public {
        pageSize = uint8(bound(pageSize, 1, 4));
        spendAfterPage %= 3;
        uint256[5] memory seen;
        uint256 cursor;
        uint256 pages;
        bool restarted;
        while (true) {
            try charms.utxosOf(_key(coin), alice, cursor, pageSize) returns (
                UtxoRef[] memory page, uint256 next
            ) {
                for (uint256 i; i < page.length; ++i) {
                    ++seen[page[i].index];
                }
                cursor = next;
            } catch (bytes memory reason) {
                assertEq(bytes4(reason), ICharmsErrors.InvalidCursor.selector);
                assertFalse(restarted, "one round of spends, so one restart at most");
                restarted = true;
                delete seen;
                cursor = 0;
                continue;
            }
            if (pages++ == spendAfterPage) {
                for (uint256 r; r < 5; ++r) {
                    if (spendMask & (1 << r) != 0) _spend(r);
                }
            }
            if (cursor == 0) break;
        }
        for (uint256 r; r < 5; ++r) {
            if (spendMask & (1 << r) == 0) assertEq(seen[r], 1, "a live receipt, once");
            else assertLe(seen[r], 1, "a spent receipt, at most once");
        }
    }

    function test_aZeroLimitReverts() public {
        vm.expectRevert(ICharmsErrors.ZeroLimit.selector);
        charms.utxosOf(_key(coin), alice, 0, 0);
    }

    function test_aCursorThatNamesNoUtxoOfTheListReverts() public {
        vm.expectRevert(ICharmsErrors.InvalidCursor.selector);
        charms.utxosOf(_key(coin), alice, 2, 10);

        (, uint256 aliceCursor) = charms.utxosOf(_key(coin), alice, 0, 1);
        vm.expectRevert(ICharmsErrors.InvalidCursor.selector);
        charms.utxosOf(_key(coin), bob, aliceCursor, 10);
    }

    function _spend(uint256 i) internal {
        UtxoRef memory r = receipts[i];
        Spell memory s = _spell(_apps(coin), 1, 1);
        s.ins[0] = _input(r.txId, r.index, _charms(_token(0, uint64(10 + i))));
        s.outs[0] = Output(bob, _charms(_token(0, uint64(10 + i))));
        _transact(alice, s);
    }

    function _assertRefs(UtxoRef[] memory page, uint256 from, uint256 count) internal view {
        assertEq(page.length, count);
        for (uint256 i; i < count; ++i) {
            _assertRef(page[i], from + i);
        }
    }

    function _assertRef(UtxoRef memory got, uint256 receipt) internal view {
        assertEq(got.txId, receipts[receipt].txId);
        assertEq(got.index, receipts[receipt].index, "receipt index");
    }
}
