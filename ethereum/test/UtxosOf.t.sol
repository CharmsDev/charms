// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

/// @notice A wallet that pages `utxosOf` from cursor 0 to the end collects every UTXO that stays
/// live while it pages, even when the UTXO a cursor names is spent between calls.
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

    function test_pagingContinuesAfterTheCursorUtxoIsSpent() public {
        (UtxoRef[] memory page, uint256 next) = charms.utxosOf(_key(coin), alice, 0, 2);
        _assertRefs(page, 0, 2);

        _spend(2);
        (page, next) = charms.utxosOf(_key(coin), alice, next, 10);

        assertEq(page.length, 2, "the two receipts after the spent cursor");
        _assertRef(page[0], 3);
        _assertRef(page[1], 4);
        assertEq(next, 0);
    }

    function test_pagingFollowsARunOfSpentUtxos() public {
        (, uint256 next) = charms.utxosOf(_key(coin), alice, 0, 2);
        _spend(2);
        _spend(3);

        (UtxoRef[] memory page, uint256 last) = charms.utxosOf(_key(coin), alice, next, 10);

        assertEq(page.length, 1);
        _assertRef(page[0], 4);
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
