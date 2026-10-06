// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {CharmToken} from "../src/CharmToken.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

/// @notice Spending UTXOs through `transact` must not leave work behind for the next facade
/// transfer: an owner who spent 128 receipts still transfers within a fixed gas budget.
contract SpentUtxosTest is CharmsTestBase {
    uint256 internal constant GAS_CAP = 700_000;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    App internal coin;
    CharmToken internal token;
    UtxoRef[] internal receipts;

    function setUp() public override {
        super.setUp();
        coin = _app(T, "coin");
        _receive(64);
        _receive(64);
        _receive(1);
        token = CharmToken(charms.ensureToken(coin));
        _spendToBob(0, 64);
        _spendToBob(64, 64);
    }

    function test_transferAfterSpendingReceiptsFitsTheGasCap() public {
        assertEq(token.balanceOf(alice), 1);

        vm.prank(alice);
        (bool ok,) =
            address(token).call{gas: GAS_CAP}(abi.encodeCall(CharmToken.transfer, (carol, 1)));

        assertTrue(ok, "transfer ran out of gas walking spent entries");
        assertEq(token.balanceOf(carol), 1);
    }

    function test_transferFromAfterSpendingReceiptsFitsTheGasCap() public {
        vm.prank(alice);
        token.approve(carol, 1);

        vm.prank(carol);
        (bool ok,) = address(token).call{gas: GAS_CAP}(
            abi.encodeCall(CharmToken.transferFrom, (alice, carol, 1))
        );

        assertTrue(ok, "transferFrom ran out of gas walking spent entries");
        assertEq(token.balanceOf(carol), 1);
    }

    function test_utxosOfListsOnlyTheLiveReceipt() public view {
        (UtxoRef[] memory page, uint256 next) = charms.utxosOf(_key(coin), alice, 0, 200);
        assertEq(page.length, 1);
        assertEq(page[0].txId, receipts[128].txId);
        assertEq(page[0].index, receipts[128].index);
        assertEq(next, 0);
    }

    /// @dev Bob spends his own placeholder in a proved spell whose outputs pay Alice one unit
    /// each, so they are receipts at the back of Alice's queue.
    function _receive(uint256 count) internal {
        bytes32 placeholder = _placeholder(bob);
        Spell memory s = _spell(_apps(coin), 1, count);
        s.ins[0].utxo = UtxoRef(placeholder, 0);
        for (uint256 i; i < count; ++i) {
            s.outs[i] = Output(alice, _charms(_token(0, 1)));
        }
        vm.prank(bob);
        bytes32 txId = charms.transact(s, bytes32(0), PROOF, new bytes[](0));
        for (uint256 i; i < count; ++i) {
            receipts.push(UtxoRef(txId, uint32(i)));
        }
    }

    function _spendToBob(uint256 from, uint256 count) internal {
        Spell memory s = _spell(_apps(coin), count, 1);
        for (uint256 i; i < count; ++i) {
            UtxoRef memory r = receipts[from + i];
            s.ins[i] = _input(r.txId, r.index, _charms(_token(0, 1)));
        }
        s.outs[0] = Output(bob, _charms(_token(0, uint64(count))));
        _transact(alice, s);
    }
}
