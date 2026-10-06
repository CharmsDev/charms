// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {CharmToken} from "../src/CharmToken.sol";
import {ICharmToken, ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract CoreTest is CharmsTestBase {
    address internal alice;
    uint256 internal aliceKey;
    address internal bob = makeAddr("bob");

    function setUp() public override {
        super.setUp();
        (alice, aliceKey) = makeAddrAndKey("alice");
    }

    function test_placeholderIsAnEmptyUtxoAndItsAnchorIsSingleUse() public {
        Spell memory s = _spell(new App[](0), 0, 1);
        s.outs[0].owner = alice;
        bytes32 expected = _txId(s, alice, bytes32(uint256(7)));

        vm.prank(alice);
        bytes32 txId = charms.transact(s, bytes32(uint256(7)), "", new bytes[](0));

        assertEq(txId, expected);
        (uint8 kind, address owner) = _kind(txId, 0);
        assertEq(kind, 0);
        assertEq(owner, alice);
        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.AnchorUsed.selector);
        charms.transact(s, bytes32(uint256(7)), "", new bytes[](0));
    }

    function test_provedMintThenNativeTransferSignedByTheOwner() public {
        App memory coin = _app(T, "coin");
        bytes32 minted = _mintOne(alice, _apps(coin), _charms(_token(0, 1000)));
        assertEq(_balance(coin, alice), 1000);
        assertEq(charms.totalSupply(_key(coin)), 1000);

        Spell memory s = _spell(_apps(coin), 1, 2);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 1000)));
        s.outs[0] = Output(bob, _charms(_token(0, 300)));
        s.outs[1] = Output(alice, _charms(_token(0, 700)));
        bytes32 txId = _txId(s, bob, 0);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(aliceKey, txId);

        vm.prank(bob);
        assertEq(charms.transact(s, bytes32(0), "", sigs), txId);

        assertEq(_balance(coin, alice), 700);
        assertEq(_balance(coin, bob), 300);
        assertEq(charms.totalSupply(_key(coin)), 1000);
        (uint8 kind, address owner, uint64 amount,) = charms.utxo(UtxoRef(txId, 0));
        assertEq(kind, 1);
        assertEq(owner, bob);
        assertEq(amount, 300);

        vm.prank(bob);
        vm.expectRevert(ICharmsErrors.InputSpent.selector);
        charms.transact(s, bytes32(0), "", sigs);
    }

    function test_facadeTransferKeepsTheSendersOtherCharmsOnChange() public {
        App memory coin = _app(T, "coin");
        App memory art = _app(N, "art");
        App[] memory apps = _apps(coin, art);
        uint32 c = apps[0].tag == T ? 0 : 1;
        Charm[] memory held = c == 0
            ? _charms(_token(0, 50), _nft(1, hex"6461727421"))
            : _charms(_nft(0, hex"6461727421"), _token(1, 50));
        _mintOne(alice, apps, held);
        CharmToken token = CharmToken(charms.ensureToken(coin));

        vm.expectEmit(address(token));
        emit ICharmToken.Transfer(alice, bob, 50);
        vm.prank(alice);
        token.transfer(bob, 50);

        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(bob), 50);
        assertEq(token.totalSupply(), 50);
        (UtxoRef[] memory bobs,) = charms.utxosOf(_key(coin), bob, 0, 10);
        assertEq(bobs.length, 1);
        (uint8 kind, address owner) = _kind(bobs[0].txId, 1);
        assertEq(kind, 2, "change output still holds the NFT");
        assertEq(owner, alice);
    }

    function test_wrapAndUnwrapEth() public {
        _deployPhase1();
        vm.deal(alice, 1 ether);
        (App memory vault, uint8 scale,) = charms.vaultOf(address(0));
        assertEq(scale, 10);
        assertEq(vault.vk, VAULT_VK);

        vm.prank(alice);
        charms.wrap{value: 0.5 ether}(address(0), 0.5 ether / 1e10, alice, bytes32(0));
        assertEq(_balance(vault, alice), 5e7);
        (,, uint256 locked) = charms.vaultOf(address(0));
        assertEq(locked, 0.5 ether);

        vm.prank(alice);
        charms.unwrap(address(0), 2e7, bob);
        assertEq(bob.balance, 0.2 ether);
        assertEq(_balance(vault, alice), 3e7);
        (,, locked) = charms.vaultOf(address(0));
        assertEq(locked, 0.3 ether);
        assertEq(address(charms).balance, 0.3 ether);
    }
}
