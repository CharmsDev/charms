// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {SpellCodec} from "../src/libraries/SpellCodec.sol";

contract ProvedCallTest is Test {
    function test_a_rich_proved_call_decodes_to_the_guest_cbor() public view {
        bytes memory data = vm.parseBytes(vm.readFile("test/vectors/proved-claim-call.hex"));
        bytes memory expect = vm.parseBytes(vm.readFile("test/vectors/proved-claim-cbor.hex"));
        bytes memory body = new bytes(data.length - 4);
        for (uint256 i; i < body.length; ++i) {
            body[i] = data[i + 4];
        }
        (ICharmsTypes.Spell memory spell,,,) =
            abi.decode(body, (ICharmsTypes.Spell, bytes32, bytes, bytes[]));
        assertEq(SpellCodec.encode(spell), expect);
        assertEq(spell.apps.length, 2);
        assertEq(spell.versionedApps.length, 1);
        assertEq(spell.ins.length, 1);
        assertEq(spell.refs.length, 1);
        assertEq(spell.outs.length, 3);
        assertEq(spell.beamedOuts.length, 1);
    }
}
