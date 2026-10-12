// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";

import {Charms} from "../src/Charms.sol";
import {ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {SpellCodec} from "../src/libraries/SpellCodec.sol";

contract CreatePlaceholder is Script {
    function run(address proxy) external returns (bytes32 txId) {
        Charms charms = Charms(payable(proxy));
        require(charms.SPELL_VERSION() == 16, "proxy is not v16");

        ICharmsTypes.Spell memory s;
        s.version = 16;
        s.outs = new ICharmsTypes.Output[](1);
        s.outs[0].owner = msg.sender;
        bytes32 salt = bytes32(uint256(1));

        vm.startBroadcast();
        txId = charms.transact(s, salt, "", new bytes[](0));
        vm.stopBroadcast();

        bytes32 beam = sha256(SpellCodec.utxoIdBytes(txId, 0));
        console.log("owner", msg.sender);
        console.log("salt");
        console.logBytes32(salt);
        console.log("txId");
        console.logBytes32(txId);
        console.log("beam");
        console.logBytes32(beam);
    }
}
