// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";

import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";

/// @notice Upgrades a phase-1 proxy to spell version 16.
/// `programVKey` is the 32 bytes `charms spell vk` prints.
contract UpgradeToV16 is Script {
    function run(address proxy, address verifier, bytes32 programVKey)
        external
        returns (Charms charms)
    {
        require(proxy != address(0) && verifier != address(0), "zero address");
        require(programVKey != bytes32(0), "program vkey is zero");

        charms = Charms(payable(proxy));
        require(charms.SPELL_VERSION() == 15, "proxy is not phase-1");
        require(msg.sender == charms.admin(), "broadcaster is not the admin");

        vm.startBroadcast();
        CharmsApply applier = new CharmsApply(16, programVKey, ISP1Verifier(verifier));
        Charms next = new Charms(applier);
        charms.upgradeToAndCall(address(next), "");
        vm.stopBroadcast();

        require(charms.SPELL_VERSION() == 16, "upgrade did not take");
        require(CharmsApply(address(charms.APPLY())).PROGRAM_VKEY() == programVKey, "vkey mismatch");
        require(
            address(CharmsApply(address(charms.APPLY())).VERIFIER()) == verifier,
            "verifier mismatch"
        );
        console.log("CharmsApply", address(applier));
        console.log("implementation", address(next));
    }
}
