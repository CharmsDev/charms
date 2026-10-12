// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";

import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";

/// @notice Deploys the phase-1 Charms proxy with `new`, for a local chain.
contract DeployLocal is Script {
    function run() external returns (Charms charms) {
        vm.startBroadcast();
        CharmsApply applier = new CharmsApply(15, bytes32(0), ISP1Verifier(address(0)));
        Charms implementation = new Charms(applier);
        charms = Charms(
            payable(address(
                    new CharmsProxy(
                        address(implementation), abi.encodeCall(Charms.initialize, (msg.sender))
                    )
                ))
        );
        vm.stopBroadcast();

        require(charms.SPELL_VERSION() == 15, "not the phase-1 build");
        require(charms.admin() == msg.sender, "admin is the broadcaster");
        console.log("ETHEREUM_CHARMS", address(charms));
    }
}
