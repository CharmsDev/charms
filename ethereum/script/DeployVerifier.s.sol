// SPDX-License-Identifier: MIT
pragma solidity =0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {SP1Verifier} from "sp1-contracts/v6.1.0/SP1VerifierGroth16.sol";

/// @notice Deploys Succinct's stock Groth16 verifier. Charms passes it the
/// proof bytes `verify_gnark_v6` already accepts.
contract DeployVerifier is Script {
    function run() external returns (address verifier) {
        vm.startBroadcast();
        verifier = address(new SP1Verifier());
        vm.stopBroadcast();
        console.log("SP1Verifier", verifier);
    }
}
