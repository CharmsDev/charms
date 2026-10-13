// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";

import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";

/// @notice Deploys the first Charms release at spell version 16. The proxy address is
/// `ETHEREUM_CHARMS`, and it depends only on `deployer`, `admin`, and this bytecode.
/// @dev `deployer` is a CREATE2 factory that takes `salt ‖ initCode` as calldata, such as
/// 0x4e59b44847b379578588920ca78fbf26c0b4956c. A rerun after a partial deployment finishes it.
/// `initialize` creates the shared `CharmToken` implementation. This script does not deploy
/// per-app clones.
///
/// forge script script/Deploy.s.sol --sig "run(address,address)" <deployer> <admin> \
///     --rpc-url <url> --broadcast
contract Deploy is Script {
    /// @dev Same bytes as `charms-lib`'s `SPELL_VK`.
    bytes32 public constant PROGRAM_VKEY =
        hex"0060f1593d80473ff16c56a15c9042aa0e61fe54d8ec34638853dc4946f25d3e";

    bytes32 public constant VERIFIER_SALT = keccak256("charms-sp1-verifier-v1");
    bytes32 public constant APPLY_SALT = keccak256("charms-apply-v16");
    bytes32 public constant IMPLEMENTATION_SALT = keccak256("charms-implementation-v16");
    bytes32 public constant PROXY_SALT = keccak256("charms-proxy-v1");

    function run(address deployer, address admin) external returns (Charms charms) {
        require(deployer.code.length != 0, "deployer has no code");
        require(admin != address(0), "admin is zero");

        // Groth16Verifier pins solc 0.8.20, so this script loads that artifact
        // instead of importing it into the 0.8.37 compilation.
        bytes memory verifierInit = vm.getCode("SP1VerifierGroth16.sol:SP1Verifier");
        require(verifierInit.length != 0, "verifier bytecode missing");

        vm.startBroadcast();
        address verifier = _create2(deployer, VERIFIER_SALT, verifierInit);
        address applier = _create2(
            deployer,
            APPLY_SALT,
            abi.encodePacked(
                type(CharmsApply).creationCode, abi.encode(uint32(16), PROGRAM_VKEY, verifier)
            )
        );
        address implementation = _create2(
            deployer,
            IMPLEMENTATION_SALT,
            abi.encodePacked(type(Charms).creationCode, abi.encode(applier))
        );
        charms = Charms(
            payable(_create2(
                    deployer,
                    PROXY_SALT,
                    abi.encodePacked(
                        type(CharmsProxy).creationCode,
                        abi.encode(implementation, abi.encodeCall(Charms.initialize, (admin)))
                    )
                ))
        );
        vm.stopBroadcast();

        require(charms.admin() == admin, "admin not set");
        require(charms.SPELL_VERSION() == 16, "not spell version 16");
        require(charms.APPLY().PROGRAM_VKEY() == PROGRAM_VKEY, "program vkey mismatch");
        require(address(charms.APPLY().VERIFIER()) == verifier, "verifier not set");
        console.log("SP1Verifier", verifier);
        console.log("CharmsApply", applier);
        console.log("Charms implementation", implementation);
        console.log("ETHEREUM_CHARMS", address(charms));
    }

    function _create2(address deployer, bytes32 salt, bytes memory initCode)
        internal
        returns (address deployed)
    {
        deployed = vm.computeCreate2Address(salt, keccak256(initCode), deployer);
        if (deployed.code.length != 0) return deployed;
        (bool ok,) = deployer.call(abi.encodePacked(salt, initCode));
        require(ok && deployed.code.length != 0, "CREATE2 deployment failed");
    }
}
