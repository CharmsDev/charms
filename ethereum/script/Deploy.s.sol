// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";

import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";

/// @notice Deploys the phase-1 (spell version 15) Charms. The proxy address is `ETHEREUM_CHARMS`,
/// and it depends only on `deployer`, `admin`, and this bytecode.
/// @dev `deployer` is a CREATE2 factory that takes `salt ‖ initCode` as calldata, such as
/// 0x4e59b44847b379578588920ca78fbf26c0b4956c. A rerun after a partial deployment finishes it.
///
/// forge script script/Deploy.s.sol --sig "run(address,address)" <deployer> <admin> \
///     --rpc-url <url> --broadcast
contract Deploy is Script {
    bytes32 public constant PROXY_SALT = keccak256("charms-proxy-v1");
    bytes32 public constant APPLY_SALT = keccak256("charms-apply-v15");
    bytes32 public constant IMPLEMENTATION_SALT = keccak256("charms-implementation-v15");

    function run(address deployer, address admin) external returns (Charms charms) {
        require(deployer.code.length != 0, "deployer has no code");
        require(admin != address(0), "admin is zero");

        vm.startBroadcast();
        address applier = _create2(
            deployer,
            APPLY_SALT,
            abi.encodePacked(
                type(CharmsApply).creationCode, abi.encode(uint32(15), bytes32(0), address(0))
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
        require(charms.SPELL_VERSION() == 15, "not the phase-1 build");
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
