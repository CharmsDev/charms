// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {Deploy} from "../script/Deploy.s.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";

contract DeployTest is Test {
    /// @dev The keyless deterministic-deployment proxy and its runtime code.
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes internal constant FACTORY_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    address internal admin = makeAddr("admin");
    Deploy internal script;

    function setUp() public {
        vm.etch(FACTORY, FACTORY_CODE);
        script = new Deploy();
    }

    function test_deploysThePhase1ProxyAtItsCreate2Address() public {
        Charms charms = script.run(FACTORY, admin);

        address implementation = address(
            uint160(
                uint256(
                    vm.load(
                        address(charms),
                        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
                    )
                )
            )
        );
        bytes memory proxyInit = abi.encodePacked(
            type(CharmsProxy).creationCode,
            abi.encode(implementation, abi.encodeCall(Charms.initialize, (admin)))
        );
        assertEq(
            address(charms),
            vm.computeCreate2Address(keccak256("charms-proxy-v1"), keccak256(proxyInit), FACTORY)
        );
        assertEq(charms.admin(), admin);
        assertEq(charms.SPELL_VERSION(), 15);
        assertEq(address(charms.APPLY().VERIFIER()), address(0));
        assertGt(vm.computeCreateAddress(address(charms), 1).code.length, 0);
    }

    function test_rerunKeepsTheSameDeployment() public {
        Charms first = script.run(FACTORY, admin);
        Charms second = script.run(FACTORY, admin);
        assertEq(address(second), address(first));
    }

    function test_adminIsPartOfTheProxyAddress() public {
        Charms one = script.run(FACTORY, admin);
        Charms other = script.run(FACTORY, makeAddr("other admin"));
        assertTrue(address(one) != address(other));
    }

    function test_refusesAZeroAdmin() public {
        vm.expectRevert(bytes("admin is zero"));
        script.run(FACTORY, address(0));
    }
}
