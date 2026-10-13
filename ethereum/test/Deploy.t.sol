// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {Deploy} from "../script/Deploy.s.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
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

    function test_deploysSpellVersion16AtItsCreate2Address() public {
        Charms charms = script.run(FACTORY, admin);

        bytes memory verifierInit = vm.getCode("SP1VerifierGroth16.sol:SP1Verifier");
        address verifier = vm.computeCreate2Address(
            keccak256("charms-sp1-verifier-v1"), keccak256(verifierInit), FACTORY
        );
        address applier = vm.computeCreate2Address(
            keccak256("charms-apply-v16"),
            keccak256(
                abi.encodePacked(
                    type(CharmsApply).creationCode,
                    abi.encode(uint32(16), script.PROGRAM_VKEY(), verifier)
                )
            ),
            FACTORY
        );
        address implementation = vm.computeCreate2Address(
            keccak256("charms-implementation-v16"),
            keccak256(abi.encodePacked(type(Charms).creationCode, abi.encode(applier))),
            FACTORY
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
        assertEq(charms.SPELL_VERSION(), 16);
        assertEq(charms.APPLY().PROGRAM_VKEY(), script.PROGRAM_VKEY());
        assertEq(
            script.PROGRAM_VKEY(),
            hex"0060f1593d80473ff16c56a15c9042aa0e61fe54d8ec34638853dc4946f25d3e"
        );
        assertEq(address(charms.APPLY().VERIFIER()), verifier);
        assertGt(verifier.code.length, 0);
        assertGt(vm.computeCreateAddress(address(charms), 1).code.length, 0);
        assertEq(vm.computeCreateAddress(address(charms), 2).code.length, 0);
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
