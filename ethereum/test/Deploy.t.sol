// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {Deploy} from "../script/Deploy.s.sol";
import {CharmToken} from "../src/CharmToken.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";
import {ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";

contract DeployTest is Test {
    /// @dev The keyless deterministic-deployment proxy and its runtime code.
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes internal constant FACTORY_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    bytes32 internal constant PROGRAM_VKEY =
        0x0060f1593d80473ff16c56a15c9042aa0e61fe54d8ec34638853dc4946f25d3e;

    address internal admin = makeAddr("admin");
    Deploy internal script;

    function setUp() public {
        vm.etch(FACTORY, FACTORY_CODE);
        script = new Deploy();
    }

    function test_installsSpellVersion16AtItsCreate2Address() public {
        Charms charms = script.run(FACTORY, admin);

        address implementation = _implementation(charms);
        bytes memory proxyInit = abi.encodePacked(
            type(CharmsProxy).creationCode,
            abi.encode(implementation, abi.encodeCall(Charms.initialize, (admin)))
        );
        assertEq(
            address(charms),
            vm.computeCreate2Address(script.PROXY_SALT(), keccak256(proxyInit), FACTORY)
        );
        assertEq(charms.admin(), admin);
        assertEq(charms.SPELL_VERSION(), 16);
        assertEq(charms.APPLY().PROGRAM_VKEY(), PROGRAM_VKEY);

        address verifier = address(charms.APPLY().VERIFIER());
        assertEq(
            verifier,
            vm.computeCreate2Address(
                script.VERIFIER_SALT(), keccak256(vm.getCode(script.VERIFIER_ARTIFACT())), FACTORY
            )
        );
        assertGt(verifier.code.length, 0);

        address token = vm.computeCreateAddress(address(charms), 1);
        assertGt(token.code.length, 0);
        assertEq(address(CharmToken(token).charms()), address(charms));

        ICharmsTypes.App memory app =
            ICharmsTypes.App(uint32(0x74), keccak256("app"), keccak256("vk"));
        assertEq(charms.tokenAddress(app).code.length, 0);

        script.check(charms, admin);
    }

    function test_groth16HashMatchesTheVector() public view {
        string memory json = vm.readFile("test/vectors/spells.json");
        assertEq(script.GROTH16_VK_HASH(), vm.parseJsonBytes32(json, "$.sp1.groth16VkHash"));
    }

    function test_rerunKeepsTheSameDeployment() public {
        Charms first = script.run(FACTORY, admin);
        Charms second = script.run(FACTORY, admin);
        assertEq(address(second), address(first));
        assertEq(address(second.APPLY()), address(first.APPLY()));
        assertEq(address(second.APPLY().VERIFIER()), address(first.APPLY().VERIFIER()));
    }

    function test_adminIsPartOfTheProxyAddress() public {
        Charms one = script.run(FACTORY, admin);
        Charms other = script.run(FACTORY, makeAddr("other admin"));
        assertTrue(address(one) != address(other));
        assertEq(address(one.APPLY()), address(other.APPLY()));
        assertEq(address(one.APPLY().VERIFIER()), address(other.APPLY().VERIFIER()));
        assertEq(_implementation(one), _implementation(other));
    }

    function test_refusesAZeroAdmin() public {
        address verifier = vm.computeCreate2Address(
            script.VERIFIER_SALT(), keccak256(vm.getCode(script.VERIFIER_ARTIFACT())), FACTORY
        );
        vm.expectRevert(bytes("admin is zero"));
        script.run(FACTORY, address(0));
        assertEq(verifier.code.length, 0);
    }

    function test_nativeWrapNeedsNoProof() public {
        Charms charms = script.run(FACTORY, admin);
        uint64 units = uint64(1 ether / 10 ** 10);
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        charms.wrap{value: 1 ether}(address(0), units, admin, bytes32(uint256(1)));
        assertEq(address(charms).balance, 1 ether);
    }

    function test_checkRefusesAnOldBuild() public {
        Charms old = Charms(
            payable(address(
                    new CharmsProxy(
                        address(
                            new Charms(new CharmsApply(15, bytes32(0), ISP1Verifier(address(0))))
                        ),
                        abi.encodeCall(Charms.initialize, (admin))
                    )
                ))
        );
        vm.expectRevert(bytes("spell version"));
        script.check(old, admin);
    }

    function _implementation(Charms charms) internal view returns (address) {
        return address(
            uint160(
                uint256(
                    vm.load(
                        address(charms),
                        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
                    )
                )
            )
        );
    }
}
