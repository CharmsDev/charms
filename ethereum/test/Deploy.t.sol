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
import {CharmsIds} from "../src/libraries/CharmsIds.sol";
import {SpellCodec} from "../src/libraries/SpellCodec.sol";

contract DeployTest is Test {
    /// @dev The keyless deterministic-deployment proxy and its runtime code.
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes internal constant FACTORY_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    bytes32 internal constant PROGRAM_VKEY =
        0x0060f1593d80473ff16c56a15c9042aa0e61fe54d8ec34638853dc4946f25d3e;
    address internal constant CALLER = 0x1111111111111111111111111111111111111111;
    address internal constant REF_OWNER = 0x2222222222222222222222222222222222222222;
    address internal constant NEXT_OWNER = 0x3333333333333333333333333333333333333333;
    bytes32 internal constant PLACEHOLDER_TX =
        0x97c2b57e3d80acbe4b1d574557e61dc8737d890a029674075a98f7a892054f7c;

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

    function test_claimEncodingMatchesTheProvedSpell() public {
        Charms charms = script.run(FACTORY, admin);
        assertEq(address(charms), 0x7269cC778B9b90EEe6717B3D3050E372E399d8E7);
        (, ICharmsTypes.Spell memory claim) = _placeholder(charms);
        assertEq(
            SpellCodec.encode(claim), vm.parseBytes(vm.readFile("test/vectors/v16-claim-cbor.hex"))
        );
    }

    function test_realV16ProofChangesState() public {
        Charms charms = script.run(FACTORY, admin);
        (bytes32 txId, ICharmsTypes.Spell memory claim) = _placeholder(charms);
        bytes memory proof = _v16Proof();
        bytes memory cbor = SpellCodec.encode(claim);
        vm.expectCall(
            address(charms.APPLY().VERIFIER()),
            abi.encodeCall(
                ISP1Verifier.verifyProof,
                (PROGRAM_VKEY, SpellCodec.publicValues(PROGRAM_VKEY, cbor), proof)
            )
        );

        vm.prank(CALLER);
        bytes32 created = charms.transact(claim, bytes32(0), proof, new bytes[](0));

        assertEq(_owner(charms, txId, 0), address(0));
        assertEq(_owner(charms, txId, 1), REF_OWNER);
        assertEq(_owner(charms, created, 0), NEXT_OWNER);
    }

    function test_corruptedV16ProofLeavesStateUnchanged() public {
        Charms charms = script.run(FACTORY, admin);
        (bytes32 txId, ICharmsTypes.Spell memory claim) = _placeholder(charms);
        bytes memory proof = _v16Proof();
        proof[proof.length - 1] ^= 0x01;
        bytes32 created =
            CharmsIds.ethTxId(block.chainid, address(charms), bytes32(0), SpellCodec.encode(claim));

        vm.prank(CALLER);
        vm.expectRevert();
        charms.transact(claim, bytes32(0), proof, new bytes[](0));

        assertEq(_owner(charms, txId, 0), CALLER);
        assertEq(_owner(charms, txId, 1), REF_OWNER);
        assertEq(_owner(charms, created, 0), address(0));
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

    /// @dev Chain 31337 and salt 1. Output 0 is spent. Output 1 is the reference.
    function _placeholder(Charms charms)
        internal
        returns (bytes32 txId, ICharmsTypes.Spell memory claim)
    {
        vm.chainId(31_337);
        ICharmsTypes.Spell memory created;
        created.version = 16;
        created.outs = new ICharmsTypes.Output[](2);
        created.outs[0].owner = CALLER;
        created.outs[1].owner = REF_OWNER;
        vm.prank(CALLER);
        txId = charms.transact(created, bytes32(uint256(1)), "", new bytes[](0));
        assertEq(txId, PLACEHOLDER_TX);

        claim.version = 16;
        claim.ins = new ICharmsTypes.Input[](1);
        claim.ins[0].utxo = ICharmsTypes.UtxoRef(txId, 0);
        claim.refs = new ICharmsTypes.UtxoRef[](1);
        claim.refs[0] = ICharmsTypes.UtxoRef(txId, 1);
        claim.outs = new ICharmsTypes.Output[](1);
        claim.outs[0].owner = NEXT_OWNER;
    }

    function _v16Proof() internal view returns (bytes memory) {
        return vm.parseJsonBytes(vm.readFile("test/vectors/v16-deploy-proof.json"), ".proof");
    }

    function _owner(Charms charms, bytes32 txId, uint32 index)
        internal
        view
        returns (address owner)
    {
        (owner,) = charms.utxo(ICharmsTypes.UtxoRef(txId, index));
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
