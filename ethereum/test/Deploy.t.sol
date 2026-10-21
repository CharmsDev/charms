// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {CharmTokenNext} from "../script/CharmTokenNext.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {CharmToken} from "../src/CharmToken.sol";
import {CharmTokenProxy} from "../src/CharmTokenProxy.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsInitializer} from "../src/CharmsInitializer.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";
import {ICharmsLedger, ICharmsTypes} from "../src/interfaces/ICharms.sol";
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
        0x779bc5a626e8fce3529fd2faaae158c358a6b57a4f7652563a646323f74eb97c;
    /// @dev The checked-in Groth16 proof commits to a spell whose input id was
    /// created at this proxy.
    address internal constant PREVIOUS_PROXY = 0x7269cC778B9b90EEe6717B3D3050E372E399d8E7;
    bytes32 internal constant PREVIOUS_PLACEHOLDER =
        0x97c2b57e3d80acbe4b1d574557e61dc8737d890a029674075a98f7a892054f7c;

    address internal admin = makeAddr("admin");
    address internal signer = makeAddr("metadataSigner");
    Deploy internal script;

    function setUp() public {
        vm.etch(FACTORY, FACTORY_CODE);
        script = new Deploy();
    }

    function test_installsSpellVersion16AtItsCreate2Address() public {
        Charms charms = script.run(FACTORY, admin, signer);

        address initializer = vm.computeCreate2Address(
            script.INITIALIZER_SALT(), keccak256(type(CharmsInitializer).creationCode), FACTORY
        );
        bytes memory proxyInit = abi.encodePacked(
            type(CharmsProxy).creationCode,
            abi.encode(initializer, abi.encodeCall(CharmsInitializer.initialize, (admin)))
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

        address forwarder = vm.computeCreateAddress(address(charms), 1);
        assertGt(forwarder.code.length, 0);
        assertEq(address(CharmTokenProxy(forwarder).charms()), address(charms));
        assertTrue(forwarder != charms.tokenImplementation());
        assertEq(address(CharmToken(charms.tokenImplementation()).charms()), address(charms));

        ICharmsTypes.App memory app =
            ICharmsTypes.App(uint32(0x74), keccak256("app"), keccak256("vk"));
        assertEq(charms.tokenAddress(app).code.length, 0);

        script.check(charms, admin, signer);
    }

    function test_groth16HashMatchesTheVector() public view {
        string memory json = vm.readFile("test/vectors/spells.json");
        assertEq(script.GROTH16_VK_HASH(), vm.parseJsonBytes32(json, "$.sp1.groth16VkHash"));
    }

    function test_rerunKeepsTheSameDeployment() public {
        Charms first = script.run(FACTORY, admin, signer);
        Charms second = script.run(FACTORY, admin, signer);
        assertEq(address(second), address(first));
        assertEq(address(second.APPLY()), address(first.APPLY()));
        assertEq(address(second.APPLY().VERIFIER()), address(first.APPLY().VERIFIER()));
    }

    function test_rerunLeavesATokenUpgradeInPlace() public {
        Charms charms = script.run(FACTORY, admin, signer);
        ICharmsTypes.App memory coin =
            ICharmsTypes.App(uint32(0x74), keccak256("coin"), keccak256("coin/vk"));
        address clone = charms.ensureToken(coin);
        CharmTokenNext nextToken = new CharmTokenNext(ICharmsLedger(address(charms)));
        Charms next = new Charms(charms.APPLY(), address(nextToken), signer);
        vm.prank(admin);
        charms.upgradeToAndCall(address(next), "");
        assertEq(CharmTokenNext(clone).revision(), 2);

        Charms again = script.run(FACTORY, admin, signer);

        assertEq(address(again), address(charms));
        assertEq(_implementation(again), address(next));
        assertEq(again.tokenImplementation(), address(nextToken));
        assertEq(CharmTokenNext(clone).revision(), 2);
    }

    function test_adminIsPartOfTheProxyAddress() public {
        Charms one = script.run(FACTORY, admin, signer);
        Charms other = script.run(FACTORY, makeAddr("other admin"), signer);
        assertTrue(address(one) != address(other));
        assertEq(address(one.APPLY()), address(other.APPLY()));
        assertEq(address(one.APPLY().VERIFIER()), address(other.APPLY().VERIFIER()));
        assertTrue(_implementation(one) != _implementation(other));
        assertTrue(one.tokenImplementation() != other.tokenImplementation());
    }

    function test_refusesAZeroAdmin() public {
        address verifier = vm.computeCreate2Address(
            script.VERIFIER_SALT(), keccak256(vm.getCode(script.VERIFIER_ARTIFACT())), FACTORY
        );
        vm.expectRevert(bytes("admin is zero"));
        script.run(FACTORY, address(0), signer);
        assertEq(verifier.code.length, 0);
    }

    function test_nativeWrapNeedsNoProof() public {
        Charms charms = script.run(FACTORY, admin, signer);
        uint64 units = uint64(1 ether / 10 ** 10);
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        charms.wrap{value: 1 ether}(address(0), units, admin, bytes32(uint256(1)));
        assertEq(address(charms).balance, 1 ether);
    }

    function test_claimEncodingAtTheCreate2Address() public {
        Charms charms = script.run(FACTORY, admin, signer);
        assertEq(address(charms), 0x083f086405cCCc5cEAdC29c8Ed36bBA4d13d39Fd);
        (, ICharmsTypes.Spell memory claim) = _placeholder(charms, PLACEHOLDER_TX);
        assertEq(
            SpellCodec.encode(claim), vm.parseBytes(vm.readFile("test/vectors/v16-claim-cbor.hex"))
        );
    }

    function test_realV16ProofChangesState() public {
        Charms charms = _proofCharms();
        (bytes32 txId, ICharmsTypes.Spell memory claim) = _placeholder(charms, PREVIOUS_PLACEHOLDER);
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
        Charms charms = _proofCharms();
        (bytes32 txId, ICharmsTypes.Spell memory claim) = _placeholder(charms, PREVIOUS_PLACEHOLDER);
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
        CharmsInitializer init = new CharmsInitializer();
        uint64 nonce = vm.getNonce(address(this));
        address predicted = vm.computeCreateAddress(address(this), nonce + 3);
        CharmToken token = new CharmToken(ICharmsLedger(predicted));
        Charms impl = new Charms(
            new CharmsApply(15, bytes32(0), ISP1Verifier(address(0))), address(token), signer
        );
        Charms old = Charms(
            payable(address(
                    new CharmsProxy(
                        address(init), abi.encodeCall(CharmsInitializer.initialize, (admin))
                    )
                ))
        );
        assertEq(address(old), predicted);
        vm.prank(admin);
        old.upgradeToAndCall(address(impl), "");
        vm.expectRevert(bytes("spell version"));
        script.check(old, admin, signer);
    }

    function _proofCharms() internal returns (Charms charms) {
        Charms deployed = script.run(FACTORY, admin, signer);
        vm.etch(PREVIOUS_PROXY, address(deployed).code);
        bytes32 slot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        vm.store(PREVIOUS_PROXY, slot, vm.load(address(deployed), slot));
        charms = Charms(payable(PREVIOUS_PROXY));
    }

    /// @dev Chain 31337 and salt 1. Output 0 is spent. Output 1 is the reference.
    function _placeholder(Charms charms, bytes32 expected)
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
        assertEq(txId, expected);

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
