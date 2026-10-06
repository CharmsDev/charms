// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {Charms} from "../../src/Charms.sol";
import {CharmsApply} from "../../src/CharmsApply.sol";
import {CharmsProxy} from "../../src/CharmsProxy.sol";
import {ICharmsTypes} from "../../src/interfaces/ICharms.sol";
import {ISP1Verifier} from "../../src/interfaces/ISP1Verifier.sol";
import {CharmsIds} from "../../src/libraries/CharmsIds.sol";
import {SpellCodec} from "../../src/libraries/SpellCodec.sol";
import {MockVerifier} from "./Mocks.sol";

abstract contract CharmsTestBase is Test, ICharmsTypes {
    uint32 internal constant T = 0x74;
    uint32 internal constant N = 0x6e;
    uint32 internal constant S = 0x73;
    uint32 internal constant X = 0x78;
    bytes internal constant NULL = hex"f6";
    bytes internal constant PROOF = hex"c0ffee";
    bytes32 internal constant PROGRAM_VKEY = keccak256("v16 program vk");
    bytes32 internal constant VAULT_VK = sha256("charms/ethereum/vault/v1");

    address internal admin = makeAddr("admin");
    MockVerifier internal verifier;
    Charms internal charms;

    uint256 internal salts;

    function setUp() public virtual {
        verifier = new MockVerifier();
        charms = _deploy(16, PROGRAM_VKEY, verifier);
    }

    function _deploy(uint32 version, bytes32 vk, ISP1Verifier v) internal returns (Charms) {
        Charms impl = new Charms(new CharmsApply(version, vk, v));
        CharmsProxy proxy =
            new CharmsProxy(address(impl), abi.encodeCall(Charms.initialize, (admin)));
        return Charms(payable(address(proxy)));
    }

    function _deployPhase1() internal {
        charms = _deploy(15, bytes32(0), ISP1Verifier(address(0)));
    }

    function _app(uint32 tag, string memory label) internal pure returns (App memory) {
        return App(tag, keccak256(bytes(label)), keccak256(abi.encodePacked(label, "/vk")));
    }

    function _spell(App[] memory apps, uint256 nIns, uint256 nOuts)
        internal
        view
        returns (Spell memory s)
    {
        s.version = charms.SPELL_VERSION();
        s.apps = apps;
        s.publicInputs = new bytes[](apps.length);
        for (uint256 i; i < apps.length; ++i) {
            s.publicInputs[i] = NULL;
        }
        s.ins = new Input[](nIns);
        s.outs = new Output[](nOuts);
    }

    function _apps(App memory a) internal pure returns (App[] memory apps) {
        apps = new App[](1);
        apps[0] = a;
    }

    function _apps(App memory a, App memory b) internal pure returns (App[] memory apps) {
        apps = new App[](2);
        (apps[0], apps[1]) = _lt(a, b) ? (a, b) : (b, a);
    }

    function _lt(App memory a, App memory b) internal pure returns (bool) {
        if (a.tag != b.tag) return a.tag < b.tag;
        if (a.identity != b.identity) return a.identity < b.identity;
        return a.vk < b.vk;
    }

    function _token(uint32 app, uint64 amount) internal pure returns (Charm memory) {
        return Charm(app, amount, "");
    }

    function _nft(uint32 app, bytes memory data) internal pure returns (Charm memory) {
        return Charm(app, 0, data);
    }

    function _charms(Charm memory a) internal pure returns (Charm[] memory c) {
        c = new Charm[](1);
        c[0] = a;
    }

    function _charms(Charm memory a, Charm memory b) internal pure returns (Charm[] memory c) {
        c = new Charm[](2);
        (c[0], c[1]) = (a, b);
    }

    function _input(bytes32 txId, uint32 index, Charm[] memory opening)
        internal
        pure
        returns (Input memory input)
    {
        input.utxo = UtxoRef(txId, index);
        input.charms = opening;
    }

    function _txId(Spell memory s, address sender, bytes32 salt) internal view returns (bytes32) {
        bytes32 anchor = s.ins.length == 0 ? keccak256(abi.encode(sender, salt)) : bytes32(0);
        return CharmsIds.ethTxId(block.chainid, address(charms), anchor, SpellCodec.encode(s));
    }

    /// @dev Computed from the CHIP rather than read from the contract.
    function _spendDigest(bytes32 txId) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("Charms"),
                keccak256("1"),
                block.chainid,
                address(charms)
            )
        );
        bytes32 structHash = keccak256(abi.encode(keccak256("Spend(bytes32 txId)"), txId));
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _sign(uint256 key, bytes32 txId) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, _spendDigest(txId));
        return abi.encodePacked(r, s, v);
    }

    function _transact(address sender, Spell memory s) internal returns (bytes32) {
        vm.prank(sender);
        return charms.transact(s, bytes32(0), "", new bytes[](0));
    }

    function _placeholder(address owner) internal returns (bytes32 txId) {
        Spell memory s = _spell(new App[](0), 0, 1);
        s.outs[0].owner = owner;
        vm.prank(owner);
        txId = charms.transact(s, bytes32(++salts), "", new bytes[](0));
    }

    /// @dev Needs the default v16 deployment.
    function _mint(App[] memory apps, Output[] memory outs) internal returns (bytes32 txId) {
        address owner = outs[0].owner;
        bytes32 placeholder = _placeholder(owner);
        Spell memory s = _spell(apps, 1, 0);
        s.ins[0].utxo = UtxoRef(placeholder, 0);
        s.outs = outs;
        vm.prank(owner);
        txId = charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function _mintOne(address owner, App[] memory apps, Charm[] memory held)
        internal
        returns (bytes32)
    {
        Output[] memory outs = new Output[](1);
        outs[0] = Output(owner, held);
        return _mint(apps, outs);
    }

    function _balance(App memory app, address owner) internal view returns (uint256) {
        return charms.balanceOf(_key(app), owner);
    }

    function _key(App memory app) internal pure returns (bytes32) {
        return keccak256(abi.encode(app.tag, app.identity, app.vk));
    }

    /// @dev `vaults` is slot 8 of the frozen layout, and `locked` is the third word of a `Vault`.
    function _locked(address token) internal view returns (uint256) {
        bytes32 vault = keccak256(abi.encode(token, uint256(8)));
        return uint256(vm.load(address(charms), bytes32(uint256(vault) + 2)));
    }

    function _kind(bytes32 txId, uint32 index) internal view returns (uint8 kind, address owner) {
        (kind, owner,,) = charms.utxo(UtxoRef(txId, index));
    }
}
