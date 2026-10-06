// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharmToken, ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {CborWellFormed} from "../src/libraries/CborWellFormed.sol";
import {SpellCodec} from "../src/libraries/SpellCodec.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";

contract ProvedTest is CharmsTestBase {
    bytes internal constant ART = hex"6461727421";
    bytes32 internal constant DEST = keccak256("beam destination");

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    App internal coin;
    App internal art;

    function setUp() public override {
        super.setUp();
        coin = _app(T, "coin");
        art = _app(N, "art");
    }

    function test_verifierGetsTheProgramVKeyTheCommittedSpellAndTheProof() public {
        Spell memory s = _claim(alice, coin, 1000);
        bytes memory publicValues =
            bytes.concat(hex"82", _uintArray(PROGRAM_VKEY), SpellCodec.encode(s));

        vm.expectCall(
            address(verifier),
            abi.encodeCall(ISP1Verifier.verifyProof, (PROGRAM_VKEY, publicValues, PROOF)),
            1
        );
        _prove(alice, s);

        assertEq(_balance(coin, alice), 1000);
    }

    function test_rejectedProofRevertsTheSpell() public {
        Spell memory s = _claim(alice, coin, 1000);
        verifier.setReject(true);

        vm.prank(alice);
        vm.expectRevert(bytes("proof rejected"));
        charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function test_nativeSpellIsAppliedWithoutTheVerifier() public {
        bytes32 minted = _mintOne(alice, _apps(coin), _charms(_token(0, 1000)));
        verifier.setReject(true);
        Spell memory s = _spell(_apps(coin), 1, 1);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 1000)));
        s.outs[0] = Output(bob, _charms(_token(0, 1000)));

        _transact(alice, s);

        assertEq(_balance(coin, bob), 1000);
    }

    function test_provedSpellWithoutInputsIsRefused() public {
        Spell memory s = _spell(_apps(_app(X, "custom")), 0, 1);
        s.outs[0].owner = alice;

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.ProvedSpellWithoutInputs.selector);
        charms.transact(s, bytes32(uint256(1)), PROOF, new bytes[](0));
    }

    function test_provedSpellStillNeedsTheInputOwnersAuthorization() public {
        Spell memory s = _claim(alice, coin, 1000);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(ICharmsErrors.BadSignature.selector, alice));
        charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function test_provedSpellWithAWrongOpeningIsRefused() public {
        bytes32 minted = _mintOne(alice, _apps(coin), _charms(_token(0, 1000)));
        Spell memory s = _spell(_apps(coin), 1, 1);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 999)));
        s.outs[0] = Output(alice, _charms(_token(0, 2000)));
        _expectProvedRevert(s, ICharmsErrors.OpeningMismatch.selector);
    }

    function test_wellFormedNftDataIsAccepted() public {
        bytes32 txId = _prove(alice, _claimWithArt(ART));

        (uint8 kind, address owner) = _kind(txId, 0);
        assertEq(kind, 2);
        assertEq(owner, alice);
    }

    function test_nftDataThatEndsInsideAnArrayIsMalformed() public {
        _expectProvedRevert(_claimWithArt(hex"8201"), ICharmsErrors.MalformedBlob.selector);
    }

    function test_publicInputWithTrailingBytesIsMalformed() public {
        Spell memory s = _claim(alice, coin, 1000);
        s.publicInputs[0] = hex"f600";
        _expectProvedRevert(s, ICharmsErrors.MalformedBlob.selector);
    }

    function test_nftDataNestedSeventeenDeepIsMalformed() public {
        bytes memory nested = hex"00";
        for (uint256 i; i < 17; ++i) {
            nested = bytes.concat(hex"81", nested);
        }
        _expectProvedRevert(_claimWithArt(nested), ICharmsErrors.MalformedBlob.selector);
    }

    function test_indefiniteLengthNftDataIsMalformed() public {
        _expectProvedRevert(_claimWithArt(hex"9f01ff"), ICharmsErrors.MalformedBlob.selector);
    }

    function test_anUnclosedArraySplicedIntoTheSpellSwallowsTheNextField() public {
        bytes memory cbor = SpellCodec.encode(_claimWithArt(hex"8201"));
        uint256 map = _indexOf(cbor, hex"a2008201011903e8");

        assertFalse(CborWellFormed.isSingleItem(hex"8201"), "alone, the blob is not one item");
        assertTrue(
            CborWellFormed.isSingleItem(_slice(cbor, map + 2, 3)),
            "in the spell, coin's app index completes the array as its second item"
        );
        assertTrue(
            CborWellFormed.isSingleItem(_slice(cbor, map, 14)),
            "the charm map then reads 1000 as a key and the coins field name as its value"
        );
    }

    function test_balancedBeamOutIsNativeAndTheBeamedOutputIsNotAUtxo() public {
        (Spell memory s,) = _beamOut();

        bytes32 txId = _transact(alice, s);

        (uint8 kind, address owner, uint64 amount,) = charms.utxo(UtxoRef(txId, 0));
        assertEq(kind, 0);
        assertEq(owner, address(0), "the beamed output has no record");
        assertEq(amount, 0);
        (kind, owner, amount,) = charms.utxo(UtxoRef(txId, 1));
        assertEq(kind, 1);
        assertEq(owner, alice);
        assertEq(amount, 600);
    }

    function test_beamOutLowersSupplyByTheBeamedAmount() public {
        (Spell memory s,) = _beamOut();

        _transact(alice, s);

        assertEq(charms.totalSupply(_key(coin)), 600);
        assertEq(_balance(coin, alice), 600);
    }

    function test_beamOutRecordsItsBlockNumber() public {
        (Spell memory s, bytes32 minted) = _beamOut();
        vm.roll(4242);

        bytes32 txId = _transact(alice, s);

        assertEq(charms.beamSourceAt(txId), 4242);
        assertEq(charms.beamSourceAt(minted), 0, "a spell without beamed outputs records nothing");
    }

    function test_beamOutBurnsThroughAnExistingToken() public {
        (Spell memory s,) = _beamOut();
        address token = charms.ensureToken(coin);

        vm.expectEmit(token);
        emit ICharmToken.Transfer(alice, address(0), 400);
        _transact(alice, s);
    }

    function test_provedBeamInSpendsThePlaceholderAndRaisesSupply() public {
        Spell memory s = _claim(bob, coin, 400);
        bytes32 placeholder = s.ins[0].utxo.txId;

        bytes32 txId = _prove(bob, s);

        assertEq(charms.totalSupply(_key(coin)), 400);
        assertEq(_balance(coin, bob), 400);
        (, address owner) = _kind(placeholder, 0);
        assertEq(owner, address(0), "the placeholder is spent");
        (uint8 kind, address holder) = _kind(txId, 0);
        assertEq(kind, 1);
        assertEq(holder, bob);
    }

    function test_beamInWithoutAProofIsRefused() public {
        Spell memory s = _claim(bob, coin, 400);

        vm.prank(bob);
        vm.expectRevert(ICharmsErrors.ProofRequired.selector);
        charms.transact(s, bytes32(0), "", new bytes[](0));
    }

    function test_beamInMintsThroughAnExistingToken() public {
        Spell memory s = _claim(bob, coin, 400);
        address token = charms.ensureToken(coin);

        vm.expectEmit(token);
        emit ICharmToken.Transfer(address(0), bob, 400);
        _prove(bob, s);
    }

    function test_beamInOfMoreVaultUnitsThanBeamedOutIsUndercollateralized() public {
        App memory vault = _wrapThenBeamOut(1000, 400);
        Spell memory s = _claim(bob, vault, 401);

        vm.prank(bob);
        vm.expectRevert(ICharmsErrors.VaultUndercollateralized.selector);
        charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function test_beamInOfTheVaultUnitsBeamedOutIsAccepted() public {
        App memory vault = _wrapThenBeamOut(1000, 400);

        _prove(bob, _claim(bob, vault, 400));

        assertEq(charms.totalSupply(_key(vault)), 1000);
        assertEq(_balance(vault, bob), 400);
        (,, uint256 locked) = charms.vaultOf(address(0));
        assertEq(locked, 1000e10, "a beam-in does not touch the collateral");
    }

    function test_provedBurnLowersSupply() public {
        bytes32 minted = _mintOne(alice, _apps(coin), _charms(_token(0, 1000)));
        Spell memory s = _spell(_apps(coin), 1, 1);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 1000)));
        s.outs[0] = Output(alice, _charms(_token(0, 700)));

        _prove(alice, s);

        assertEq(charms.totalSupply(_key(coin)), 700);
        assertEq(_balance(coin, alice), 700);
    }

    function test_liveRefIsAcceptedAndStaysLive() public {
        bytes32 ref = _placeholder(bob);
        Spell memory s = _claim(alice, coin, 100);
        s.refs = _refs(UtxoRef(ref, 0));

        _prove(alice, s);

        (uint8 kind, address owner) = _kind(ref, 0);
        assertEq(kind, 0);
        assertEq(owner, bob, "a ref is read, not spent");
        assertEq(_balance(coin, alice), 100);
    }

    function test_spentRefIsRefused() public {
        bytes32 ref = _placeholder(bob);
        Spell memory spend = _spell(new App[](0), 1, 1);
        spend.ins[0].utxo = UtxoRef(ref, 0);
        spend.outs[0].owner = bob;
        _transact(bob, spend);
        Spell memory s = _claim(alice, coin, 100);
        s.refs = _refs(UtxoRef(ref, 0));

        _expectProvedRevert(s, ICharmsErrors.RefNotLive.selector);
    }

    function test_refThatIsAlsoAnInputIsRefused() public {
        Spell memory s = _claim(alice, coin, 100);
        s.refs = _refs(s.ins[0].utxo);
        _expectProvedRevert(s, ICharmsErrors.RefNotLive.selector);
    }

    function test_provedSpellMayChangeAPin() public {
        Pin memory v1 = Pin(coin.vk, 1, keccak256("coin wasm v1"));
        Pin memory v2 = Pin(coin.vk, 2, keccak256("coin wasm v2"));
        bytes32 pinned = _mintPinned(alice, 100, v1);
        Spell memory bump = _spell(_apps(coin), 1, 1);
        bump.ins[0] = _input(pinned, 0, _charms(_token(0, 100)));
        bump.ins[0].pins = _pins(v1);
        bump.versionedApps = _pins(v2);
        bump.outs[0] = Output(alice, _charms(_token(0, 100)));
        bytes32 bumped = _prove(alice, bump);

        Spell memory s = _spell(_apps(coin), 1, 1);
        s.ins[0] = _input(bumped, 0, _charms(_token(0, 100)));
        s.ins[0].pins = _pins(v2);
        s.versionedApps = _pins(v2);
        s.outs[0] = Output(bob, _charms(_token(0, 100)));
        _transact(alice, s);

        assertEq(_balance(coin, bob), 100, "the bumped UTXO opens with the new pin");
    }

    function _claim(address owner, App memory app, uint64 amount)
        internal
        returns (Spell memory s)
    {
        bytes32 placeholder = _placeholder(owner);
        s = _spell(_apps(app), 1, 1);
        s.ins[0].utxo = UtxoRef(placeholder, 0);
        s.outs[0] = Output(owner, _charms(_token(0, amount)));
    }

    function _claimWithArt(bytes memory data) internal returns (Spell memory s) {
        bytes32 placeholder = _placeholder(alice);
        s = _spell(_apps(art, coin), 1, 1);
        s.ins[0].utxo = UtxoRef(placeholder, 0);
        s.outs[0] = Output(alice, _charms(_nft(0, data), _token(1, 1000)));
    }

    function _beamOut() internal returns (Spell memory s, bytes32 minted) {
        minted = _mintOne(alice, _apps(coin), _charms(_token(0, 1000)));
        s = _spell(_apps(coin), 1, 2);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 1000)));
        s.outs[0] = Output(address(0), _charms(_token(0, 400)));
        s.outs[1] = Output(alice, _charms(_token(0, 600)));
        s.beamedOuts = _beamed(0);
    }

    function _wrapThenBeamOut(uint64 wrapped, uint64 beamed) internal returns (App memory vault) {
        vm.deal(alice, uint256(wrapped) * 1e10);
        vm.prank(alice);
        bytes32 w =
            charms.wrap{value: uint256(wrapped) * 1e10}(address(0), wrapped, alice, bytes32(0));
        (vault,,) = charms.vaultOf(address(0));
        Spell memory s = _spell(_apps(vault), 1, 2);
        s.ins[0] = _input(w, 0, _charms(_token(0, wrapped)));
        s.outs[0] = Output(address(0), _charms(_token(0, beamed)));
        s.outs[1] = Output(alice, _charms(_token(0, wrapped - beamed)));
        s.beamedOuts = _beamed(0);
        _transact(alice, s);
    }

    function _mintPinned(address owner, uint64 amount, Pin memory pin) internal returns (bytes32) {
        Spell memory s = _claim(owner, coin, amount);
        s.versionedApps = _pins(pin);
        return _prove(owner, s);
    }

    function _prove(address sender, Spell memory s) internal returns (bytes32) {
        vm.prank(sender);
        return charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function _expectProvedRevert(Spell memory s, bytes4 err) internal {
        vm.prank(alice);
        vm.expectRevert(err);
        charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    /// @dev `[u8; 32]` in ciborium's serde: `0x98 0x20`, then each byte as a shortest-form uint.
    function _uintArray(bytes32 b) internal pure returns (bytes memory out) {
        out = hex"9820";
        for (uint256 i; i < 32; ++i) {
            uint8 x = uint8(b[i]);
            out = x < 24 ? bytes.concat(out, bytes1(x)) : bytes.concat(out, hex"18", bytes1(x));
        }
    }

    function _beamed(uint32 index) internal pure returns (BeamedOut[] memory b) {
        b = new BeamedOut[](1);
        b[0] = BeamedOut(index, DEST);
    }

    function _refs(UtxoRef memory u) internal pure returns (UtxoRef[] memory refs) {
        refs = new UtxoRef[](1);
        refs[0] = u;
    }

    function _pins(Pin memory p) internal pure returns (Pin[] memory pins) {
        pins = new Pin[](1);
        pins[0] = p;
    }

    function _indexOf(bytes memory haystack, bytes memory needle) internal pure returns (uint256) {
        for (uint256 i; i + needle.length <= haystack.length; ++i) {
            uint256 j;
            while (j < needle.length && haystack[i + j] == needle[j]) ++j;
            if (j == needle.length) return i;
        }
        revert("needle not found");
    }

    function _slice(bytes memory b, uint256 start, uint256 length)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(length);
        for (uint256 i; i < length; ++i) {
            out[i] = b[start + i];
        }
    }
}
