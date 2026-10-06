// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";

import {ICharmsErrors} from "../src/interfaces/ICharms.sol";
import {SpellCodec} from "../src/libraries/SpellCodec.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";
import {Wallet1271} from "./utils/Mocks.sol";

contract TransactTest is CharmsTestBase {
    bytes internal constant ART = hex"6461727421";
    bytes32 internal constant DEST = keccak256("beam destination");

    address internal alice;
    uint256 internal aliceKey;
    address internal bob;
    uint256 internal bobKey;
    address internal carol;
    uint256 internal carolKey;

    App internal coin;
    App internal gem;
    App internal art;
    Pin internal v1;
    Pin internal v2;

    function setUp() public override {
        super.setUp();
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");
        (carol, carolKey) = makeAddrAndKey("carol");
        coin = _app(T, "coin");
        gem = _app(T, "gem");
        art = _app(N, "art");
        v1 = Pin(coin.vk, 1, keccak256("coin wasm v1"));
        v2 = Pin(coin.vk, 2, keccak256("coin wasm v2"));
    }

    function test_zeroInputSpellWithOnlyEmptyOutputsCreatesPlaceholders() public {
        Spell memory s = _spell(new App[](0), 0, 2);
        s.outs[0].owner = alice;
        s.outs[1].owner = bob;

        vm.prank(alice);
        bytes32 txId = charms.transact(s, bytes32(uint256(7)), "", new bytes[](0));

        assertEq(txId, _txId(s, alice, bytes32(uint256(7))));
        (uint8 kind, address owner) = _kind(txId, 0);
        assertEq(kind, 0);
        assertEq(owner, alice);
        (kind, owner) = _kind(txId, 1);
        assertEq(kind, 0);
        assertEq(owner, bob);
    }

    function test_zeroInputSpellThatCreatesACharmIsRefused() public {
        Spell memory s = _spell(_apps(coin), 0, 1);
        s.outs[0] = Output(alice, _charms(_token(0, 5)));

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.NotPlaceholderOrWrap.selector);
        charms.transact(s, bytes32(uint256(1)), "", new bytes[](0));
    }

    function test_zeroInputSpellThatCreatesACharmIsRefusedEvenWithAProof() public {
        Spell memory s = _spell(_apps(coin), 0, 1);
        s.outs[0] = Output(alice, _charms(_token(0, 5)));

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.NotPlaceholderOrWrap.selector);
        charms.transact(s, bytes32(uint256(1)), PROOF, new bytes[](0));
    }

    function test_spellWithInputsMustUseAZeroSalt() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.SaltNotZero.selector);
        charms.transact(s, bytes32(uint256(1)), "", new bytes[](0));
    }

    function test_ownersSpendSignatureLetsAnotherAccountSubmit() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, carol);
        bytes32 txId = _txId(s, bob, 0);

        vm.prank(bob);
        assertEq(charms.transact(s, bytes32(0), "", _one(_sign(aliceKey, txId))), txId);

        assertEq(_balance(coin, carol), 100);
        assertEq(_balance(coin, alice), 0);
    }

    function test_spendingAnotherOwnersInputWithoutASignatureReverts() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(ICharmsErrors.BadSignature.selector, alice));
        charms.transact(s, bytes32(0), "", new bytes[](0));
    }

    function test_aSignatureBeyondTheInputOwnersReverts() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        bytes32 txId = _txId(s, bob, 0);
        bytes[] memory sigs = _two(_sign(aliceKey, txId), _sign(carolKey, txId));

        vm.prank(bob);
        vm.expectRevert(ICharmsErrors.BadSignatureCount.selector);
        charms.transact(s, bytes32(0), "", sigs);
    }

    function test_aSignatureFromAnotherKeyReverts() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        bytes[] memory sigs = _one(_sign(carolKey, _txId(s, bob, 0)));

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(ICharmsErrors.BadSignature.selector, alice));
        charms.transact(s, bytes32(0), "", sigs);
    }

    function test_aSignatureDoesNotCoverAnotherSpell() public {
        bytes32 minted = _coinFor(alice, 100);
        bytes memory sig = _sign(aliceKey, _txId(_spendTo(minted, 0, 100, bob), bob, 0));
        Spell memory redirected = _spendTo(minted, 0, 100, carol);

        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(ICharmsErrors.BadSignature.selector, alice));
        charms.transact(redirected, bytes32(0), "", _one(sig));
    }

    function test_contractOwnerAuthorizesThroughErc1271() public {
        Wallet1271 wallet = new Wallet1271(carol);
        bytes32 minted = _coinFor(address(wallet), 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        bytes32 txId = _txId(s, bob, 0);
        bytes memory sig = _sign(carolKey, txId);

        vm.expectCall(
            address(wallet), abi.encodeCall(Wallet1271.isValidSignature, (_spendDigest(txId), sig))
        );
        vm.prank(bob);
        charms.transact(s, bytes32(0), "", _one(sig));

        assertEq(_balance(coin, bob), 100);
        assertEq(_balance(coin, address(wallet)), 0);
    }

    function test_erc1271OwnerRefusesASignatureFromAnotherKey() public {
        Wallet1271 wallet = new Wallet1271(carol);
        bytes32 minted = _coinFor(address(wallet), 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        bytes[] memory sigs = _one(_sign(aliceKey, _txId(s, bob, 0)));

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(ICharmsErrors.BadSignature.selector, address(wallet))
        );
        charms.transact(s, bytes32(0), "", sigs);
    }

    function test_twoInputsOfOneOwnerNeedOneSignature() public {
        Spell memory s = _twoCoinsOfAlice();
        bytes32 txId = _txId(s, bob, 0);

        vm.prank(bob);
        charms.transact(s, bytes32(0), "", _one(_sign(aliceKey, txId)));

        assertEq(_balance(coin, bob), 100);
        assertEq(_balance(coin, alice), 0);
    }

    function test_oneOwnerSigningOncePerInputReverts() public {
        Spell memory s = _twoCoinsOfAlice();
        bytes memory sig = _sign(aliceKey, _txId(s, bob, 0));
        bytes[] memory sigs = _two(sig, sig);

        vm.prank(bob);
        vm.expectRevert(ICharmsErrors.BadSignatureCount.selector);
        charms.transact(s, bytes32(0), "", sigs);
    }

    function test_signaturesFollowTheOrderInWhichOwnersFirstAppear() public {
        Spell memory s = _fourInputsOfThreeOwners();
        bytes32 txId = _txId(s, carol, 0);

        vm.prank(carol);
        charms.transact(s, bytes32(0), "", _two(_sign(bobKey, txId), _sign(aliceKey, txId)));

        assertEq(_balance(coin, carol), 100);
        assertEq(_balance(coin, bob), 0);
        assertEq(_balance(coin, alice), 0);
    }

    function test_signaturesOutOfThatOrderRevert() public {
        Spell memory s = _fourInputsOfThreeOwners();
        bytes32 txId = _txId(s, carol, 0);
        bytes[] memory sigs = _two(_sign(aliceKey, txId), _sign(bobKey, txId));

        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(ICharmsErrors.BadSignature.selector, bob));
        charms.transact(s, bytes32(0), "", sigs);
    }

    function test_openingWithTheWrongAmountReverts() public {
        bytes32 minted = _coinFor(alice, 100);
        _expectRejected(_spendTo(minted, 0, 99, bob), ICharmsErrors.OpeningMismatch.selector);
    }

    function test_openingWithTheWrongAppReverts() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spell(_apps(gem), 1, 1);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 100)));
        s.outs[0] = Output(bob, _charms(_token(0, 100)));
        _expectRejected(s, ICharmsErrors.OpeningMismatch.selector);
    }

    function test_bundleOpeningThatDropsAPinReverts() public {
        bytes32 pinned = _mintPinned(alice, 100);
        Spell memory s = _spendTo(pinned, 0, 100, bob);
        s.versionedApps = _pins(v1);
        _expectRejected(s, ICharmsErrors.OpeningMismatch.selector);
    }

    function test_bundleOpeningThatDropsACharmReverts() public {
        bytes32 held = _bundle();
        Spell memory s = _spell(_apps(art, coin), 1, 1);
        s.ins[0] = _input(held, 0, _charms(_token(1, 100)));
        s.outs[0] = Output(bob, _charms(_token(1, 100)));
        _expectRejected(s, ICharmsErrors.OpeningMismatch.selector);
    }

    function test_spendingASpentInputReverts() public {
        bytes32 minted = _coinFor(alice, 100);
        _transact(alice, _spendTo(minted, 0, 100, bob));
        _expectRejected(_spendTo(minted, 0, 100, carol), ICharmsErrors.InputSpent.selector);
    }

    function test_spendingOneInputTwiceInASpellReverts() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spell(_apps(coin), 2, 1);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 100)));
        s.ins[1] = _input(minted, 0, _charms(_token(0, 100)));
        s.outs[0] = Output(alice, _charms(_token(0, 200)));
        _expectRejected(s, ICharmsErrors.InputSpent.selector);
    }

    function test_appsOutOfOrderAreNotCanonical() public {
        bytes32 held = _bundle();
        Spell memory s = _bundleTransfer(held);
        (s.apps[0], s.apps[1]) = (coin, art);
        s.ins[0].charms = _charms(_token(0, 100), _nft(1, ART));
        s.outs[0].charms = _charms(_token(0, 60), _nft(1, ART));
        s.outs[1].charms = _charms(_token(0, 40));
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_charmsOutOfAppOrderAreNotCanonical() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.outs[0].charms = _charms(_token(1, 60), _nft(0, ART));
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_tokenCharmWithDataIsNotCanonical() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        s.outs[0].charms[0].data = hex"00";
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_tokenCharmWithAmountZeroIsNotCanonical() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spell(_apps(coin), 1, 2);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 100)));
        s.outs[0] = Output(bob, _charms(_token(0, 100)));
        s.outs[1] = Output(carol, _charms(_token(0, 0)));
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_nonTokenCharmWithAnAmountIsNotCanonical() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.outs[0].charms[0].amount = 1;
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_publicInputCountOtherThanTheAppCountIsNotCanonical() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        s.publicInputs = new bytes[](2);
        (s.publicInputs[0], s.publicInputs[1]) = (NULL, NULL);
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_ownerZeroOnAnOutputThatIsNotBeamedIsNotCanonical() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, address(0));
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_beamedOutputWithAnOwnerIsNotCanonical() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        s.beamedOuts = _beamed(0);
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_beamedOutsOutOfIndexOrderAreNotCanonical() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spell(_apps(coin), 1, 2);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 100)));
        s.outs[0] = Output(address(0), _charms(_token(0, 40)));
        s.outs[1] = Output(address(0), _charms(_token(0, 60)));
        s.beamedOuts = new BeamedOut[](2);
        (s.beamedOuts[0], s.beamedOuts[1]) = (BeamedOut(1, DEST), BeamedOut(0, DEST));
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_scrollsOutOfIndexOrderAreNotCanonical() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spell(_apps(coin), 1, 2);
        s.ins[0] = _input(minted, 0, _charms(_token(0, 100)));
        s.outs[0] = Output(bob, _charms(_token(0, 40)));
        s.outs[1] = Output(alice, _charms(_token(0, 60)));
        s.scrolls = new uint32[](2);
        (s.scrolls[0], s.scrolls[1]) = (1, 0);
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_versionedAppsOutOfVkOrderAreNotCanonical() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        s.versionedApps = new Pin[](2);
        s.versionedApps[0] = Pin(bytes32(uint256(2)), 1, keccak256("second wasm"));
        s.versionedApps[1] = Pin(bytes32(uint256(1)), 1, keccak256("first wasm"));
        _expectRejected(s, ICharmsErrors.NotCanonical.selector);
    }

    function test_surrogateCodePointTagIsInvalid() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _withApp(_spendTo(minted, 0, 100, bob), _app(0xd800, "surrogate"));
        _expectRejected(s, ICharmsErrors.InvalidTag.selector);
    }

    function test_tagAboveTheLastUnicodeScalarIsInvalid() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _withApp(_spendTo(minted, 0, 100, bob), _app(0x110000, "beyond"));
        _expectRejected(s, ICharmsErrors.InvalidTag.selector);
    }

    function test_aSpellMayCreateSixtyFourOutputs() public {
        Spell memory s = _spell(new App[](0), 0, 64);
        for (uint256 i; i < 64; ++i) {
            s.outs[i].owner = alice;
        }

        bytes32 txId = _transact(alice, s);

        (uint8 kind, address owner) = _kind(txId, 63);
        assertEq(kind, 0);
        assertEq(owner, alice);
    }

    function test_sixtyFiveOutputsExceedTheLimit() public {
        Spell memory s = _spell(new App[](0), 0, 65);
        for (uint256 i; i < 65; ++i) {
            s.outs[i].owner = alice;
        }
        _expectRejected(s, ICharmsErrors.LimitExceeded.selector);
    }

    function test_sixtyFiveInputsExceedTheLimit() public {
        Spell memory s = _spell(new App[](0), 65, 1);
        s.outs[0].owner = alice;
        _expectRejected(s, ICharmsErrors.LimitExceeded.selector);
    }

    function test_sixtyFiveAppsExceedTheLimit() public {
        App[] memory apps = new App[](65);
        for (uint256 i; i < 65; ++i) {
            apps[i] = App(uint32(0x100 + i), keccak256("app"), keccak256("app/vk"));
        }
        Spell memory s = _spell(apps, 0, 1);
        s.outs[0].owner = alice;
        _expectRejected(s, ICharmsErrors.LimitExceeded.selector);
    }

    function test_publicValuesOver96KiBExceedTheLimit() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        s.publicInputs[0] = bytes.concat(hex"5a00018000", new bytes(96 * 1024));
        _expectRejected(s, ICharmsErrors.LimitExceeded.selector);
    }

    function test_balancedBundleTransferIsNative() public {
        bytes32 txId = _transact(alice, _bundleTransfer(_bundle()));

        (uint8 kind, address owner) = _kind(txId, 0);
        assertEq(kind, 2);
        assertEq(owner, bob);
        (kind, owner) = _kind(txId, 1);
        assertEq(kind, 1);
        assertEq(owner, alice);
        assertEq(_balance(coin, bob), 60);
        assertEq(_balance(coin, alice), 40);
        assertEq(charms.totalSupply(_key(coin)), 100);
    }

    function test_creatingTokenUnitsNeedsAProof() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.outs[1].charms[0].amount = 41;
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_destroyingTokenUnitsNeedsAProof() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.outs[1].charms[0].amount = 39;
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_tokenSumsPastU64NeedAProof() public {
        bytes32 big = _coinFor(alice, type(uint64).max);
        bytes32 one = _coinFor(alice, 1);
        Spell memory s = _spell(_apps(coin), 2, 2);
        s.ins[0] = _input(big, 0, _charms(_token(0, type(uint64).max)));
        s.ins[1] = _input(one, 0, _charms(_token(0, 1)));
        s.outs[0] = Output(bob, _charms(_token(0, 1)));
        s.outs[1] = Output(alice, _charms(_token(0, type(uint64).max)));
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_changingNftDataNeedsAProof() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.outs[0].charms[0].data = hex"6462617421";
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_destroyingAnNftNeedsAProof() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.outs[0].charms = _charms(_token(1, 60));
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_nonNullPublicInputNeedsAProof() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.publicInputs[1] = hex"01";
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_listingACustomTagAppNeedsAProof() public {
        Spell memory s = _withApp(_bundleTransfer(_bundle()), _app(X, "custom"));
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_movingACustomTagCharmUnchangedNeedsAProof() public {
        App[] memory apps = _apps(coin, _app(X, "custom"));
        bytes32 held = _mintOne(alice, apps, _charms(_token(0, 100), _nft(1, ART)));
        Spell memory s = _spell(apps, 1, 1);
        s.ins[0] = _input(held, 0, _charms(_token(0, 100), _nft(1, ART)));
        s.outs[0] = Output(bob, _charms(_token(0, 100), _nft(1, ART)));
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_spellWithARefNeedsAProof() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.refs = new UtxoRef[](1);
        s.refs[0] = UtxoRef(_placeholder(carol), 0);
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_spellWithAScrollNeedsAProof() public {
        Spell memory s = _bundleTransfer(_bundle());
        s.scrolls = new uint32[](1);
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_pinnedTransferThatKeepsThePinIsNative() public {
        bytes32 pinned = _mintPinned(alice, 100);
        (,,, bytes memory before) = charms.utxo(UtxoRef(pinned, 0));

        bytes32 txId = _transact(alice, _pinnedSpend(pinned, v1));

        (uint8 kind, address owner,, bytes memory body) = charms.utxo(UtxoRef(txId, 0));
        assertEq(kind, 2);
        assertEq(owner, bob);
        assertEq(body, before, "the new output stores the same charm and pin");
        assertEq(_balance(coin, bob), 100);
    }

    function test_changingAPinNeedsAProof() public {
        bytes32 pinned = _mintPinned(alice, 100);
        _expectRejected(_pinnedSpend(pinned, v2), ICharmsErrors.ProofRequired.selector);
    }

    function test_declaringAPinForUnpinnedUnitsNeedsAProof() public {
        bytes32 plain = _coinFor(alice, 100);
        Spell memory s = _spendTo(plain, 0, 100, bob);
        s.versionedApps = _pins(v1);
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_mergingPinnedAndUnpinnedUnitsOfOneAppNeedsAProof() public {
        bytes32 pinned = _mintPinned(alice, 100);
        bytes32 plain = _coinFor(alice, 50);
        Spell memory s = _spell(_apps(coin), 2, 1);
        s.ins[0] = _input(pinned, 0, _charms(_token(0, 100)));
        s.ins[0].pins = _pins(v1);
        s.ins[1] = _input(plain, 0, _charms(_token(0, 50)));
        s.versionedApps = _pins(v1);
        s.outs[0] = Output(alice, _charms(_token(0, 150)));
        _expectRejected(s, ICharmsErrors.ProofRequired.selector);
    }

    function test_nativeSpellWithAProofIsRefused() public {
        Spell memory s = _bundleTransfer(_bundle());

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.ProofNotRequired.selector);
        charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function test_spellOfAnotherVersionIsUnsupported() public {
        bytes32 minted = _coinFor(alice, 100);
        Spell memory s = _spendTo(minted, 0, 100, bob);
        s.version = 17;

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(ICharmsErrors.UnsupportedVersion.selector, uint32(17))
        );
        charms.transact(s, bytes32(0), "", new bytes[](0));
    }

    function test_phase1RefusesBeamedOutputs() public {
        _deployPhase1();
        (App memory vault, bytes32 wrapped) = _wrapEth(alice, 1000);
        Spell memory s = _spell(_apps(vault), 1, 1);
        s.ins[0] = _input(wrapped, 0, _charms(_token(0, 1000)));
        s.outs[0] = Output(address(0), _charms(_token(0, 1000)));
        s.beamedOuts = _beamed(0);
        _expectRejected(s, ICharmsErrors.BeamingUnsupported.selector);
    }

    function test_phase1RefusesProofs() public {
        _deployPhase1();
        bytes32 placeholder = _placeholder(alice);
        Spell memory s = _spell(_apps(coin), 1, 1);
        s.ins[0].utxo = UtxoRef(placeholder, 0);
        s.outs[0] = Output(alice, _charms(_token(0, 100)));

        vm.prank(alice);
        vm.expectRevert(ICharmsErrors.ProofsUnsupported.selector);
        charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function test_placeholderLogCarriesItsIdItsAnchorAndTheSpell() public {
        Spell memory s = _spell(new App[](0), 0, 1);
        s.outs[0].owner = alice;
        bytes32 salt = bytes32(uint256(7));

        vm.recordLogs();
        vm.prank(alice);
        bytes32 txId = charms.transact(s, salt, "", new bytes[](0));

        (bytes32 logged, bytes32 anchor, bytes memory spell) = _transactionLog();
        assertEq(logged, txId);
        assertEq(anchor, keccak256(abi.encode(alice, salt)));
        assertEq(spell, SpellCodec.encode(s));
        assertEq(
            txId,
            keccak256(
                abi.encodePacked(
                    "charms/ethereum/tx/v1", block.chainid, address(charms), anchor, spell
                )
            ),
            "the id hashes the CHIP preimage"
        );
    }

    function test_spendLogHasAZeroAnchor() public {
        Spell memory s = _bundleTransfer(_bundle());

        vm.recordLogs();
        bytes32 txId = _transact(alice, s);

        (bytes32 logged, bytes32 anchor, bytes memory spell) = _transactionLog();
        assertEq(logged, txId);
        assertEq(anchor, bytes32(0));
        assertEq(spell, SpellCodec.encode(s));
    }

    function test_utxoOfAPlaceholderIsAnOwnedEmptyRecord() public {
        bytes32 placeholder = _placeholder(alice);

        (uint8 kind, address owner, uint64 amount, bytes memory body) =
            charms.utxo(UtxoRef(placeholder, 0));
        assertEq(kind, 0);
        assertEq(owner, alice);
        assertEq(amount, 0);
        assertEq(body.length, 0);
    }

    function test_utxoOfASingleUnpinnedTokenIsPlainWithItsAmount() public {
        bytes32 minted = _coinFor(alice, 100);

        (uint8 kind, address owner, uint64 amount, bytes memory body) =
            charms.utxo(UtxoRef(minted, 0));
        assertEq(kind, 1);
        assertEq(owner, alice);
        assertEq(amount, 100);
        assertEq(body.length, 0);
    }

    function test_utxoOfAnNftBundleCarriesABody() public {
        bytes32 held = _bundle();

        (uint8 kind, address owner,, bytes memory body) = charms.utxo(UtxoRef(held, 0));
        assertEq(kind, 2);
        assertEq(owner, alice);
        assertTrue(_contains(body, ART), "the body holds the NFT data");
    }

    function test_utxoOfAPinnedTokenIsABundleThatHoldsThePin() public {
        bytes32 pinned = _mintPinned(alice, 100);

        (uint8 kind, address owner,, bytes memory body) = charms.utxo(UtxoRef(pinned, 0));
        assertEq(kind, 2);
        assertEq(owner, alice);
        assertTrue(_contains(body, abi.encodePacked(v1.wasmHash)), "the body holds the pin");
    }

    function test_utxoOfAnUnknownIdIsEmptyWithNoOwner() public view {
        (uint8 kind, address owner, uint64 amount, bytes memory body) =
            charms.utxo(UtxoRef(keccak256("unknown"), 0));
        assertEq(kind, 0);
        assertEq(owner, address(0));
        assertEq(amount, 0);
        assertEq(body.length, 0);
    }

    function test_utxoOfASpentOutputReadsAsUnknown() public {
        bytes32 held = _bundle();
        _transact(alice, _bundleTransfer(held));

        (uint8 kind, address owner, uint64 amount, bytes memory body) =
            charms.utxo(UtxoRef(held, 0));
        assertEq(kind, 0);
        assertEq(owner, address(0));
        assertEq(amount, 0);
        assertEq(body.length, 0);
    }

    function test_utxosOfPagesUntilTheCursorComesBackZero() public {
        bytes32 minted = _fiveCoinsOfAlice();
        bytes32 key = _key(coin);

        (UtxoRef[] memory page, uint256 next) = charms.utxosOf(key, alice, 0, 2);
        assertEq(page.length, 2);
        _assertRef(page[0], minted, 1);
        _assertRef(page[1], minted, 2);
        assertTrue(next != 0, "more UTXOs follow");

        (page, next) = charms.utxosOf(key, alice, next, 2);
        assertEq(page.length, 2);
        _assertRef(page[0], minted, 3);
        _assertRef(page[1], minted, 4);
        assertTrue(next != 0, "more UTXOs follow");

        (page, next) = charms.utxosOf(key, alice, next, 2);
        assertEq(page.length, 1);
        _assertRef(page[0], minted, 5);
        assertEq(next, 0, "the list is exhausted");
    }

    function test_utxosOfSkipsSpentUtxos() public {
        bytes32 minted = _fiveCoinsOfAlice();
        _transact(alice, _spendTo(minted, 2, 20, bob));

        (UtxoRef[] memory page, uint256 next) = charms.utxosOf(_key(coin), alice, 0, 10);
        assertEq(page.length, 4);
        _assertRef(page[0], minted, 1);
        _assertRef(page[1], minted, 3);
        _assertRef(page[2], minted, 4);
        _assertRef(page[3], minted, 5);
        assertEq(next, 0);
    }

    function test_utxosOfAppKeyZeroPagesEmptyUtxos() public {
        bytes32 first = _placeholder(alice);
        bytes32 second = _placeholder(alice);
        bytes32 third = _placeholder(alice);

        (UtxoRef[] memory page, uint256 next) = charms.utxosOf(bytes32(0), alice, 0, 2);
        assertEq(page.length, 2);
        _assertRef(page[0], first, 0);
        _assertRef(page[1], second, 0);
        assertTrue(next != 0, "more placeholders follow");

        (page, next) = charms.utxosOf(bytes32(0), alice, next, 2);
        assertEq(page.length, 1);
        _assertRef(page[0], third, 0);
        assertEq(next, 0);
    }

    function test_changeGoesToTheFrontOfTheOwnersList() public {
        (bytes32 minted, bytes32 split) = _aliceSplitsTwenty();

        (UtxoRef[] memory page,) = charms.utxosOf(_key(coin), alice, 0, 10);
        assertEq(page.length, 2);
        _assertRef(page[0], split, 1);
        _assertRef(page[1], minted, 1);
    }

    function test_receiptsGoToTheBackOfTheRecipientsList() public {
        (bytes32 minted, bytes32 split) = _aliceSplitsTwenty();

        (UtxoRef[] memory page,) = charms.utxosOf(_key(coin), bob, 0, 10);
        assertEq(page.length, 2);
        _assertRef(page[0], minted, 3);
        _assertRef(page[1], split, 0);
    }

    function _coinFor(address owner, uint64 amount) internal returns (bytes32) {
        return _mintOne(owner, _apps(coin), _charms(_token(0, amount)));
    }

    function _spendTo(bytes32 txId, uint32 index, uint64 amount, address to)
        internal
        view
        returns (Spell memory s)
    {
        s = _spell(_apps(coin), 1, 1);
        s.ins[0] = _input(txId, index, _charms(_token(0, amount)));
        s.outs[0] = Output(to, _charms(_token(0, amount)));
    }

    /// @dev `art` sorts before `coin`.
    function _bundle() internal returns (bytes32) {
        return _mintOne(alice, _apps(art, coin), _charms(_nft(0, ART), _token(1, 100)));
    }

    function _bundleTransfer(bytes32 held) internal view returns (Spell memory s) {
        s = _spell(_apps(art, coin), 1, 2);
        s.ins[0] = _input(held, 0, _charms(_nft(0, ART), _token(1, 100)));
        s.outs[0] = Output(bob, _charms(_nft(0, ART), _token(1, 60)));
        s.outs[1] = Output(alice, _charms(_token(1, 40)));
    }

    function _mintPinned(address owner, uint64 amount) internal returns (bytes32) {
        bytes32 placeholder = _placeholder(owner);
        Spell memory s = _spell(_apps(coin), 1, 1);
        s.versionedApps = _pins(v1);
        s.ins[0].utxo = UtxoRef(placeholder, 0);
        s.outs[0] = Output(owner, _charms(_token(0, amount)));
        vm.prank(owner);
        return charms.transact(s, bytes32(0), PROOF, new bytes[](0));
    }

    function _pinnedSpend(bytes32 pinned, Pin memory declared)
        internal
        view
        returns (Spell memory s)
    {
        s = _spendTo(pinned, 0, 100, bob);
        s.ins[0].pins = _pins(v1);
        s.versionedApps = _pins(declared);
    }

    function _twoCoinsOfAlice() internal returns (Spell memory s) {
        bytes32 a = _coinFor(alice, 30);
        bytes32 b = _coinFor(alice, 70);
        s = _spell(_apps(coin), 2, 1);
        s.ins[0] = _input(a, 0, _charms(_token(0, 30)));
        s.ins[1] = _input(b, 0, _charms(_token(0, 70)));
        s.outs[0] = Output(bob, _charms(_token(0, 100)));
    }

    function _fourInputsOfThreeOwners() internal returns (Spell memory s) {
        Output[] memory outs = new Output[](4);
        outs[0] = Output(carol, _charms(_token(0, 10)));
        outs[1] = Output(bob, _charms(_token(0, 20)));
        outs[2] = Output(alice, _charms(_token(0, 30)));
        outs[3] = Output(bob, _charms(_token(0, 40)));
        bytes32 minted = _mint(_apps(coin), outs);
        s = _spell(_apps(coin), 4, 1);
        for (uint32 i; i < 4; ++i) {
            s.ins[i] = _input(minted, i, _charms(_token(0, outs[i].charms[0].amount)));
        }
        s.outs[0] = Output(carol, _charms(_token(0, 100)));
    }

    /// @dev Carol's placeholder pays for alice's outputs, so they are receipts in output order.
    function _fiveCoinsOfAlice() internal returns (bytes32) {
        Output[] memory outs = new Output[](6);
        outs[0] = Output(carol, new Charm[](0));
        for (uint256 i = 1; i < 6; ++i) {
            outs[i] = Output(alice, _charms(_token(0, uint64(10 * i))));
        }
        return _mint(_apps(coin), outs);
    }

    function _aliceSplitsTwenty() internal returns (bytes32 minted, bytes32 split) {
        Output[] memory outs = new Output[](4);
        outs[0] = Output(carol, new Charm[](0));
        outs[1] = Output(alice, _charms(_token(0, 10)));
        outs[2] = Output(alice, _charms(_token(0, 20)));
        outs[3] = Output(bob, _charms(_token(0, 30)));
        minted = _mint(_apps(coin), outs);
        Spell memory s = _spell(_apps(coin), 1, 2);
        s.ins[0] = _input(minted, 2, _charms(_token(0, 20)));
        s.outs[0] = Output(bob, _charms(_token(0, 5)));
        s.outs[1] = Output(alice, _charms(_token(0, 15)));
        split = _transact(alice, s);
    }

    function _wrapEth(address owner, uint64 units)
        internal
        returns (App memory vault, bytes32 txId)
    {
        vm.deal(owner, uint256(units) * 1e10);
        vm.prank(owner);
        txId = charms.wrap{value: uint256(units) * 1e10}(address(0), units, owner, bytes32(0));
        (vault,,) = charms.vaultOf(address(0));
    }

    /// @dev `extra` must sort after every app already in `s`.
    function _withApp(Spell memory s, App memory extra) internal pure returns (Spell memory) {
        uint256 n = s.apps.length;
        App[] memory apps = new App[](n + 1);
        bytes[] memory inputs = new bytes[](n + 1);
        for (uint256 i; i < n; ++i) {
            (apps[i], inputs[i]) = (s.apps[i], s.publicInputs[i]);
        }
        (apps[n], inputs[n]) = (extra, NULL);
        (s.apps, s.publicInputs) = (apps, inputs);
        return s;
    }

    function _expectRejected(Spell memory s, bytes4 err) internal {
        vm.prank(alice);
        vm.expectRevert(err);
        charms.transact(s, bytes32(0), "", new bytes[](0));
    }

    function _transactionLog()
        internal
        view
        returns (bytes32 txId, bytes32 anchor, bytes memory spell)
    {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == address(charms)
                    && logs[i].topics[0] == ICharmsErrors.Transaction.selector
            ) {
                (anchor, spell) = abi.decode(logs[i].data, (bytes32, bytes));
                return (logs[i].topics[1], anchor, spell);
            }
        }
        revert("no Transaction log");
    }

    function _beamed(uint32 index) internal pure returns (BeamedOut[] memory b) {
        b = new BeamedOut[](1);
        b[0] = BeamedOut(index, DEST);
    }

    function _pins(Pin memory p) internal pure returns (Pin[] memory pins) {
        pins = new Pin[](1);
        pins[0] = p;
    }

    function _one(bytes memory sig) internal pure returns (bytes[] memory sigs) {
        sigs = new bytes[](1);
        sigs[0] = sig;
    }

    function _two(bytes memory a, bytes memory b) internal pure returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        (sigs[0], sigs[1]) = (a, b);
    }

    function _assertRef(UtxoRef memory u, bytes32 txId, uint32 index) internal pure {
        assertEq(u.txId, txId);
        assertEq(u.index, index);
    }

    function _contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        for (uint256 i; i + needle.length <= haystack.length; ++i) {
            uint256 j;
            while (j < needle.length && haystack[i + j] == needle[j]) ++j;
            if (j == needle.length) return true;
        }
        return false;
    }
}
