// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {CharmsStorage} from "./CharmsStorage.sol";
import {ICharmTokenHooks} from "./interfaces/ICharms.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {CborWellFormed} from "./libraries/CborWellFormed.sol";
import {appKey} from "./libraries/CharmTokenClone.sol";
import {CharmsIds} from "./libraries/CharmsIds.sol";
import {SpellCodec} from "./libraries/SpellCodec.sol";
import {UtxoBody} from "./libraries/UtxoBody.sol";
import {UtxoList} from "./libraries/UtxoList.sol";

/// @notice `_apply` of CHIP-0020: the only writer of UTXO, supply, balance, and vault state.
/// `Charms` `delegatecall`s `applySpell`, so this code runs in the proxy's storage.
/// @dev Which spell version this build accepts, its `programVKey`, and its verifier are fixed in
/// the bytecode. A zero verifier is the phase-1 build: it rejects proofs and `beamedOuts`.
contract CharmsApply is CharmsStorage {
    using UtxoList for UtxoList.List;

    uint256 internal constant MAX_PUBLIC_VALUES = 96 * 1024;
    bytes32 internal constant SPEND_TYPEHASH = keccak256("Spend(bytes32 txId)");
    bytes32 internal constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    uint32 public immutable SPELL_VERSION;
    bytes32 public immutable PROGRAM_VKEY;
    ISP1Verifier public immutable VERIFIER;

    constructor(uint32 spellVersion, bytes32 programVKey, ISP1Verifier verifier) {
        SPELL_VERSION = spellVersion;
        PROGRAM_VKEY = programVKey;
        VERIFIER = verifier;
    }

    /// @dev Spells built by `wrap`, `unwrap`, and `tokenTransfer` carry no proof, so one that is
    /// not native reverts with `ProofRequired`.
    /// @dev Payable because `wrap` reaches it by `delegatecall`, which keeps `msg.value`.
    function applySpell(Spell memory s, Context memory c) external payable returns (bytes32 txId) {
        if (s.version != SPELL_VERSION) revert UnsupportedVersion(s.version);
        _checkShape(s);
        bool proofs = address(VERIFIER) != address(0);
        if (s.beamedOuts.length != 0 && !proofs) revert BeamingUnsupported();
        bytes32[] memory keys = new bytes32[](s.apps.length);
        for (uint256 i; i < keys.length; ++i) {
            keys[i] = appKey(s.apps[i]);
        }

        if (s.ins.length == 0) {
            if (usedAnchors[c.anchor]) revert AnchorUsed();
            if (c.move.delta <= 0 && !_isPlaceholder(s)) revert NotPlaceholderOrWrap();
        }
        (address[] memory owners, bytes32[] memory inputKeys) = _openInputs(s, keys);
        for (uint256 i; i < s.refs.length; ++i) {
            bytes32 ref = _utxoKey(s.refs[i].txId, s.refs[i].index);
            if (head[ref].owner == address(0) || _containsKey(inputKeys, inputKeys.length, ref)) {
                revert RefNotLive();
            }
        }

        bytes memory cbor = SpellCodec.encode(s);
        if (SpellCodec.publicValuesLength(PROGRAM_VKEY, cbor.length) > MAX_PUBLIC_VALUES) {
            revert LimitExceeded();
        }
        txId = CharmsIds.ethTxId(block.chainid, address(this), c.anchor, cbor);
        _authorize(txId, owners, c.authorized, c.signatures);

        if (_isNative(s, keys, c.move)) {
            if (c.proof.length != 0) revert ProofNotRequired();
        } else {
            if (c.proof.length == 0) revert ProofRequired();
            if (!proofs) revert ProofsUnsupported();
            if (s.ins.length == 0) revert ProvedSpellWithoutInputs();
            _checkBlobs(s);
            VERIFIER.verifyProof(PROGRAM_VKEY, SpellCodec.publicValues(PROGRAM_VKEY, cbor), c.proof);
        }

        _spendInputs(s, keys, inputKeys, owners);
        _createOutputs(s, keys, txId, owners);
        if (s.ins.length == 0) usedAnchors[c.anchor] = true;
        if (c.move.delta != 0) _moveVault(c.move);
        _checkVaults(s, keys);
        if (s.beamedOuts.length != 0) beamSources[txId] = block.number;
        emit Transaction(txId, c.anchor, cbor);
        _emitTransfers(s, owners);
    }

    /// @dev Calldata order is the CBOR order, so this checks it rather than sorting.
    function _checkShape(Spell memory s) private pure {
        if (s.apps.length > MAX_ITEMS || s.ins.length > MAX_ITEMS || s.outs.length > MAX_ITEMS) {
            revert LimitExceeded();
        }
        if (s.publicInputs.length != s.apps.length) revert NotCanonical();
        for (uint256 i; i < s.apps.length; ++i) {
            uint32 tag = s.apps[i].tag;
            if (tag > 0x10ffff || (tag >= 0xd800 && tag <= 0xdfff)) revert InvalidTag();
            if (i != 0 && !_appLess(s.apps[i - 1], s.apps[i])) revert NotCanonical();
        }
        _checkPinOrder(s.versionedApps);
        for (uint256 i; i < s.ins.length; ++i) {
            _checkCharms(s.apps, s.ins[i].charms);
            _checkPinOrder(s.ins[i].pins);
        }
        uint256 b;
        for (uint256 i; i < s.outs.length; ++i) {
            _checkCharms(s.apps, s.outs[i].charms);
            bool beamed = b < s.beamedOuts.length && s.beamedOuts[b].index == i;
            if (beamed) ++b;
            if (beamed != (s.outs[i].owner == address(0))) revert NotCanonical();
        }
        if (b != s.beamedOuts.length) revert NotCanonical();
        for (uint256 i; i < s.scrolls.length; ++i) {
            if (s.scrolls[i] >= s.outs.length || (i != 0 && s.scrolls[i - 1] >= s.scrolls[i])) {
                revert NotCanonical();
            }
        }
    }

    function _checkCharms(App[] memory apps, Charm[] memory charms) private pure {
        for (uint256 j; j < charms.length; ++j) {
            Charm memory c = charms[j];
            if (c.app >= apps.length || (j != 0 && charms[j - 1].app >= c.app)) {
                revert NotCanonical();
            }
            bool token = apps[c.app].tag == TAG_T;
            if (token ? c.amount == 0 || c.data.length != 0 : c.amount != 0 || c.data.length == 0) {
                revert NotCanonical();
            }
        }
    }

    function _checkPinOrder(Pin[] memory pins) private pure {
        for (uint256 i = 1; i < pins.length; ++i) {
            if (pins[i - 1].vk >= pins[i].vk) revert NotCanonical();
        }
    }

    /// @dev Checks that every input is live, appears once, and opens to what was stored. Writes
    /// nothing, so a signature check reads the state the signer saw.
    function _openInputs(Spell memory s, bytes32[] memory keys)
        private
        view
        returns (address[] memory owners, bytes32[] memory inputKeys)
    {
        owners = new address[](s.ins.length);
        inputKeys = new bytes32[](s.ins.length);
        for (uint256 i; i < s.ins.length; ++i) {
            Input memory input = s.ins[i];
            bytes32 key = _utxoKey(input.utxo.txId, input.utxo.index);
            Head memory h = head[key];
            if (h.owner == address(0) || _containsKey(inputKeys, i, key)) revert InputSpent();
            if (h.kind == Kind.Empty) {
                if (input.charms.length != 0 || input.pins.length != 0) revert OpeningMismatch();
            } else if (h.kind == Kind.Plain) {
                if (input.charms.length != 1 || input.pins.length != 0) revert OpeningMismatch();
                Charm memory c = input.charms[0];
                if (keys[c.app] != h.link || c.amount != h.amount) revert OpeningMismatch();
            } else {
                bytes memory opening = UtxoBody.encode(s.apps, input.charms, input.pins);
                if (keccak256(opening) != h.link) revert OpeningMismatch();
            }
            owners[i] = h.owner;
            inputKeys[i] = key;
        }
    }

    /// @dev Deletes each opened input and unlinks it from every list that holds it.
    function _spendInputs(
        Spell memory s,
        bytes32[] memory keys,
        bytes32[] memory inputKeys,
        address[] memory owners
    ) private {
        for (uint256 i; i < inputKeys.length; ++i) {
            bytes32 key = inputKeys[i];
            address owner = owners[i];
            Kind kind = head[key].kind;
            if (kind == Kind.Empty) emptyUtxos[owner].remove(key);
            else if (kind == Kind.Bundle) delete body[key];
            delete head[key];
            Charm[] memory charms = s.ins[i].charms;
            for (uint256 j; j < charms.length; ++j) {
                Charm memory c = charms[j];
                if (s.apps[c.app].tag != TAG_T) continue;
                balance[owner][keys[c.app]] -= c.amount;
                supply[keys[c.app]] -= c.amount;
                utxos[owner][keys[c.app]].remove(key);
            }
        }
    }

    function _authorize(
        bytes32 txId,
        address[] memory owners,
        address authorized,
        bytes[] memory signatures
    ) private view {
        bytes32 domain = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH, keccak256("Charms"), keccak256("1"), block.chainid, address(this)
            )
        );
        bytes32 digest =
            MessageHashUtils.toTypedDataHash(domain, keccak256(abi.encode(SPEND_TYPEHASH, txId)));
        uint256 used;
        for (uint256 i; i < owners.length; ++i) {
            address owner = owners[i];
            if (owner == authorized || _contains(owners, i, owner)) continue;
            if (
                used == signatures.length
                    || !SignatureChecker.isValidSignatureNow(owner, digest, signatures[used])
            ) revert BadSignature(owner);
            ++used;
        }
        if (used != signatures.length) revert BadSignatureCount();
    }

    /// @dev The guest's simple-transfer path plus what only this contract can see. Beam-ins
    /// fail the sums here: an empty input adds nothing while the outputs gain charms.
    function _isNative(Spell memory s, bytes32[] memory keys, VaultMove memory move)
        private
        pure
        returns (bool)
    {
        if (s.refs.length != 0 || s.scrolls.length != 0) return false;
        uint256 n = s.apps.length;
        for (uint256 i; i < n; ++i) {
            if (s.apps[i].tag != TAG_T && s.apps[i].tag != TAG_N) return false;
            if (keccak256(s.publicInputs[i]) != keccak256(CBOR_NULL)) return false;
        }
        if (!_pinsUnchanged(s)) return false;

        uint256[] memory sumIn = new uint256[](n);
        uint256[] memory sumOut = new uint256[](n);
        bytes32[] memory nftIn = _nfts(s, sumIn, true);
        bytes32[] memory nftOut = _nfts(s, sumOut, false);
        for (uint256 i; i < n; ++i) {
            if (s.apps[i].tag != TAG_T) continue;
            if (sumIn[i] > type(uint64).max || sumOut[i] > type(uint64).max) return false;
            int256 delta = keys[i] == move.appKey ? move.delta : int256(0);
            if (int256(sumIn[i]) + delta != int256(sumOut[i])) return false;
        }
        return _sameMultiset(nftIn, nftOut);
    }

    /// @dev Adds token amounts into `sums` and returns one hash per NFT charm, keyed by app.
    function _nfts(Spell memory s, uint256[] memory sums, bool inputs)
        private
        pure
        returns (bytes32[] memory nfts)
    {
        uint256 groups = inputs ? s.ins.length : s.outs.length;
        uint256 count;
        for (uint256 i; i < groups; ++i) {
            count += (inputs ? s.ins[i].charms : s.outs[i].charms).length;
        }
        nfts = new bytes32[](count);
        uint256 n;
        for (uint256 i; i < groups; ++i) {
            Charm[] memory charms = inputs ? s.ins[i].charms : s.outs[i].charms;
            for (uint256 j; j < charms.length; ++j) {
                Charm memory c = charms[j];
                if (s.apps[c.app].tag == TAG_T) sums[c.app] += c.amount;
                else nfts[n++] = keccak256(abi.encode(c.app, c.data));
            }
        }
        assembly ("memory-safe") {
            mstore(nfts, n)
        }
    }

    function _sameMultiset(bytes32[] memory a, bytes32[] memory b) private pure returns (bool) {
        if (a.length != b.length) return false;
        bool[] memory used = new bool[](a.length);
        for (uint256 i; i < b.length; ++i) {
            uint256 j;
            while (j < a.length && (used[j] || a[j] != b[i])) ++j;
            if (j == a.length) return false;
            used[j] = true;
        }
        return true;
    }

    /// @dev `versionedApps` must be exactly the pins the inputs store, and the inputs must agree.
    function _pinsUnchanged(Spell memory s) private pure returns (bool) {
        Pin[] memory va = s.versionedApps;
        bool[] memory seen = new bool[](va.length);
        for (uint256 i; i < s.ins.length; ++i) {
            Pin[] memory pins = s.ins[i].pins;
            for (uint256 j; j < pins.length; ++j) {
                uint256 k;
                while (k < va.length && va[k].vk != pins[j].vk) ++k;
                if (k == va.length) return false;
                if (va[k].version != pins[j].version || va[k].wasmHash != pins[j].wasmHash) {
                    return false;
                }
                seen[k] = true;
            }
        }
        for (uint256 k; k < va.length; ++k) {
            if (!seen[k]) return false;
        }
        return true;
    }

    function _checkBlobs(Spell memory s) private pure {
        for (uint256 i; i < s.publicInputs.length; ++i) {
            if (!CborWellFormed.isSingleItem(s.publicInputs[i])) revert MalformedBlob();
        }
        for (uint256 i; i < s.outs.length; ++i) {
            Charm[] memory charms = s.outs[i].charms;
            for (uint256 j; j < charms.length; ++j) {
                if (s.apps[charms[j].app].tag == TAG_T) continue;
                if (!CborWellFormed.isSingleItem(charms[j].data)) revert MalformedBlob();
            }
        }
    }

    /// @dev Change (an output whose owner owned an input) goes to the front of each deque and
    /// every other receipt to the back. Beamed outputs are not UTXOs.
    function _createOutputs(
        Spell memory s,
        bytes32[] memory keys,
        bytes32 txId,
        address[] memory inputOwners
    ) private {
        uint256 b;
        for (uint256 j; j < s.outs.length; ++j) {
            if (b < s.beamedOuts.length && s.beamedOuts[b].index == j) {
                ++b;
                continue;
            }
            Output memory o = s.outs[j];
            bytes32 key = _utxoKey(txId, uint32(j));
            if (o.charms.length == 0) {
                head[key] = Head(o.owner, Kind.Empty, uint8(j), 0, txId, 0);
                emptyUtxos[o.owner].pushBack(key);
                continue;
            }
            Pin[] memory pins = _pinsOf(s, o.charms);
            Charm memory first = o.charms[0];
            if (o.charms.length == 1 && pins.length == 0 && s.apps[first.app].tag == TAG_T) {
                head[key] = Head(o.owner, Kind.Plain, uint8(j), first.amount, txId, keys[first.app]);
            } else {
                bytes memory record = UtxoBody.encode(s.apps, o.charms, pins);
                head[key] = Head(o.owner, Kind.Bundle, uint8(j), 0, txId, keccak256(record));
                body[key] = record;
            }
            bool change = _contains(inputOwners, inputOwners.length, o.owner);
            for (uint256 k; k < o.charms.length; ++k) {
                Charm memory c = o.charms[k];
                if (s.apps[c.app].tag != TAG_T) continue;
                bytes32 ak = keys[c.app];
                balance[o.owner][ak] += c.amount;
                supply[ak] += c.amount;
                if (change) utxos[o.owner][ak].pushFront(key);
                else utxos[o.owner][ak].pushBack(key);
            }
        }
    }

    /// @dev The `versionedApps` entries whose vk is the vk of an app on this output.
    function _pinsOf(Spell memory s, Charm[] memory charms)
        private
        pure
        returns (Pin[] memory pins)
    {
        Pin[] memory va = s.versionedApps;
        pins = new Pin[](va.length);
        uint256 n;
        for (uint256 k; k < va.length; ++k) {
            for (uint256 j; j < charms.length; ++j) {
                if (s.apps[charms[j].app].vk == va[k].vk) {
                    pins[n++] = va[k];
                    break;
                }
            }
        }
        assembly ("memory-safe") {
            mstore(pins, n)
        }
    }

    function _moveVault(VaultMove memory move) private {
        Vault storage v = vaults[move.token];
        if (v.appKey == 0) {
            v.appKey = move.appKey;
            v.scale = move.scale;
            vaultTokens[move.appKey] = move.token;
        }
        uint256 units = uint256(move.delta > 0 ? move.delta : -move.delta);
        uint256 underlying = units * 10 ** move.scale;
        if (move.delta > 0) v.locked += underlying;
        else v.locked -= underlying;
    }

    /// @dev On every apply that touches a vault app: the Ethereum supply is covered by `locked`,
    /// and the contract holds at least `locked` of the underlying.
    function _checkVaults(Spell memory s, bytes32[] memory keys) private view {
        for (uint256 i; i < s.apps.length; ++i) {
            if (s.apps[i].vk != VAULT_VK || s.apps[i].tag != TAG_T) continue;
            address token = vaultTokens[keys[i]];
            Vault storage v = vaults[token];
            uint256 resident = supply[keys[i]];
            if (v.appKey != keys[i]) {
                if (resident != 0) revert VaultUndercollateralized();
                continue;
            }
            uint256 locked = v.locked;
            uint256 held = token == address(0)
                ? address(this).balance
                : IERC20(token).balanceOf(address(this));
            if (resident * 10 ** v.scale > locked || held < locked) {
                revert VaultUndercollateralized();
            }
        }
    }

    /// @dev For each tag-`t` app whose clone exists, nets each owner's change and pairs senders
    /// with receivers in order of appearance. What is left over is a mint from or a burn to 0.
    function _emitTransfers(Spell memory s, address[] memory inputOwners) private {
        for (uint256 i; i < s.apps.length; ++i) {
            if (s.apps[i].tag != TAG_T) continue;
            address token = _tokenAddress(s.apps[i]);
            if (token.code.length == 0) continue;
            (address[] memory who, int256[] memory delta) = _netDeltas(s, i, inputOwners);
            _emitNetted(ICharmTokenHooks(token), who, delta);
        }
    }

    function _netDeltas(Spell memory s, uint256 app, address[] memory inputOwners)
        private
        pure
        returns (address[] memory who, int256[] memory delta)
    {
        who = new address[](s.ins.length + s.outs.length);
        delta = new int256[](who.length);
        uint256 n;
        for (uint256 j; j < s.ins.length; ++j) {
            uint256 amount = _amountOfApp(s.ins[j].charms, app);
            if (amount != 0) n = _addDelta(who, delta, n, inputOwners[j], -int256(amount));
        }
        for (uint256 j; j < s.outs.length; ++j) {
            address owner = s.outs[j].owner;
            uint256 amount = _amountOfApp(s.outs[j].charms, app);
            if (amount != 0 && owner != address(0)) {
                n = _addDelta(who, delta, n, owner, int256(amount));
            }
        }
        assembly ("memory-safe") {
            mstore(who, n)
            mstore(delta, n)
        }
    }

    function _addDelta(
        address[] memory who,
        int256[] memory delta,
        uint256 n,
        address owner,
        int256 amount
    ) private pure returns (uint256) {
        for (uint256 k; k < n; ++k) {
            if (who[k] == owner) {
                delta[k] += amount;
                return n;
            }
        }
        who[n] = owner;
        delta[n] = amount;
        return n + 1;
    }

    function _emitNetted(ICharmTokenHooks token, address[] memory who, int256[] memory delta)
        private
    {
        uint256 r;
        for (uint256 i; i < who.length; ++i) {
            if (delta[i] >= 0) continue;
            uint256 owed = uint256(-delta[i]);
            while (owed != 0) {
                while (r < who.length && delta[r] <= 0) ++r;
                if (r == who.length) {
                    token.emitTransfer(who[i], address(0), owed);
                    break;
                }
                uint256 x = owed < uint256(delta[r]) ? owed : uint256(delta[r]);
                token.emitTransfer(who[i], who[r], x);
                delta[r] -= int256(x);
                owed -= x;
            }
        }
        for (; r < who.length; ++r) {
            if (delta[r] > 0) token.emitTransfer(address(0), who[r], uint256(delta[r]));
        }
    }

    function _amountOfApp(Charm[] memory charms, uint256 app) private pure returns (uint256) {
        for (uint256 j; j < charms.length; ++j) {
            if (charms[j].app == app) return charms[j].amount;
        }
        return 0;
    }

    function _isPlaceholder(Spell memory s) private pure returns (bool) {
        for (uint256 i; i < s.outs.length; ++i) {
            if (s.outs[i].charms.length != 0) return false;
        }
        return true;
    }

    /// @dev Whether `x` is among the first `n` entries of `a`.
    function _contains(address[] memory a, uint256 n, address x) private pure returns (bool) {
        for (uint256 i; i < n; ++i) {
            if (a[i] == x) return true;
        }
        return false;
    }

    function _containsKey(bytes32[] memory a, uint256 n, bytes32 x) private pure returns (bool) {
        for (uint256 i; i < n; ++i) {
            if (a[i] == x) return true;
        }
        return false;
    }
}
