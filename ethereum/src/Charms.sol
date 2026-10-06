// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {CharmToken} from "./CharmToken.sol";
import {CharmsApply} from "./CharmsApply.sol";
import {CharmsStorage} from "./CharmsStorage.sol";
import {ICharmTokenHooks, ICharms, ICharmsLedger, IUpgradeable} from "./interfaces/ICharms.sol";
import {CharmTokenClone, appKey} from "./libraries/CharmTokenClone.sol";
import {CharmsIds} from "./libraries/CharmsIds.sol";
import {UtxoBody} from "./libraries/UtxoBody.sol";
import {UtxoList} from "./libraries/UtxoList.sol";

/// @notice The Charms implementation behind `CharmsProxy` (CHIP-0020): the consensus for Ethereum
/// Charms transactions. It owns UTXOs, supply, balances, the vault, and anchors in the proxy's
/// storage, builds the spells behind ERC-20 transfers and the vault, and is the UUPS upgrade
/// target.
/// @dev Every spell is applied by `CharmsApply`, whose address is fixed in this bytecode, so a new
/// implementation brings its own. The split keeps both under the EIP-170 size limit.
contract Charms is
    CharmsStorage,
    ICharms,
    ICharmsLedger,
    IUpgradeable,
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardTransient
{
    using SafeERC20 for IERC20;

    uint8 internal constant ETH_SCALE = 10;
    uint8 internal constant UNIT_DECIMALS = 8;

    CharmsApply public immutable APPLY;
    uint32 public immutable SPELL_VERSION;

    struct Pick {
        Head head;
        UtxoBody.Held[] held;
        Pin[] pins;
    }

    struct Entry {
        App app;
        uint256 total;
        bytes data;
    }

    /// @dev One argument instead of five keeps the optimizer from cloning `_transferSpell` for
    /// `unwrap`'s constant recipient.
    struct Transfer {
        App app;
        bytes32 key;
        address from;
        address to;
        uint64 amount;
    }

    constructor(CharmsApply applier) {
        APPLY = applier;
        SPELL_VERSION = applier.SPELL_VERSION();
        _disableInitializers();
    }

    receive() external payable {
        revert EthRejected();
    }

    /// @notice Runs once, from the proxy constructor. Stores the admin and creates the shared
    /// `CharmToken` implementation as the proxy's first contract, so its address is
    /// `CREATE(proxy, nonce 1)` on every chain.
    function initialize(address admin_) external initializer {
        admin = admin_;
        assert(address(new CharmToken()) == _charmTokenImplementation());
    }

    function upgradeToAndCall(address newImplementation, bytes memory data)
        public
        payable
        override(IUpgradeable, UUPSUpgradeable)
    {
        super.upgradeToAndCall(newImplementation, data);
    }

    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != admin) revert NotAdmin();
    }

    function transact(
        Spell calldata spell,
        bytes32 salt,
        bytes calldata proof,
        bytes[] calldata signatures
    ) external nonReentrant returns (bytes32) {
        Context memory c;
        c.authorized = msg.sender;
        c.proof = proof;
        c.signatures = signatures;
        if (spell.ins.length == 0) c.anchor = keccak256(abi.encode(msg.sender, salt));
        else if (salt != 0) revert SaltNotZero();
        return _apply(spell, c);
    }

    function wrap(address token, uint64 amount, address owner, bytes32 salt)
        external
        payable
        nonReentrant
        returns (bytes32)
    {
        uint8 scale = _scale(token);
        Vault storage v = vaults[token];
        if (v.appKey != 0 && v.scale != scale) revert ScaleChanged();
        uint256 underlying = uint256(amount) * 10 ** scale;
        if (token == address(0)) {
            if (msg.value != underlying) revert UnderlyingAmountMismatch();
        } else {
            if (msg.value != 0) revert UnderlyingAmountMismatch();
            uint256 before = IERC20(token).balanceOf(address(this));
            IERC20(token).safeTransferFrom(msg.sender, address(this), underlying);
            if (IERC20(token).balanceOf(address(this)) - before != underlying) {
                revert UnderlyingAmountMismatch();
            }
        }
        App memory app = _vaultApp(token);
        Spell memory s;
        s.version = SPELL_VERSION;
        s.apps = new App[](1);
        s.apps[0] = app;
        s.publicInputs = new bytes[](1);
        s.publicInputs[0] = CBOR_NULL;
        s.outs = new Output[](1);
        s.outs[0].owner = owner;
        s.outs[0].charms = new Charm[](1);
        s.outs[0].charms[0] = Charm(0, amount, "");
        Context memory c;
        c.authorized = msg.sender;
        c.anchor = keccak256(abi.encode(msg.sender, salt));
        c.move = VaultMove(token, appKey(app), scale, int256(uint256(amount)));
        return _apply(s, c);
    }

    function unwrap(address token, uint64 amount, address to)
        external
        nonReentrant
        returns (bytes32 txId)
    {
        Vault storage v = vaults[token];
        bytes32 key = v.appKey;
        if (key == 0) revert InsufficientBalance();
        uint8 scale = v.scale;
        if (_scale(token) != scale) revert ScaleChanged();
        Spell memory s =
            _transferSpell(Transfer(_vaultApp(token), key, msg.sender, address(0), amount));
        Context memory c;
        c.authorized = msg.sender;
        c.move = VaultMove(token, key, scale, -int256(uint256(amount)));
        txId = _apply(s, c);
        uint256 underlying = uint256(amount) * 10 ** scale;
        if (token == address(0)) {
            (bool ok,) = to.call{value: underlying}("");
            if (!ok) revert EthTransferFailed();
        } else {
            IERC20(token).safeTransfer(to, underlying);
        }
    }

    function tokenTransfer(App calldata app, address from, address to, uint256 amount)
        external
        nonReentrant
    {
        if (app.tag != TAG_T) revert NotTokenTag();
        if (msg.sender != _tokenAddress(app)) revert NotToken();
        if (to == address(0) || to == address(this)) revert InvalidRecipient();
        if (amount > type(uint64).max) revert AmountTooLarge();
        if (amount == 0) {
            ICharmTokenHooks(msg.sender).emitTransfer(from, to, 0);
            return;
        }
        Spell memory s = _transferSpell(Transfer(app, appKey(app), from, to, uint64(amount)));
        Context memory c;
        c.authorized = from;
        _apply(s, c);
        if (from == to) ICharmTokenHooks(msg.sender).emitTransfer(from, to, amount);
    }

    function ensureToken(App calldata app) external returns (address token) {
        if (app.tag != TAG_T) revert NotTokenTag();
        token = _tokenAddress(app);
        if (token.code.length != 0) return token;
        bytes memory init = CharmTokenClone.initCode(_charmTokenImplementation(), app);
        bytes32 salt = appKey(app);
        address deployed;
        assembly ("memory-safe") {
            deployed := create2(0, add(init, 32), mload(init), salt)
        }
        assert(deployed == token);
    }

    function tokenAddress(App calldata app) external view returns (address) {
        if (app.tag != TAG_T) revert NotTokenTag();
        return _tokenAddress(app);
    }

    function beamSourceAt(bytes32 txId) external view returns (uint256) {
        return beamSources[txId];
    }

    function totalSupply(bytes32 key) external view returns (uint256) {
        return supply[key];
    }

    function balanceOf(bytes32 key, address owner) external view returns (uint256) {
        return balance[owner][key];
    }

    function utxosOf(bytes32 key, address owner, uint256 cursor, uint256 limit)
        external
        view
        returns (UtxoRef[] memory page, uint256 nextCursor)
    {
        UtxoList.List storage list = key == 0 ? emptyUtxos[owner] : utxos[owner][key];
        bytes32 start = cursor == 0 ? list.first : bytes32(cursor);
        if (head[start].owner != owner) return (page, 0);
        uint256 n;
        bytes32 k = start;
        while (k != 0 && n < limit) {
            k = list.links[k].next;
            ++n;
        }
        page = new UtxoRef[](n);
        k = start;
        for (uint256 i; i < n; ++i) {
            Head storage h = head[k];
            page[i] = UtxoRef(h.txId, h.index);
            k = list.links[k].next;
        }
        nextCursor = uint256(k);
    }

    function utxo(UtxoRef calldata u)
        external
        view
        returns (uint8 kind, address owner, uint64 amount, bytes memory record)
    {
        bytes32 key = _utxoKey(u.txId, u.index);
        Head storage h = head[key];
        if (h.kind == Kind.Bundle) record = body[key];
        return (uint8(h.kind), h.owner, h.amount, record);
    }

    function vaultOf(address token)
        external
        view
        returns (App memory app, uint8 scale, uint256 locked)
    {
        Vault storage v = vaults[token];
        return (_vaultApp(token), v.appKey != 0 ? v.scale : _scale(token), v.locked);
    }

    function name(App calldata app) external view returns (string memory) {
        if (app.vk != VAULT_VK) return "Charm";
        return IERC20Metadata(_vaultUnderlyingErc20(app)).name();
    }

    function symbol(App calldata app) external view returns (string memory) {
        if (app.vk != VAULT_VK) return "CHARM";
        return IERC20Metadata(_vaultUnderlyingErc20(app)).symbol();
    }

    function decimals(App calldata app) external view returns (uint8) {
        if (app.vk != VAULT_VK) return 0;
        address token = _vaultUnderlying(app);
        if (token == address(0)) return UNIT_DECIMALS;
        (bool known, uint256 d) = _decimals(token);
        if (!known) revert MetadataUnspecified();
        return d < UNIT_DECIMALS ? uint8(d) : UNIT_DECIMALS;
    }

    /// @dev The native spell behind `transfer` and `unwrap`: inputs from the front of
    /// `utxos[from][app]`, one output of `amount` to `to` (none when `to` is zero, which burns),
    /// and one change output to `from` carrying the remainder and every other charm.
    function _transferSpell(Transfer memory request) private view returns (Spell memory s) {
        (App memory app, bytes32 key, address from, address to, uint64 amount) =
            (request.app, request.key, request.from, request.to, request.amount);
        if (amount == 0) revert ZeroAmount();
        if (amount > balance[from][key]) revert InsufficientBalance();
        Pick[] memory picks = _select(app, key, from, amount);

        Entry[] memory entries = new Entry[](MAX_ITEMS);
        uint256 na;
        Pin[] memory pins = new Pin[](MAX_ITEMS);
        uint256 np;
        for (uint256 i; i < picks.length; ++i) {
            UtxoBody.Held[] memory held = picks[i].held;
            for (uint256 j; j < held.length; ++j) {
                uint256 e = _entryOf(entries, na, held[j].app);
                if (e == na) {
                    if (na == MAX_ITEMS) revert LimitExceeded();
                    entries[na++].app = held[j].app;
                }
                if (held[j].app.tag == TAG_T) entries[e].total += held[j].amount;
                else entries[e].data = held[j].data;
            }
            for (uint256 j; j < picks[i].pins.length; ++j) {
                Pin memory p = picks[i].pins[j];
                uint256 k;
                while (k < np && pins[k].vk != p.vk) ++k;
                if (k == np) pins[np++] = p;
            }
        }
        _sortEntries(entries, na);
        _sortPins(pins, np);

        s.version = SPELL_VERSION;
        s.apps = new App[](na);
        s.publicInputs = new bytes[](na);
        for (uint256 i; i < na; ++i) {
            s.apps[i] = entries[i].app;
            s.publicInputs[i] = CBOR_NULL;
        }
        assembly ("memory-safe") {
            mstore(pins, np)
        }
        s.versionedApps = pins;
        s.ins = new Input[](picks.length);
        for (uint256 i; i < picks.length; ++i) {
            Pick memory p = picks[i];
            Charm[] memory charms = new Charm[](p.held.length);
            for (uint256 j; j < charms.length; ++j) {
                UtxoBody.Held memory h = p.held[j];
                charms[j] = Charm(uint32(_entryOf(entries, na, h.app)), h.amount, h.data);
            }
            s.ins[i] = Input(UtxoRef(p.head.txId, p.head.index), charms, p.pins);
        }

        uint256 t = _entryOf(entries, na, app);
        uint256 remainder = entries[t].total - amount;
        bool change = remainder != 0 || na > 1;
        uint256 first = to == address(0) ? 0 : 1;
        s.outs = new Output[](first + (change ? 1 : 0));
        if (first == 1) {
            s.outs[0].owner = to;
            s.outs[0].charms = new Charm[](1);
            s.outs[0].charms[0] = Charm(uint32(t), amount, "");
        }
        if (change) {
            Charm[] memory charms = new Charm[](remainder == 0 ? na - 1 : na);
            uint256 c;
            for (uint256 i; i < na; ++i) {
                if (i == t) {
                    if (remainder != 0) charms[c++] = Charm(uint32(i), uint64(remainder), "");
                } else if (entries[i].app.tag == TAG_T) {
                    charms[c++] = Charm(uint32(i), uint64(entries[i].total), "");
                } else {
                    charms[c++] = Charm(uint32(i), 0, entries[i].data);
                }
            }
            s.outs[first] = Output(from, charms);
        }
    }

    /// @dev Walks `utxos[from][app]` from the front. A UTXO with a custom-tag charm is skipped;
    /// so is one that would put a second NFT of the same app, a conflicting pin, or a `u64`
    /// overflow on the one change output. Once `amount` is covered, the next front UTXO is
    /// taken too when it fits, so a passive holder's UTXO count stays bounded.
    function _select(App memory app, bytes32 key, address from, uint64 amount)
        private
        view
        returns (Pick[] memory picks)
    {
        UtxoList.List storage list = utxos[from][key];
        picks = new Pick[](MAX_ITEMS);
        uint256 n;
        uint256 sum;
        uint256 blocked;
        bytes32 pinHash;
        for (bytes32 k = list.first; k != 0 && n < MAX_ITEMS; k = list.links[k].next) {
            bool covered = sum >= amount;
            Pick memory p = _load(k, app);
            uint256 units = _amountOf(p.held, app);
            if (_hasCustomTag(p.held)) {
                if (covered) break;
                blocked += units;
                continue;
            }
            bytes32 ph = _pinHash(p.pins, app.vk);
            if (n != 0 && ph != pinHash) {
                if (covered) break;
                revert MixedVersions();
            }
            if (!_fits(picks, n, p)) {
                if (covered) break;
                continue;
            }
            pinHash = ph;
            picks[n++] = p;
            sum += units;
            if (covered) break;
        }
        if (sum < amount) {
            if (blocked >= amount - sum) revert RequiresProvedSpell();
            revert InsufficientBalance();
        }
        assembly ("memory-safe") {
            mstore(picks, n)
        }
    }

    function _load(bytes32 key, App memory app) private view returns (Pick memory p) {
        Head memory h = head[key];
        p.head = h;
        if (h.kind == Kind.Plain) {
            p.held = new UtxoBody.Held[](1);
            p.held[0] = UtxoBody.Held(app, h.amount, "");
        } else {
            (p.held, p.pins) = UtxoBody.decode(body[key]);
        }
    }

    /// @dev Whether `p` can join `picks` in one native spell with one change output.
    function _fits(Pick[] memory picks, uint256 n, Pick memory p) private pure returns (bool) {
        for (uint256 j; j < p.held.length; ++j) {
            UtxoBody.Held memory h = p.held[j];
            uint256 total = h.amount;
            for (uint256 i; i < n; ++i) {
                UtxoBody.Held[] memory other = picks[i].held;
                for (uint256 k; k < other.length; ++k) {
                    if (!_appEq(other[k].app, h.app)) continue;
                    if (h.app.tag != TAG_T) return false;
                    total += other[k].amount;
                }
            }
            if (total > type(uint64).max) return false;
        }
        for (uint256 j; j < p.pins.length; ++j) {
            for (uint256 i; i < n; ++i) {
                Pin[] memory other = picks[i].pins;
                for (uint256 k; k < other.length; ++k) {
                    if (other[k].vk != p.pins[j].vk) continue;
                    if (
                        other[k].version != p.pins[j].version
                            || other[k].wasmHash != p.pins[j].wasmHash
                    ) return false;
                }
            }
        }
        return true;
    }

    function _hasCustomTag(UtxoBody.Held[] memory held) private pure returns (bool) {
        for (uint256 j; j < held.length; ++j) {
            if (held[j].app.tag != TAG_T && held[j].app.tag != TAG_N) return true;
        }
        return false;
    }

    function _amountOf(UtxoBody.Held[] memory held, App memory app) private pure returns (uint256) {
        for (uint256 j; j < held.length; ++j) {
            if (_appEq(held[j].app, app)) return held[j].amount;
        }
        return 0;
    }

    /// @dev Hash of the pin stored for `vk`, or zero when the UTXO stores none.
    function _pinHash(Pin[] memory pins, bytes32 vk) private pure returns (bytes32) {
        for (uint256 j; j < pins.length; ++j) {
            if (pins[j].vk == vk) return keccak256(abi.encode(pins[j]));
        }
        return 0;
    }

    function _entryOf(Entry[] memory entries, uint256 n, App memory app)
        private
        pure
        returns (uint256 i)
    {
        while (i < n && !_appEq(entries[i].app, app)) ++i;
    }

    function _sortEntries(Entry[] memory entries, uint256 n) private pure {
        for (uint256 i = 1; i < n; ++i) {
            Entry memory e = entries[i];
            uint256 j = i;
            while (j != 0 && _appLess(e.app, entries[j - 1].app)) {
                entries[j] = entries[j - 1];
                --j;
            }
            entries[j] = e;
        }
    }

    function _sortPins(Pin[] memory pins, uint256 n) private pure {
        for (uint256 i = 1; i < n; ++i) {
            Pin memory p = pins[i];
            uint256 j = i;
            while (j != 0 && p.vk < pins[j - 1].vk) {
                pins[j] = pins[j - 1];
                --j;
            }
            pins[j] = p;
        }
    }

    function _vaultApp(address token) private view returns (App memory) {
        return App(TAG_T, CharmsIds.vaultIdentity(block.chainid, address(this), token), VAULT_VK);
    }

    /// @dev ETH is fixed at 18 decimals. An ERC-20 keeps its own unit up to 8 decimals.
    function _scale(address token) private view returns (uint8) {
        if (token == address(0)) return ETH_SCALE;
        (bool known, uint256 d) = _decimals(token);
        return known && d > UNIT_DECIMALS ? uint8(d - UNIT_DECIMALS) : 0;
    }

    function _decimals(address token) private view returns (bool known, uint256 d) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeCall(IERC20Metadata.decimals, ()));
        if (!ok || ret.length < 32) return (false, 0);
        d = abi.decode(ret, (uint256));
        if (d > type(uint8).max) revert InvalidDecimals();
        return (true, d);
    }

    /// @dev The underlying of a registered vault app. Reverts for an unregistered one, whose
    /// underlying cannot be recovered from its identity hash.
    function _vaultUnderlying(App memory app) private view returns (address token) {
        bytes32 key = appKey(app);
        token = vaultTokens[key];
        if (vaults[token].appKey != key) revert MetadataUnspecified();
    }

    function _vaultUnderlyingErc20(App memory app) private view returns (address token) {
        token = _vaultUnderlying(app);
        if (token == address(0)) revert MetadataUnspecified();
    }

    function _apply(Spell memory s, Context memory c) private returns (bytes32) {
        bytes memory ret = Address.functionDelegateCall(
            address(APPLY), abi.encodeCall(CharmsApply.applySpell, (s, c))
        );
        return abi.decode(ret, (bytes32));
    }
}
