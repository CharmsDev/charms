// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Vm} from "forge-std/Vm.sol";

import {CharmToken} from "../../src/CharmToken.sol";
import {Charms} from "../../src/Charms.sol";
import {ICharmsErrors} from "../../src/interfaces/ICharms.sol";
import {UtxoBody} from "../../src/libraries/UtxoBody.sol";
import {CharmsTestBase} from "../utils/CharmsTestBase.sol";
import {MockToken, Wallet1271} from "../utils/Mocks.sol";

/// @dev Three EOAs, then the ERC-1271 wallet, which cannot receive ETH.
uint256 constant ACTORS = 4;
uint256 constant WALLET = 3;
/// @dev Two app tokens, then the ETH vault and the ERC-20 vault.
uint256 constant TOKENS = 4;
uint256 constant FIRST_VAULT = 2;
uint256 constant VAULTS = 2;
uint256 constant OPS = 9;
/// @dev Underlying base units per vault unit. ETH is fixed at scale 10, and an 18-decimal ERC-20
/// gets scale 18 - 8.
uint256 constant UNIT = 1e10;

/// @notice Drives one v16 `Charms` deployment the way wallets, token holders, and a prover do, and
/// keeps a ghost of every output it caused: the ref, the owner, and the charms CHIP-0020 says the
/// contract stores there.
/// @dev Calls into `Charms` do not bubble reverts. Each one is tallied, so a run reports how many
/// calls succeeded.
contract Handler is CharmsTestBase {
    enum Op {
        Wrap,
        Unwrap,
        Transfer,
        TransferFrom,
        Transact,
        Placeholder,
        Mint,
        BeamOut,
        BeamIn
    }

    /// @dev The charms on one output: an amount per token app, 0 when absent, and the data of the
    /// NFT, empty when absent.
    struct Holding {
        uint64[TOKENS] tokens;
        bytes nft;
    }

    /// @dev A beamed output has no owner and is never live.
    struct Utxo {
        UtxoRef ref;
        address owner;
        bool live;
        Holding held;
    }

    /// @dev Units of one token app by the rows of CHIP-0020's Supply table.
    struct Flow {
        uint256 minted;
        uint256 wrapped;
        uint256 unwrapped;
        uint256 beamedIn;
        uint256 beamedOut;
    }

    struct Tally {
        uint256 ok;
        uint256 skipped;
        uint256 reverted;
    }

    /// @dev The NFT app has tag `n`, which sorts before `t`, so it is index 0 whenever present.
    struct Layout {
        App[] apps;
        uint32[TOKENS] index;
    }

    uint256 internal constant COIN_A = 0;
    uint256 internal constant COIN_B = 1;
    uint256 internal constant MAX_MINT = 1e12;
    uint256 internal constant MAX_WRAP = 1e9;

    MockToken public immutable mock;
    address[ACTORS] public actors;
    uint256[ACTORS] internal keys;
    App internal nftApp;
    App[TOKENS] internal tokenApps;
    /// @dev Token app indexes in `App` order, the order a spell lists them in.
    uint256[TOKENS] public order;

    Utxo[] internal ghosts;
    uint256[] internal liveIds;
    mapping(uint256 id => uint256) internal livePos;
    Flow[TOKENS] internal flows;
    uint256[VAULTS] public underlyingIn;
    uint256[VAULTS] public underlyingOut;
    Tally[OPS] internal tallies;
    bytes[OPS] internal lastRevert;
    uint256 internal nfts;
    uint256 internal beams;

    constructor(Charms charms_) {
        charms = charms_;
        MockToken token = new MockToken("Mock", "MOCK", 18);
        mock = token;
        (actors[0], keys[0]) = makeAddrAndKey("alice");
        (actors[1], keys[1]) = makeAddrAndKey("bob");
        (actors[2], keys[2]) = makeAddrAndKey("carol");
        address signer;
        (signer, keys[WALLET]) = makeAddrAndKey("wallet signer");
        actors[WALLET] = address(new Wallet1271(signer));
        for (uint256 a; a < ACTORS; ++a) {
            vm.deal(actors[a], 1e30);
            token.mint(actors[a], 1e30);
            vm.prank(actors[a]);
            token.approve(address(charms_), type(uint256).max);
        }
        nftApp = _app(N, "art");
        tokenApps[COIN_A] = _app(T, "coin a");
        tokenApps[COIN_B] = _app(T, "coin b");
        (tokenApps[FIRST_VAULT],,) = charms_.vaultOf(address(0));
        (tokenApps[FIRST_VAULT + 1],,) = charms_.vaultOf(address(token));
        for (uint256 i; i < TOKENS; ++i) {
            uint256 j = i;
            while (j != 0 && _lt(tokenApps[i], tokenApps[order[j - 1]])) {
                order[j] = order[j - 1];
                --j;
            }
            order[j] = i;
        }
    }

    function wrap(uint256 vaultSeed, uint256 senderSeed, uint256 ownerSeed, uint256 amountSeed)
        external
    {
        uint256 v = vaultSeed % VAULTS;
        address sender = actors[senderSeed % ACTORS];
        address owner = actors[ownerSeed % ACTORS];
        uint64 units = uint64(bound(amountSeed, 1, MAX_WRAP));
        uint256 before = _underlyingBalance(v, sender);
        (bool ok, bytes memory ret) = _call(
            Op.Wrap,
            sender,
            address(charms),
            v == 0 ? units * UNIT : 0,
            abi.encodeCall(charms.wrap, (underlying(v), units, owner, bytes32(++salts)))
        );
        if (!ok) return;
        _create(abi.decode(ret, (bytes32)), 0, owner, _only(FIRST_VAULT + v, units));
        flows[FIRST_VAULT + v].wrapped += units;
        underlyingIn[v] += before - _underlyingBalance(v, sender);
        _ok(Op.Wrap);
    }

    function unwrap(uint256 vaultSeed, uint256 holderSeed, uint256 toSeed, uint256 amountSeed)
        external
    {
        uint256 v = vaultSeed % VAULTS;
        uint256 t = FIRST_VAULT + v;
        uint256[TOKENS][ACTORS] memory most = _selectable();
        (bool found, uint256 a) = _holderOf(most, t, holderSeed);
        if (!found) {
            _skip(Op.Unwrap);
            return;
        }
        address from = actors[a];
        address to = actors[toSeed % WALLET];
        uint64 amount = uint64(bound(amountSeed, 1, most[a][t]));
        uint256[] memory candidates = _liveHolding(from, t);
        uint256 before = _underlyingBalance(v, to);
        (bool ok, bytes memory ret) = _call(
            Op.Unwrap,
            from,
            address(charms),
            0,
            abi.encodeCall(charms.unwrap, (underlying(v), amount, to))
        );
        if (!ok) return;
        _settle(candidates, t, amount, from, address(0), abi.decode(ret, (bytes32)));
        flows[t].unwrapped += amount;
        underlyingOut[v] += _underlyingBalance(v, to) - before;
        _ok(Op.Unwrap);
    }

    function transfer(uint256 holderSeed, uint256 toSeed, uint256 amountSeed) external {
        _transfer(Op.Transfer, holderSeed, 0, toSeed, amountSeed);
    }

    function transferFrom(
        uint256 holderSeed,
        uint256 spenderSeed,
        uint256 toSeed,
        uint256 amountSeed
    ) external {
        _transfer(Op.TransferFrom, holderSeed, spenderSeed, toSeed, amountSeed);
    }

    function transact(uint256 inputSeed, uint256 senderSeed, uint256 shapeSeed, uint256 splitSeed)
        external
    {
        uint256 live = liveIds.length;
        if (live == 0) {
            _skip(Op.Transact);
            return;
        }
        uint256[] memory ins = new uint256[](live > 1 && shapeSeed % 2 == 1 ? 2 : 1);
        uint256 first = inputSeed % live;
        ins[0] = liveIds[first];
        if (ins.length == 2) {
            ins[1] = liveIds[(first + 1 + (inputSeed >> 128) % (live - 1)) % live];
        }

        Holding memory pool;
        bytes[2] memory found;
        uint256 nftCount;
        for (uint256 i; i < ins.length; ++i) {
            Holding memory held = ghosts[ins[i]].held;
            for (uint256 t; t < TOKENS; ++t) {
                pool.tokens[t] += held.tokens[t];
            }
            if (held.nft.length != 0) found[nftCount++] = held.nft;
        }

        Holding[] memory outs = new Holding[](nftCount == 2 ? 2 : 1 + (shapeSeed >> 1) % 2);
        address[] memory owners = new address[](outs.length);
        for (uint256 j; j < outs.length; ++j) {
            owners[j] = actors[(shapeSeed >> (8 * (j + 1))) % ACTORS];
        }
        for (uint256 t; t < TOKENS; ++t) {
            uint64 total = pool.tokens[t];
            uint64 x = outs.length == 1
                ? total
                : uint64(bound(uint256(keccak256(abi.encode(splitSeed, t))), 0, total));
            outs[0].tokens[t] = x;
            if (outs.length == 2) outs[1].tokens[t] = total - x;
        }
        if (nftCount == 1) outs[(shapeSeed >> 2) % outs.length].nft = found[0];
        if (nftCount == 2) (outs[0].nft, outs[1].nft) = (found[0], found[1]);

        if (_submit(Op.Transact, actors[senderSeed % ACTORS], ins, outs, owners, "")) {
            _ok(Op.Transact);
        }
    }

    function placeholder(uint256 senderSeed, uint256 ownerSeed) external {
        address owner = actors[ownerSeed % ACTORS];
        if (_submit(
                Op.Placeholder,
                actors[senderSeed % ACTORS],
                new uint256[](0),
                new Holding[](1),
                _list(owner),
                ""
            )) _ok(Op.Placeholder);
    }

    function mint(uint256 ownerSeed, uint256 recipientSeed, uint256 shapeSeed, uint256 amountSeed)
        external
    {
        address owner = actors[ownerSeed % ACTORS];
        Holding[] memory outs = new Holding[](1);
        uint256 shape = 1 + shapeSeed % 7;
        if (shape & 1 != 0) outs[0].nft = abi.encodePacked(hex"44", uint32(++nfts));
        if (shape & 2 != 0) outs[0].tokens[COIN_A] = uint64(bound(amountSeed, 1, MAX_MINT));
        if (shape & 4 != 0) outs[0].tokens[COIN_B] = uint64(bound(amountSeed >> 128, 1, MAX_MINT));
        (bool ok, uint256 placeholderId) = _placeholderOf(Op.Mint, owner);
        if (!ok) return;
        address recipient = actors[recipientSeed % ACTORS];
        if (!_submit(Op.Mint, owner, _list(placeholderId), outs, _list(recipient), PROOF)) return;
        flows[COIN_A].minted += outs[0].tokens[COIN_A];
        flows[COIN_B].minted += outs[0].tokens[COIN_B];
        _ok(Op.Mint);
    }

    function beamOut(uint256 inputSeed, uint256 senderSeed, uint256 amountSeed, uint256 shapeSeed)
        external
    {
        (bool found, uint256 id) = _liveWithTokens(inputSeed);
        if (!found) {
            _skip(Op.BeamOut);
            return;
        }
        Holding memory change = ghosts[id].held;
        uint256 t = _someToken(change, shapeSeed);
        uint64 x = uint64(bound(amountSeed, 1, change.tokens[t]));
        change.tokens[t] -= x;
        bool kept = _kindOf(change) != 0;
        Holding[] memory outs = new Holding[](kept ? 2 : 1);
        address[] memory owners = new address[](outs.length);
        uint256 beamed = kept ? (shapeSeed >> 8) % 2 : 0;
        outs[beamed] = _only(t, x);
        if (kept) (outs[1 - beamed], owners[1 - beamed]) = (change, ghosts[id].owner);
        if (!_submit(Op.BeamOut, actors[senderSeed % ACTORS], _list(id), outs, owners, "")) return;
        flows[t].beamedOut += x;
        _ok(Op.BeamOut);
    }

    /// @dev Claims no more vault units than have beamed out, so the vault cap holds.
    function beamIn(uint256 vaultSeed, uint256 ownerSeed, uint256 amountSeed) external {
        uint256 t = FIRST_VAULT + vaultSeed % VAULTS;
        uint256 abroad = flows[t].beamedOut - flows[t].beamedIn;
        if (abroad == 0) {
            _skip(Op.BeamIn);
            return;
        }
        address owner = actors[ownerSeed % ACTORS];
        Holding[] memory outs = new Holding[](1);
        outs[0] = _only(t, uint64(bound(amountSeed, 1, abroad)));
        (bool ok, uint256 placeholderId) = _placeholderOf(Op.BeamIn, owner);
        if (!ok || !_submit(Op.BeamIn, owner, _list(placeholderId), outs, _list(owner), PROOF)) {
            return;
        }
        flows[t].beamedIn += outs[0].tokens[t];
        _ok(Op.BeamIn);
    }

    function ghostCount() external view returns (uint256) {
        return ghosts.length;
    }

    function ghost(uint256 id) external view returns (Utxo memory) {
        return ghosts[id];
    }

    function kindOf(uint256 id) external view returns (uint8) {
        return _kindOf(ghosts[id].held);
    }

    /// @notice The ghost's charms on `id`, in the order its spell listed them.
    function heldOf(uint256 id) external view returns (UtxoBody.Held[] memory held) {
        Holding memory h = ghosts[id].held;
        held = new UtxoBody.Held[](_charmCount(h));
        uint256 n;
        if (h.nft.length != 0) held[n++] = UtxoBody.Held(nftApp, 0, h.nft);
        for (uint256 k; k < TOKENS; ++k) {
            uint256 t = order[k];
            if (h.tokens[t] != 0) held[n++] = UtxoBody.Held(tokenApps[t], h.tokens[t], "");
        }
    }

    function balances() external view returns (uint256[TOKENS][ACTORS] memory bal) {
        for (uint256 i; i < liveIds.length; ++i) {
            Utxo storage u = ghosts[liveIds[i]];
            uint256 a = _actorIndex(u.owner);
            for (uint256 t; t < TOKENS; ++t) {
                bal[a][t] += u.held.tokens[t];
            }
        }
    }

    function emptyCounts() external view returns (uint256[ACTORS] memory n) {
        for (uint256 i; i < liveIds.length; ++i) {
            Utxo storage u = ghosts[liveIds[i]];
            if (_kindOf(u.held) == 0) ++n[_actorIndex(u.owner)];
        }
    }

    /// @notice Ethereum-resident supply of token `t` by the Supply table.
    function supplyOf(uint256 t) external view returns (uint256) {
        Flow storage f = flows[t];
        return f.minted + f.wrapped + f.beamedIn - f.unwrapped - f.beamedOut;
    }

    function flow(uint256 t) external view returns (Flow memory) {
        return flows[t];
    }

    function tokenApp(uint256 t) external view returns (App memory) {
        return tokenApps[t];
    }

    function underlying(uint256 v) public view returns (address) {
        return v == 0 ? address(0) : address(mock);
    }

    function tally(uint256 op) external view returns (Tally memory) {
        return tallies[op];
    }

    function lastRevertOf(uint256 op) external view returns (bytes memory) {
        return lastRevert[op];
    }

    function _transfer(
        Op op,
        uint256 holderSeed,
        uint256 spenderSeed,
        uint256 toSeed,
        uint256 amountSeed
    ) internal {
        uint256[TOKENS][ACTORS] memory most = _selectable();
        (bool found, uint256 a, uint256 t) = _pick(most, holderSeed);
        if (!found) {
            _skip(op);
            return;
        }
        address from = actors[a];
        address to = actors[toSeed % ACTORS];
        uint64 amount = uint64(bound(amountSeed, 1, most[a][t]));
        address token = charms.ensureToken(tokenApps[t]);
        address caller = from;
        bytes memory data = abi.encodeCall(CharmToken.transfer, (to, amount));
        if (op == Op.TransferFrom) {
            caller = actors[spenderSeed % ACTORS];
            vm.prank(from);
            CharmToken(token).approve(caller, amount);
            data = abi.encodeCall(CharmToken.transferFrom, (from, to, amount));
        }
        uint256[] memory candidates = _liveHolding(from, t);
        vm.recordLogs();
        (bool ok,) = _call(op, caller, token, 0, data);
        bytes32 txId = _loggedTxId();
        if (!ok) return;
        _settle(candidates, t, amount, from, to, txId);
        _ok(op);
    }

    /// @dev `transfer` and `unwrap` choose their inputs inside `Charms`. The ghost reads which of
    /// `from`'s UTXOs holding token `t` are gone and expects the outputs CHIP-0020 prescribes:
    /// `amount` of `t` to `to` at index 0 (none when `to` is zero), then one change output for
    /// `from` with everything else those inputs held.
    function _settle(
        uint256[] memory candidates,
        uint256 t,
        uint64 amount,
        address from,
        address to,
        bytes32 txId
    ) internal {
        Holding memory rest;
        for (uint256 i; i < candidates.length; ++i) {
            Utxo storage u = ghosts[candidates[i]];
            (, address owner,,) = charms.utxo(u.ref);
            if (owner != address(0)) continue;
            Holding memory held = u.held;
            for (uint256 k; k < TOKENS; ++k) {
                rest.tokens[k] += held.tokens[k];
            }
            if (held.nft.length != 0) rest.nft = held.nft;
            _spend(candidates[i]);
        }
        rest.tokens[t] = rest.tokens[t] > amount ? rest.tokens[t] - amount : 0;
        uint32 index;
        if (to != address(0)) _create(txId, index++, to, _only(t, amount));
        if (_kindOf(rest) != 0) _create(txId, index, from, rest);
    }

    /// @dev A zero owner beams that output out.
    function _submit(
        Op op,
        address sender,
        uint256[] memory ins,
        Holding[] memory outs,
        address[] memory owners,
        bytes memory proof
    ) internal returns (bool ok) {
        Holding[] memory spent = new Holding[](ins.length);
        for (uint256 i; i < ins.length; ++i) {
            spent[i] = ghosts[ins[i]].held;
        }
        Layout memory l = _layout(spent, outs);
        Spell memory s = _spell(l.apps, ins.length, outs.length);
        address[] memory signers = new address[](ins.length);
        uint256 nSigners;
        for (uint256 i; i < ins.length; ++i) {
            Utxo storage u = ghosts[ins[i]];
            s.ins[i] = Input(u.ref, _charmsOf(spent[i], l), new Pin[](0));
            address o = u.owner;
            if (o != sender && !_contains(signers, nSigners, o)) signers[nSigners++] = o;
        }
        uint256 nBeamed;
        for (uint256 j; j < outs.length; ++j) {
            s.outs[j] = Output(owners[j], _charmsOf(outs[j], l));
            if (owners[j] == address(0)) ++nBeamed;
        }
        s.beamedOuts = new BeamedOut[](nBeamed);
        nBeamed = 0;
        for (uint256 j; j < outs.length; ++j) {
            if (owners[j] != address(0)) continue;
            s.beamedOuts[nBeamed++] = BeamedOut(uint32(j), keccak256(abi.encode("beam", ++beams)));
        }
        bytes32 salt = ins.length == 0 ? bytes32(++salts) : bytes32(0);
        bytes32 txId = _txId(s, sender, salt);
        bytes[] memory sigs = new bytes[](nSigners);
        for (uint256 k; k < nSigners; ++k) {
            sigs[k] = _sign(keys[_actorIndex(signers[k])], txId);
        }
        (ok,) = _call(
            op, sender, address(charms), 0, abi.encodeCall(charms.transact, (s, salt, proof, sigs))
        );
        if (!ok) return false;
        for (uint256 i; i < ins.length; ++i) {
            _spend(ins[i]);
        }
        for (uint256 j; j < outs.length; ++j) {
            _create(txId, uint32(j), owners[j], outs[j]);
        }
    }

    function _call(Op op, address sender, address target, uint256 value, bytes memory data)
        internal
        returns (bool ok, bytes memory ret)
    {
        vm.prank(sender);
        (ok, ret) = target.call{value: value}(data);
        if (!ok) {
            ++tallies[uint256(op)].reverted;
            lastRevert[uint256(op)] = ret;
        }
    }

    function _create(bytes32 txId, uint32 index, address owner, Holding memory held) internal {
        uint256 id = ghosts.length;
        Utxo storage u = ghosts.push();
        u.ref = UtxoRef(txId, index);
        u.owner = owner;
        u.held = held;
        if (owner == address(0)) return;
        u.live = true;
        livePos[id] = liveIds.length;
        liveIds.push(id);
    }

    function _spend(uint256 id) internal {
        ghosts[id].live = false;
        uint256 last = liveIds[liveIds.length - 1];
        uint256 pos = livePos[id];
        liveIds[pos] = last;
        livePos[last] = pos;
        liveIds.pop();
    }

    function _placeholderOf(Op op, address owner) internal returns (bool ok, uint256 id) {
        for (uint256 i; i < liveIds.length; ++i) {
            Utxo storage u = ghosts[liveIds[i]];
            if (u.owner == owner && _kindOf(u.held) == 0) return (true, liveIds[i]);
        }
        id = ghosts.length;
        ok = _submit(op, owner, new uint256[](0), new Holding[](1), _list(owner), "");
    }

    /// @dev For each actor and token, an amount `transfer` and `unwrap` can always select: the
    /// token on the actor's UTXOs without the NFT, plus the smallest amount on one with it. The
    /// one change output holds one NFT of an app, so a selection takes at most one UTXO with it.
    function _selectable() internal view returns (uint256[TOKENS][ACTORS] memory most) {
        uint256[TOKENS][ACTORS] memory least;
        for (uint256 i; i < liveIds.length; ++i) {
            Utxo storage u = ghosts[liveIds[i]];
            uint256 a = _actorIndex(u.owner);
            bool withNft = u.held.nft.length != 0;
            for (uint256 t; t < TOKENS; ++t) {
                uint256 x = u.held.tokens[t];
                if (x == 0) continue;
                if (!withNft) most[a][t] += x;
                else if (least[a][t] == 0 || x < least[a][t]) least[a][t] = x;
            }
        }
        for (uint256 a; a < ACTORS; ++a) {
            for (uint256 t; t < TOKENS; ++t) {
                most[a][t] += least[a][t];
            }
        }
    }

    function _pick(uint256[TOKENS][ACTORS] memory most, uint256 seed)
        internal
        pure
        returns (bool found, uint256 a, uint256 t)
    {
        uint256 start = seed % (ACTORS * TOKENS);
        for (uint256 k; k < ACTORS * TOKENS; ++k) {
            uint256 c = (start + k) % (ACTORS * TOKENS);
            (a, t) = (c / TOKENS, c % TOKENS);
            if (most[a][t] != 0) return (true, a, t);
        }
    }

    function _holderOf(uint256[TOKENS][ACTORS] memory most, uint256 t, uint256 seed)
        internal
        pure
        returns (bool found, uint256 a)
    {
        for (uint256 k; k < ACTORS; ++k) {
            a = (seed % ACTORS + k) % ACTORS;
            if (most[a][t] != 0) return (true, a);
        }
    }

    function _liveHolding(address owner, uint256 t) internal view returns (uint256[] memory ids) {
        ids = new uint256[](liveIds.length);
        uint256 n;
        for (uint256 i; i < liveIds.length; ++i) {
            Utxo storage u = ghosts[liveIds[i]];
            if (u.owner == owner && u.held.tokens[t] != 0) ids[n++] = liveIds[i];
        }
        assembly ("memory-safe") {
            mstore(ids, n)
        }
    }

    function _liveWithTokens(uint256 seed) internal view returns (bool, uint256) {
        uint256 live = liveIds.length;
        for (uint256 k; k < live; ++k) {
            uint256 id = liveIds[(seed % live + k) % live];
            uint64[TOKENS] storage amounts = ghosts[id].held.tokens;
            for (uint256 t; t < TOKENS; ++t) {
                if (amounts[t] != 0) return (true, id);
            }
        }
        return (false, 0);
    }

    function _someToken(Holding memory h, uint256 seed) internal pure returns (uint256 t) {
        uint256 present;
        for (t = 0; t < TOKENS; ++t) {
            if (h.tokens[t] != 0) ++present;
        }
        uint256 skip = seed % present;
        for (t = 0; t < TOKENS; ++t) {
            if (h.tokens[t] == 0) continue;
            if (skip == 0) return t;
            --skip;
        }
    }

    function _layout(Holding[] memory a, Holding[] memory b)
        internal
        view
        returns (Layout memory l)
    {
        bool withNft;
        bool[TOKENS] memory has;
        for (uint256 i; i < a.length + b.length; ++i) {
            Holding memory h = i < a.length ? a[i] : b[i - a.length];
            withNft = withNft || h.nft.length != 0;
            for (uint256 t; t < TOKENS; ++t) {
                has[t] = has[t] || h.tokens[t] != 0;
            }
        }
        uint256 n = withNft ? 1 : 0;
        for (uint256 t; t < TOKENS; ++t) {
            if (has[t]) ++n;
        }
        l.apps = new App[](n);
        n = 0;
        if (withNft) l.apps[n++] = nftApp;
        for (uint256 k; k < TOKENS; ++k) {
            uint256 t = order[k];
            if (!has[t]) continue;
            l.index[t] = uint32(n);
            l.apps[n++] = tokenApps[t];
        }
    }

    function _charmsOf(Holding memory h, Layout memory l) internal view returns (Charm[] memory c) {
        c = new Charm[](_charmCount(h));
        uint256 n;
        if (h.nft.length != 0) c[n++] = _nft(0, h.nft);
        for (uint256 k; k < TOKENS; ++k) {
            uint256 t = order[k];
            if (h.tokens[t] != 0) c[n++] = _token(l.index[t], h.tokens[t]);
        }
    }

    /// @dev CHIP-0020's kind table: no charms is Empty (0), one tag-`t` charm with no pin is
    /// Plain (1), anything else is Bundle (2).
    function _kindOf(Holding memory h) internal pure returns (uint8) {
        uint256 n = _charmCount(h);
        if (n == 0) return 0;
        return n == 1 && h.nft.length == 0 ? 1 : 2;
    }

    function _charmCount(Holding memory h) internal pure returns (uint256 n) {
        if (h.nft.length != 0) ++n;
        for (uint256 t; t < TOKENS; ++t) {
            if (h.tokens[t] != 0) ++n;
        }
    }

    function _only(uint256 t, uint64 amount) internal pure returns (Holding memory h) {
        h.tokens[t] = amount;
    }

    function _list(uint256 id) internal pure returns (uint256[] memory ids) {
        ids = new uint256[](1);
        ids[0] = id;
    }

    function _list(address owner) internal pure returns (address[] memory owners) {
        owners = new address[](1);
        owners[0] = owner;
    }

    function _contains(address[] memory list, uint256 n, address x) internal pure returns (bool) {
        for (uint256 i; i < n; ++i) {
            if (list[i] == x) return true;
        }
        return false;
    }

    function _actorIndex(address owner) internal view returns (uint256 a) {
        while (actors[a] != owner) ++a;
    }

    function _underlyingBalance(uint256 v, address who) internal view returns (uint256) {
        return v == 0 ? who.balance : mock.balanceOf(who);
    }

    function _loggedTxId() internal view returns (bytes32 txId) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == address(charms)
                    && logs[i].topics[0] == ICharmsErrors.Transaction.selector
            ) txId = logs[i].topics[1];
        }
    }

    function _ok(Op op) internal {
        ++tallies[uint256(op)].ok;
    }

    function _skip(Op op) internal {
        ++tallies[uint256(op)].skipped;
    }
}
