// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {console} from "forge-std/console.sol";

import {CharmToken} from "../src/CharmToken.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";
import {UtxoBody} from "../src/libraries/UtxoBody.sol";
import {CharmsHarness} from "./invariant/CharmsHarness.sol";
import {ACTORS, FIRST_VAULT, Handler, OPS, TOKENS, UNIT, VAULTS} from "./invariant/Handler.sol";
import {CharmsTestBase} from "./utils/CharmsTestBase.sol";
import {MockVerifier} from "./utils/Mocks.sol";

/// @notice CHIP-0020's phase-1 invariants for the supply, balance, and locked tables.
contract InvariantsTest is CharmsTestBase {
    CharmsHarness internal harness;
    Handler internal handler;

    function setUp() public override {
        verifier = new MockVerifier();
        CharmsHarness impl = new CharmsHarness(new CharmsApply(16, PROGRAM_VKEY, verifier));
        CharmsProxy proxy =
            new CharmsProxy(address(impl), abi.encodeCall(Charms.initialize, (admin)));
        charms = Charms(payable(address(proxy)));
        harness = CharmsHarness(payable(address(proxy)));
        handler = new Handler(charms);

        bytes4[] memory ops = new bytes4[](OPS);
        ops[0] = Handler.wrap.selector;
        ops[1] = Handler.unwrap.selector;
        ops[2] = Handler.transfer.selector;
        ops[3] = Handler.transferFrom.selector;
        ops[4] = Handler.transact.selector;
        ops[5] = Handler.placeholder.selector;
        ops[6] = Handler.mint.selector;
        ops[7] = Handler.beamOut.selector;
        ops[8] = Handler.beamIn.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector(address(handler), ops));
    }

    function invariant_balanceOfIsTheSumOverLiveUtxos() public view {
        uint256[TOKENS][ACTORS] memory ghost = handler.balances();
        for (uint256 a; a < ACTORS; ++a) {
            address owner = handler.actors(a);
            for (uint256 t; t < TOKENS; ++t) {
                bytes32 key = _key(handler.tokenApp(t));
                uint256 cached = charms.balanceOf(key, owner);
                assertEq(cached, harness.utxoBalance(key, owner), "balanceOf is the UTXO records");
                assertEq(cached, ghost[a][t], "balanceOf is the handler's live UTXOs");
            }
        }
    }

    function invariant_totalSupplyIsTheSumOfBalances() public view {
        for (uint256 t; t < TOKENS; ++t) {
            App memory app = handler.tokenApp(t);
            bytes32 key = _key(app);
            uint256 sum;
            for (uint256 a; a < ACTORS; ++a) {
                sum += charms.balanceOf(key, handler.actors(a));
            }
            uint256 supply = charms.totalSupply(key);
            assertEq(supply, sum, "every resident unit is on an actor's UTXO");
            assertEq(supply, handler.supplyOf(t), "supply moved by the Supply table");
            if (app.vk == VAULT_VK) continue;
            address token = charms.tokenAddress(app);
            if (token.code.length != 0) {
                assertEq(CharmToken(token).totalSupply(), supply, "the clone reports the supply");
            }
        }
    }

    function invariant_vaultLockedMatchesWrapsAndCoversSupply() public view {
        for (uint256 v; v < VAULTS; ++v) {
            address token = handler.underlying(v);
            (App memory app, uint8 scale) = charms.vaultOf(token);
            uint256 locked = _locked(token);
            Handler.Flow memory f = handler.flow(FIRST_VAULT + v);
            assertEq(scale, 10, "both vaults have scale 10");
            assertEq(
                locked, UNIT * (f.wrapped - f.unwrapped), "locked is 10^scale (wrapped - unwrapped)"
            );
            assertEq(
                locked,
                handler.underlyingIn(v) - handler.underlyingOut(v),
                "locked is the underlying paid in minus paid out"
            );
            uint256 held = token == address(0)
                ? address(charms).balance
                : IERC20(token).balanceOf(address(charms));
            assertGe(held, locked, "the contract holds at least locked");
            assertLe(
                charms.totalSupply(_key(app)) * UNIT, locked, "supply 10^scale is at most locked"
            );
        }
    }

    function invariant_utxoRecordsMatchTheGhost() public view {
        uint256 n = handler.ghostCount();
        for (uint256 id; id < n; ++id) {
            Handler.Utxo memory g = handler.ghost(id);
            (uint8 kind, address owner, uint64 amount, bytes memory body) = charms.utxo(g.ref);
            if (!g.live) {
                assertEq(owner, address(0), "a spent or beamed output has no owner");
                assertEq(kind, 0, "a spent or beamed output reads as Empty");
                continue;
            }
            assertEq(owner, g.owner, "owner");
            assertEq(kind, handler.kindOf(id), "kind");
            if (kind != 2) assertEq(body.length, 0, "Empty and unpinned Plain have no body");
            if (kind == 1) {
                UtxoBody.Held[] memory only = handler.heldOf(id);
                assertEq(amount, only[0].amount, "a Plain UTXO stores its amount in head");
            }
            if (kind == 2) {
                (UtxoBody.Held[] memory held, Pin[] memory pins) = UtxoBody.decode(body);
                assertEq(abi.encode(held), abi.encode(handler.heldOf(id)), "bundle charms");
                assertEq(pins.length, 0, "no pins");
            }
        }
    }

    function invariant_emptyUtxosListTheLivePlaceholders() public view {
        uint256[ACTORS] memory ghost = handler.emptyCounts();
        for (uint256 a; a < ACTORS; ++a) {
            assertEq(harness.emptyUtxoCount(handler.actors(a)), ghost[a], "live placeholders");
        }
    }

    function afterInvariant() public view {
        string[OPS] memory names = [
            string("wrap"),
            "unwrap",
            "transfer",
            "transferFrom",
            "transact",
            "placeholder",
            "mint",
            "beamOut",
            "beamIn"
        ];
        uint256 ok;
        uint256 reverted;
        for (uint256 op; op < OPS; ++op) {
            Handler.Tally memory t = handler.tally(op);
            console.log(names[op], t.ok, t.skipped, t.reverted);
            if (t.reverted != 0) console.logBytes(handler.lastRevertOf(op));
            ok += t.ok;
            reverted += t.reverted;
        }
        console.log("succeeded", ok);
        assertEq(reverted, 0, "a call the CHIP accepts reverted");
    }
}

/// @notice A random run of facade transfers between two holders, over plain UTXOs and a bundle
/// that also carries an NFT.
contract FacadeTransferFuzzTest is CharmsTestBase {
    function test_facadeTransfersBetweenTwoHoldersKeepTheirSumAndTheSupply(uint256[10] memory steps)
        public
    {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        App memory coin = _app(T, "coin");
        App memory art = _app(N, "art");
        _mintOne(alice, _apps(coin), _charms(_token(0, 600)));
        _mintOne(alice, _apps(art, coin), _charms(_nft(0, hex"4401020304"), _token(1, 250)));
        _mintOne(bob, _apps(coin), _charms(_token(0, 150)));
        CharmToken token = CharmToken(charms.ensureToken(coin));

        address[2] memory holders = [alice, bob];
        uint256[2] memory expected = [uint256(850), 150];
        for (uint256 i; i < steps.length; ++i) {
            uint256 from = steps[i] % 2;
            if (expected[from] == 0) from = 1 - from;
            uint256 amount = bound(steps[i] >> 1, 1, expected[from]);
            vm.prank(holders[from]);
            token.transfer(holders[1 - from], amount);
            expected[from] -= amount;
            expected[1 - from] += amount;

            assertEq(token.balanceOf(alice), expected[0], "alice");
            assertEq(token.balanceOf(bob), expected[1], "bob");
            assertEq(token.balanceOf(alice) + token.balanceOf(bob), 1000, "the sum is conserved");
            assertEq(token.totalSupply(), 1000, "supply is conserved");
        }
    }
}
