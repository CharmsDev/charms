// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {Charms} from "../src/Charms.sol";
import {ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {appKey} from "../src/libraries/CharmTokenClone.sol";
import {Deploy} from "./Deploy.s.sol";

/// @notice Fresh-anvil demo: deploy phase-1 Charms, wrap 1 ETH, send the charm, unwrap it.
/// @dev Charms is the contract that locks ETH and records who owns the claim. This script uses
/// native ETH only. Phase-1 sets the proof verifier to address(0). Wrap, a plain `transact`
/// transfer, and unwrap need no proof. The ETH vault does not create an ERC-20; `tokenAddress`
/// and `ensureToken` return address(0).
///
/// Steps:
/// 1. Etch the keyless CREATE2 factory (same bytecode as `Deploy.t.sol`). Anvil often already
///    has it; the script writes it anyway so deploy still works when it is missing.
///    `vm.etch` updates this simulation; `anvil_setCode` writes that bytecode on the node.
/// 2. Deploy Charms through that factory, same CREATE2 path as `Deploy.s.sol` / `Deploy.t.sol`.
/// 3. Wrap 1 ETH. Account #0 sends 1 ETH and gets one vault UTXO: the unspent record of that
///    deposit. Its id is (tx id, index 0). That tx id is Charms' id, not the Ethereum tx hash.
/// 4. `transact` spends that UTXO and creates a new one owned by account #1. No ETH moves.
///    The spell's input and output amounts match, so Charms checks it itself and the proof is
///    empty. Account #0 is the input owner, so no extra signature is required.
/// 5. Account #1 unwraps. Charms sends the 1 ETH to account #1 and that UTXO is spent.
///
/// The ETH vault's scale is 10: 1 vault unit = 10^10 wei, so 1 ETH = 10^8 units.
/// Logged ETH balances are from this simulation, which does not charge gas. Charms' balance
/// is exact here and on anvil: 0, then 1 ETH through the send, then 0. A later `cast balance`
/// of either account is lower by the gas that anvil charged.
///
/// Restart anvil before each run. The wrap salt is fixed, so a second run reverts.
/// Run the forge command from `ethereum/`. `--private-key` is anvil account #0
/// (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266). The script signs the unwrap with account #1
/// (0x70997970C51812dc3A010C7d01b50e0d17dc79C8).
///
///   anvil
///
///   forge script script/Demo.s.sol \
///     --rpc-url http://127.0.0.1:8545 \
///     --broadcast \
///     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
contract Demo is Script {
    /// @dev Arachnid deterministic-deployment proxy. Same address and runtime as `Deploy.t.sol`.
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes internal constant FACTORY_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    /// @dev Anvil account #0. `--private-key` above must be this key. Deploy, wrap, and the
    /// send all sign with it.
    uint256 internal constant ANVIL_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address internal constant HOLDER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    /// @dev Anvil account #1. Receives the vault charm and unwraps it.
    uint256 internal constant RECIPIENT_KEY =
        0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    address internal constant RECIPIENT = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    /// @dev Names this deposit. Any unused value works; this one is fixed for the demo.
    bytes32 internal constant WRAP_SALT = bytes32(uint256(1));

    /// @dev One CBOR null item. A native transfer carries no app input.
    bytes internal constant CBOR_NULL = hex"f6";

    function run() external {
        require(vm.addr(ANVIL_KEY) == HOLDER, "anvil key is not account #0");
        require(vm.addr(RECIPIENT_KEY) == RECIPIENT, "anvil key is not account #1");
        uint256 weiPerUnit = 10 ** 10;
        uint64 units = uint64(1 ether / weiPerUnit);

        console2.log("chain id (anvil is 31337)", block.chainid);
        console2.log("holder (anvil account #0)", HOLDER);
        console2.log("recipient (anvil account #1)", RECIPIENT);

        console2.log("=== 1. etch CREATE2 factory ===");
        console2.log("write Deploy's factory bytecode; this anvil may already include it");
        console2.log("factory", FACTORY);
        console2.log("factory code bytes before", FACTORY.code.length);
        // `vm.etch` changes this simulation only. `anvil_setCode` writes the same bytecode
        // to the node so the broadcast transactions can call the factory.
        vm.etch(FACTORY, FACTORY_CODE);
        vm.rpcJson(
            "anvil_setCode",
            string.concat("[\"", vm.toString(FACTORY), "\",\"", vm.toString(FACTORY_CODE), "\"]")
        );
        console2.log("factory code bytes after", FACTORY.code.length);
        require(FACTORY.code.length == FACTORY_CODE.length, "factory was not etched");

        console2.log("=== 2. deploy Charms ===");
        console2.log("Charms locks ETH. Phase-1 verifier is address(0), so no proof is required");
        console2.log("call Deploy.run(factory, admin)");
        console2.log("  factory", FACTORY);
        console2.log("  admin", HOLDER);
        Deploy deployScript = new Deploy();
        Charms charms = deployScript.run(FACTORY, HOLDER);
        console2.log("Charms (the proxy you call)", address(charms));
        console2.log("admin", charms.admin());
        console2.log("spell version", uint256(charms.SPELL_VERSION()));
        console2.log("verifier", address(charms.APPLY().VERIFIER()));
        require(charms.admin() == HOLDER, "admin was not set");
        require(charms.SPELL_VERSION() == 15, "not the phase-1 spell version");
        require(address(charms.APPLY().VERIFIER()) == address(0), "verifier is not address(0)");

        console2.log("call Charms.vaultOf(address(0))");
        (ICharmsTypes.App memory vault, uint8 scale) = charms.vaultOf(address(0));
        // Id of this ETH vault in the balance mapping. Not a token address.
        bytes32 vaultKey = appKey(vault);
        console2.log("ETH vault scale (1 unit = 10^scale wei)", uint256(scale));
        require(scale == 10, "unexpected ETH vault scale");
        require(uint256(units) * weiPerUnit == 1 ether, "wrap amount is not 1 ETH");

        console2.log("=== 3. wrap 1 ETH ===");
        console2.log("wrap sends ETH in and records one UTXO (the unspent deposit)");
        console2.log("ETH balances below are whole ETH; this simulation does not charge gas");
        console2.log("holder balance before wrap (ETH)", HOLDER.balance / 1 ether);
        console2.log("recipient balance before wrap (ETH)", RECIPIENT.balance / 1 ether);
        console2.log("Charms balance before wrap (ETH)", address(charms).balance / 1 ether);
        console2.log("holder vault units before wrap", charms.balanceOf(vaultKey, HOLDER));
        console2.log("wei per vault unit", weiPerUnit);
        console2.log("wrap amount (vault units)", uint256(units));
        console2.log("ETH sent (wei)", uint256(1 ether));
        console2.log("call Charms.wrap{value: 1 ether}(address(0), units, holder, salt)");
        console2.log("  token", address(0));
        console2.log("  amount (vault units)", uint256(units));
        console2.log("  owner", HOLDER);
        console2.log("  salt", vm.toString(WRAP_SALT));
        console2.log("  msg.value (wei)", uint256(1 ether));

        vm.startBroadcast(ANVIL_KEY);
        bytes32 wrapTxId = charms.wrap{value: 1 ether}(address(0), units, HOLDER, WRAP_SALT);
        vm.stopBroadcast();

        console2.log("UTXO id = (tx id, index). tx id is Charms' id, not the Ethereum hash");
        console2.log("wrap returned UTXO tx id", vm.toString(wrapTxId));
        (ICharmsTypes.UtxoRef[] memory utxos,) = charms.utxosOf(vaultKey, HOLDER, 0, 10);
        require(utxos.length == 1, "wrap did not create one UTXO");
        console2.log("stored vault UTXO tx id", vm.toString(utxos[0].txId));
        console2.log("stored vault UTXO index", uint256(utxos[0].index));
        (address utxoOwner,) = charms.utxo(utxos[0]);
        console2.log("vault UTXO owner", utxoOwner);
        console2.log("holder balance after wrap (ETH)", HOLDER.balance / 1 ether);
        console2.log("Charms balance after wrap (ETH)", address(charms).balance / 1 ether);
        console2.log("Charms balance after wrap (wei)", address(charms).balance);
        console2.log("holder vault units after wrap", charms.balanceOf(vaultKey, HOLDER));
        console2.log("call Charms.tokenAddress(eth vault app)");
        address tokenFace = charms.tokenAddress(vault);
        console2.log("  returned (0 = native ETH, no ERC-20)", tokenFace);
        console2.log("call Charms.ensureToken(eth vault app)");
        address ensured = charms.ensureToken(vault);
        console2.log("  returned (same address, deploys nothing)", ensured);
        require(utxos[0].txId == wrapTxId && utxos[0].index == 0, "UTXO id is not the wrap output");
        require(utxoOwner == HOLDER, "UTXO owner is not the holder");
        require(address(charms).balance == 1 ether, "Charms did not lock 1 ETH");
        require(charms.balanceOf(vaultKey, HOLDER) == units, "vault units mismatch");
        require(tokenFace == address(0), "ETH vault tokenAddress must be 0");
        require(ensured == address(0), "ETH vault ensureToken must be 0");

        console2.log("=== 4. send the vault charm with transact ===");
        console2.log("spend the holder's UTXO and create one owned by the recipient");
        console2.log("ETH stays locked in Charms; only the claim moves");
        console2.log("holder vault units before send", charms.balanceOf(vaultKey, HOLDER));
        console2.log("recipient vault units before send", charms.balanceOf(vaultKey, RECIPIENT));
        console2.log("Charms balance before send (wei)", address(charms).balance);

        // One app (the ETH vault). Charm.app 0 is that app. Amounts in and out are equal,
        // so this is a plain transfer: empty proof, salt 0 because the spell has an input.
        ICharmsTypes.Spell memory send;
        send.version = charms.SPELL_VERSION();
        send.apps = new ICharmsTypes.App[](1);
        send.apps[0] = vault;
        send.publicInputs = new bytes[](1);
        send.publicInputs[0] = CBOR_NULL;
        send.ins = new ICharmsTypes.Input[](1);
        send.ins[0].utxo = ICharmsTypes.UtxoRef(wrapTxId, 0);
        send.ins[0].charms = new ICharmsTypes.Charm[](1);
        send.ins[0].charms[0] = ICharmsTypes.Charm(0, units, "");
        send.outs = new ICharmsTypes.Output[](1);
        send.outs[0].owner = RECIPIENT;
        send.outs[0].charms = new ICharmsTypes.Charm[](1);
        send.outs[0].charms[0] = ICharmsTypes.Charm(0, units, "");

        console2.log("call Charms.transact(spell, salt, proof, signatures)");
        console2.log("  salt", uint256(0));
        console2.log("  proof", "empty");
        console2.log("  signatures", "none; msg.sender owns the input");
        console2.log("  spell.version", uint256(send.version));
        console2.log("  spell.publicInputs[0]", "0xf6 (CBOR null)");
        console2.log("  spell.ins[0].utxo.txId", vm.toString(wrapTxId));
        console2.log("  spell.ins[0].utxo.index", uint256(0));
        console2.log("  spell.ins[0].charms[0].app", uint256(0));
        console2.log("  spell.ins[0].charms[0].amount", uint256(units));
        console2.log("  spell.outs[0].owner", RECIPIENT);
        console2.log("  spell.outs[0].charms[0].app", uint256(0));
        console2.log("  spell.outs[0].charms[0].amount", uint256(units));

        vm.startBroadcast(ANVIL_KEY);
        bytes32 sendTxId = charms.transact(send, bytes32(0), "", new bytes[](0));
        vm.stopBroadcast();

        console2.log("send returned UTXO tx id", vm.toString(sendTxId));
        (utxos,) = charms.utxosOf(vaultKey, HOLDER, 0, 10);
        console2.log("holder UTXO count after send", utxos.length);
        (ICharmsTypes.UtxoRef[] memory received,) = charms.utxosOf(vaultKey, RECIPIENT, 0, 10);
        require(received.length == 1, "send did not create one UTXO");
        console2.log("recipient UTXO tx id", vm.toString(received[0].txId));
        console2.log("recipient UTXO index", uint256(received[0].index));
        (utxoOwner,) = charms.utxo(received[0]);
        console2.log("recipient UTXO owner", utxoOwner);
        console2.log("holder vault units after send", charms.balanceOf(vaultKey, HOLDER));
        console2.log("recipient vault units after send", charms.balanceOf(vaultKey, RECIPIENT));
        console2.log("Charms balance after send (wei)", address(charms).balance);
        require(utxos.length == 0, "holder UTXO was not spent");
        require(received[0].txId == sendTxId && received[0].index == 0, "send UTXO id mismatch");
        require(utxoOwner == RECIPIENT, "sent UTXO owner is not the recipient");
        require(charms.balanceOf(vaultKey, HOLDER) == 0, "holder still has vault units");
        require(charms.balanceOf(vaultKey, RECIPIENT) == units, "recipient vault units mismatch");
        require(address(charms).balance == 1 ether, "send moved the locked ETH");

        console2.log("=== 5. recipient unwraps ===");
        console2.log("unwrap spends the recipient's UTXO and sends the locked ETH to them");
        console2.log("recipient balance before unwrap (ETH)", RECIPIENT.balance / 1 ether);
        console2.log("Charms balance before unwrap (ETH)", address(charms).balance / 1 ether);
        console2.log("Charms balance before unwrap (wei)", address(charms).balance);
        console2.log("recipient vault units before unwrap", charms.balanceOf(vaultKey, RECIPIENT));
        console2.log("unwrap amount (vault units)", uint256(units));
        console2.log("call Charms.unwrap(address(0), units, recipient)");
        console2.log("  token", address(0));
        console2.log("  amount (vault units)", uint256(units));
        console2.log("  to", RECIPIENT);

        // This simulation does not charge gas, so the recipient gains exactly 1 ETH.
        uint256 recipientBeforeUnwrap = RECIPIENT.balance;
        vm.startBroadcast(RECIPIENT_KEY);
        bytes32 unwrapTxId = charms.unwrap(address(0), units, RECIPIENT);
        vm.stopBroadcast();

        (received,) = charms.utxosOf(vaultKey, RECIPIENT, 0, 10);
        console2.log(
            "unwrap returned Charms tx id (not the Ethereum hash)", vm.toString(unwrapTxId)
        );
        uint256 recipientReceived = RECIPIENT.balance - recipientBeforeUnwrap;
        console2.log("recipient received on unwrap (wei)", recipientReceived);
        console2.log("recipient balance after unwrap (ETH)", RECIPIENT.balance / 1 ether);
        console2.log("holder balance after unwrap (ETH)", HOLDER.balance / 1 ether);
        console2.log("Charms balance after unwrap (ETH)", address(charms).balance / 1 ether);
        console2.log("Charms balance after unwrap (wei)", address(charms).balance);
        console2.log("recipient vault units after unwrap", charms.balanceOf(vaultKey, RECIPIENT));
        console2.log("recipient UTXO count after unwrap", received.length);
        require(recipientReceived == 1 ether, "recipient did not receive 1 ETH");
        require(address(charms).balance == 0, "Charms still holds ETH");
        require(charms.balanceOf(vaultKey, RECIPIENT) == 0, "recipient vault balance remains");
        require(charms.balanceOf(vaultKey, HOLDER) == 0, "holder vault balance remains");
        require(received.length == 0, "vault UTXO is still unspent");
        console2.log("SUCCESS: wrapped 1 ETH, sent the charm, unwrapped to the recipient.");
    }
}
