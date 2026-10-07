// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {Charms} from "../src/Charms.sol";
import {ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {appKey} from "../src/libraries/CharmTokenClone.sol";
import {Deploy} from "./Deploy.s.sol";

/// @notice Fresh-anvil demo: deploy phase-1 Charms, wrap 1 ETH, unwrap it.
/// @dev Charms is the contract that locks ETH and records the holder's claim. This script uses
/// native ETH only. Phase-1 sets the proof verifier to address(0), so wrap and unwrap need no
/// proof. The ETH vault does not create an ERC-20; after the wrap, `tokenAddress` and
/// `ensureToken` both return address(0).
///
/// Steps:
/// 1. Etch the keyless CREATE2 factory (same bytecode as `Deploy.t.sol`). Anvil often already
///    has it; the script writes it anyway so deploy still works when it is missing.
///    `vm.etch` updates this simulation; `anvil_setCode` writes that bytecode on the node.
/// 2. Deploy Charms through that factory, same CREATE2 path as `Deploy.s.sol` / `Deploy.t.sol`.
/// 3. Wrap 1 ETH. The holder sends 1 ETH and gets one vault UTXO: the unspent record of that
///    deposit. Its id is (tx id, index 0). That tx id is Charms' id, not the Ethereum tx hash.
/// 4. Unwrap the full amount. Charms sends the 1 ETH back and that UTXO is spent.
///
/// The ETH vault's scale is 10: 1 vault unit = 10^10 wei, so 1 ETH = 10^8 units.
/// Logged ETH balances are from this simulation, which does not charge gas, so the holder
/// moves by exactly 1 ETH. Charms' balance is exact here and on anvil: 0, then 1 ETH, then 0.
/// A later `cast balance` of the holder is lower by the gas that anvil charged.
///
/// Restart anvil before each run. The wrap salt is fixed, so a second run reverts.
/// Run the forge command from `ethereum/`. Account #0 is
/// 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266.
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

    /// @dev Anvil account #0. `--private-key` in the command above must be this key.
    /// `Deploy.s.sol` signs with that CLI key; wrap and unwrap sign with this same key.
    uint256 internal constant ANVIL_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address internal constant HOLDER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    /// @dev Names this deposit. Any unused value works; this one is fixed for the demo.
    bytes32 internal constant WRAP_SALT = bytes32(uint256(1));

    function run() external {
        require(vm.addr(ANVIL_KEY) == HOLDER, "anvil key is not account #0");
        uint256 weiPerUnit = 10 ** 10;
        uint64 units = uint64(1 ether / weiPerUnit);

        console2.log("chain id (anvil is 31337)", block.chainid);
        console2.log("holder (anvil account #0)", HOLDER);

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
        Deploy deployScript = new Deploy();
        Charms charms = deployScript.run(FACTORY, HOLDER);
        console2.log("Charms (the proxy you call)", address(charms));
        console2.log("admin", charms.admin());
        console2.log("spell version", uint256(charms.SPELL_VERSION()));
        console2.log("verifier", address(charms.APPLY().VERIFIER()));
        require(charms.admin() == HOLDER, "admin was not set");
        require(charms.SPELL_VERSION() == 15, "not the phase-1 spell version");
        require(address(charms.APPLY().VERIFIER()) == address(0), "verifier is not address(0)");

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
        console2.log("Charms balance before wrap (ETH)", address(charms).balance / 1 ether);
        console2.log("holder vault units before wrap", charms.balanceOf(vaultKey, HOLDER));
        console2.log("wei per vault unit", weiPerUnit);
        console2.log("wrap amount (vault units)", uint256(units));
        console2.log("ETH sent (wei)", uint256(1 ether));

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
        address tokenFace = charms.tokenAddress(vault);
        address ensured = charms.ensureToken(vault);
        console2.log("tokenAddress (0 = native ETH, no ERC-20)", tokenFace);
        console2.log("ensureToken (same address, deploys nothing)", ensured);
        require(utxos[0].txId == wrapTxId && utxos[0].index == 0, "UTXO id is not the wrap output");
        require(utxoOwner == HOLDER, "UTXO owner is not the holder");
        require(address(charms).balance == 1 ether, "Charms did not lock 1 ETH");
        require(charms.balanceOf(vaultKey, HOLDER) == units, "vault units mismatch");
        require(tokenFace == address(0), "ETH vault tokenAddress must be 0");
        require(ensured == address(0), "ETH vault ensureToken must be 0");

        console2.log("=== 4. unwrap all ===");
        console2.log("unwrap spends the UTXO and sends the locked ETH back to the holder");
        console2.log("holder balance before unwrap (ETH)", HOLDER.balance / 1 ether);
        console2.log("Charms balance before unwrap (ETH)", address(charms).balance / 1 ether);
        console2.log("Charms balance before unwrap (wei)", address(charms).balance);
        console2.log("holder vault units before unwrap", charms.balanceOf(vaultKey, HOLDER));
        console2.log("unwrap amount (vault units)", uint256(units));

        // This simulation does not charge gas, so the holder gains exactly 1 ETH.
        uint256 holderBeforeUnwrap = HOLDER.balance;
        vm.startBroadcast(ANVIL_KEY);
        bytes32 unwrapTxId = charms.unwrap(address(0), units, HOLDER);
        vm.stopBroadcast();

        (utxos,) = charms.utxosOf(vaultKey, HOLDER, 0, 10);
        console2.log(
            "unwrap returned Charms tx id (not the Ethereum hash)", vm.toString(unwrapTxId)
        );
        uint256 holderReceived = HOLDER.balance - holderBeforeUnwrap;
        console2.log("holder received on unwrap (wei)", holderReceived);
        console2.log("holder balance after unwrap (ETH)", HOLDER.balance / 1 ether);
        console2.log("Charms balance after unwrap (ETH)", address(charms).balance / 1 ether);
        console2.log("Charms balance after unwrap (wei)", address(charms).balance);
        console2.log("holder vault units after unwrap", charms.balanceOf(vaultKey, HOLDER));
        console2.log("vault UTXO count after unwrap", utxos.length);
        require(holderReceived == 1 ether, "holder did not receive 1 ETH");
        require(address(charms).balance == 0, "Charms still holds ETH");
        require(charms.balanceOf(vaultKey, HOLDER) == 0, "vault balance remains");
        require(utxos.length == 0, "vault UTXO is still unspent");
        console2.log("SUCCESS: wrapped 1 ETH, then unwrapped it. Charms ETH balance is 0.");
    }
}
