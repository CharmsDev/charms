// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";

import {CharmToken} from "../src/CharmToken.sol";
import {Charms} from "../src/Charms.sol";
import {ICharmsLedger, ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {CharmTokenNext} from "./CharmTokenNext.sol";

/// @notice After `Deploy`, install a second `CharmToken` and show the same clone running it.
/// @dev The broadcast key must be the proxy admin. `revision()` exists only on `CharmTokenNext`.
///
/// forge script script/ShowTokenUpgrade.s.sol --sig "run(address)" <proxy> \
///     --rpc-url http://127.0.0.1:8545 --broadcast \
///     --private-key <admin key>
contract ShowTokenUpgrade is Script {
    function run(address proxy) external {
        Charms charms = Charms(payable(proxy));
        ICharmsTypes.App memory coin =
            ICharmsTypes.App(uint32(0x74), keccak256("coin"), keccak256("coin/vk"));

        vm.startBroadcast();
        address clone = charms.ensureToken(coin);
        string memory nameBefore = CharmToken(clone).name();
        address logicBefore = charms.tokenImplementation();
        CharmTokenNext nextToken = new CharmTokenNext(ICharmsLedger(proxy));
        Charms next = new Charms(charms.APPLY(), address(nextToken), charms.metadataSigner());
        charms.upgradeToAndCall(address(next), "");
        vm.stopBroadcast();

        require(charms.tokenAddress(coin) == clone, "token address changed");
        require(charms.tokenImplementation() == address(nextToken), "logic was not installed");
        require(logicBefore != address(nextToken), "logic did not change");
        require(CharmTokenNext(clone).revision() == 2, "clone is not running the new logic");
        require(
            keccak256(bytes(CharmToken(clone).name())) == keccak256(bytes(nameBefore)),
            "name changed"
        );

        console.log("clone", clone);
        console.log("CharmToken before", logicBefore);
        console.log("CharmToken after", address(nextToken));
        console.log("revision", CharmTokenNext(clone).revision());
        console.log("name", CharmToken(clone).name());
        console.log("ETHEREUM_CHARMS", proxy);
    }
}
