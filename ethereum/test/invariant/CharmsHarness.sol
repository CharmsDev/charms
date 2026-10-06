// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Charms} from "../../src/Charms.sol";
import {CharmsApply} from "../../src/CharmsApply.sol";
import {appKey} from "../../src/libraries/CharmTokenClone.sol";
import {UtxoBody} from "../../src/libraries/UtxoBody.sol";
import {UtxoList} from "../../src/libraries/UtxoList.sol";

/// @notice `Charms` plus the views CHIP-0020 names for the invariant tests. A proxy over this
/// contract runs them on the storage `_apply` writes, without reading the `balance` cache.
contract CharmsHarness is Charms {
    constructor(CharmsApply applier) Charms(applier) {}

    function utxoBalance(bytes32 key, address owner) external view returns (uint256 sum) {
        UtxoList.List storage list = utxos[owner][key];
        bytes32 prev;
        for (bytes32 k = list.first; k != 0; k = list.links[k].next) {
            require(list.links[k].prev == prev, "broken prev link");
            Head storage h = head[k];
            require(h.owner == owner, "spent or foreign UTXO in the list");
            if (h.kind == Kind.Plain) {
                require(h.link == key, "plain UTXO in another app's list");
                sum += h.amount;
            } else {
                require(h.kind == Kind.Bundle, "empty UTXO in an app list");
                (UtxoBody.Held[] memory held,) = UtxoBody.decode(body[k]);
                bool found;
                for (uint256 j; j < held.length; ++j) {
                    if (appKey(held[j].app) != key) continue;
                    sum += held[j].amount;
                    found = true;
                }
                require(found, "bundle without this app in its list");
            }
            prev = k;
        }
        require(list.last == prev, "last is not the final member");
    }

    function emptyUtxoCount(address owner) external view returns (uint256 count) {
        UtxoList.List storage list = emptyUtxos[owner];
        bytes32 prev;
        for (bytes32 k = list.first; k != 0; k = list.links[k].next) {
            require(list.links[k].prev == prev, "broken prev link");
            Head storage h = head[k];
            require(h.owner == owner && h.kind == Kind.Empty, "spent or foreign UTXO in the list");
            ++count;
            prev = k;
        }
        require(list.last == prev, "last is not the final member");
    }
}
