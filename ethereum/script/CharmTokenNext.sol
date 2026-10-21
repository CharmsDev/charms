// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {CharmToken} from "../src/CharmToken.sol";
import {ICharmsLedger} from "../src/interfaces/ICharms.sol";

/// @notice A later `CharmToken` with one extra view.
/// @dev Storage matches `CharmToken`. `revision` is how a caller tells this
/// bytecode from the one it replaced. Not part of the production deployment.
contract CharmTokenNext is CharmToken {
    constructor(ICharmsLedger charms_) CharmToken(charms_) {}

    function revision() external pure returns (uint256) {
        return 2;
    }
}
