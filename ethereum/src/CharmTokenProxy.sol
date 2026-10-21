// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ICharms} from "./interfaces/ICharms.sol";

/// @notice Shared forwarder baked into every non-vault clone.
/// @dev The clone `delegatecall`s here, so `address(this)` is the clone and a
/// storage read would hit the clone. This contract does not read storage. It
/// asks the Charms proxy for the current implementation and `delegatecall`s
/// that. There is no ERC-1967 slot and no `upgradeTo`.
contract CharmTokenProxy {
    ICharms public immutable charms;

    constructor() {
        charms = ICharms(msg.sender);
    }

    fallback() external {
        address impl = charms.tokenImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
