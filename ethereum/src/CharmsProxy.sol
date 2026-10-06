// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice The stable `Charms` address. Every call, including a plain ETH transfer, is
/// `delegatecall`ed to the implementation in the ERC-1967 slot. There is no admin branch here;
/// the upgrade function lives on the implementation.
contract CharmsProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory initialize)
        payable
        ERC1967Proxy(implementation, initialize)
    {}

    receive() external payable {
        _fallback();
    }
}
