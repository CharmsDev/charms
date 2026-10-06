// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ICharmsTypes} from "../interfaces/ICharms.sol";

/// @notice The ledger and CREATE2 key of one app: `keccak256(abi.encode(uint32 tag, bytes32
/// identity, bytes32 vk))`.
function appKey(ICharmsTypes.App memory app) pure returns (bytes32) {
    return keccak256(abi.encode(app.tag, app.identity, app.vk));
}

/// @notice A `CharmToken` is a clones-with-immutable-args proxy (the wighawag scheme) whose
/// immutable args are the packed `App` (68 bytes) followed by their length as a `uint16`.
library CharmTokenClone {
    /// @notice 10-byte creation code, the 55-byte forwarding runtime around the implementation
    /// address, then `abi.encodePacked(uint32 tag, bytes32 identity, bytes32 vk)` and `0x0044`.
    function initCode(address implementation, ICharmsTypes.App memory app)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            hex"61007d3d81600a3d39f3",
            hex"3d3d3d3d363d3d376100466037363936610046013d73",
            implementation,
            hex"5af43d3d93803e603557fd5bf3",
            app.tag,
            app.identity,
            app.vk,
            hex"0044"
        );
    }

    /// @notice `CREATE2(deployer, appKey(app), initCode)`.
    function predict(address deployer, address implementation, ICharmsTypes.App memory app)
        internal
        pure
        returns (address)
    {
        bytes32 initHash = keccak256(initCode(implementation, app));
        return address(
            uint160(uint256(keccak256(abi.encodePacked(hex"ff", deployer, appKey(app), initHash))))
        );
    }
}
