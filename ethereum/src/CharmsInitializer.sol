// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {CharmTokenProxy} from "./CharmTokenProxy.sol";
import {CharmsAuth} from "./CharmsAuth.sol";

/// @notice First implementation behind `CharmsProxy`.
/// @dev Creation code carries neither the token implementation nor the metadata
/// signer, so the proxy address is known before those contracts exist.
/// `initialize` stores the admin and creates `CharmTokenProxy` at nonce 1.
contract CharmsInitializer is CharmsAuth {
    constructor() {
        _disableInitializers();
    }

    /// @notice Runs once, from the proxy constructor.
    function initialize(address admin_) external initializer {
        if (admin_ == address(0)) revert ZeroAdmin();
        admin = admin_;
        CharmTokenProxy forwarder = new CharmTokenProxy();
        assert(address(forwarder) == _charmTokenProxy());
    }
}
