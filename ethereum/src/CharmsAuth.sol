// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {CharmsStorage} from "./CharmsStorage.sol";
import {ICharmToken, ICharms, IUpgradeable} from "./interfaces/ICharms.sol";

/// @notice Upgrade checks shared by `CharmsInitializer` and `Charms`.
/// @dev The next implementation's token and signer are read with staticcalls.
/// A contract that does not expose them fails before the ERC-1967 write.
abstract contract CharmsAuth is CharmsStorage, Initializable, UUPSUpgradeable, IUpgradeable {
    function upgradeToAndCall(address newImplementation, bytes memory data)
        public
        payable
        override(IUpgradeable, UUPSUpgradeable)
    {
        super.upgradeToAndCall(newImplementation, data);
    }

    function _authorizeUpgrade(address next) internal view override {
        if (msg.sender != admin) revert NotAdmin();
        address impl = _staticAddress(next, ICharms.tokenImplementation.selector);
        if (impl.code.length == 0) revert NoTokenImplementation();
        if (_staticAddress(impl, ICharmToken.charms.selector) != address(this)) {
            revert TokenCharmsMismatch();
        }
        if (_staticAddress(next, ICharms.metadataSigner.selector) == address(0)) {
            revert ZeroMetadataSigner();
        }
    }

    function _staticAddress(address target, bytes4 selector) private view returns (address value) {
        (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSelector(selector));
        if (!ok || data.length != 32) return address(0);
        value = abi.decode(data, (address));
    }
}
