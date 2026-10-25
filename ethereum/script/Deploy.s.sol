// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";

import {CharmToken} from "../src/CharmToken.sol";
import {CharmTokenProxy} from "../src/CharmTokenProxy.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsInitializer} from "../src/CharmsInitializer.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";
import {ICharmsLedger} from "../src/interfaces/ICharms.sol";
import {IStockSP1Verifier} from "../src/interfaces/ISP1Verifier.sol";

/// @notice Installs Charms at spell version 16. The proxy address is `ETHEREUM_CHARMS`.
/// @dev `deployer` is a CREATE2 factory that takes `salt ‖ initCode` as calldata, such as
/// 0x4e59b44847b379578588920ca78fbf26c0b4956c.
///
/// forge script script/Deploy.s.sol \
///     --sig "run(address,address,address)" <deployer> <admin> <metadataSigner> \
///     --rpc-url <url> --broadcast --private-key <admin key>
contract Deploy is Script {
    uint32 public constant SPELL_VERSION = 16;
    /// @dev `charms-lib`'s `SPELL_VK`.
    bytes32 public constant PROGRAM_VKEY =
        0x001a111b6bb33afb441abfce5fef266f789855ab6eba5522c6ea41265e66de95;
    /// @dev SHA-256 of the Groth16 verifying key. Same value as `$.sp1.groth16VkHash`.
    bytes32 public constant GROTH16_VK_HASH =
        0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;

    string public constant VERIFIER_ARTIFACT = "SP1VerifierGroth16.sol:SP1Verifier";

    bytes32 public constant VERIFIER_SALT = keccak256("sp1-verifier-groth16");
    bytes32 public constant APPLY_SALT = keccak256("charms-apply");
    bytes32 public constant INITIALIZER_SALT = keccak256("charms-initializer");
    bytes32 public constant TOKEN_SALT = keccak256("charms-token");
    bytes32 public constant IMPLEMENTATION_SALT = keccak256("charms-implementation");
    bytes32 public constant PROXY_SALT = keccak256("charms-proxy-v1");

    bytes32 internal constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    function run(address deployer, address admin, address metadataSigner)
        external
        returns (Charms charms)
    {
        require(deployer.code.length != 0, "deployer has no code");
        require(admin != address(0), "admin is zero");
        require(metadataSigner != address(0), "metadata signer is zero");
        bytes memory verifierInit = vm.getCode(VERIFIER_ARTIFACT);

        vm.startBroadcast(admin);
        address initializer =
            _create2(deployer, INITIALIZER_SALT, type(CharmsInitializer).creationCode);
        bytes memory proxyInit = abi.encodePacked(
            type(CharmsProxy).creationCode,
            abi.encode(initializer, abi.encodeCall(CharmsInitializer.initialize, (admin)))
        );
        address predicted = vm.computeCreate2Address(PROXY_SALT, keccak256(proxyInit), deployer);
        address token = _create2(
            deployer,
            TOKEN_SALT,
            abi.encodePacked(type(CharmToken).creationCode, abi.encode(ICharmsLedger(predicted)))
        );
        address verifier = _create2(deployer, VERIFIER_SALT, verifierInit);
        address applier = _create2(
            deployer,
            APPLY_SALT,
            abi.encodePacked(
                type(CharmsApply).creationCode, abi.encode(SPELL_VERSION, PROGRAM_VKEY, verifier)
            )
        );
        address implementation = _create2(
            deployer,
            IMPLEMENTATION_SALT,
            abi.encodePacked(type(Charms).creationCode, abi.encode(applier, token, metadataSigner))
        );
        charms = Charms(payable(_create2(deployer, PROXY_SALT, proxyInit)));
        if (_implementation(address(charms)) == initializer) {
            charms.upgradeToAndCall(implementation, "");
        }
        vm.stopBroadcast();

        check(charms, admin, metadataSigner);
        console.log("SP1Verifier", verifier);
        console.log("CharmsApply", applier);
        console.log("CharmsInitializer", initializer);
        console.log("CharmToken", token);
        console.log("CharmTokenProxy", vm.computeCreateAddress(address(charms), 1));
        console.log("Charms implementation", implementation);
        console.log("ETHEREUM_CHARMS", address(charms));
    }

    /// @notice Reverts unless `charms` is this release under `admin`.
    function check(Charms charms, address admin, address metadataSigner) public view {
        require(admin != address(0), "admin is zero");
        require(metadataSigner != address(0), "metadata signer is zero");
        require(charms.admin() == admin, "admin");
        require(charms.metadataSigner() == metadataSigner, "metadata signer");
        require(charms.SPELL_VERSION() == SPELL_VERSION, "spell version");
        require(charms.tokenImplementation().code.length != 0, "token implementation");
        require(
            address(CharmToken(charms.tokenImplementation()).charms()) == address(charms),
            "token charms"
        );
        address forwarder = vm.computeCreateAddress(address(charms), 1);
        require(forwarder.code.length != 0, "forwarder");
        require(address(CharmTokenProxy(forwarder).charms()) == address(charms), "forwarder charms");
        CharmsApply applier = charms.APPLY();
        require(applier.PROGRAM_VKEY() == PROGRAM_VKEY, "program vkey");
        address verifier = address(applier.VERIFIER());
        require(verifier.code.length != 0, "verifier has no code");
        require(
            IStockSP1Verifier(verifier).VERIFIER_HASH() == GROTH16_VK_HASH,
            "not the Groth16 verifier"
        );
    }

    function _create2(address deployer, bytes32 salt, bytes memory initCode)
        internal
        returns (address deployed)
    {
        deployed = vm.computeCreate2Address(salt, keccak256(initCode), deployer);
        if (deployed.code.length != 0) return deployed;
        (bool ok,) = deployer.call(abi.encodePacked(salt, initCode));
        require(ok && deployed.code.length != 0, "CREATE2 deployment failed");
    }

    function _implementation(address proxy) internal view returns (address) {
        return address(uint160(uint256(vm.load(proxy, IMPLEMENTATION_SLOT))));
    }
}
