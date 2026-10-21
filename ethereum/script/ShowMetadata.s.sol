// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";

import {CharmToken} from "../src/CharmToken.sol";
import {Charms} from "../src/Charms.sol";
import {CharmsApply} from "../src/CharmsApply.sol";
import {CharmsInitializer} from "../src/CharmsInitializer.sol";
import {CharmsProxy} from "../src/CharmsProxy.sol";
import {ICharmsLedger, ICharmsTypes} from "../src/interfaces/ICharms.sol";
import {MockVerifier} from "../test/utils/Mocks.sol";

/// @notice Anvil walk of tag-`t` `setMetadata`. Spell version stays 16.
contract ShowMetadata is Script, ICharmsTypes {
    uint32 internal constant TAG_T = 0x74;

    function run() external {
        uint256 deployerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        uint256 signerKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
        address deployer = vm.addr(deployerKey);
        address signer = vm.addr(signerKey);
        App memory coin = App({tag: TAG_T, identity: keccak256("coin"), vk: keccak256("coin/vk")});
        Metadata memory metadata = Metadata({
            name: "Example",
            symbol: "EX",
            decimals: 8,
            description: "One fungible charm.",
            url: "https://example.com",
            image: "ipfs://bafyexample",
            imageHash: bytes32(uint256(1))
        });

        vm.startBroadcast(deployerKey);
        uint64 nonce = vm.getNonce(deployer);
        MockVerifier verifier = new MockVerifier();
        CharmsApply applier = new CharmsApply(16, keccak256("v16 program vk"), verifier);
        CharmsInitializer initializer = new CharmsInitializer();
        address predicted = vm.computeCreateAddress(deployer, nonce + 5);
        CharmToken implementation = new CharmToken(ICharmsLedger(predicted));
        Charms logic = new Charms(applier, address(implementation), signer);
        CharmsProxy proxy = new CharmsProxy(
            address(initializer), abi.encodeCall(CharmsInitializer.initialize, (deployer))
        );
        Charms charms = Charms(payable(address(proxy)));
        charms.upgradeToAndCall(address(logic), "");

        address token = charms.ensureToken(coin);
        console.log("proxy", address(charms));
        console.log("metadataSigner", charms.metadataSigner());
        console.log("token", token);
        console.log("spell", charms.SPELL_VERSION());

        charms.setMetadata(coin, metadata, 1, _sign(signerKey, charms, coin, metadata, 1));
        _log(charms, token, coin);

        Metadata memory next = metadata;
        next.name = "Renamed";
        next.symbol = "RN";
        next.description = "Updated.";
        next.url = "https://renamed.example";
        next.image = "ar://renamed";
        next.imageHash = bytes32(uint256(2));
        charms.setMetadata(coin, next, 2, _sign(signerKey, charms, coin, next, 2));
        console.log("after second setMetadata");
        _log(charms, token, coin);
        vm.stopBroadcast();

        next.decimals = 6;
        (bool decimalsOk,) = address(charms)
            .call(
                abi.encodeCall(
                    Charms.setMetadata, (coin, next, 3, _sign(signerKey, charms, coin, next, 3))
                )
            );
        bytes memory bad = _sign(signerKey, charms, coin, metadata, 4);
        bad[0] = bytes1(uint8(bad[0]) ^ 1);
        (bool badOk,) =
            address(charms).call(abi.encodeCall(Charms.setMetadata, (coin, metadata, 4, bad)));
        console.log("decimals change accepted", decimalsOk);
        console.log("bad signature accepted", badOk);
        console.log("decimals still", CharmToken(token).decimals());
        console.log("name still", CharmToken(token).name());
    }

    function _log(Charms charms, address token, App memory coin) internal view {
        CharmToken face = CharmToken(token);
        console.log("name", face.name());
        console.log("symbol", face.symbol());
        console.log("decimals", face.decimals());
        console.log("version", charms.metadataVersion(coin));
        console.log("contractURI", face.contractURI());
    }

    function _sign(
        uint256 signerKey,
        Charms charms,
        App memory coin,
        Metadata memory metadata,
        uint64 version
    ) internal view returns (bytes memory) {
        bytes32 metadataHash = keccak256(
            abi.encode(
                metadata.name,
                metadata.symbol,
                metadata.decimals,
                metadata.description,
                metadata.url,
                metadata.image,
                metadata.imageHash
            )
        );
        bytes32 digest = keccak256(
            abi.encode(
                keccak256(
                    "CharmsMetadata(uint256 chainId,address charms,bytes32 appKey,uint64 version,bytes32 metadataHash)"
                ),
                block.chainid,
                address(charms),
                keccak256(abi.encode(coin.tag, coin.identity, coin.vk)),
                version,
                metadataHash
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
