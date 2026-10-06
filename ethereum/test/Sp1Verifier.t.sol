// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";

interface IStockSP1Verifier is ISP1Verifier {
    function VERIFIER_HASH() external pure returns (bytes32);
    function VK_ROOT() external pure returns (bytes32);
}

/// @notice CHIP-0020 phase 0: Succinct's stock SP1 v6.1.0 Groth16 verifier, unchanged, against
/// what a Charms v15 proof commits to. The expected values come from `charms-client` through the
/// vector generator.
contract Sp1VerifierTest is Test {
    string internal constant REAL_PROOF = "test/vectors/v15-proof.json";

    IStockSP1Verifier internal verifier;
    string internal json;

    function setUp() public {
        verifier = IStockSP1Verifier(vm.deployCode("SP1VerifierGroth16.sol:SP1Verifier"));
        json = vm.readFile("test/vectors/spells.json");
    }

    function test_stockVerifierChecksTheCharmsV15Groth16Key() public view {
        assertEq(verifier.VERIFIER_HASH(), vm.parseJsonBytes32(json, "$.sp1.groth16VkHash"));
    }

    function test_stockVerifierChecksTheCharmsV15VkRoot() public view {
        assertEq(verifier.VK_ROOT(), vm.parseJsonBytes32(json, "$.sp1.vkRoot"));
    }

    /// @dev Skipped until `test/vectors/v15-proof.json` exists. To create it from a Bitcoin
    /// transaction that carries a v15 spell, run from `ethereum/`:
    /// `cargo run --manifest-path vectors/Cargo.toml -- --proof <tx.hex> test/vectors/v15-proof.json`
    function test_realV15ProofVerifies() public {
        vm.skip(!vm.exists(REAL_PROOF));
        string memory proof = vm.readFile(REAL_PROOF);
        verifier.verifyProof(
            vm.parseJsonBytes32(proof, "$.programVKey"),
            vm.parseJsonBytes(proof, "$.publicValues"),
            vm.parseJsonBytes(proof, "$.proof")
        );
    }
}
