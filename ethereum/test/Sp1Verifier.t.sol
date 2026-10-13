// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";

import {Deploy} from "../script/Deploy.s.sol";
import {IStockSP1Verifier} from "../src/interfaces/ISP1Verifier.sol";

/// @notice CHIP-0020 phase 0: Succinct's stock SP1 v6.1.0 Groth16 verifier, unchanged, against
/// what a Charms v15 proof commits to. The expected values come from `charms-client` through the
/// vector generator.
contract Sp1VerifierTest is Test {
    string internal constant REAL_PROOF = "test/vectors/v15-proof.json";

    IStockSP1Verifier internal verifier;
    string internal json;

    function setUp() public {
        verifier = IStockSP1Verifier(vm.deployCode(new Deploy().VERIFIER_ARTIFACT()));
        json = vm.readFile("test/vectors/spells.json");
    }

    function test_stockVerifierChecksTheCharmsV15Groth16Key() public view {
        assertEq(verifier.VERIFIER_HASH(), vm.parseJsonBytes32(json, "$.sp1.groth16VkHash"));
    }

    function test_stockVerifierChecksTheCharmsV15VkRoot() public view {
        assertEq(verifier.VK_ROOT(), vm.parseJsonBytes32(json, "$.sp1.vkRoot"));
    }

    /// @dev `test/vectors/v15-proof.json` is one v15 Groth16 proof of a spell with
    /// empty inputs. `programVKey` is the key that proof commits. The stock verifier
    /// checks those bytes. Later proofs commit the rebuilt spell-checker key.
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
