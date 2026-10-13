// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Succinct's SP1 verifier entry point. Reverts when the proof does not verify.
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @notice Hash and root of Succinct's stock Groth16 verifier.
interface IStockSP1Verifier is ISP1Verifier {
    function VERIFIER_HASH() external pure returns (bytes32);
    function VK_ROOT() external pure returns (bytes32);
}
