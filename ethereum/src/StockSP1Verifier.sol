// SPDX-License-Identifier: MIT
pragma solidity =0.8.20;

// Re-exports Succinct's v6.1.0 Groth16 verifier so `forge script` compiles it.
// The verifier pins solc 0.8.20. A 0.8.37 file cannot import it.
import {SP1Verifier} from "sp1-contracts/v6.1.0/SP1VerifierGroth16.sol";
