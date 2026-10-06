// SPDX-License-Identifier: MIT
pragma solidity =0.8.20;

// Compiles Succinct's v6.1.0 Groth16 verifier, which pins solc 0.8.20, as its own unit so tests
// can deploy the artifact.
import {SP1Verifier} from "sp1-contracts/v6.1.0/SP1VerifierGroth16.sol";
