// SPDX-License-Identifier: MIT
pragma solidity =0.8.20;

// `forge test` does not compile an unreferenced file in `src/`. This contract does.
import {SP1Verifier} from "sp1-contracts/v6.1.0/SP1VerifierGroth16.sol";

contract StockSP1VerifierFixture {
    function pin() external pure returns (string memory) {
        return type(SP1Verifier).name;
    }
}
