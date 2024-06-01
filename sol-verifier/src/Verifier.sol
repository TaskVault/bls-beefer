// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import { B12_381Lib } from "b12-sol/B12.sol";

contract Verifier {
    function verify(B12_381Lib.PairingArg[] memory argVec) public pure returns (bool) {
        return pairing(argVec);
    }
}