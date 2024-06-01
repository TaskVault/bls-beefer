// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import {Test, console} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol";

contract VerifierTest is Test {
    Counter public counter;

    function setUp() public {
        counter = new Verifier();
    }
}
