// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

pragma experimental ABIEncoderV2;

import "b12-sol/B12.sol";

contract Verifier {
    using B12_381Lib for B12.G1Point;
    using B12_381Lib for B12.G2Point;

    B12.G2Point private NEGATED_G2_GENERATOR;

    constructor() public {
        B12.Fp2 memory x = B12.Fp2(
            B12.Fp(0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8, 0x24aa2b2f08f0a91260805272dc51051),
            B12.Fp(0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e, 0x13e02b6052719f607dacd3a088274f65)
        );
        B12.Fp2 memory y = B12.Fp2(
            B12.Fp(0xb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa, 0xd1b3cc2c7027888be51d9ef691d77bc),
            B12.Fp(0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed, 0x13fa4d4a0ad8b1ce186ed5061789213d)
        );
        NEGATED_G2_GENERATOR = B12.G2Point(x, y);
    }

    function verifySignature(
        bytes memory messageHashBytes, 
        bytes memory publicKeyBytes, 
        bytes memory signatureBytes
    ) public view returns (bool) {
        // Parse bytes to points
        B12.G1Point memory messageHash = B12.parseG1(messageHashBytes, 0);
        B12.G2Point memory publicKey = B12.parseG2(publicKeyBytes, 0);
        B12.G1Point memory signature = B12.parseG1(signatureBytes, 0);

        // Verify the signature
        B12.PairingArg[] memory args = new B12.PairingArg[](2);
        args[0] = B12.PairingArg(messageHash, publicKey);
        args[1] = B12.PairingArg(signature, NEGATED_G2_GENERATOR);
        return B12_381Lib.pairing(args);
    }
}