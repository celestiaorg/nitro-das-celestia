// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@nitro-contracts/osp/ICustomDAProofValidator.sol";
import "./lib/CelestiaBatchVerifier.sol";

contract CelestiaDAProofValidator is ICustomDAProofValidator {
    uint256 private constant CERT_SIZE_LEN = 8;
    uint256 private constant CLAIMED_VALID_LEN = 1;
    uint256 private constant CERT_HEADER = 0x01;
    uint256 private constant PROVIDER_TYPE = 0x0c;

    address public immutable blobstreamX;

    constructor(address _blobstreamX) {
        blobstreamX = _blobstreamX;
    }

    function validateReadPreimage(
        bytes32 certHash,
        uint256 offset,
        bytes calldata proof
    ) external view override returns (bytes memory preimageChunk) {
        uint256 certSize = uint256(uint64(bytes8(proof[0:CERT_SIZE_LEN])));
        require(proof.length >= CERT_SIZE_LEN + certSize, "Proof too short for certificate");
        bytes calldata certificate = proof[CERT_SIZE_LEN:CERT_SIZE_LEN + certSize];

        require(keccak256(certificate) == certHash, "Certificate hash mismatch");
        require(certificate.length >= 128, "Invalid certificate length");
        require(certificate[0] == bytes1(uint8(CERT_HEADER)), "Invalid certificate header");
        require(certificate[1] == bytes1(uint8(PROVIDER_TYPE)), "Invalid provider type");

        // Extract proof bytes from certificate: last 4 bytes before proof is proofLen
        uint256 proofLen = uint256(uint32(bytes4(certificate[124:128])));
        require(certificate.length == 128 + proofLen, "Invalid proof length");

        // Validate certificate proof on-chain
        CelestiaBatchVerifier.Result res = CelestiaBatchVerifier.verifyBatch(blobstreamX, certificate[68:]);
        require(res == CelestiaBatchVerifier.Result.IN_BLOBSTREAM, "Invalid Celestia proof");

        // offset-based preimage read is handled by the preimage oracle; return empty
        return preimageChunk;
    }

    function validateCertificate(
        bytes calldata proof
    ) external view override returns (bool isValid) {
        require(proof.length >= CERT_SIZE_LEN, "Proof too short");
        uint256 certSize = uint256(uint64(bytes8(proof[0:CERT_SIZE_LEN])));
        require(
            proof.length >= CERT_SIZE_LEN + certSize + CLAIMED_VALID_LEN,
            "Proof too short for cert and validity"
        );

        bytes calldata certificate = proof[CERT_SIZE_LEN:CERT_SIZE_LEN + certSize];
        if (certificate.length < 128) {
            return false;
        }
        if (certificate[0] != bytes1(uint8(CERT_HEADER))) {
            return false;
        }
        if (certificate[1] != bytes1(uint8(PROVIDER_TYPE))) {
            return false;
        }

        uint256 proofLen = uint256(uint32(bytes4(certificate[124:128])));
        if (certificate.length != 128 + proofLen) {
            return false;
        }

        CelestiaBatchVerifier.Result res = CelestiaBatchVerifier.verifyBatch(blobstreamX, certificate[68:]);
        return res == CelestiaBatchVerifier.Result.IN_BLOBSTREAM;
    }
}
