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
        require(certificate.length == 102, "Invalid certificate length");
        require(certificate[0] == bytes1(uint8(CERT_HEADER)), "Invalid certificate header");
        require(certificate[1] == bytes1(uint8(PROVIDER_TYPE)), "Invalid provider type");

        // Validate certificate proof on-chain. Proof data is supplied in the proof bytes after the cert.
        uint256 proofStart = CERT_SIZE_LEN + certSize + CLAIMED_VALID_LEN;
        bytes calldata proofData = proof[proofStart:];
        CelestiaBatchVerifier.Result res = CelestiaBatchVerifier.verifyBatch(blobstreamX, proofData);
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
        if (certificate.length != 102) {
            return false;
        }
        if (certificate[0] != bytes1(uint8(CERT_HEADER))) {
            return false;
        }
        if (certificate[1] != bytes1(uint8(PROVIDER_TYPE))) {
            return false;
        }

        uint256 proofStart = CERT_SIZE_LEN + certSize + CLAIMED_VALID_LEN;
        bytes calldata proofData = proof[proofStart:];
        CelestiaBatchVerifier.Result res = CelestiaBatchVerifier.verifyBatch(blobstreamX, proofData);
        return res == CelestiaBatchVerifier.Result.IN_BLOBSTREAM;
    }
}
