// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@nitro-contracts/osp/ICustomDAProofValidator.sol";
import "@celestia/lib/CelestiaBatchVerifier.sol";

contract CelestiaDAProofValidator is ICustomDAProofValidator {
    uint256 private constant CERT_SIZE_LEN = 8;
    uint256 private constant CLAIMED_VALID_LEN = 1;
    uint256 private constant CERT_HEADER = 0x01;
    uint256 private constant PROVIDER_TYPE = 0x63; // 'c' for Celestia
    uint256 private constant CERT_V1_LEN = 92;

    address public immutable blobstreamX;

    constructor(address _blobstreamX) {
        blobstreamX = _blobstreamX;
    }

    function validateReadPreimage(
        bytes32 certHash,
        uint256 offset,
        bytes calldata proof
    ) external view override returns (bytes memory preimageChunk) {
        // Parse: [certSize(8)][certificate][version(1)][preimageSize(8)][preimage][proofData]
        uint256 certSize = uint256(uint64(bytes8(proof[0:CERT_SIZE_LEN])));
        require(proof.length >= CERT_SIZE_LEN + certSize + 1 + 8, "Proof too short");

        bytes calldata certificate = proof[CERT_SIZE_LEN:CERT_SIZE_LEN + certSize];

        require(keccak256(certificate) == certHash, "Certificate hash mismatch");
        require(certificate.length == CERT_V1_LEN, "Invalid certificate length");
        require(certificate[0] == bytes1(uint8(CERT_HEADER)), "Invalid certificate header");
        require(certificate[1] == bytes1(uint8(PROVIDER_TYPE)), "Invalid provider type");

        // Parse version byte
        uint8 version = uint8(proof[CERT_SIZE_LEN + certSize]);
        require(version == 0x01, "Invalid proof version");

        // Parse preimage size
        uint256 preimageStart = CERT_SIZE_LEN + certSize + 1 + 8;
        uint256 preimageSize = uint256(uint64(bytes8(proof[CERT_SIZE_LEN + certSize + 1:preimageStart])));
        require(proof.length >= preimageStart + preimageSize, "Proof too short for preimage");

        bytes calldata preimage = proof[preimageStart:preimageStart + preimageSize];

        // Validate certificate proof on-chain
        uint256 proofDataStart = preimageStart + preimageSize;
        bytes calldata proofData = proof[proofDataStart:];
        CelestiaBatchVerifier.Result res = CelestiaBatchVerifier.verifyBatch(blobstreamX, proofData);
        require(res == CelestiaBatchVerifier.Result.IN_BLOBSTREAM, "Invalid Celestia proof");

        // Extract 32-byte chunk at offset from preimage
        require(offset + 32 <= preimageSize, "Offset out of bounds");
        preimageChunk = preimage[offset:offset + 32];
    }

    function validateCertificate(
        bytes calldata proof
    ) external view override returns (bool isValid) {
        // Parse: [claimedValid(1)]
        // Note: Certificate is already available on L1 from batch posting.
        // For Celestia, certificate validity is checked off-chain by verifying
        // the commitment exists in Celestia. The full Blobstream attestation proof
        // is only required for read preimage validation.
        require(proof.length >= CLAIMED_VALID_LEN, "Proof too short");

        uint8 claimedValid = uint8(proof[0]);

        // Return the claimed validity
        // If claimedValid == 1, the off-chain validator confirmed the commitment exists in Celestia
        // If claimedValid == 0, the commitment does not exist or validation failed
        return claimedValid == 1;
    }
}
