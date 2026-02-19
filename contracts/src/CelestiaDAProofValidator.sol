// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@nitro-contracts/osp/ICustomDAProofValidator.sol";
import "blobstream-contracts/IDAOracle.sol";
import "blobstream-contracts/DataRootTuple.sol";
import "blobstream-contracts/lib/tree/binary/BinaryMerkleProof.sol";
import "blobstream-contracts/lib/verifier/DAVerifier.sol";
import "blobstream-contracts/lib/tree/namespace/NamespaceMerkleTree.sol";
import "blobstream-contracts/lib/tree/Types.sol";

/// @title CelestiaDAProofValidator
/// @notice Validates Celestia DA certificates and preimage proofs for the Arbitrum fraud-proof system.
///
/// Certificate format (92 bytes, big-endian):
///   [0]      CustomDAHeaderFlag  = 0x01
///   [1]      CelestiaProviderTag = 0x63
///   [2..3]   version             (uint16, must be 1)
///   [4..11]  blockHeight         (uint64)
///   [12..19] start               (uint64)  – ODS share index within a row
///   [20..27] sharesLength        (uint64)
///   [28..59] txCommitment        (bytes32) – blob commitment used for retrieval
///   [60..91] dataRoot            (bytes32) – Celestia block data hash
///
/// Read-preimage proof format (passed in `proof` to validateReadPreimage):
///   [certSize(8)][certificate(92)][version(1)=0x01][preimageSize(8)][preimage][blobstreamProofData]
///
/// blobstreamProofData is ABI-encoded as:
///   (address blobstreamAddr, NamespaceNode namespaceNode, BinaryMerkleProof rowProof, AttestationProof attestationProof)
///
/// Certificate-validity proof format (passed in `proof` to validateCertificate):
///   [certSize(8)][certificate(92)][claimedValid(1)]
///
contract CelestiaDAProofValidator is ICustomDAProofValidator {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    uint256 private constant CERT_SIZE_FIELD_LEN  = 8;
    uint256 private constant CLAIMED_VALID_LEN     = 1;
    uint256 private constant PROOF_VERSION_LEN     = 1;
    uint256 private constant PREIMAGE_SIZE_FIELD   = 8;

    bytes1  private constant CERT_HEADER           = 0x01;
    bytes1  private constant CELESTIA_PROVIDER_TAG = 0x63;
    uint16  private constant CERT_VERSION          = 1;
    uint256 private constant CERT_V1_LEN           = 92;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    address public immutable blobstreamX;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor(address _blobstreamX) {
        blobstreamX = _blobstreamX;
    }

    // -------------------------------------------------------------------------
    // ICustomDAProofValidator
    // -------------------------------------------------------------------------

    /// @inheritdoc ICustomDAProofValidator
    /// @dev Proof layout:
    ///   [0..7]                  certSize (8 bytes, big-endian uint64)
    ///   [8..8+certSize-1]       certificate
    ///   [8+certSize]            version byte (must be 0x01)
    ///   [8+certSize+1..+8]      preimageSize (8 bytes, big-endian uint64)
    ///   [8+certSize+9..+N]      preimage data (N = preimageSize bytes)
    ///   [8+certSize+9+N..]      blobstreamProofData (ABI-encoded)
    function validateReadPreimage(
        bytes32 certHash,
        uint256 offset,
        bytes calldata proof
    ) external view override returns (bytes memory preimageChunk) {
        // ------------------------------------------------------------------
        // 1. Extract and authenticate the certificate
        // ------------------------------------------------------------------
        require(proof.length >= CERT_SIZE_FIELD_LEN, "Proof too short: certSize field missing");

        uint256 certSize = uint256(uint64(bytes8(proof[0:CERT_SIZE_FIELD_LEN])));
        uint256 afterCert = CERT_SIZE_FIELD_LEN + certSize;

        require(proof.length >= afterCert, "Proof too short: certificate truncated");

        bytes calldata certificate = proof[CERT_SIZE_FIELD_LEN:afterCert];

        // The OSP already verified certHash == keccak256(certificate) before calling us,
        // but we double-check for defence in depth.
        require(keccak256(certificate) == certHash, "Certificate hash mismatch");

        // Structural validation of the certificate itself
        _requireValidCertStructure(certificate);

        // ------------------------------------------------------------------
        // 2. Parse preimage metadata
        // ------------------------------------------------------------------
        uint256 versionOffset    = afterCert;
        uint256 preimSzOffset    = versionOffset + PROOF_VERSION_LEN;
        uint256 preimDataOffset  = preimSzOffset + PREIMAGE_SIZE_FIELD;

        require(proof.length >= preimDataOffset, "Proof too short: preimage header missing");

        uint8 version = uint8(proof[versionOffset]);
        require(version == 0x01, "Invalid proof version");

        uint256 preimageSize = uint256(uint64(bytes8(proof[preimSzOffset:preimDataOffset])));
        uint256 proofDataOffset = preimDataOffset + preimageSize;

        require(proof.length >= proofDataOffset, "Proof too short: preimage data truncated");

        bytes calldata preimage   = proof[preimDataOffset:proofDataOffset];
        bytes calldata proofData  = proof[proofDataOffset:];

        // ------------------------------------------------------------------
        // 3. Validate the Blobstream inclusion proof
        // ------------------------------------------------------------------
        _requireBlobstreamProof(certificate, proofData);

        // ------------------------------------------------------------------
        // 4. Return the 32-byte chunk at the requested offset
        // ------------------------------------------------------------------
        if (offset >= preimageSize) {
            return new bytes(0);
        }
        uint256 remaining = preimageSize - offset;
        uint256 chunkSize = remaining > 32 ? 32 : remaining;
        bytes memory chunk = new bytes(chunkSize);
        for (uint256 i = 0; i < chunkSize; i++) {
            chunk[i] = preimage[offset + i];
        }
        return chunk;
    }

    /// @inheritdoc ICustomDAProofValidator
    /// @dev Proof layout:
    ///   [0..7]               certSize (8 bytes, big-endian uint64)
    ///   [8..8+certSize-1]    certificate
    ///   [8+certSize]         claimedValid (1 byte: 0x01 = valid, 0x00 = invalid)
    ///
    /// IMPORTANT: This function MUST NOT revert for invalid certificates –
    /// it returns false instead.  Only truly unexpected conditions should revert.
    function validateCertificate(
        bytes calldata proof
    ) external pure override returns (bool isValid) {
        // ------------------------------------------------------------------
        // 1. Minimum length guard
        // ------------------------------------------------------------------
        if (proof.length < CERT_SIZE_FIELD_LEN + CERT_V1_LEN + CLAIMED_VALID_LEN) {
            return false;
        }

        uint256 certSize = uint256(uint64(bytes8(proof[0:CERT_SIZE_FIELD_LEN])));
        uint256 afterCert = CERT_SIZE_FIELD_LEN + certSize;

        if (proof.length < afterCert + CLAIMED_VALID_LEN) {
            return false;
        }

        bytes calldata certificate = proof[CERT_SIZE_FIELD_LEN:afterCert];

        // ------------------------------------------------------------------
        // 2. Structural certificate validation (returns false, never reverts)
        // ------------------------------------------------------------------
        if (!_isValidCertStructure(certificate)) {
            return false;
        }

        // ------------------------------------------------------------------
        // 3. Read the off-chain validator's claimed validity
        //    The OSP will verify this claim independently against our return value.
        // ------------------------------------------------------------------
        uint8 claimedValid = uint8(proof[afterCert]);
        return claimedValid == 1;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// @notice Returns true iff the certificate bytes are structurally valid.
    ///         Never reverts.
    function _isValidCertStructure(bytes calldata cert) internal pure returns (bool) {
        if (cert.length != CERT_V1_LEN) return false;
        if (cert[0] != CERT_HEADER)           return false;
        if (cert[1] != CELESTIA_PROVIDER_TAG) return false;

        uint16 version = uint16(bytes2(cert[2:4]));
        if (version != CERT_VERSION) return false;

        // blockHeight at [4..11] must be non-zero
        uint64 blockHeight = uint64(bytes8(cert[4:12]));
        if (blockHeight == 0) return false;

        // sharesLength at [20..27] must be non-zero
        uint64 sharesLength = uint64(bytes8(cert[20:28]));
        if (sharesLength == 0) return false;

        // txCommitment at [28..59] must be non-zero
        bytes32 txCommitment = bytes32(cert[28:60]);
        if (txCommitment == bytes32(0)) return false;

        // dataRoot at [60..91] must be non-zero
        bytes32 dataRoot = bytes32(cert[60:92]);
        if (dataRoot == bytes32(0)) return false;

        return true;
    }

    /// @notice Asserts structural validity and reverts if the certificate is malformed.
    ///         Used in validateReadPreimage where a malformed cert is a protocol error.
    function _requireValidCertStructure(bytes calldata cert) internal pure {
        require(cert.length == CERT_V1_LEN,            "Invalid certificate length");
        require(cert[0] == CERT_HEADER,                "Invalid certificate header");
        require(cert[1] == CELESTIA_PROVIDER_TAG,      "Invalid Celestia provider tag");
        uint16 version = uint16(bytes2(cert[2:4]));
        require(version == CERT_VERSION,               "Unsupported certificate version");
        require(uint64(bytes8(cert[4:12]))  != 0,      "Zero blockHeight in certificate");
        require(uint64(bytes8(cert[20:28])) != 0,      "Zero sharesLength in certificate");
        require(bytes32(cert[28:60]) != bytes32(0),    "Zero txCommitment in certificate");
        require(bytes32(cert[60:92]) != bytes32(0),    "Zero dataRoot in certificate");
    }

    /// @notice Decodes the blobstream proof data and verifies the row-root inclusion.
    /// @dev proofData is ABI-encoded as:
    ///   (address blobstreamAddr, NamespaceNode namespaceNode,
    ///    BinaryMerkleProof rowProof, AttestationProof attestationProof)
    ///
    ///   The certificate's blockHeight and dataRoot are validated against the
    ///   attestation proof to ensure they match what is committed in Blobstream.
    function _requireBlobstreamProof(
        bytes calldata certificate,
        bytes calldata proofData
    ) internal view {
        require(proofData.length > 0, "Missing Blobstream proof data");

        (
            ,
            NamespaceNode memory namespaceNode,
            BinaryMerkleProof memory rowProof,
            AttestationProof memory attestationProof
        ) = abi.decode(proofData, (address, NamespaceNode, BinaryMerkleProof, AttestationProof));

        // Cross-check the proof height and data root against the certificate first.
        uint64 certHeight    = uint64(bytes8(certificate[4:12]));
        bytes32 certDataRoot = bytes32(certificate[60:92]);

        require(
            attestationProof.tuple.height == certHeight,
            "Blobstream proof height does not match certificate blockHeight"
        );
        require(
            attestationProof.tuple.dataRoot == certDataRoot,
            "Blobstream proof dataRoot does not match certificate dataRoot"
        );

        // verifyRowRootToDataRootTupleRoot (v3.1.0) requires the data root as a
        // 5th argument; use the value from the attestation tuple (already validated
        // above to equal certDataRoot).
        // Use the immutable blobstreamX address; ignore the encoded address for security.
        (bool valid, ) = DAVerifier.verifyRowRootToDataRootTupleRoot(
            IDAOracle(blobstreamX),
            namespaceNode,
            rowProof,
            attestationProof,
            attestationProof.tuple.dataRoot
        );
        require(valid, "Invalid Blobstream row-root inclusion proof");
    }
}
