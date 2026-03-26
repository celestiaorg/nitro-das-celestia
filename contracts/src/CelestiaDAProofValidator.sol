// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@nitro-contracts/osp/ICustomDAProofValidator.sol";
import "../lib/IDAOracle.sol";
import "../lib/DAVerifier.sol";

/// @title CelestiaDAProofValidator
/// @notice Validates Celestia DA certificates and read-preimage proofs.
///
/// This contract validates two types of proofs:
/// 1. Read preimage proofs - for retrieving data from Celestia
/// 2. Certificate validity proofs - for validating certificate authenticity
///
/// ============================================================================
///                         CELESTIA DA CERTIFICATE
/// ============================================================================
///
/// The certificate is a 92-byte blob that identifies a data commitment
/// on Celestia. It carries the block height, share range, and data root.
///
/// Certificate V1 Layout (92 bytes):
/// +--------+----------+---------+------------------------------+
/// | Offset |   Size   |  Type   |        Description           |
/// +--------+----------+---------+------------------------------+
/// | 0      | 1 byte   | uint8   | header = 0x01                |
/// | 1      | 1 byte   | uint8   | providerType = 0x63 ('c')    |
/// | 2-3    | 2 bytes  | uint16  | certVersion = 1              |
/// | 4-11   | 8 bytes  | uint64  | blockHeight                  |
/// | 12-19  | 8 bytes  | uint64  | start (first share index)    |
/// | 20-27  | 8 bytes  | uint64  | sharesLength                 |
/// | 28-59  | 32 bytes | bytes32 | txCommitment                 |
/// | 60-91  | 32 bytes | bytes32 | dataRoot                     |
/// +--------+----------+---------+------------------------------+
///
/// ============================================================================
///                           FULL PROOF LAYOUT
/// ============================================================================
///
/// Full proofs passed to this contract have the following structure:
///
///     [certSize (8 bytes)][certificate (certSize bytes)][customProof]
///
///     +------------------+-------------------+------------------+
///     |    certSize      |    certificate    |    customProof   |
///     |    (8 bytes)     |    (92 bytes)     |    (variable)    |
///     +------------------+-------------------+------------------+
///
/// ============================================================================
///                          CUSTOM PROOF FORMATS
/// ============================================================================
///
/// READ PREIMAGE PROOF (for data retrieval):
/// +---------------------------+--------+------+-------------------+
/// | Field                     | Offset | Size | Description       |
/// +---------------------------+--------+------+-------------------+
/// | version                   | 0      | 1    | = 0x01            |
/// | offset (in payload)       | 1      | 8    | uint64            |
/// | payloadSize               | 9      | 8    | uint64            |
/// | chunkLen                  | 17     | 1    | uint8             |
/// | firstShareIndexInBlob     | 18     | 8    | uint64            |
/// | shareCount                | 26     | 1    | uint8             |
/// | payloadSizeProofLen       | 27     | 8    | uint64            |
/// | payloadSizeProof          | 35     | var  | abi.encode(addr,  |
/// |                           |        |      |   SharesProof)    |
/// | sharesProof               | var    | var  | abi.encode(addr,  |
/// |                           |        |      |   SharesProof)    |
/// +---------------------------+--------+------+-------------------+
///
/// CERTIFICATE VALIDITY PROOF (for authentication):
/// +---------------------------+--------+------+-------------------+
/// | Field                     | Offset | Size | Description       |
/// +---------------------------+--------+------+-------------------+
/// | claimedValid              | 0      | 1    | bool (= 0x01)     |
/// | version                   | 1      | 1    | = 0x01            |
/// | attestationProof          | 2      | var  | abi.encode(       |
/// |                           |        |      |   AttestationProof|
/// +---------------------------+--------+------+-------------------+
///
/// ============================================================================
///                          CELESTIA SHARE FORMAT
/// ============================================================================
///
/// Celestia data is stored in 512-byte shares with the following layout:
///
/// FIRST SHARE (contains sequence length prefix):
/// +-------------------------------------------------------------+
/// |  Namespace (29 bytes)  | Info (1) | Sequence Len (4 bytes)  |
/// |       bytes 0-28       | byte 29  |       bytes 30-33       |
/// +------------------------+----------+-------------------------+
/// |                    Payload Data (478 bytes max)             |
/// |                         bytes 34-511                        |
/// +-------------------------------------------------------------+
///
/// CONTINUATION SHARE (shares 1, 2, ...):
/// +-------------------------------------------------------------+
/// |  Namespace (29 bytes)  | Info (1) |     Payload Data        |
/// |       bytes 0-28       | byte 29  |    bytes 30-511 (482)   |
/// +-------------------------------------------------------------+
///
/// @dev Onchain certificate validity is defined by certificate structure and
///      Blobstream attestation of the certificate's (blockHeight, dataRoot) tuple.
///      `txCommitment` is carried in the certificate format but is not independently
///      re-derived or enforced in Solidity.
contract CelestiaDAProofValidator is ICustomDAProofValidator {
    // =========================================================================
    //                          CERTIFICATE CONSTANTS
    // =========================================================================

    /// @notice Certificate V1 total length in bytes
    uint256 private constant CERT_V1_LEN = 92;

    /// @notice Magic header byte for Celestia DA certificates
    bytes1 private constant CERT_HEADER = 0x01;

    /// @notice Provider type tag for Celestia ('c' = 0x63)
    bytes1 private constant CELESTIA_PROVIDER_TAG = 0x63;

    /// @notice Current supported certificate version
    uint16 private constant CERT_VERSION = 1;

    /// @notice Size of uint64 fields in bytes (used throughout)
    uint256 private constant UINT64_SIZE = 8;

    /// @notice Certificate field offsets within the 92-byte certificate
    /// @dev These match the layout documented in the contract header
    uint256 private constant CERT_HEADER_OFFSET = 0;
    uint256 private constant CERT_PROVIDER_TYPE_OFFSET = 1;
    uint256 private constant CERT_VERSION_OFFSET = 2;
    uint256 private constant CERT_BLOCK_HEIGHT_OFFSET = 4;
    uint256 private constant CERT_START_OFFSET = 12;
    uint256 private constant CERT_SHARES_LENGTH_OFFSET = 20;
    uint256 private constant CERT_TX_COMMITMENT_OFFSET = 28;
    uint256 private constant CERT_DATA_ROOT_OFFSET = 60;

    // =========================================================================
    //                         PROOF HEADER CONSTANTS
    // =========================================================================

    /// @notice Version byte for read preimage proofs
    uint8 private constant READ_PROOF_VERSION = 0x01;

    /// @notice Version byte for validity proofs
    uint8 private constant VALIDITY_PROOF_VERSION = 0x01;

    /// @notice Total length of read proof header before proof bodies
    /// @dev 1 (version) + 8 (offset) + 8 (payloadSize) + 1 (chunkLen) + 8 (firstShareIndexInBlob) + 1 (shareCount) + 8 (payloadSizeProofLen) = 35
    uint256 private constant READ_PROOF_HEADER_LEN = 35;

    /// @notice Read proof header field offsets (after version byte)
    uint256 private constant READ_PROOF_OFFSET_FIELD = 1;
    uint256 private constant READ_PROOF_PAYLOAD_SIZE_FIELD = 9;
    uint256 private constant READ_PROOF_CHUNK_LEN_FIELD = 17;
    uint256 private constant READ_PROOF_FIRST_SHARE_INDEX_FIELD = 18;
    uint256 private constant READ_PROOF_SHARE_COUNT_FIELD = 26;
    uint256 private constant READ_PROOF_PAYLOAD_SIZE_PROOF_LEN_FIELD = 27;

    // =========================================================================
    //                        CELESTIA SHARE CONSTANTS
    // =========================================================================

    /// @notice Size of a Celestia share in bytes
    uint256 private constant CELESTIA_SHARE_SIZE = 512;

    /// @notice Size of namespace ID prefix in each share
    uint256 private constant CELESTIA_NAMESPACE_SIZE = 29;

    /// @notice Size of info byte in each share
    uint256 private constant CELESTIA_SHARE_INFO_SIZE = 1;

    /// @notice Size of sequence length field in first share (4 bytes = uint32)
    uint256 private constant CELESTIA_SEQUENCE_LEN_SIZE = 4;

    /// @notice Offset where sequence length starts in first share
    /// @dev = namespace_size + info_size = 29 + 1 = 30
    uint256 private constant CELESTIA_SEQUENCE_LEN_OFFSET = CELESTIA_NAMESPACE_SIZE + CELESTIA_SHARE_INFO_SIZE;

    /// @notice Offset where payload data starts in first share
    /// @dev = namespace_size + info_size + sequence_len_size = 29 + 1 + 4 = 34
    uint256 private constant CELESTIA_FIRST_SHARE_PAYLOAD_START =
        CELESTIA_SEQUENCE_LEN_OFFSET + CELESTIA_SEQUENCE_LEN_SIZE;

    /// @notice Offset where payload data starts in continuation shares
    /// @dev = namespace_size + info_size = 29 + 1 = 30
    uint256 private constant CELESTIA_CONT_SHARE_PAYLOAD_START = CELESTIA_NAMESPACE_SIZE + CELESTIA_SHARE_INFO_SIZE;

    /// @notice Maximum payload bytes in first share
    /// @dev = 512 - 34 = 478 bytes
    uint256 private constant CELESTIA_FIRST_SHARE_PAYLOAD_CAP = CELESTIA_SHARE_SIZE - CELESTIA_FIRST_SHARE_PAYLOAD_START;

    /// @notice Maximum payload bytes in continuation shares
    /// @dev = 512 - 30 = 482 bytes
    uint256 private constant CELESTIA_CONT_SHARE_PAYLOAD_CAP = CELESTIA_SHARE_SIZE - CELESTIA_CONT_SHARE_PAYLOAD_START;

    /// @notice Maximum size of preimage chunks returned (32 bytes)
    uint256 private constant PREIMAGE_CHUNK_SIZE = 32;

    /// @notice Default maximum message size: 32 MiB
    uint256 private constant DEFAULT_MAX_MESSAGE_SIZE = 32 * 1024 * 1024;

    // =========================================================================
    //                             STATE VARIABLES
    // =========================================================================

    /// @notice Address of the BlobstreamX oracle contract for attestation verification
    address public immutable blobstreamX;

    /// @notice Owner address authorized to update configuration
    address public owner;

    /// @notice Maximum allowed message size in bytes
    uint256 private maxMessageSize;

    // =========================================================================
    //                               EVENTS
    // =========================================================================

    event OwnerUpdated(address indexed previousOwner, address indexed newOwner);
    event MaxMessageSizeUpdated(uint256 previousMaxMessageSize, uint256 newMaxMessageSize);

    // =========================================================================
    //                              MODIFIERS
    // =========================================================================

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // =========================================================================
    //                             CONSTRUCTOR
    // =========================================================================

    constructor(address _blobstreamX) {
        require(_blobstreamX != address(0), "Invalid blobstreamX address");
        blobstreamX = _blobstreamX;
        owner = msg.sender;
        maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE;
    }

    // =========================================================================
    //                           ADMIN FUNCTIONS
    // =========================================================================

    function getMaxMessageSize() external view returns (uint256) {
        return maxMessageSize;
    }

    function setMaxMessageSize(uint256 _maxMessageSize) external onlyOwner {
        require(_maxMessageSize > 0, "Invalid max message size");
        uint256 previous = maxMessageSize;
        maxMessageSize = _maxMessageSize;
        emit MaxMessageSizeUpdated(previous, _maxMessageSize);
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        address previous = owner;
        owner = newOwner;
        emit OwnerUpdated(previous, newOwner);
    }

    // =========================================================================
    //                          PROOF VALIDATION
    // =========================================================================

    /// @notice Validates a read preimage proof and returns the requested data chunk
    /// @param certHash The expected keccak256 hash of the certificate
    /// @param offset The byte offset within the payload to read from
    /// @param proof The full proof data containing [certSize][certificate][customProof]
    /// @return preimageChunk The requested chunk of preimage data (up to 32 bytes)
    ///
    /// Proof format:
    ///   - First 8 bytes: certificate size (uint64)
    ///   - Next certSize bytes: the certificate
    ///   - Remaining bytes: custom read proof with:
    ///       * version (1 byte)
    ///       * offset in payload (8 bytes)
    ///       * payloadSize (8 bytes)
    ///       * chunkLen (1 byte)
    ///       * firstShareIndexInBlob (8 bytes)
    ///       * shareCount (1 byte)
    ///       * payloadSizeProofLen (8 bytes)
    ///       * abi.encode(address, SharesProof) for payloadSizeProof (first share only)
    ///       * abi.encode(address, SharesProof) for sharesProof (requested chunk shares)
    function validateReadPreimage(bytes32 certHash, uint256 offset, bytes calldata proof)
        external
        view
        override
        returns (bytes memory preimageChunk)
    {
        // Parse the proof to extract certificate and custom proof data
        (bytes calldata certificate, bytes calldata customProof) = _parseFullProof(proof);

        // Verify the certificate matches the expected hash
        require(keccak256(certificate) == certHash, "Certificate hash mismatch");
        _requireValidCertStructure(certificate);

        // Parse and validate the read proof header
        require(customProof.length >= READ_PROOF_HEADER_LEN, "Proof too short: custom read proof header missing");
        require(uint8(customProof[0]) == READ_PROOF_VERSION, "Invalid read proof version");

        ReadProofHeader memory header = _decodeReadProofHeader(customProof);
        require(header.offset == offset, "Offset mismatch");
        require(header.chunkLen == _expectedChunkLen(offset, header.payloadSize), "Invalid chunkLen");

        // Extract certificate fields
        CertificateData memory certData = _extractCertificateData(certificate);

        // Validate that the requested shares fall within the certificate's range
        _validateShareRange(certData, offset, header.firstShareIndexInBlob, header.shareCount);

        // Verify the shares inclusion proof via Blobstream
        uint256 payloadSizeProofLen = _readUint64(customProof, READ_PROOF_PAYLOAD_SIZE_PROOF_LEN_FIELD);
        uint256 payloadSizeProofStart = READ_PROOF_HEADER_LEN;
        uint256 payloadSizeProofEnd = payloadSizeProofStart + payloadSizeProofLen;
        require(customProof.length >= payloadSizeProofEnd, "Payload size proof truncated");

        bytes calldata payloadSizeProofData = customProof[payloadSizeProofStart:payloadSizeProofEnd];
        bytes calldata sharesProofData = customProof[payloadSizeProofEnd:];
        require(sharesProofData.length > 0, "Missing shares proof data");

        address encodedBlobstream;
        SharesProof memory sharesProof;
        (encodedBlobstream, sharesProof) = abi.decode(sharesProofData, (address, SharesProof));
        require(encodedBlobstream == blobstreamX, "Blobstream address mismatch");

        // Verify the shares proof matches the certificate data
        require(
            sharesProof.attestationProof.tuple.height == certData.blockHeight,
            "Shares proof height does not match certificate blockHeight"
        );
        require(
            sharesProof.attestationProof.tuple.dataRoot == certData.dataRoot,
            "Shares proof dataRoot does not match certificate dataRoot"
        );

        (bool valid,) = DAVerifier.verifySharesToDataRootTupleRoot(IDAOracle(blobstreamX), sharesProof);
        require(valid, "Invalid Celestia shares inclusion proof");

        if (header.firstShareIndexInBlob == certData.start) {
            require(sharesProof.data.length > 0, "Shares count mismatch");
            require(header.payloadSize == _decodeSequenceLen(sharesProof.data[0]), "Payload size mismatch");
        } else {
            require(payloadSizeProofData.length > 0, "Missing payload size proof data");

            SharesProof memory payloadSizeProof;
            (encodedBlobstream, payloadSizeProof) = abi.decode(payloadSizeProofData, (address, SharesProof));
            require(encodedBlobstream == blobstreamX, "Blobstream address mismatch");

            require(
                payloadSizeProof.attestationProof.tuple.height == certData.blockHeight,
                "Payload size proof height does not match certificate blockHeight"
            );
            require(
                payloadSizeProof.attestationProof.tuple.dataRoot == certData.dataRoot,
                "Payload size proof dataRoot does not match certificate dataRoot"
            );

            (bool payloadSizeProofValid,) =
                DAVerifier.verifySharesToDataRootTupleRoot(IDAOracle(blobstreamX), payloadSizeProof);
            require(payloadSizeProofValid, "Invalid payload size inclusion proof");
            require(payloadSizeProof.data.length == 1, "Invalid payload size proof share count");
            require(payloadSizeProof.data[0].length == CELESTIA_SHARE_SIZE, "Invalid share length");
            require(header.payloadSize == _decodeSequenceLen(payloadSizeProof.data[0]), "Payload size mismatch");
        }

        // Validate shares data
        require(sharesProof.data.length == header.shareCount, "Shares count mismatch");
        for (uint256 i = 0; i < header.shareCount; i++) {
            require(sharesProof.data[i].length == CELESTIA_SHARE_SIZE, "Invalid share length");
        }

        // Extract the requested chunk from the shares
        return _extractChunk(sharesProof, offset, header.chunkLen, header.payloadSize);
    }

    /// @notice Validates a certificate's authenticity via Blobstream attestation
    /// @param proof The proof data containing [certSize][certificate][claimedValid][version][AttestationProof]
    /// @return isValid True if the certificate is valid, false otherwise
    ///
    /// Proof format:
    ///   - First 8 bytes: certificate size (uint64)
    ///   - Next certSize bytes: the certificate
    ///   - Next 1 byte: claimedValid (must be 0x01)
    ///   - Next 1 byte: version (must be 0x01)
    ///   - Remaining: abi.encode(AttestationProof)
    function validateCertificate(bytes calldata proof) external view override returns (bool isValid) {
        if (proof.length < UINT64_SIZE + 2) {
            return false;
        }

        uint256 certSize = _readUint64(proof, 0);
        uint256 afterCert = UINT64_SIZE + certSize;
        if (proof.length < afterCert + 2) {
            return false;
        }

        bytes calldata certificate = proof[UINT64_SIZE:afterCert];
        if (!_isValidCertStructure(certificate)) {
            return false;
        }

        // Skip the claimedValid byte and validate version
        bytes calldata custom = proof[afterCert + 1:];
        if (custom.length < 1) {
            return false;
        }
        if (uint8(custom[0]) != VALIDITY_PROOF_VERSION) {
            return false;
        }

        // Decode attestation proof
        bytes calldata attestationProofData = custom[1:];
        if (attestationProofData.length == 0) {
            return false;
        }

        AttestationProof memory attestationProof;
        try this.decodeAttestationProof(attestationProofData) returns (AttestationProof memory decoded) {
            attestationProof = decoded;
        } catch {
            return false;
        }

        // Verify attestation matches certificate
        CertificateData memory certData = _extractCertificateData(certificate);
        if (attestationProof.tuple.height != certData.blockHeight) {
            return false;
        }
        if (attestationProof.tuple.dataRoot != certData.dataRoot) {
            return false;
        }

        // Verify via Blobstream
        return IDAOracle(blobstreamX).verifyAttestation(
            attestationProof.tupleRootNonce, attestationProof.tuple, attestationProof.proof
        );
    }

    /// @notice External helper for try/catch decoding of AttestationProof
    /// @dev This allows validateCertificate to return false instead of reverting
    function decodeAttestationProof(bytes calldata proofData) external pure returns (AttestationProof memory) {
        return abi.decode(proofData, (AttestationProof));
    }

    // =========================================================================
    //                        PROOF PARSING HELPERS
    // =========================================================================

    /// @notice Parses the full proof to extract certificate and custom proof
    /// @param proof The full proof bytes: [certSize][certificate][customProof]
    /// @return certificate The extracted certificate bytes
    /// @return customProof The extracted custom proof bytes
    function _parseFullProof(bytes calldata proof)
        internal
        pure
        returns (bytes calldata certificate, bytes calldata customProof)
    {
        require(proof.length >= UINT64_SIZE, "Proof too short: certSize field missing");

        uint256 certSize = _readUint64(proof, 0);
        uint256 afterCert = UINT64_SIZE + certSize;
        require(proof.length >= afterCert, "Proof too short: certificate truncated");

        certificate = proof[UINT64_SIZE:afterCert];
        customProof = proof[afterCert:];
    }

    /// @notice Structure to hold decoded read proof header fields
    struct ReadProofHeader {
        uint256 offset;
        uint256 payloadSize;
        uint256 chunkLen;
        uint256 firstShareIndexInBlob;
        uint256 shareCount;
    }

    /// @notice Decodes the read proof header from custom proof data
    /// @param custom The custom proof data starting with version byte
    /// @return header The decoded ReadProofHeader struct
    function _decodeReadProofHeader(bytes calldata custom) internal pure returns (ReadProofHeader memory header) {
        header.offset = _readUint64(custom, READ_PROOF_OFFSET_FIELD);
        header.payloadSize = _readUint64(custom, READ_PROOF_PAYLOAD_SIZE_FIELD);
        header.chunkLen = uint8(custom[READ_PROOF_CHUNK_LEN_FIELD]);
        header.firstShareIndexInBlob = _readUint64(custom, READ_PROOF_FIRST_SHARE_INDEX_FIELD);
        header.shareCount = uint8(custom[READ_PROOF_SHARE_COUNT_FIELD]);
    }

    /// @notice Structure to hold extracted certificate fields
    struct CertificateData {
        uint64 blockHeight;
        uint256 start;
        uint256 sharesLength;
        bytes32 txCommitment;
        bytes32 dataRoot;
    }

    /// @notice Extracts all relevant fields from a certificate
    /// @param cert The certificate bytes (must be 92 bytes)
    /// @return data The extracted CertificateData struct
    function _extractCertificateData(bytes calldata cert) internal pure returns (CertificateData memory data) {
        data.blockHeight = _certBlockHeight(cert);
        data.start = _certStart(cert);
        data.sharesLength = _certSharesLength(cert);
        data.txCommitment = _certTxCommitment(cert);
        data.dataRoot = _certDataRoot(cert);
    }

    // =========================================================================
    //                       CERTIFICATE VALIDATION
    // =========================================================================

    /// @notice Validates certificate structure and reverts if invalid
    /// @param cert The certificate bytes to validate
    function _requireValidCertStructure(bytes calldata cert) internal pure {
        require(cert.length == CERT_V1_LEN, "Invalid certificate length");
        require(cert[CERT_HEADER_OFFSET] == CERT_HEADER, "Invalid certificate header");
        require(cert[CERT_PROVIDER_TYPE_OFFSET] == CELESTIA_PROVIDER_TAG, "Invalid Celestia provider tag");
        require(_readUint16(cert, CERT_VERSION_OFFSET) == CERT_VERSION, "Unsupported certificate version");
        require(_certBlockHeight(cert) != 0, "Zero blockHeight in certificate");
        require(_certSharesLength(cert) != 0, "Zero sharesLength in certificate");
        require(_certTxCommitment(cert) != bytes32(0), "Zero txCommitment in certificate");
        require(_certDataRoot(cert) != bytes32(0), "Zero dataRoot in certificate");
    }

    /// @notice Checks if certificate structure is valid (returns bool, no revert)
    /// @param cert The certificate bytes to check
    /// @return True if certificate structure is valid
    function _isValidCertStructure(bytes calldata cert) internal pure returns (bool) {
        if (cert.length != CERT_V1_LEN) return false;
        if (cert[CERT_HEADER_OFFSET] != CERT_HEADER) return false;
        if (cert[CERT_PROVIDER_TYPE_OFFSET] != CELESTIA_PROVIDER_TAG) return false;
        if (_readUint16(cert, CERT_VERSION_OFFSET) != CERT_VERSION) return false;
        if (_certBlockHeight(cert) == 0) return false;
        if (_certSharesLength(cert) == 0) return false;
        if (_certTxCommitment(cert) == bytes32(0)) return false;
        if (_certDataRoot(cert) == bytes32(0)) return false;

        return true;
    }

    /// @notice Validates that the requested share range falls within certificate bounds
    /// @param certData The certificate data
    /// @param offset The offset within the payload data
    /// @param firstShareIndexInBlob The index of the first requested share in the blob
    /// @param shareCount The number of shares requested (1 or 2)
    function _validateShareRange(
        CertificateData memory certData,
        uint256 offset,
        uint256 firstShareIndexInBlob,
        uint256 shareCount
    ) internal pure {
        // Calculate which share (0-indexed within the blob) the offset falls into
        uint256 shareRel = _payloadOffsetToShareRel(offset);
        uint256 expectedFirstShareIndex = certData.start + shareRel;

        require(firstShareIndexInBlob == expectedFirstShareIndex, "Invalid firstShareIndexInBlob");
        require(firstShareIndexInBlob >= certData.start, "Share index before cert range");
        require(
            firstShareIndexInBlob + shareCount <= certData.start + certData.sharesLength, "Share index past cert range"
        );
        require(shareCount == 1 || shareCount == 2, "Invalid shareCount");
    }

    // =========================================================================
    //                        SHARE OFFSET CALCULATIONS
    // =========================================================================

    /// @notice Converts a payload byte offset to the share index (0-indexed)
    /// @param payloadOffset The offset within the payload data
    /// @return The share index (0 for first share, 1+ for continuation shares)
    ///
    /// First share holds up to CELESTIA_FIRST_SHARE_PAYLOAD_CAP bytes (478).
    /// Each continuation share holds up to CELESTIA_CONT_SHARE_PAYLOAD_CAP bytes (482).
    function _payloadOffsetToShareRel(uint256 payloadOffset) internal pure returns (uint256) {
        if (payloadOffset < CELESTIA_FIRST_SHARE_PAYLOAD_CAP) {
            return 0;
        }
        return 1 + ((payloadOffset - CELESTIA_FIRST_SHARE_PAYLOAD_CAP) / CELESTIA_CONT_SHARE_PAYLOAD_CAP);
    }

    /// @notice Calculates the total payload bytes covered by shares up to shareRel
    /// @param shareRel The share index (0-indexed)
    /// @return The total payload bytes that fit in shares [0, shareRel)
    function _payloadStartForShareRel(uint256 shareRel) internal pure returns (uint256) {
        if (shareRel == 0) {
            return 0;
        }
        return CELESTIA_FIRST_SHARE_PAYLOAD_CAP + (shareRel - 1) * CELESTIA_CONT_SHARE_PAYLOAD_CAP;
    }

    /// @notice Returns the maximum payload capacity for a given share
    /// @param shareRel The share index (0-indexed)
    /// @return The maximum payload bytes that can fit in this share
    function _payloadCapacityForShareRel(uint256 shareRel) internal pure returns (uint256) {
        if (shareRel == 0) {
            return CELESTIA_FIRST_SHARE_PAYLOAD_CAP;
        }
        return CELESTIA_CONT_SHARE_PAYLOAD_CAP;
    }

    /// @notice Returns the byte offset where payload data starts within a share
    /// @param shareRel The share index (0-indexed)
    /// @return The byte offset within the share where payload data begins
    function _payloadDataStartInShare(uint256 shareRel) internal pure returns (uint256) {
        if (shareRel == 0) {
            return CELESTIA_FIRST_SHARE_PAYLOAD_START;
        }
        return CELESTIA_CONT_SHARE_PAYLOAD_START;
    }

    // =========================================================================
    //                          CHUNK EXTRACTION
    // =========================================================================

    /// @notice Extracts a chunk of data from the provided shares
    /// @param sharesProof The shares proof containing the share data
    /// @param offset The requested offset within the payload
    /// @param chunkLen The number of bytes to extract
    /// @param payloadSize The total size of the payload
    /// @return out The extracted chunk bytes
    function _extractChunk(SharesProof memory sharesProof, uint256 offset, uint256 chunkLen, uint256 payloadSize)
        internal
        pure
        returns (bytes memory out)
    {
        // Calculate which share within the certificate we're reading from
        uint256 firstRel = _payloadOffsetToShareRel(offset);

        // Get the first share and validate it has the expected header
        bytes memory firstShare = sharesProof.data[0];
        uint256 firstSharePayloadOffset = _payloadDataStartInShare(firstRel);
        require(firstShare.length >= firstSharePayloadOffset, "Invalid share header");

        // Handle empty chunk case
        if (chunkLen == 0) {
            return new bytes(0);
        }

        // Verify the requested chunk is within payload bounds
        require(offset + chunkLen <= payloadSize, "Chunk outside payload bounds");

        // Calculate where within the share's payload the requested offset falls
        uint256 sharePayloadStart = _payloadStartForShareRel(firstRel);
        uint256 sharePayloadCap = _payloadCapacityForShareRel(firstRel);
        require(offset >= sharePayloadStart, "Offset before proven share payload");

        uint256 localOffset = offset - sharePayloadStart;
        require(localOffset < sharePayloadCap, "Offset outside proven share payload");

        // Allocate output buffer
        out = new bytes(chunkLen);

        // Calculate how many bytes we can take from the first share
        uint256 firstAvailable = sharePayloadCap - localOffset;
        uint256 firstTake = chunkLen < firstAvailable ? chunkLen : firstAvailable;

        // Copy bytes from the first share
        uint256 payloadOffsetInShare = firstSharePayloadOffset + localOffset;
        for (uint256 i = 0; i < firstTake; i++) {
            out[i] = firstShare[payloadOffsetInShare + i];
        }

        // If the chunk fits entirely in the first share, we're done
        if (firstTake == chunkLen) {
            return out;
        }

        // Otherwise, continue copying from the second share
        require(sharesProof.data.length == 2, "Missing continuation share");
        bytes memory contShare = sharesProof.data[1];
        require(contShare.length >= CELESTIA_CONT_SHARE_PAYLOAD_START, "Invalid continuation share");

        uint256 remaining = chunkLen - firstTake;
        for (uint256 i = 0; i < remaining; i++) {
            out[firstTake + i] = contShare[CELESTIA_CONT_SHARE_PAYLOAD_START + i];
        }

        return out;
    }

    /// @notice Calculates the expected chunk length for a given offset and payload size
    /// @param offset The current offset within the payload
    /// @param payloadSize The total payload size
    /// @return The expected chunk length (capped at PREIMAGE_CHUNK_SIZE or remaining bytes)
    function _expectedChunkLen(uint256 offset, uint256 payloadSize) internal pure returns (uint256) {
        if (offset >= payloadSize) {
            return 0;
        }
        uint256 remain = payloadSize - offset;
        return remain > PREIMAGE_CHUNK_SIZE ? PREIMAGE_CHUNK_SIZE : remain;
    }

    /// @notice Decodes the 4-byte sequence length from the first share
    /// @param share0 The first share bytes (must contain sequence length at offset 30)
    /// @return The decoded sequence length as uint256
    function _decodeSequenceLen(bytes memory share0) internal pure returns (uint256) {
        return (uint256(uint8(share0[CELESTIA_SEQUENCE_LEN_OFFSET])) << 24)
            | (uint256(uint8(share0[CELESTIA_SEQUENCE_LEN_OFFSET + 1])) << 16)
            | (uint256(uint8(share0[CELESTIA_SEQUENCE_LEN_OFFSET + 2])) << 8)
            | uint256(uint8(share0[CELESTIA_SEQUENCE_LEN_OFFSET + 3]));
    }

    // =========================================================================
    //                      CERTIFICATE FIELD READERS
    // =========================================================================

    function _certBlockHeight(bytes calldata cert) internal pure returns (uint64) {
        return uint64(bytes8(cert[CERT_BLOCK_HEIGHT_OFFSET:CERT_BLOCK_HEIGHT_OFFSET + UINT64_SIZE]));
    }

    function _certStart(bytes calldata cert) internal pure returns (uint256) {
        return _readUint64(cert, CERT_START_OFFSET);
    }

    function _certSharesLength(bytes calldata cert) internal pure returns (uint256) {
        return _readUint64(cert, CERT_SHARES_LENGTH_OFFSET);
    }

    function _certTxCommitment(bytes calldata cert) internal pure returns (bytes32) {
        return bytes32(cert[CERT_TX_COMMITMENT_OFFSET:CERT_TX_COMMITMENT_OFFSET + 32]);
    }

    function _certDataRoot(bytes calldata cert) internal pure returns (bytes32) {
        return bytes32(cert[CERT_DATA_ROOT_OFFSET:CERT_DATA_ROOT_OFFSET + 32]);
    }

    // =========================================================================
    //                         UTILITY FUNCTIONS
    // =========================================================================

    /// @notice Reads a uint64 from calldata at the given offset
    /// @param data The calldata bytes to read from
    /// @param offset The byte offset where the uint64 starts
    /// @return The uint64 value
    function _readUint64(bytes calldata data, uint256 offset) internal pure returns (uint256) {
        return uint256(uint64(bytes8(data[offset:offset + UINT64_SIZE])));
    }

    /// @notice Reads a uint16 from calldata at the given offset
    /// @param data The calldata bytes to read from
    /// @param offset The byte offset where the uint16 starts
    /// @return The uint16 value
    function _readUint16(bytes calldata data, uint256 offset) internal pure returns (uint16) {
        return uint16(bytes2(data[offset:offset + 2]));
    }
}
