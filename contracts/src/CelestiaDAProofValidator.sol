// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@nitro-contracts/osp/ICustomDAProofValidator.sol";
import "../lib/IDAOracle.sol";
import "../lib/DAVerifier.sol";

/// @title CelestiaDAProofValidator
/// @notice Validates Celestia DA certificates and read-preimage proofs.
///
/// Certificate format (92 bytes):
/// [0]      header        (bytes1)  = 0x01
/// [1]      providerType  (bytes1)  = 0x63
/// [2..3]   certVersion   (uint16)  = 1
/// [4..11]  blockHeight   (uint64)
/// [12..19] start         (uint64)
/// [20..27] sharesLength  (uint64)
/// [28..59] txCommitment  (bytes32)
/// [60..91] dataRoot      (bytes32)
///
/// Full proof format seen by this contract:
/// [certSize(8)][certificate][customProof]
///
/// customProof (read-preimage):
/// [version(1)=0x01][offset(8)][payloadSize(8)][chunkLen(1)][firstShareIndexInBlob(8)][shareCount(1)][abi.encode(address, SharesProof)]
///
/// customProof (certificate-validity):
/// [claimedValid(1)][version(1)=0x01]
contract CelestiaDAProofValidator is ICustomDAProofValidator {
    uint256 private constant CERT_SIZE_FIELD_LEN = 8;
    uint256 private constant CERT_V1_LEN = 92;

    bytes1 private constant CERT_HEADER = 0x01;
    bytes1 private constant CELESTIA_PROVIDER_TAG = 0x63;
    uint16 private constant CERT_VERSION = 1;

    uint8 private constant READ_PROOF_VERSION = 0x01;
    uint8 private constant VALIDITY_PROOF_VERSION = 0x01;
    uint256 private constant CELESTIA_SHARE_SIZE = 512;
    uint256 private constant CELESTIA_NAMESPACE_SIZE = 29;
    uint256 private constant CELESTIA_SHARE_INFO_BYTES = 1;
    uint256 private constant CELESTIA_SEQUENCE_LEN_BYTES = 4;
    uint256 private constant CELESTIA_PAYLOAD_START =
        CELESTIA_NAMESPACE_SIZE + CELESTIA_SHARE_INFO_BYTES + CELESTIA_SEQUENCE_LEN_BYTES;
    uint256 private constant CELESTIA_CONT_SHARE_PAYLOAD_START =
        CELESTIA_NAMESPACE_SIZE + CELESTIA_SHARE_INFO_BYTES;
    uint256 private constant CELESTIA_FIRST_SHARE_PAYLOAD_CAP =
        CELESTIA_SHARE_SIZE - CELESTIA_PAYLOAD_START;
    uint256 private constant CELESTIA_CONT_SHARE_PAYLOAD_CAP =
        CELESTIA_SHARE_SIZE - CELESTIA_CONT_SHARE_PAYLOAD_START;

    address public immutable blobstreamX;

    constructor(address _blobstreamX) {
        blobstreamX = _blobstreamX;
    }

    function validateReadPreimage(
        bytes32 certHash,
        uint256 offset,
        bytes calldata proof
    ) external view override returns (bytes memory preimageChunk) {
        require(proof.length >= CERT_SIZE_FIELD_LEN, "Proof too short: certSize field missing");

        uint256 certSize = uint256(uint64(bytes8(proof[0:CERT_SIZE_FIELD_LEN])));
        uint256 afterCert = CERT_SIZE_FIELD_LEN + certSize;
        require(proof.length >= afterCert, "Proof too short: certificate truncated");

        bytes calldata certificate = proof[CERT_SIZE_FIELD_LEN:afterCert];
        require(keccak256(certificate) == certHash, "Certificate hash mismatch");
        _requireValidCertStructure(certificate);

        bytes calldata custom = proof[afterCert:];
        require(custom.length >= 27, "Proof too short: custom read proof header missing");

        uint256 pos = 0;
        require(uint8(custom[pos]) == READ_PROOF_VERSION, "Invalid read proof version");
        pos++;

        uint256 proofOffset = uint256(uint64(bytes8(custom[pos:pos + 8])));
        pos += 8;
        require(proofOffset == offset, "Offset mismatch");

        uint256 payloadSize = uint256(uint64(bytes8(custom[pos:pos + 8])));
        pos += 8;

        uint256 chunkLen = uint8(custom[pos]);
        pos++;

        uint256 firstShareIndexInBlob = uint256(uint64(bytes8(custom[pos:pos + 8])));
        pos += 8;

        uint256 shareCount = uint8(custom[pos]);
        pos++;

        require(chunkLen == _expectedChunkLen(offset, payloadSize), "Invalid chunkLen");

        uint256 certStart = uint256(uint64(bytes8(certificate[12:20])));
        uint256 certSharesLength = uint256(uint64(bytes8(certificate[20:28])));
        uint64 certHeight = uint64(bytes8(certificate[4:12]));
        bytes32 certDataRoot = bytes32(certificate[60:92]);

        uint256 shareRel = _payloadOffsetToShareRel(proofOffset);
        uint256 expectedFirstShareIndex = certStart + shareRel;
        require(firstShareIndexInBlob == expectedFirstShareIndex, "Invalid firstShareIndexInBlob");
        require(firstShareIndexInBlob >= certStart, "Share index before cert range");
        require(
            firstShareIndexInBlob + shareCount <= certStart + certSharesLength,
            "Share index past cert range"
        );
        require(shareCount == 1 || shareCount == 2, "Invalid shareCount");

        bytes calldata sharesProofData = custom[pos:];
        require(sharesProofData.length > 0, "Missing shares proof data");

        (address encodedBlobstream, SharesProof memory sharesProof) = abi.decode(
            sharesProofData,
            (address, SharesProof)
        );
        encodedBlobstream;

        require(
            sharesProof.attestationProof.tuple.height == certHeight,
            "Shares proof height does not match certificate blockHeight"
        );
        require(
            sharesProof.attestationProof.tuple.dataRoot == certDataRoot,
            "Shares proof dataRoot does not match certificate dataRoot"
        );

        (bool valid, ) = DAVerifier.verifySharesToDataRootTupleRoot(
            IDAOracle(blobstreamX),
            sharesProof
        );
        require(valid, "Invalid Celestia shares inclusion proof");

        require(sharesProof.data.length == shareCount, "Shares count mismatch");
        for (uint256 i = 0; i < shareCount; i++) {
            require(sharesProof.data[i].length == CELESTIA_SHARE_SIZE, "Invalid share length");
        }

        uint256 firstRel = firstShareIndexInBlob - certStart;
        bytes memory share = sharesProof.data[0];
        uint256 firstSharePayloadOffset = _payloadDataStartInShare(firstRel);
        require(share.length >= firstSharePayloadOffset, "Invalid share header");

        if (firstRel == 0) {
            require(payloadSize == _decodeSequenceLen(share), "Payload size mismatch");
        }

        if (chunkLen == 0) {
            return new bytes(0);
        }

        require(offset + chunkLen <= payloadSize, "Chunk outside payload bounds");

        uint256 sharePayloadStart = _payloadStartForShareRel(firstRel);
        uint256 sharePayloadCap = _payloadCapacityForShareRel(firstRel);
        require(offset >= sharePayloadStart, "Offset before proven share payload");
        uint256 localOffset = offset - sharePayloadStart;
        require(localOffset < sharePayloadCap, "Offset outside proven share payload");

        bytes memory out = new bytes(chunkLen);
        uint256 firstAvailable = sharePayloadCap - localOffset;
        uint256 firstTake = chunkLen < firstAvailable ? chunkLen : firstAvailable;
        uint256 payloadOffsetInShare = firstSharePayloadOffset + localOffset;
        for (uint256 i = 0; i < firstTake; i++) {
            out[i] = share[payloadOffsetInShare + i];
        }
        if (firstTake == chunkLen) {
            return out;
        }

        require(shareCount == 2, "Missing continuation share");
        bytes memory cont = sharesProof.data[1];
        require(cont.length >= CELESTIA_CONT_SHARE_PAYLOAD_START, "Invalid continuation share");
        uint256 rem = chunkLen - firstTake;
        for (uint256 i = 0; i < rem; i++) {
            out[firstTake + i] = cont[CELESTIA_CONT_SHARE_PAYLOAD_START + i];
        }
        return out;
    }

    function validateCertificate(
        bytes calldata proof
    ) external pure override returns (bool isValid) {
        if (proof.length < CERT_SIZE_FIELD_LEN + CERT_V1_LEN + 1) {
            return false;
        }

        uint256 certSize = uint256(uint64(bytes8(proof[0:CERT_SIZE_FIELD_LEN])));
        uint256 afterCert = CERT_SIZE_FIELD_LEN + certSize;
        if (proof.length < afterCert + 1) {
            return false;
        }

        bytes calldata certificate = proof[CERT_SIZE_FIELD_LEN:afterCert];
        if (!_isValidCertStructure(certificate)) {
            return false;
        }

        uint8 claimedValid = uint8(proof[afterCert]);
        if (proof.length > afterCert + 1) {
            uint8 proofVersion = uint8(proof[afterCert + 1]);
            if (proofVersion != VALIDITY_PROOF_VERSION) {
                return false;
            }
        }
        return claimedValid == 1;
    }

    function _isValidCertStructure(bytes calldata cert) internal pure returns (bool) {
        if (cert.length != CERT_V1_LEN) return false;
        if (cert[0] != CERT_HEADER) return false;
        if (cert[1] != CELESTIA_PROVIDER_TAG) return false;

        uint16 version = uint16(bytes2(cert[2:4]));
        if (version != CERT_VERSION) return false;

        uint64 blockHeight = uint64(bytes8(cert[4:12]));
        if (blockHeight == 0) return false;

        uint64 sharesLength = uint64(bytes8(cert[20:28]));
        if (sharesLength == 0) return false;

        bytes32 txCommitment = bytes32(cert[28:60]);
        if (txCommitment == bytes32(0)) return false;

        bytes32 dataRoot = bytes32(cert[60:92]);
        if (dataRoot == bytes32(0)) return false;

        return true;
    }

    function _requireValidCertStructure(bytes calldata cert) internal pure {
        require(cert.length == CERT_V1_LEN, "Invalid certificate length");
        require(cert[0] == CERT_HEADER, "Invalid certificate header");
        require(cert[1] == CELESTIA_PROVIDER_TAG, "Invalid Celestia provider tag");
        require(uint16(bytes2(cert[2:4])) == CERT_VERSION, "Unsupported certificate version");
        require(uint64(bytes8(cert[4:12])) != 0, "Zero blockHeight in certificate");
        require(uint64(bytes8(cert[20:28])) != 0, "Zero sharesLength in certificate");
        require(bytes32(cert[28:60]) != bytes32(0), "Zero txCommitment in certificate");
        require(bytes32(cert[60:92]) != bytes32(0), "Zero dataRoot in certificate");
    }

    function _payloadOffsetToShareRel(uint256 payloadOffset) internal pure returns (uint256) {
        // Celestia payload layout:
        // - share 0 payload: 478 bytes (512 - 29 namespace - 1 info - 4 sequence length)
        // - continuation payload: 482 bytes (512 - 29 namespace - 1 info)
        if (payloadOffset < CELESTIA_FIRST_SHARE_PAYLOAD_CAP) {
            return 0;
        }
        return 1 + ((payloadOffset - CELESTIA_FIRST_SHARE_PAYLOAD_CAP) / CELESTIA_CONT_SHARE_PAYLOAD_CAP);
    }

    function _payloadStartForShareRel(uint256 shareRel) internal pure returns (uint256) {
        if (shareRel == 0) {
            return 0;
        }
        return CELESTIA_FIRST_SHARE_PAYLOAD_CAP + (shareRel - 1) * CELESTIA_CONT_SHARE_PAYLOAD_CAP;
    }

    function _payloadCapacityForShareRel(uint256 shareRel) internal pure returns (uint256) {
        if (shareRel == 0) {
            return CELESTIA_FIRST_SHARE_PAYLOAD_CAP;
        }
        return CELESTIA_CONT_SHARE_PAYLOAD_CAP;
    }

    function _payloadDataStartInShare(uint256 shareRel) internal pure returns (uint256) {
        if (shareRel == 0) {
            return CELESTIA_PAYLOAD_START;
        }
        return CELESTIA_CONT_SHARE_PAYLOAD_START;
    }

    function _expectedChunkLen(uint256 offset, uint256 payloadSize) internal pure returns (uint256) {
        if (offset >= payloadSize) {
            return 0;
        }
        uint256 remain = payloadSize - offset;
        return remain > 32 ? 32 : remain;
    }

    function _decodeSequenceLen(bytes memory share0) internal pure returns (uint256) {
        return (uint256(uint8(share0[30])) << 24) |
            (uint256(uint8(share0[31])) << 16) |
            (uint256(uint8(share0[32])) << 8) |
            uint256(uint8(share0[33]));
    }
}
