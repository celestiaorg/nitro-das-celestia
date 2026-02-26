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

        uint256 expectedChunkLen = 0;
        if (offset < payloadSize) {
            uint256 remain = payloadSize - offset;
            expectedChunkLen = remain > 32 ? 32 : remain;
        }
        require(chunkLen == expectedChunkLen, "Invalid chunkLen");

        uint256 certStart = uint256(uint64(bytes8(certificate[12:20])));
        uint256 certSharesLength = uint256(uint64(bytes8(certificate[20:28])));
        uint64 certHeight = uint64(bytes8(certificate[4:12]));
        bytes32 certDataRoot = bytes32(certificate[60:92]);

        uint256 shareRel = proofOffset / CELESTIA_SHARE_SIZE;
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

        bytes memory share = sharesProof.data[0];
        require(share.length >= CELESTIA_PAYLOAD_START, "Invalid share header");

        uint256 sequenceLen = (uint256(uint8(share[30])) << 24) |
            (uint256(uint8(share[31])) << 16) |
            (uint256(uint8(share[32])) << 8) |
            uint256(uint8(share[33]));
        require(payloadSize == sequenceLen, "Payload size mismatch");

        if (chunkLen == 0) {
            return new bytes(0);
        }

        require(offset + chunkLen <= sequenceLen, "Chunk outside payload bounds");

        bytes memory out = new bytes(chunkLen);
        if (offset < CELESTIA_FIRST_SHARE_PAYLOAD_CAP) {
            uint256 firstAvailable = CELESTIA_FIRST_SHARE_PAYLOAD_CAP - offset;
            uint256 firstTake = chunkLen < firstAvailable ? chunkLen : firstAvailable;
            uint256 payloadOffsetInShare = CELESTIA_PAYLOAD_START + offset;
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

        // Offset starts in continuation payload region. Current proof generator provides 2 shares for this case.
        require(shareCount == 2, "Missing continuation share");
        uint256 contOffset = offset - CELESTIA_FIRST_SHARE_PAYLOAD_CAP;
        require(
            contOffset + chunkLen <= CELESTIA_CONT_SHARE_PAYLOAD_CAP,
            "Chunk crosses unsupported continuation boundary"
        );
        bytes memory contShare = sharesProof.data[1];
        require(contShare.length >= CELESTIA_CONT_SHARE_PAYLOAD_START, "Invalid continuation share");
        uint256 contStart = CELESTIA_CONT_SHARE_PAYLOAD_START + contOffset;
        for (uint256 i = 0; i < chunkLen; i++) {
            out[i] = contShare[contStart + i];
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
}
