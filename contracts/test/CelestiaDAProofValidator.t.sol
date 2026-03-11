// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import "../src/CelestiaDAProofValidator.sol";
import "./mocks/MockBlobstream.sol";
import "../lib/DataRootTuple.sol";
import "../lib/tree/binary/BinaryMerkleProof.sol";
import "../lib/tree/binary/TreeHasher.sol";
import "../lib/tree/namespace/NamespaceMerkleMultiproof.sol";
import "../lib/tree/namespace/TreeHasher.sol";
import "../lib/tree/Types.sol";

contract CelestiaDAProofValidatorTest is Test {
    MockBlobstream internal mockBlobstream;
    CelestiaDAProofValidator internal validator;

    uint64 internal certHeight = 100;
    uint64 internal certStart = 20;
    uint64 internal certSharesLength = 2;

    bytes internal share0;
    bytes internal share1;
    Namespace internal ns;
    NamespaceNode internal rowRoot0;
    NamespaceNode internal rowRoot1;
    bytes32 internal certDataRoot;
    bytes internal validCert;
    bytes internal payload;

    function setUp() public {
        ns = Namespace({version: hex"00", id: bytes28(0)});

        payload = _buildPayload(560);
        (share0, share1) = _buildTwoSharesWithPayload(payload);

        rowRoot0 = leafDigest(ns, share0);
        rowRoot1 = leafDigest(ns, share1);

        bytes memory rowRootBytes0 = abi.encodePacked(rowRoot0.min.toBytes(), rowRoot0.max.toBytes(), rowRoot0.digest);
        bytes memory rowRootBytes1 = abi.encodePacked(rowRoot1.min.toBytes(), rowRoot1.max.toBytes(), rowRoot1.digest);
        certDataRoot = nodeDigest(leafDigest(rowRootBytes0), leafDigest(rowRootBytes1));

        validCert = _buildCert(certHeight, certStart, certSharesLength, keccak256("tx-commitment"), certDataRoot);

        mockBlobstream = new MockBlobstream();
        mockBlobstream.initialize(0);
        validator = new CelestiaDAProofValidator(address(mockBlobstream));

        DataRootTuple memory tuple = DataRootTuple({height: certHeight, dataRoot: certDataRoot});
        bytes32 commitment = leafDigest(abi.encode(tuple));
        mockBlobstream.submitDataCommitment(commitment, 0, certHeight + 1);
    }

    function test_validateCertificate_valid_claimed1() public {
        bytes memory proof = _buildValidityProof(validCert, _attestationProof(certHeight, certDataRoot), bytes1(0x01));
        assertTrue(validator.validateCertificate(proof));
    }

    function test_validateCertificate_valid_claimed0_returnsFalse() public {
        bytes memory proof = abi.encodePacked(uint64(validCert.length), validCert, bytes1(0x00), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_invalidStructure_claimed1_returnsFalse() public {
        bytes memory badCert = bytes(validCert);
        badCert[0] = 0x00;
        bytes memory proof = abi.encodePacked(uint64(badCert.length), badCert, bytes1(0x01), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_badClaimedValidByteIgnoredWhenAttested() public {
        bytes memory proof = _buildValidityProof(validCert, _attestationProof(certHeight, certDataRoot), bytes1(0x00));
        assertTrue(validator.validateCertificate(proof));
    }

    function test_validateCertificate_wrongValidityVersion_returnsFalse() public {
        bytes memory proof = abi.encodePacked(
            uint64(validCert.length), validCert, bytes1(0x01), bytes1(0x02), abi.encode(_attestationProof(certHeight, certDataRoot))
        );
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_missingAttestationPayload_returnsFalse() public {
        bytes memory proof = abi.encodePacked(uint64(validCert.length), validCert, bytes1(0x01), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_malformedAttestationPayload_returnsFalse() public {
        bytes memory proof = abi.encodePacked(uint64(validCert.length), validCert, bytes1(0x01), bytes1(0x01), hex"deadbeef");
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_wrongTupleHeight_returnsFalse() public {
        bytes memory proof = _buildValidityProof(validCert, _attestationProof(certHeight + 1, certDataRoot), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_wrongTupleDataRoot_returnsFalse() public {
        bytes32 badDataRoot = bytes32(uint256(certDataRoot) ^ uint256(1));
        bytes memory proof = _buildValidityProof(validCert, _attestationProof(certHeight, badDataRoot), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_wrongProofNonce_returnsFalse() public {
        AttestationProof memory attestationProof = _attestationProof(certHeight, certDataRoot);
        attestationProof.tupleRootNonce = 999;
        bytes memory proof = _buildValidityProof(validCert, attestationProof, bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_zeroBlockHeight_returnsFalse() public {
        bytes memory badCert = _buildCert(0, certStart, certSharesLength, keccak256("tx-commitment"), certDataRoot);
        bytes memory proof = _buildValidityProof(badCert, _attestationProof(certHeight, certDataRoot), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_zeroSharesLength_returnsFalse() public {
        bytes memory badCert = _buildCert(certHeight, certStart, 0, keccak256("tx-commitment"), certDataRoot);
        bytes memory proof = _buildValidityProof(badCert, _attestationProof(certHeight, certDataRoot), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_zeroTxCommitment_returnsFalse() public {
        bytes memory badCert = _buildCert(certHeight, certStart, certSharesLength, bytes32(0), certDataRoot);
        bytes memory proof = _buildValidityProof(badCert, _attestationProof(certHeight, certDataRoot), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateCertificate_zeroDataRoot_returnsFalse() public {
        bytes memory badCert = _buildCert(certHeight, certStart, certSharesLength, keccak256("tx-commitment"), bytes32(0));
        bytes memory proof = _buildValidityProof(badCert, _attestationProof(certHeight, certDataRoot), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateReadPreimage_singleShareChunk() public {
        uint64 offset = 0;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length), false, false);
        bytes memory out = validator.validateReadPreimage(keccak256(validCert), offset, proof);

        assertEq(out.length, 32);
        for (uint256 i = 0; i < 32; i++) {
            assertEq(out[i], payload[i]);
        }
    }

    function test_validateReadPreimage_crossShareChunk() public {
        uint64 offset = 448;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length), false, false);
        bytes memory out = validator.validateReadPreimage(keccak256(validCert), offset, proof);

        assertEq(out.length, 32);
        for (uint256 i = 0; i < 32; i++) {
            assertEq(out[i], payload[offset + i]);
        }
    }

    function test_validateReadPreimage_continuationShareChunk() public {
        uint64 offset = 480;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length), false, false);
        bytes memory out = validator.validateReadPreimage(keccak256(validCert), offset, proof);

        assertEq(out.length, 32);
        for (uint256 i = 0; i < 32; i++) {
            assertEq(out[i], payload[offset + i]);
        }
    }

    function test_validateReadPreimage_wrongCertHash_reverts() public {
        uint64 offset = 64;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length), false, false);
        vm.expectRevert("Certificate hash mismatch");
        validator.validateReadPreimage(keccak256("wrong"), offset, proof);
    }

    function test_validateReadPreimage_badSharesProof_reverts() public {
        uint64 offset = 64;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length), true, false);
        vm.expectRevert("Invalid Celestia shares inclusion proof");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_evilDataGoodCert_reverts() public {
        // Evil payload under the same good certificate should fail share inclusion.
        uint64 offset = 64;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length), true, false);
        vm.expectRevert("Invalid Celestia shares inclusion proof");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_evilDataEvilCert_reverts() public {
        // Evil cert hash passed while proof still carries good cert bytes.
        uint64 offset = 64;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length), false, false);
        bytes memory evilCert = _buildCert(certHeight, certStart, certSharesLength, keccak256("evil-tx"), certDataRoot);
        vm.expectRevert("Certificate hash mismatch");
        validator.validateReadPreimage(keccak256(evilCert), offset, proof);
    }

    function test_validateReadPreimage_badIndex_reverts() public {
        uint64 offset = 64;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length), false, true);
        vm.expectRevert("Invalid firstShareIndexInBlob");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_wrongOffset_reverts() public {
        uint64 offset = 64;
        bytes memory proof = _buildReadProofWithOffset(offset, uint64(payload.length), offset + 32);
        vm.expectRevert("Offset mismatch");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_wrongChunkLen_reverts() public {
        uint64 offset = 64;
        bytes memory proof = _buildReadProofWithChunkLen(offset, uint64(payload.length), 31);
        vm.expectRevert("Invalid chunkLen");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_wrongShareCount_reverts() public {
        uint64 offset = 64;
        bytes memory proof = _buildReadProofWithForcedShareCount(offset, uint64(payload.length), 0);
        vm.expectRevert("Invalid shareCount");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_wrongPayloadSize_reverts() public {
        uint64 offset = 0;
        bytes memory proof = _buildReadProof(offset, uint64(payload.length - 1), false, false);
        vm.expectRevert("Payload size mismatch");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_wrongTupleHeight_reverts() public {
        uint64 offset = 64;
        bytes memory proof =
            _buildReadProofWithTuple(offset, uint64(payload.length), certHeight + 1, certDataRoot, false, false, type(uint8).max);
        vm.expectRevert("Shares proof height does not match certificate blockHeight");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_wrongTupleDataRoot_reverts() public {
        uint64 offset = 64;
        bytes32 badDataRoot = bytes32(uint256(certDataRoot) ^ uint256(1));
        bytes memory proof =
            _buildReadProofWithTuple(offset, uint64(payload.length), certHeight, badDataRoot, false, false, type(uint8).max);
        vm.expectRevert("Shares proof dataRoot does not match certificate dataRoot");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function test_validateReadPreimage_missingContinuationShare_reverts() public {
        uint64 offset = 448;
        bytes memory proof = _buildReadProofWithForcedShareCount(offset, uint64(payload.length), 1);
        vm.expectRevert("Missing continuation share");
        validator.validateReadPreimage(keccak256(validCert), offset, proof);
    }

    function _buildReadProof(uint64 offset, uint64 payloadSize, bool tamperProof, bool badIndex)
        internal
        view
        returns (bytes memory)
    {
        return _buildReadProofWithTuple(offset, payloadSize, certHeight, certDataRoot, tamperProof, badIndex, type(uint8).max);
    }

    function _buildReadProofWithForcedShareCount(uint64 offset, uint64 payloadSize, uint8 forcedShareCount)
        internal
        view
        returns (bytes memory)
    {
        return _buildReadProofWithTuple(offset, payloadSize, certHeight, certDataRoot, false, false, forcedShareCount);
    }

    function _buildReadProofWithOffset(uint64 offset, uint64 payloadSize, uint64 encodedOffset)
        internal
        view
        returns (bytes memory)
    {
        return _buildReadProofCustom(offset, payloadSize, encodedOffset, expectedChunkLen(offset, payloadSize), 1);
    }

    function _buildReadProofWithChunkLen(uint64 offset, uint64 payloadSize, uint8 chunkLen)
        internal
        view
        returns (bytes memory)
    {
        return _buildReadProofCustom(offset, payloadSize, offset, chunkLen, 1);
    }

    function _buildReadProofCustom(
        uint64 offset,
        uint64 payloadSize,
        uint64 encodedOffset,
        uint8 chunkLen,
        uint8 encodedShareCount
    ) internal view returns (bytes memory) {
        bytes memory proof = _buildReadProof(offset, payloadSize, false, false);
        uint256 proofStart = 8 + validCert.length;
        proof[proofStart + 1] = bytes1(uint8(encodedOffset >> 56));
        proof[proofStart + 2] = bytes1(uint8(encodedOffset >> 48));
        proof[proofStart + 3] = bytes1(uint8(encodedOffset >> 40));
        proof[proofStart + 4] = bytes1(uint8(encodedOffset >> 32));
        proof[proofStart + 5] = bytes1(uint8(encodedOffset >> 24));
        proof[proofStart + 6] = bytes1(uint8(encodedOffset >> 16));
        proof[proofStart + 7] = bytes1(uint8(encodedOffset >> 8));
        proof[proofStart + 8] = bytes1(uint8(encodedOffset));
        proof[proofStart + 17] = bytes1(chunkLen);
        proof[proofStart + 26] = bytes1(encodedShareCount);
        return proof;
    }

    function _buildReadProofWithTuple(
        uint64 offset,
        uint64 payloadSize,
        uint64 tupleHeight,
        bytes32 tupleDataRoot,
        bool tamperProof,
        bool badIndex,
        uint8 forcedShareCount
    ) internal view returns (bytes memory) {
        DataRootTuple memory tuple = DataRootTuple({height: tupleHeight, dataRoot: tupleDataRoot});

        bytes memory rowRootBytes0 = abi.encodePacked(rowRoot0.min.toBytes(), rowRoot0.max.toBytes(), rowRoot0.digest);
        bytes memory rowRootBytes1 = abi.encodePacked(rowRoot1.min.toBytes(), rowRoot1.max.toBytes(), rowRoot1.digest);

        uint8 chunkLen = 0;
        if (offset < payloadSize) {
            uint64 rem = payloadSize - offset;
            chunkLen = uint8(rem > 32 ? 32 : rem);
        }
        uint64 shareRel = _payloadOffsetToShareRel(offset);
        uint64 sharePayloadStart = _payloadStartForShareRel(shareRel);
        uint64 sharePayloadCap = _payloadCapacityForShareRel(shareRel);
        uint64 localOffset = offset - sharePayloadStart;
        bool cross = localOffset + chunkLen > sharePayloadCap;
        uint8 shareCount = cross ? 2 : 1;
        if (forcedShareCount != type(uint8).max) {
            shareCount = forcedShareCount;
        }
        uint64 firstShareIndex = certStart + shareRel;
        if (badIndex) firstShareIndex++;

        bytes[] memory data = new bytes[](shareCount);
        if (shareCount > 0) {
            data[0] = firstShareIndex == certStart ? share0 : share1;
        }
        if (shareCount == 2) data[1] = share1;
        if (tamperProof) data[0][40] = bytes1(uint8(data[0][40]) ^ 0x01);

        NamespaceMerkleMultiproof[] memory shareProofs = new NamespaceMerkleMultiproof[](shareCount);
        NamespaceNode[] memory noSide = new NamespaceNode[](0);
        for (uint256 i = 0; i < shareCount; i++) {
            shareProofs[i] = NamespaceMerkleMultiproof({beginKey: 0, endKey: 1, sideNodes: noSide});
        }

        NamespaceNode[] memory rowRoots = new NamespaceNode[](shareCount);
        BinaryMerkleProof[] memory rowProofs = new BinaryMerkleProof[](shareCount);

        bytes32 digest0 = leafDigest(rowRootBytes0);
        bytes32 digest1 = leafDigest(rowRootBytes1);

        if (shareCount == 0) {
            // Deliberately empty: the validator should reject the header before decoding proof internals.
        } else if (shareCount == 1) {
            if (firstShareIndex == certStart) {
                rowRoots[0] = rowRoot0;
                bytes32[] memory side0 = new bytes32[](1);
                side0[0] = digest1;
                rowProofs[0] = BinaryMerkleProof({sideNodes: side0, key: 0, numLeaves: 2});
            } else {
                rowRoots[0] = rowRoot1;
                bytes32[] memory side1 = new bytes32[](1);
                side1[0] = digest0;
                rowProofs[0] = BinaryMerkleProof({sideNodes: side1, key: 1, numLeaves: 2});
            }
        } else {
            rowRoots[0] = rowRoot0;
            rowRoots[1] = rowRoot1;
            bytes32[] memory sideA = new bytes32[](1);
            sideA[0] = digest1;
            rowProofs[0] = BinaryMerkleProof({sideNodes: sideA, key: 0, numLeaves: 2});
            bytes32[] memory sideB = new bytes32[](1);
            sideB[0] = digest0;
            rowProofs[1] = BinaryMerkleProof({sideNodes: sideB, key: 1, numLeaves: 2});
        }

        BinaryMerkleProof memory tupleProof = BinaryMerkleProof({sideNodes: new bytes32[](0), key: 0, numLeaves: 1});

        SharesProof memory sharesProof = SharesProof({
            data: data,
            shareProofs: shareProofs,
            namespace: ns,
            rowRoots: rowRoots,
            rowProofs: rowProofs,
            attestationProof: AttestationProof({tupleRootNonce: 1, tuple: tuple, proof: tupleProof})
        });

        bytes memory custom = abi.encodePacked(
            bytes1(0x01),
            bytes8(offset),
            bytes8(payloadSize),
            bytes1(chunkLen),
            bytes8(firstShareIndex),
            bytes1(shareCount),
            abi.encode(address(mockBlobstream), sharesProof)
        );
        return abi.encodePacked(bytes8(uint64(validCert.length)), validCert, custom);
    }

    function _buildValidityProof(bytes memory certificate, AttestationProof memory attestationProof, bytes1 claimedValid)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint64(certificate.length), certificate, claimedValid, bytes1(0x01), abi.encode(attestationProof));
    }

    function _attestationProof(uint64 height, bytes32 dataRoot) internal pure returns (AttestationProof memory) {
        DataRootTuple memory tuple = DataRootTuple({height: height, dataRoot: dataRoot});
        BinaryMerkleProof memory tupleProof = BinaryMerkleProof({sideNodes: new bytes32[](0), key: 0, numLeaves: 1});
        return AttestationProof({tupleRootNonce: 1, tuple: tuple, proof: tupleProof});
    }

    function expectedChunkLen(uint64 offset, uint64 payloadSize) internal pure returns (uint8) {
        if (offset >= payloadSize) {
            return 0;
        }
        uint64 rem = payloadSize - offset;
        return uint8(rem > 32 ? 32 : rem);
    }

    function _buildCert(uint64 blockHeight, uint64 start, uint64 sharesLength, bytes32 txc, bytes32 dataRoot)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes1(0x01),
            bytes1(0x63),
            bytes2(uint16(1)),
            bytes8(blockHeight),
            bytes8(start),
            bytes8(sharesLength),
            txc,
            dataRoot
        );
    }

    function _buildPayload(uint256 len) internal pure returns (bytes memory p) {
        p = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            p[i] = bytes1(uint8(i % 251));
        }
    }

    function _buildTwoSharesWithPayload(bytes memory pl) internal pure returns (bytes memory s0, bytes memory s1) {
        s0 = new bytes(512);
        s1 = new bytes(512);
        s0[29] = bytes1(0x01); // info byte (first share)
        uint32 len = uint32(pl.length);
        s0[30] = bytes1(uint8(len >> 24));
        s0[31] = bytes1(uint8(len >> 16));
        s0[32] = bytes1(uint8(len >> 8));
        s0[33] = bytes1(uint8(len));
        // Continuation share carries namespace + info byte, payload starts at 30.
        s1[29] = bytes1(0x00);

        uint256 firstCap = 512 - 34;
        uint256 firstTake = pl.length < firstCap ? pl.length : firstCap;
        for (uint256 i = 0; i < firstTake; i++) {
            s0[34 + i] = pl[i];
        }
        for (uint256 i = firstTake; i < pl.length; i++) {
            s1[30 + (i - firstTake)] = pl[i];
        }
    }

    function _payloadOffsetToShareRel(uint64 payloadOffset) internal pure returns (uint64) {
        if (payloadOffset < 478) {
            return 0;
        }
        return 1 + ((payloadOffset - 478) / 482);
    }

    function _payloadStartForShareRel(uint64 shareRel) internal pure returns (uint64) {
        if (shareRel == 0) {
            return 0;
        }
        return 478 + ((shareRel - 1) * 482);
    }

    function _payloadCapacityForShareRel(uint64 shareRel) internal pure returns (uint64) {
        if (shareRel == 0) {
            return 478;
        }
        return 482;
    }
}
