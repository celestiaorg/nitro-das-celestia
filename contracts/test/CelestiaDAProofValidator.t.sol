// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/CelestiaDAProofValidator.sol";
import "./mocks/MockBlobstream.sol";
import "blobstream-contracts/DataRootTuple.sol";
import "blobstream-contracts/lib/tree/binary/BinaryMerkleProof.sol";
import "blobstream-contracts/lib/tree/binary/BinaryMerkleTree.sol";
import "blobstream-contracts/lib/tree/Types.sol";

/// @title CelestiaDAProofValidatorTest
/// @notice Foundry test suite for CelestiaDAProofValidator.
///
/// Certificate layout (92 bytes):
///   [0]      0x01  – CustomDAHeaderFlag
///   [1]      0x63  – CelestiaProviderTag
///   [2..3]   0x0001 – version
///   [4..11]  blockHeight  (uint64 big-endian)
///   [12..19] start        (uint64 big-endian)
///   [20..27] sharesLength (uint64 big-endian)
///   [28..59] txCommitment (bytes32)
///   [60..91] dataRoot     (bytes32)
///
/// validateCertificate proof layout:
///   [certSize(8)][certificate(92)][claimedValid(1)]
///
/// validateReadPreimage proof layout:
///   [certSize(8)][certificate(92)][version(1)=0x01][preimageSize(8)][preimage][blobstreamProofData]
contract CelestiaDAProofValidatorTest is Test {
    // -------------------------------------------------------------------------
    // Constants mirroring the contract
    // -------------------------------------------------------------------------
    uint256 constant CERT_V1_LEN  = 92;
    bytes1  constant CERT_HEADER  = 0x01;
    bytes1  constant PROVIDER_TAG = 0x63;

    // -------------------------------------------------------------------------
    // Test state
    // -------------------------------------------------------------------------
    MockBlobstream           internal mockBlobstream;
    CelestiaDAProofValidator internal validator;

    // A canonical valid certificate used across many tests
    bytes internal validCert;

    // The NamespaceNode used as the single row root in preimage proofs.
    // Its serialised form drives the computation of certDataRoot (see setUp).
    NamespaceNode internal testNsNode;

    // Matching dataRoot and blockHeight used in the mock blobstream setup.
    // certDataRoot is computed in setUp() so that it equals the Binary-Merkle
    // leaf hash of testNsNode, making BinaryMerkleTree.verify pass.
    uint64  internal certHeight   = 100;
    bytes32 internal certDataRoot;          // set in setUp()
    bytes32 internal txCommitment = keccak256("tx-commitment");
    uint64  internal certStart    = 3;
    uint64  internal certShares   = 1;

    // Payload used for preimage tests
    bytes internal payload = "hello celestia preimage proof test";

    // -------------------------------------------------------------------------
    // Setup
    // -------------------------------------------------------------------------
    function setUp() public {
        // ------------------------------------------------------------------
        // 1. Build the NamespaceNode that will serve as the single row root.
        //    Use a non-zero digest so the leaf hash is meaningful.
        // ------------------------------------------------------------------
        testNsNode = NamespaceNode({
            min:    Namespace({version: hex"00", id: bytes28(0)}),
            max:    Namespace({version: hex"00", id: bytes28(0)}),
            digest: keccak256("row-root-digest")
        });

        // ------------------------------------------------------------------
        // 2. Derive certDataRoot from testNsNode.
        //
        //    DAVerifier.verifyRowRootToDataRootTupleRoot calls:
        //      bytes memory rowRoot = abi.encodePacked(
        //          _rowRoot.min.toBytes(),   // bytes29
        //          _rowRoot.max.toBytes(),   // bytes29
        //          _rowRoot.digest           // bytes32
        //      );  // total 90 bytes
        //    then BinaryMerkleTree.verify(_root, _rowProof, rowRoot)
        //    which for a 1-leaf proof (numLeaves=1, key=0, sideNodes=[]) checks:
        //      sha256(LEAF_PREFIX || rowRoot) == _root
        //    where LEAF_PREFIX = 0x00.
        //
        //    So certDataRoot must equal sha256(0x00 || rowRootBytes).
        // ------------------------------------------------------------------
        bytes memory rowRootBytes = abi.encodePacked(
            testNsNode.min.toBytes(),
            testNsNode.max.toBytes(),
            testNsNode.digest
        );
        certDataRoot = sha256(abi.encodePacked(bytes1(0x00), rowRootBytes));

        // ------------------------------------------------------------------
        // 3. Deploy contracts
        // ------------------------------------------------------------------
        mockBlobstream = new MockBlobstream();
        mockBlobstream.initialize(0);
        validator = new CelestiaDAProofValidator(address(mockBlobstream));

        // ------------------------------------------------------------------
        // 4. Build the canonical valid certificate using the derived certDataRoot
        // ------------------------------------------------------------------
        validCert = _buildCert(certHeight, certStart, certShares, txCommitment, certDataRoot);

        // ------------------------------------------------------------------
        // 5. Seed the mock blobstream with a commitment covering certHeight.
        //    The commitment is the root of a 1-leaf Binary Merkle tree whose
        //    single leaf is abi.encode(DataRootTuple{certHeight, certDataRoot}).
        //    This is consistent with how MockBlobstream.verifyAttestation checks:
        //      BinaryMerkleTree.verify(root, proof, abi.encode(_tuple))
        // ------------------------------------------------------------------
        DataRootTuple memory tuple = DataRootTuple({
            height:   certHeight,
            dataRoot: certDataRoot
        });
        bytes32 leaf       = _hashLeaf(tuple);
        bytes32 commitment = _singleLeafRoot(leaf);
        mockBlobstream.submitDataCommitment(commitment, 0, certHeight + 1);
    }

    // =========================================================================
    // validateCertificate — valid cases
    // =========================================================================

    function test_validateCertificate_valid_claimed1() public {
        bytes memory proof = _buildValidityProof(validCert, 1);
        bool ok = validator.validateCertificate(proof);
        assertTrue(ok, "should return true for claimedValid=1 and well-formed cert");
    }

    function test_validateCertificate_valid_claimed0_returnsfalse() public {
        // claimedValid=0 means the off-chain validator said the cert is invalid.
        // The contract should return false, NOT revert.
        bytes memory proof = _buildValidityProof(validCert, 0);
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "should return false for claimedValid=0");
    }

    // =========================================================================
    // validateCertificate — invalid cert structure (must return false, never revert)
    // =========================================================================

    function test_validateCertificate_wrongHeader_noRevert() public {
        bytes memory bad = _buildCert(certHeight, certStart, certShares, txCommitment, certDataRoot);
        bad[0] = 0x02; // wrong header byte
        bytes memory proof = _buildValidityProof(bad, 1);
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "wrong header must return false");
    }

    function test_validateCertificate_wrongProviderTag_noRevert() public {
        bytes memory bad = _buildCert(certHeight, certStart, certShares, txCommitment, certDataRoot);
        bad[1] = 0xFF;
        bytes memory proof = _buildValidityProof(bad, 1);
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "wrong provider tag must return false");
    }

    function test_validateCertificate_wrongVersion_noRevert() public {
        bytes memory bad = _buildCert(certHeight, certStart, certShares, txCommitment, certDataRoot);
        bad[2] = 0x00;
        bad[3] = 0x02; // version = 2
        bytes memory proof = _buildValidityProof(bad, 1);
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "wrong version must return false");
    }

    function test_validateCertificate_zeroBlockHeight_noRevert() public {
        bytes memory bad = _buildCert(0, certStart, certShares, txCommitment, certDataRoot);
        bytes memory proof = _buildValidityProof(bad, 1);
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "zero blockHeight must return false");
    }

    function test_validateCertificate_zeroSharesLength_noRevert() public {
        bytes memory bad = _buildCert(certHeight, certStart, 0, txCommitment, certDataRoot);
        bytes memory proof = _buildValidityProof(bad, 1);
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "zero sharesLength must return false");
    }

    function test_validateCertificate_zeroTxCommitment_noRevert() public {
        bytes memory bad = _buildCert(certHeight, certStart, certShares, bytes32(0), certDataRoot);
        bytes memory proof = _buildValidityProof(bad, 1);
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "zero txCommitment must return false");
    }

    function test_validateCertificate_zeroDataRoot_noRevert() public {
        bytes memory bad = _buildCert(certHeight, certStart, certShares, txCommitment, bytes32(0));
        bytes memory proof = _buildValidityProof(bad, 1);
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "zero dataRoot must return false");
    }

    function test_validateCertificate_tooShort_noRevert() public {
        // Proof is just 3 bytes – must return false without reverting
        bytes memory proof = hex"010101";
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "3-byte proof must return false");
    }

    function test_validateCertificate_wrongCertLength_noRevert() public {
        // Encode certSize=91 (one byte short) but provide the full 92-byte cert body.
        // The structural check (cert.length == 92) should return false.
        bytes memory proof = abi.encodePacked(
            uint64(91),  // certSize field – deliberately wrong
            validCert,   // still 92 bytes of cert data
            uint8(1)     // claimedValid
        );
        bool ok = validator.validateCertificate(proof);
        assertFalse(ok, "certSize != 92 must return false");
    }

    function test_validateCertificate_emptyProof_noRevert() public {
        bool ok = validator.validateCertificate(new bytes(0));
        assertFalse(ok, "empty proof must return false");
    }

    // =========================================================================
    // validateReadPreimage — valid proof with live Blobstream attestation
    // =========================================================================

    function test_validateReadPreimage_firstChunk() public {
        bytes memory proof    = _buildReadPreimageProof(validCert, payload);
        bytes32     certHash  = keccak256(validCert);
        bytes memory chunk    = validator.validateReadPreimage(certHash, 0, proof);

        assertEq(chunk.length, 32, "first chunk must be 32 bytes");
        for (uint256 i = 0; i < 32; i++) {
            assertEq(chunk[i], payload[i], "chunk byte mismatch at first chunk");
        }
    }

    function test_validateReadPreimage_secondChunk() public {
        uint256 offset       = 32;
        bytes memory proof   = _buildReadPreimageProof(validCert, payload);
        bytes32     certHash = keccak256(validCert);
        bytes memory chunk   = validator.validateReadPreimage(certHash, offset, proof);

        // payload is 34 bytes; offset 32 → 2 remaining bytes
        uint256 expected = payload.length - offset;
        assertEq(chunk.length, expected, "partial last chunk length mismatch");
        for (uint256 i = 0; i < expected; i++) {
            assertEq(chunk[i], payload[offset + i], "chunk byte mismatch at second chunk");
        }
    }

    function test_validateReadPreimage_offsetAtEnd_returnsEmpty() public {
        uint256 offset        = payload.length; // exactly at the end
        bytes memory proof    = _buildReadPreimageProof(validCert, payload);
        bytes32     certHash  = keccak256(validCert);
        bytes memory chunk    = validator.validateReadPreimage(certHash, offset, proof);
        assertEq(chunk.length, 0, "offset at end should return empty bytes");
    }

    function test_validateReadPreimage_offsetBeyondEnd_returnsEmpty() public {
        uint256 offset        = payload.length + 64;
        bytes memory proof    = _buildReadPreimageProof(validCert, payload);
        bytes32     certHash  = keccak256(validCert);
        bytes memory chunk    = validator.validateReadPreimage(certHash, offset, proof);
        assertEq(chunk.length, 0, "offset beyond end should return empty bytes");
    }

    // =========================================================================
    // validateReadPreimage — invalid cert hash (must revert)
    // =========================================================================

    function test_validateReadPreimage_wrongCertHash_reverts() public {
        bytes memory proof   = _buildReadPreimageProof(validCert, payload);
        bytes32     wrongHash = keccak256("not the cert");
        vm.expectRevert("Certificate hash mismatch");
        validator.validateReadPreimage(wrongHash, 0, proof);
    }

    // =========================================================================
    // validateReadPreimage — malformed cert bytes in proof (must revert)
    // =========================================================================

    function test_validateReadPreimage_wrongCertHeader_reverts() public {
        bytes memory bad = abi.encodePacked(validCert);
        bad[0] = 0x02;
        // keccak256(bad) != keccak256(validCert), so hash check fires first
        bytes memory proof = _buildReadPreimageProof(bad, payload);
        vm.expectRevert("Certificate hash mismatch");
        validator.validateReadPreimage(keccak256(validCert), 0, proof);
    }

    function test_validateReadPreimage_proofTooShort_reverts() public {
        bytes32 certHash = keccak256(validCert);
        vm.expectRevert();
        validator.validateReadPreimage(certHash, 0, new bytes(4));
    }

    // =========================================================================
    // validateReadPreimage — bad Blobstream proof (must revert)
    // =========================================================================

    function test_validateReadPreimage_badBlobstreamProof_reverts() public {
        bytes32 certHash = keccak256(validCert);

        // Build an attestation proof whose dataRoot does NOT match certDataRoot.
        // The contract will revert with "Blobstream proof dataRoot does not match
        // certificate dataRoot" before it even reaches DAVerifier.
        bytes32 wrongDataRoot = keccak256("completely wrong data root");
        DataRootTuple memory tuple = DataRootTuple({
            height:   certHeight,
            dataRoot: wrongDataRoot
        });
        BinaryMerkleProof memory attMerkleProof = BinaryMerkleProof({
            sideNodes: new bytes32[](0),
            key:       0,
            numLeaves: 1
        });
        AttestationProof memory attestation = AttestationProof({
            tupleRootNonce: 1,
            tuple:          tuple,
            proof:          attMerkleProof
        });

        NamespaceNode memory nsNode = NamespaceNode({
            min:    Namespace({version: hex"00", id: bytes28(0)}),
            max:    Namespace({version: hex"00", id: bytes28(0)}),
            digest: bytes32(0)
        });
        BinaryMerkleProof memory rowProof = BinaryMerkleProof({
            sideNodes: new bytes32[](0),
            key:       0,
            numLeaves: 1
        });

        bytes memory blobstreamProofData = abi.encode(
            address(mockBlobstream),
            nsNode,
            rowProof,
            attestation
        );

        bytes memory proof = abi.encodePacked(
            uint64(CERT_V1_LEN),
            validCert,
            uint8(0x01),             // proof version
            uint64(payload.length),
            payload,
            blobstreamProofData
        );

        vm.expectRevert();
        validator.validateReadPreimage(certHash, 0, proof);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// @dev Build a canonical 92-byte Celestia certificate.
    function _buildCert(
        uint64  height,
        uint64  start,
        uint64  shares,
        bytes32 txCommit,
        bytes32 dataRoot
    ) internal pure returns (bytes memory cert) {
        cert = new bytes(CERT_V1_LEN);
        cert[0] = CERT_HEADER;
        cert[1] = PROVIDER_TAG;
        // version = 1 at [2..3]
        cert[2] = 0x00;
        cert[3] = 0x01;
        // blockHeight at [4..11]
        _writeUint64(cert, 4,  height);
        // start at [12..19]
        _writeUint64(cert, 12, start);
        // sharesLength at [20..27]
        _writeUint64(cert, 20, shares);
        // txCommitment at [28..59]
        _writeBytes32(cert, 28, txCommit);
        // dataRoot at [60..91]
        _writeBytes32(cert, 60, dataRoot);
    }

    /// @dev Build the proof bytes for validateCertificate.
    ///   [certSize(8 bytes big-endian)][certificate][claimedValid(1 byte)]
    function _buildValidityProof(
        bytes memory cert,
        uint8        claimedValid
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(uint64(cert.length), cert, claimedValid);
    }

    /// @dev Build the proof bytes for validateReadPreimage.
    ///
    ///   Layout:
    ///     [certSize(8)][certificate][version=0x01(1)][preimageSize(8)][preimage][blobstreamProofData]
    ///
    ///   The Blobstream proof is a single-leaf attestation anchored to testNsNode,
    ///   whose leaf hash equals certDataRoot (computed in setUp so that
    ///   BinaryMerkleTree.verify passes with numLeaves=1, key=0, sideNodes=[]).
    ///
    ///   The attestation proof covers DataRootTuple{certHeight, certDataRoot} with
    ///   a single-leaf BinaryMerkle proof consistent with what the MockBlobstream stores.
    function _buildReadPreimageProof(
        bytes memory cert,
        bytes memory preimage
    ) internal view returns (bytes memory) {
        // ------------------------------------------------------------------
        // Attestation proof: 1-leaf Binary Merkle proof of the DataRootTuple.
        // MockBlobstream stores:
        //   state_dataCommitments[1] = sha256(0x00 || abi.encode(DataRootTuple{certHeight, certDataRoot}))
        // verifyAttestation checks:
        //   BinaryMerkleTree.verify(root, proof, abi.encode(_tuple))
        // For numLeaves=1, key=0, sideNodes=[], this reduces to:
        //   sha256(0x00 || abi.encode(tuple)) == root  ✓
        // ------------------------------------------------------------------
        DataRootTuple memory tuple = DataRootTuple({
            height:   certHeight,
            dataRoot: certDataRoot
        });
        BinaryMerkleProof memory attMerkleProof = BinaryMerkleProof({
            sideNodes: new bytes32[](0),
            key:       0,
            numLeaves: 1
        });
        AttestationProof memory attestation = AttestationProof({
            tupleRootNonce: 1,   // nonce used in submitDataCommitment
            tuple:          tuple,
            proof:          attMerkleProof
        });

        // ------------------------------------------------------------------
        // Row-root (namespace-node) proof: 1-leaf Binary Merkle proof.
        //
        // DAVerifier.verifyRowRootToDataRootTupleRoot calls:
        //   bytes memory rowRoot = abi.encodePacked(
        //       _rowRoot.min.toBytes(),  // bytes29
        //       _rowRoot.max.toBytes(),  // bytes29
        //       _rowRoot.digest          // bytes32
        //   );
        //   BinaryMerkleTree.verify(certDataRoot, rowProof, rowRoot)
        //
        // For numLeaves=1, key=0, sideNodes=[]:
        //   sha256(0x00 || rowRoot) == certDataRoot
        //
        // setUp() ensures certDataRoot = sha256(0x00 || rowRootBytes(testNsNode)),
        // so we just pass testNsNode here.
        // ------------------------------------------------------------------
        BinaryMerkleProof memory rowProof = BinaryMerkleProof({
            sideNodes: new bytes32[](0),
            key:       0,
            numLeaves: 1
        });

        bytes memory blobstreamProofData = abi.encode(
            address(mockBlobstream),
            testNsNode,
            rowProof,
            attestation
        );

        return abi.encodePacked(
            uint64(cert.length),      // certSize
            cert,                     // certificate bytes
            uint8(0x01),              // proof version
            uint64(preimage.length),  // preimage size
            preimage,                 // preimage bytes
            blobstreamProofData       // ABI-encoded Blobstream proof
        );
    }

    // -------------------------------------------------------------------------
    // Byte-level helpers
    // -------------------------------------------------------------------------

    function _writeUint64(bytes memory buf, uint256 offset, uint64 value) internal pure {
        for (uint256 i = 0; i < 8; i++) {
            buf[offset + 7 - i] = bytes1(uint8(value >> (i * 8)));
        }
    }

    function _writeBytes32(bytes memory buf, uint256 offset, bytes32 value) internal pure {
        for (uint256 i = 0; i < 32; i++) {
            buf[offset + i] = value[i];
        }
    }

    // -------------------------------------------------------------------------
    // Merkle helpers (RFC-6962 / Celestia binary Merkle tree, 1-leaf case)
    // -------------------------------------------------------------------------

    /// @dev Leaf hash: sha256(0x00 || abi.encode(tuple))
    ///      Mirrors BinaryMerkleTree.leafDigest(abi.encode(tuple)).
    function _hashLeaf(DataRootTuple memory tuple) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(uint8(0x00), abi.encode(tuple)));
    }

    /// @dev Root of a 1-leaf tree equals the leaf itself (no inner nodes).
    function _singleLeafRoot(bytes32 leaf) internal pure returns (bytes32) {
        return leaf;
    }
}
