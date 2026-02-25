// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import "../src/CelestiaDAProofValidator.sol";
import "./mocks/MockBlobstream.sol";
import "../lib/DataRootTuple.sol";
import "../lib/tree/binary/BinaryMerkleProof.sol";
import "../lib/tree/namespace/NamespaceMerkleMultiproof.sol";
import "../lib/tree/namespace/TreeHasher.sol";
import "../lib/tree/Types.sol";

contract CelestiaDAProofValidatorTest is Test {
    MockBlobstream internal mockBlobstream;
    CelestiaDAProofValidator internal validator;

    bytes internal payload;
    bytes internal validCert;
    uint64 internal certHeight = 100;

    Namespace internal ns;
    NamespaceNode internal rowRoot;
    BinaryMerkleProof internal rowProof;
    AttestationProof internal attProof;
    SharesProof internal sharesProof;

    function setUp() public {
        payload = bytes("hello celestia preimage proof test via shares proof");

        ns = Namespace({version: hex"00", id: bytes28(0)});

        // Use one share in one row for an easy-to-audit inclusion proof.
        bytes memory shareData = bytes("dummy-share-data-which-is-not-a-real-celestia-share");
        rowRoot = leafDigest(ns, shareData);

        bytes memory rowRootBytes = abi.encodePacked(
            rowRoot.min.toBytes(),
            rowRoot.max.toBytes(),
            rowRoot.digest
        );
        bytes32 certDataRoot = sha256(abi.encodePacked(bytes1(0x00), rowRootBytes));

        validCert = _buildCert(certHeight, 0, 1, keccak256("tx-commitment"), certDataRoot);

        mockBlobstream = new MockBlobstream();
        mockBlobstream.initialize(0);
        validator = new CelestiaDAProofValidator(address(mockBlobstream));

        DataRootTuple memory tuple = DataRootTuple({height: certHeight, dataRoot: certDataRoot});
        BinaryMerkleProof memory tupleProof = BinaryMerkleProof({
            sideNodes: new bytes32[](0),
            key: 0,
            numLeaves: 1
        });
        bytes32 commitment = sha256(abi.encodePacked(bytes1(0x00), abi.encode(tuple)));
        mockBlobstream.submitDataCommitment(commitment, 0, certHeight + 1);

        rowProof = BinaryMerkleProof({sideNodes: new bytes32[](0), key: 0, numLeaves: 1});
        attProof = AttestationProof({tupleRootNonce: 1, tuple: tuple, proof: tupleProof});

        NamespaceNode[] memory sideNodes = new NamespaceNode[](0);
        NamespaceMerkleMultiproof[] memory shareProofs = new NamespaceMerkleMultiproof[](1);
        shareProofs[0] = NamespaceMerkleMultiproof({beginKey: 0, endKey: 1, sideNodes: sideNodes});

        bytes[] memory data = new bytes[](1);
        data[0] = shareData;

        NamespaceNode[] memory rowRoots = new NamespaceNode[](1);
        rowRoots[0] = rowRoot;

        BinaryMerkleProof[] memory rowProofs = new BinaryMerkleProof[](1);
        rowProofs[0] = rowProof;

        sharesProof = SharesProof({
            data: data,
            shareProofs: shareProofs,
            namespace: ns,
            rowRoots: rowRoots,
            rowProofs: rowProofs,
            attestationProof: attProof
        });
    }

    function test_validateCertificate_valid_claimed1() public {
        bytes memory proof = abi.encodePacked(uint64(validCert.length), validCert, bytes1(0x01), bytes1(0x01));
        assertTrue(validator.validateCertificate(proof));
    }

    function test_validateCertificate_malformed_noRevert() public {
        bytes memory bad = abi.encodePacked(validCert);
        bad[0] = 0x02;
        bytes memory proof = abi.encodePacked(uint64(bad.length), bad, bytes1(0x01), bytes1(0x01));
        assertFalse(validator.validateCertificate(proof));
    }

    function test_validateReadPreimage_firstChunk() public {
        bytes memory proof = _buildReadProof(validCert, payload, false, false);
        bytes memory out = validator.validateReadPreimage(keccak256(validCert), 0, proof);

        assertEq(out.length, 32);
        for (uint256 i = 0; i < 32; i++) {
            assertEq(out[i], payload[i]);
        }
    }

    function test_validateReadPreimage_partialLastChunk() public {
        uint256 offset = 32;
        bytes memory proof = _buildReadProof(validCert, payload, false, false);
        bytes memory out = validator.validateReadPreimage(keccak256(validCert), offset, proof);

        uint256 expected = payload.length - offset;
        if (expected > 32) expected = 32;
        assertEq(out.length, expected);
        for (uint256 i = 0; i < expected; i++) {
            assertEq(out[i], payload[offset + i]);
        }
    }

    function test_validateReadPreimage_wrongCertHash_reverts() public {
        bytes memory proof = _buildReadProof(validCert, payload, false, false);
        vm.expectRevert("Certificate hash mismatch");
        validator.validateReadPreimage(keccak256("wrong"), 0, proof);
    }

    function test_validateReadPreimage_badBlobstreamProof_reverts() public {
        bytes memory proof = _buildReadProof(validCert, payload, true, false);
        vm.expectRevert("Shares proof dataRoot does not match certificate dataRoot");
        validator.validateReadPreimage(keccak256(validCert), 0, proof);
    }

    function test_validateReadPreimage_badSharesProof_reverts() public {
        bytes memory proof = _buildReadProof(validCert, payload, false, true);
        vm.expectRevert("Invalid Celestia shares inclusion proof");
        validator.validateReadPreimage(keccak256(validCert), 0, proof);
    }

    function _buildReadProof(
        bytes memory certificate,
        bytes memory preimage,
        bool wrongDataRoot,
        bool wrongShare
    ) internal view returns (bytes memory) {
        SharesProof memory sp = sharesProof;
        if (wrongDataRoot) {
            sp.attestationProof.tuple.dataRoot = keccak256("wrong-data-root");
        }
        if (wrongShare) {
            sp.data[0] = bytes("tampered-share");
        }

        bytes memory sharesProofData = abi.encode(address(mockBlobstream), sp);
        bytes memory custom = abi.encodePacked(bytes1(0x01), uint64(preimage.length), preimage, sharesProofData);
        return abi.encodePacked(uint64(certificate.length), certificate, custom);
    }

    function _buildCert(
        uint64 blockHeight,
        uint64 start,
        uint64 sharesLength,
        bytes32 txc,
        bytes32 dataRoot
    ) internal pure returns (bytes memory) {
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
}
