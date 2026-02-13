// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import {IBlobstreamX} from "./IBlobstreamX.sol";

import "./DAVerifier.sol";
import "./Constants.sol";
import "./DataRootTuple.sol";
import "./tree/binary/BinaryMerkleProof.sol";
import "./tree/binary/BinaryMerkleTree.sol";
import "./tree/namespace/NamespaceMerkleTree.sol";
import "./tree/Types.sol";

/**
 * @dev Go struct representation of batch data for a Celestia DA orbit chain
 *
 * @param BlockHeight The height of the block containing the blob.
 * @param Start The starting index of the blob within the block.
 * @param SharesLength The length of the shares in the blob.
 * @param DataRoot A 32-byte hash representing the root of the data.
 * @param TxCommitment A 32-byte hash representing the commitment to transactions.
 */
// struct BlobPointer {
//     uint64 BlockHeight;
//     uint64 Start;
//     uint64 SharesLength;
//     bytes32 DataRoot;
//     bytes32 TxCommitment;
// }

/// @title CelestiaBatchVerifier: Utility library to verify Nitro batches against Blobstream
/// @dev The CelestiaBatchVerifier verifies batch data against Blobstream and returns either:
/// - IN_BLOBSTREAM, meaning that the batch was found in Blobstream.
/// - COUNTERFACTUAL_COMMITMENT, meaning that the commitment's Celestia block height has been
/// proven in Blobstream not to contain the commitment
/// - UNDECIDED meaning that the block height has not been proven yet in Blobstream
/// If the proof data is invalid, it reverts
library CelestiaBatchVerifier {
    /// @dev The heights in the batch data and proof do not match
    error MismatchedHeights();

    /// @dev The attestation and or row root proof was invalid
    error InvalidProof();

    /// @title Result
    /// @notice Enumerates the possible outcomes for data verification processes.
    /// @dev Provides a standardized way to represent the verification status of data.
    enum Result {
        /// @dev Indicates the data has been verified to exist within Blobstream.
        IN_BLOBSTREAM,
        /// @dev Represents a situation where the batch data has been proven to be incorrect. Or BlobstreamX was frozen
        COUNTERFACTUAL_COMMITMENT,
        /// @dev The height for the batch data has not been committed to by Blobstream yet.
        UNDECIDED
    }

    /**
     * @notice Given some batch data with the structre of `BlobPointer`, verifyBatch validates:
     * 1. The Celestia Height for the batch data is in blobsream.
     * 2. The user supplied proof's data root exists in Blobstream.
     * 2. The the data root from the batch data and the valid user supplied proof match, and the
     *    span of shares for the batch data is available (i.e the start + length of a blob does not
     *    go outside the bounds of the origianal celestia data square for the given height)
     *
     * Rationale:
     * Validators possess the preimages for the data root and row roots, making it necessary only to verify
     * the existence and the length (span) of the index and blob length.
     * This ensures the data published by the batch poster is available.
     */
    function verifyBatch(
        address _blobstream,
        bytes calldata _data
    ) internal view returns (Result) {
        IBlobstreamX blobstreamX = IBlobstreamX(_blobstream);

        uint64 height = uint64(bytes8(_data[0:8]));

        // If the height is to far into the future (1000 blocks), return COUNTERFACTUAL_COMMITMENT
        // because the batch poster is trying to stall
        if (height > (blobstreamX.latestBlock() + 1000))
            return Result.COUNTERFACTUAL_COMMITMENT;

        // Otherwise return undecided, as the commitment still needs to be relayed to Blobstream
        if (height > blobstreamX.latestBlock()) return Result.UNDECIDED;

        (
            ,
            NamespaceNode memory namespaceNode,
            BinaryMerkleProof memory proof,
            AttestationProof memory attestationProof
        ) = abi.decode(
                _data[88:],
                (address, NamespaceNode, BinaryMerkleProof, AttestationProof)
            );

        (
            bool valid,
            uint256 proofHeight,
            bytes32 proofDataRoot,
            BinaryMerkleProof memory rowProof
        ) = verifyProof(_blobstream, namespaceNode, proof, attestationProof);

        // revert, because for a given height that has been confirmed to exist in Blobstream,
        // there has to be a valid proof
        // if (!valid) revert InvalidProof();
        if (!valid) revert("INVALID_PROOF");
        // check height against the one in the batch data, if they do not match,
        // revert, because the user supplied proof does not verify against
        // the batch's celestia height.
        // if (height != proofHeight) revert MismatchedHeights();
        if (height != proofHeight) revert("MismatchedHeights");

        // check the data root in the proof against the one in the batch data.
        // if they do not match, its a counterfactual commitment, because
        // 1. the user supplied proof proves the height was relayed to Blobstream
        //    (we know the height is valid because it's less than or equal to the latest block)
        // 2. the data root from the batch data does not exist at the height the batch poster claimed
        //    to have posted to.
        // NOTE: a celestia batch has the data root (32 bytes) at index 56
        if (bytes32(_data[56:88]) != proofDataRoot)
            return Result.COUNTERFACTUAL_COMMITMENT;

        // Calculate size of the Original Data Square (ODS)
        (uint256 squareSize, ) = DAVerifier.computeSquareSizeFromRowProof(
            rowProof
        );

        if (squareSize == 0) return Result.COUNTERFACTUAL_COMMITMENT;
        // Check that the start + length posted by the batch poster is not out of bounds
        // otherwise return counterfactual commitment
        // NOTE: a celestia batch has the start (8 bytes) and length (8 bytes) at index 8 - 24
        // we also substract 1 to account for the shares length including the start share
        // thus letting us correctly calculate the end index
        if (
            (uint64(bytes8(_data[8:16])) + uint64(bytes8(_data[16:24])) - 1) >=
            squareSize * squareSize
        ) return Result.COUNTERFACTUAL_COMMITMENT;

        // At this point, there has been:
        // 1. A succesfull proof that shows the height and data root the batch poster included
        //    in the batch data exist in Blobstream.
        // 2. A proof that the sequence the batch poster included in the batch data is inside
        //    of the data square (remember, any valid row root proof can show this is true)
        // 3. No deadlocks or incorrect counter factual commitments have been made, since:
        //    - If the height in the batch is less than the latest height in blobstrea,
        //      a valid attestation + row proof must exist for it
        //    - we have shown that the batch poster did not lie about the data root and height,
        //      nor about the span being in the bounds of the square. Thus, validators have
        //      access to the data through the preimage oracle
        return Result.IN_BLOBSTREAM;
    }

    function verifyProof(
        address _blobstream,
        NamespaceNode memory _rowRoot,
        BinaryMerkleProof memory _rowProof,
        AttestationProof memory _attestationProof
    )
        public
        view
        returns (
            bool isValid,
            uint256 proofHeight,
            bytes32 proofDataRoot,
            BinaryMerkleProof memory rowProof
        )
    {
        (bool valid, DAVerifier.ErrorCodes errorCode) = DAVerifier
            .verifyRowRootToDataRootTupleRoot(
                IDAOracle(_blobstream),
                _rowRoot,
                _rowProof,
                _attestationProof
            );

        return (
            valid,
            _attestationProof.tuple.height,
            _attestationProof.tuple.dataRoot,
            _rowProof
        );
    }
}
