// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./DataRootTuple.sol";
import "./tree/binary/BinaryMerkleProof.sol";
interface IBlobstreamX {
    /// @notice Contract is frozen.
    error ContractFrozen();

    /// @notice Data commitment stored for the block range [startBlock, endBlock) with proof nonce.
    /// @param proofNonce The nonce of the proof.
    /// @param startBlock The start block of the block range.
    /// @param endBlock The end block of the block range.
    /// @param dataCommitment The data commitment for the block range.
    event DataCommitmentStored(
        uint256 proofNonce,
        uint64 indexed startBlock,
        uint64 indexed endBlock,
        bytes32 indexed dataCommitment
    );

    /// @dev Latest height published to the BlobstreamX contract.
    function latestBlock() external view returns (uint64);

    /// @dev Nonce for proof events. Must be incremented sequentially.
    function state_proofNonce() external view returns (uint256);

    /// @dev Is the BlobstreamX contract forzen or not.
    function frozen() external view returns (bool);

    /// @dev fetches data commitment from BlobstreamX state.
    function state_dataCommitments(uint256) external view returns (bytes32);

    /// @notice Verify a Data Availability attestation.
    /// @param _tupleRootNonce Nonce of the tuple root to prove against.
    /// @param _tuple Data root tuple to prove inclusion of.
    /// @param _proof Binary Merkle tree proof that `tuple` is in the root at `_tupleRootNonce`.
    /// @return `true` is proof is valid, `false` otherwise.
    function verifyAttestation(
        uint256 _tupleRootNonce,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool);
}
