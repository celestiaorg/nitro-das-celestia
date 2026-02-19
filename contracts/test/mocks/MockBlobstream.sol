// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "blobstream-contracts/IDAOracle.sol";
import "blobstream-contracts/DataRootTuple.sol";
import "blobstream-contracts/lib/tree/binary/BinaryMerkleProof.sol";
import "blobstream-contracts/lib/tree/binary/BinaryMerkleTree.sol";
import "../../lib/IBlobstreamX.sol";

/// @notice Mock Blobstream contract for testing CelestiaDAProofValidator.
/// Implements both IDAOracle (verifyAttestation) and IBlobstreamX (latestBlock)
/// so it can be used as a drop-in for the validator contract.
contract MockBlobstream is IDAOracle, IBlobstreamX {
    uint64 public override latestBlock;
    uint256 public override state_proofNonce;
    mapping(uint256 => bytes32) public override state_dataCommitments;
    bool public override frozen;

    function initialize(uint64 _latestBlock) external {
        frozen = false;
        latestBlock = _latestBlock;
        state_proofNonce = 1;
    }

    function updateFreeze(bool _freeze) external {
        frozen = _freeze;
    }

    function updateGenesisState(uint64 _height) external {
        latestBlock = _height;
    }

    /// @notice Submit a data commitment covering [_beginBlock, _endBlock).
    /// Builds a trivial Merkle tree with a single leaf = abi.encode(DataRootTuple)
    /// so that verifyAttestation proofs generated off-chain are consistent.
    function submitDataCommitment(
        bytes32 _dataCommitment,
        uint64 _beginBlock,
        uint64 _endBlock
    ) external {
        require(latestBlock <= _beginBlock && _beginBlock < _endBlock, "INVALID RANGE");

        state_dataCommitments[state_proofNonce] = _dataCommitment;
        emit DataCommitmentStored(state_proofNonce, _beginBlock, _endBlock, _dataCommitment);

        state_proofNonce++;
        latestBlock = _endBlock;
    }

    /// @inheritdoc IDAOracle
    function verifyAttestation(
        uint256 _proofNonce,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view override(IDAOracle, IBlobstreamX) returns (bool) {
        if (frozen) revert ContractFrozen();
        if (_proofNonce == 0 || _proofNonce >= state_proofNonce) return false;

        bytes32 root = state_dataCommitments[_proofNonce];
        return BinaryMerkleTree.verify(root, _proof, abi.encode(_tuple));
    }
}
