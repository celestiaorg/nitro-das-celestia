// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../lib/IDAOracle.sol";
import "../../lib/DataRootTuple.sol";
import "../../lib/tree/binary/BinaryMerkleProof.sol";
import "../../lib/tree/binary/BinaryMerkleTree.sol";

/// @notice Mock Blobstream contract for testing CelestiaDAProofValidator.
contract MockBlobstream is IDAOracle {
    error ContractFrozen();
    event DataCommitmentStored(
        uint256 proofNonce,
        uint64 indexed startBlock,
        uint64 indexed endBlock,
        bytes32 indexed dataCommitment
    );

    uint64 public latestBlock;
    uint256 public state_proofNonce;
    mapping(uint256 => bytes32) public state_dataCommitments;
    bool public frozen;

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
    ) external view override returns (bool) {
        if (frozen) revert ContractFrozen();
        if (_proofNonce == 0 || _proofNonce >= state_proofNonce) return false;

        bytes32 root = state_dataCommitments[_proofNonce];
        (bool ok, ) = BinaryMerkleTree.verify(root, _proof, abi.encode(_tuple));
        return ok;
    }
}
