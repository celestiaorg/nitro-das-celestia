// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./DataRootTuple.sol";
import "./tree/binary/BinaryMerkleTree.sol";
import "./IBlobstreamX.sol";

contract Mockstream is IBlobstreamX {
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

    function submitDataCommitment(
        bytes32 _dataCommitment,
        uint64 _beginBlock,
        uint64 _endBlock
    ) external {
        if (latestBlock > _beginBlock || _beginBlock > _endBlock) {
            revert("INVALID RANGE");
        }
        state_dataCommitments[state_proofNonce] = _dataCommitment;

        emit DataCommitmentStored(state_proofNonce, _beginBlock, _endBlock, _dataCommitment);

        state_proofNonce++;
        latestBlock = _endBlock;
    }

    function verifyAttestation(
        uint256 _proofNonce,
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool) {
        if (frozen) {
            revert ContractFrozen();
        }

        if (_proofNonce == 0 || _proofNonce >= state_proofNonce) {
            return false;
        }

        bytes32 root = state_dataCommitments[_proofNonce];
        (bool isProofValid, ) = BinaryMerkleTree.verify(root, _proof, abi.encode(_tuple));
        return isProofValid;
    }
}
