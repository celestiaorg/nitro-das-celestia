// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import "./DataRootTuple.sol";
import "./tree/binary/BinaryMerkleProof.sol";

/// @notice Data Availability Oracle interface.
interface IDAOracle {
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
