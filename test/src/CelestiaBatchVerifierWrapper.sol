// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./lib/CelestiaBatchVerifier.sol";
import "./lib/tree/namespace/NamespaceMerkleTree.sol"; // For NamespaceNode
import "./lib/tree/binary/BinaryMerkleProof.sol"; // For BinaryMerkleProof
import "./lib/DataRootTuple.sol"; // For AttestationProof

contract CelestiaBatchVerifierWrapper {
    using CelestiaBatchVerifier for *;

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
        return
            CelestiaBatchVerifier.verifyProof(
                _blobstream,
                _rowRoot,
                _rowProof,
                _attestationProof
            );
    }

    function verifyBatch(
        address _blobstream,
        bytes calldata _data
    ) public view returns (CelestiaBatchVerifier.Result) {
        return CelestiaBatchVerifier.verifyBatch(_blobstream, _data);
    }
}
