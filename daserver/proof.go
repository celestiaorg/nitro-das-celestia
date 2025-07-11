package das

import (
	"math/big"

	"github.com/celestiaorg/celestia-node/nodebuilder/blobstream"
	"github.com/tendermint/tendermint/crypto/merkle"
)

type Namespace struct {
	Version [1]byte
	Id      [28]byte
}

type NamespaceNode struct {
	Min    Namespace
	Max    Namespace
	Digest [32]byte
}

type BinaryMerkleProof struct {
	SideNodes [][32]byte
	Key       *big.Int
	NumLeaves *big.Int
}

type DataRootTuple struct {
	Height   *big.Int
	DataRoot [32]byte
}

type AttestationProof struct {
	TupleRootNonce *big.Int
	Tuple          DataRootTuple
	Proof          BinaryMerkleProof
}

func minNamespace(innerNode []byte) Namespace {
	version := innerNode[0]
	var id [28]byte
	copy(id[:], innerNode[1:29])
	return Namespace{
		Version: [1]byte{version},
		Id:      id,
	}
}

func maxNamespace(innerNode []byte) Namespace {
	version := innerNode[29]
	var id [28]byte
	copy(id[:], innerNode[30:58])
	return Namespace{
		Version: [1]byte{version},
		Id:      id,
	}
}

func toNamespaceNode(node []byte) NamespaceNode {
	minNs := minNamespace(node)
	maxNs := maxNamespace(node)
	var digest [32]byte
	copy(digest[:], node[58:])
	return NamespaceNode{
		Min:    minNs,
		Max:    maxNs,
		Digest: digest,
	}
}

func toRowProofs(proof *merkle.Proof) BinaryMerkleProof {
	sideNodes := make([][32]byte, len(proof.Aunts))
	for j, sideNode := range proof.Aunts {
		var bzSideNode [32]byte
		copy(bzSideNode[:], sideNode)
		sideNodes[j] = bzSideNode
	}
	rowProof := BinaryMerkleProof{
		SideNodes: sideNodes,
		Key:       big.NewInt(proof.Index),
		NumLeaves: big.NewInt(proof.Total),
	}
	return rowProof
}

func toAttestationProof(
	nonce uint64,
	height uint64,
	blockDataRoot [32]byte,
	dataRootInclusionProof *blobstream.DataRootTupleInclusionProof,
) AttestationProof {
	sideNodes := make([][32]byte, len((*dataRootInclusionProof).Aunts))
	for i, sideNode := range (*dataRootInclusionProof).Aunts {
		var bzSideNode [32]byte
		copy(bzSideNode[:], sideNode)
		sideNodes[i] = bzSideNode
	}

	return AttestationProof{
		TupleRootNonce: big.NewInt(int64(nonce)),
		Tuple: DataRootTuple{
			Height:   big.NewInt(int64(height)),
			DataRoot: blockDataRoot,
		},
		Proof: BinaryMerkleProof{
			SideNodes: sideNodes,
			Key:       big.NewInt((*dataRootInclusionProof).Index),
			NumLeaves: big.NewInt((*dataRootInclusionProof).Total),
		},
	}
}
