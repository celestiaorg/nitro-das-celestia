package das

import (
	"math/big"

	"github.com/celestiaorg/celestia-node/nodebuilder/blobstream"
	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
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

// blobstreamProofArgs is the ABI argument list matching the Solidity signature:
//
//	_requireBlobstreamProof / verifyProof inputs:
//	  (address _blobstream, NamespaceNode _rowRoot, BinaryMerkleProof _rowProof, AttestationProof _attestationProof)
//
// This replaces the old celestiagen.CelestiaBatchVerifierMetaData ABI look-up.
var blobstreamProofArgs = abi.Arguments{
	{
		Name: "_blobstream",
		Type: mustABIType("address"),
	},
	{
		Name: "_rowRoot",
		Type: mustABIType("(bytes1,bytes28,bytes1,bytes28,bytes32)"),
	},
	{
		Name: "_rowProof",
		Type: mustABIType("(bytes32[],uint256,uint256)"),
	},
	{
		Name: "_attestationProof",
		Type: mustABIType("(uint256,(uint256,bytes32),(bytes32[],uint256,uint256))"),
	},
}

func mustABIType(s string) abi.Type {
	t, err := abi.NewType(s, "", nil)
	if err != nil {
		panic("invalid ABI type: " + s)
	}
	return t
}

// packBlobstreamProof ABI-encodes the four arguments that
// CelestiaDAProofValidator._requireBlobstreamProof expects via abi.decode.
func packBlobstreamProof(blobstreamAddr common.Address, nsNode NamespaceNode, rowProof BinaryMerkleProof, attProof AttestationProof) ([]byte, error) {
	// The Solidity structs use fixed-size arrays for Namespace fields.
	// abi.Arguments.Pack maps Go structs by field order, so we use anonymous structs
	// that match the Solidity layout exactly.
	type nsABI struct {
		Version [1]byte
		Id      [28]byte
	}
	type nsNodeABI struct {
		Min    nsABI
		Max    nsABI
		Digest [32]byte
	}
	type rowProofABI struct {
		SideNodes [][32]byte
		Key       *big.Int
		NumLeaves *big.Int
	}
	type dataTupleABI struct {
		Height   *big.Int
		DataRoot [32]byte
	}
	type attProofABI struct {
		TupleRootNonce *big.Int
		Tuple          dataTupleABI
		Proof          rowProofABI
	}

	return blobstreamProofArgs.Pack(
		blobstreamAddr,
		nsNodeABI{
			Min:    nsABI(nsNode.Min),
			Max:    nsABI(nsNode.Max),
			Digest: nsNode.Digest,
		},
		rowProofABI{
			SideNodes: rowProof.SideNodes,
			Key:       rowProof.Key,
			NumLeaves: rowProof.NumLeaves,
		},
		attProofABI{
			TupleRootNonce: attProof.TupleRootNonce,
			Tuple: dataTupleABI{
				Height:   attProof.Tuple.Height,
				DataRoot: attProof.Tuple.DataRoot,
			},
			Proof: rowProofABI{
				SideNodes: attProof.Proof.SideNodes,
				Key:       attProof.Proof.Key,
				NumLeaves: attProof.Proof.NumLeaves,
			},
		},
	)
}
