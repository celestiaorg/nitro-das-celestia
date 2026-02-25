package das

import (
	"math/big"

	appproof "github.com/celestiaorg/celestia-app/v6/pkg/proof"
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

type NamespaceMerkleMultiproof struct {
	BeginKey  *big.Int
	EndKey    *big.Int
	SideNodes []NamespaceNode
}

type SharesProof struct {
	Data             [][]byte
	ShareProofs      []NamespaceMerkleMultiproof
	Namespace        Namespace
	RowRoots         []NamespaceNode
	RowProofs        []BinaryMerkleProof
	AttestationProof AttestationProof
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

func toRowProofFromAppProof(proof *appproof.Proof) BinaryMerkleProof {
	sideNodes := make([][32]byte, len(proof.Aunts))
	for j, sideNode := range proof.Aunts {
		var bzSideNode [32]byte
		copy(bzSideNode[:], sideNode)
		sideNodes[j] = bzSideNode
	}
	return BinaryMerkleProof{
		SideNodes: sideNodes,
		Key:       big.NewInt(proof.Index),
		NumLeaves: big.NewInt(proof.Total),
	}
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

// sharesProofArgs encodes:
// (address blobstream, SharesProof sharesProof)
var sharesProofArgs = abi.Arguments{
	{
		Name: "blobstream",
		Type: mustABIType("address", nil),
	},
	{
		Name: "sharesProof",
		Type: mustABIType("tuple", []abi.ArgumentMarshaling{
			{Name: "data", Type: "bytes[]"},
			{Name: "shareProofs", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
				{Name: "beginKey", Type: "uint256"},
				{Name: "endKey", Type: "uint256"},
				{Name: "sideNodes", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
					{Name: "min", Type: "tuple", Components: []abi.ArgumentMarshaling{
						{Name: "version", Type: "bytes1"},
						{Name: "id", Type: "bytes28"},
					}},
					{Name: "max", Type: "tuple", Components: []abi.ArgumentMarshaling{
						{Name: "version", Type: "bytes1"},
						{Name: "id", Type: "bytes28"},
					}},
					{Name: "digest", Type: "bytes32"},
				}},
			}},
			{Name: "namespace", Type: "tuple", Components: []abi.ArgumentMarshaling{
				{Name: "version", Type: "bytes1"},
				{Name: "id", Type: "bytes28"},
			}},
			{Name: "rowRoots", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
				{Name: "min", Type: "tuple", Components: []abi.ArgumentMarshaling{
					{Name: "version", Type: "bytes1"},
					{Name: "id", Type: "bytes28"},
				}},
				{Name: "max", Type: "tuple", Components: []abi.ArgumentMarshaling{
					{Name: "version", Type: "bytes1"},
					{Name: "id", Type: "bytes28"},
				}},
				{Name: "digest", Type: "bytes32"},
			}},
			{Name: "rowProofs", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
				{Name: "sideNodes", Type: "bytes32[]"},
				{Name: "key", Type: "uint256"},
				{Name: "numLeaves", Type: "uint256"},
			}},
			{Name: "attestationProof", Type: "tuple", Components: []abi.ArgumentMarshaling{
				{Name: "tupleRootNonce", Type: "uint256"},
				{Name: "tuple", Type: "tuple", Components: []abi.ArgumentMarshaling{
					{Name: "height", Type: "uint256"},
					{Name: "dataRoot", Type: "bytes32"},
				}},
				{Name: "proof", Type: "tuple", Components: []abi.ArgumentMarshaling{
					{Name: "sideNodes", Type: "bytes32[]"},
					{Name: "key", Type: "uint256"},
					{Name: "numLeaves", Type: "uint256"},
				}},
			}},
		}),
	},
}

func mustABIType(t string, components []abi.ArgumentMarshaling) abi.Type {
	typ, err := abi.NewType(t, "", components)
	if err != nil {
		panic("invalid ABI type: " + t)
	}
	return typ
}

func packSharesProof(blobstreamAddr common.Address, sharesProof SharesProof) ([]byte, error) {
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
	type multiproofABI struct {
		BeginKey  *big.Int
		EndKey    *big.Int
		SideNodes []nsNodeABI
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
	type sharesProofABI struct {
		Data             [][]byte
		ShareProofs      []multiproofABI
		Namespace        nsABI
		RowRoots         []nsNodeABI
		RowProofs        []rowProofABI
		AttestationProof attProofABI
	}

	shareProofs := make([]multiproofABI, 0, len(sharesProof.ShareProofs))
	for _, sp := range sharesProof.ShareProofs {
		sideNodes := make([]nsNodeABI, 0, len(sp.SideNodes))
		for _, sn := range sp.SideNodes {
			sideNodes = append(sideNodes, nsNodeABI{
				Min:    nsABI(sn.Min),
				Max:    nsABI(sn.Max),
				Digest: sn.Digest,
			})
		}
		shareProofs = append(shareProofs, multiproofABI{
			BeginKey:  sp.BeginKey,
			EndKey:    sp.EndKey,
			SideNodes: sideNodes,
		})
	}

	rowRoots := make([]nsNodeABI, 0, len(sharesProof.RowRoots))
	for _, rr := range sharesProof.RowRoots {
		rowRoots = append(rowRoots, nsNodeABI{
			Min:    nsABI(rr.Min),
			Max:    nsABI(rr.Max),
			Digest: rr.Digest,
		})
	}

	rowProofs := make([]rowProofABI, 0, len(sharesProof.RowProofs))
	for _, rp := range sharesProof.RowProofs {
		rowProofs = append(rowProofs, rowProofABI{
			SideNodes: rp.SideNodes,
			Key:       rp.Key,
			NumLeaves: rp.NumLeaves,
		})
	}

	return sharesProofArgs.Pack(
		blobstreamAddr,
		sharesProofABI{
			Data:        sharesProof.Data,
			ShareProofs: shareProofs,
			Namespace: nsABI{
				Version: sharesProof.Namespace.Version,
				Id:      sharesProof.Namespace.Id,
			},
			RowRoots:  rowRoots,
			RowProofs: rowProofs,
			AttestationProof: attProofABI{
				TupleRootNonce: sharesProof.AttestationProof.TupleRootNonce,
				Tuple: dataTupleABI{
					Height:   sharesProof.AttestationProof.Tuple.Height,
					DataRoot: sharesProof.AttestationProof.Tuple.DataRoot,
				},
				Proof: rowProofABI{
					SideNodes: sharesProof.AttestationProof.Proof.SideNodes,
					Key:       sharesProof.AttestationProof.Proof.Key,
					NumLeaves: sharesProof.AttestationProof.Proof.NumLeaves,
				},
			},
		},
	)
}

// packBlobstreamProof keeps the legacy row-root-only proof packing used by GetProof.
func packBlobstreamProof(blobstreamAddr common.Address, nsNode NamespaceNode, rowProof BinaryMerkleProof, attProof AttestationProof) ([]byte, error) {
	args := abi.Arguments{
		{Name: "_blobstream", Type: mustABIType("address", nil)},
		{
			Name: "_rowRoot",
			Type: mustABIType("tuple", []abi.ArgumentMarshaling{
				{Name: "min", Type: "tuple", Components: []abi.ArgumentMarshaling{{Name: "version", Type: "bytes1"}, {Name: "id", Type: "bytes28"}}},
				{Name: "max", Type: "tuple", Components: []abi.ArgumentMarshaling{{Name: "version", Type: "bytes1"}, {Name: "id", Type: "bytes28"}}},
				{Name: "digest", Type: "bytes32"},
			}),
		},
		{
			Name: "_rowProof",
			Type: mustABIType("tuple", []abi.ArgumentMarshaling{
				{Name: "sideNodes", Type: "bytes32[]"},
				{Name: "key", Type: "uint256"},
				{Name: "numLeaves", Type: "uint256"},
			}),
		},
		{
			Name: "_attestationProof",
			Type: mustABIType("tuple", []abi.ArgumentMarshaling{
				{Name: "tupleRootNonce", Type: "uint256"},
				{Name: "tuple", Type: "tuple", Components: []abi.ArgumentMarshaling{{Name: "height", Type: "uint256"}, {Name: "dataRoot", Type: "bytes32"}}},
				{Name: "proof", Type: "tuple", Components: []abi.ArgumentMarshaling{{Name: "sideNodes", Type: "bytes32[]"}, {Name: "key", Type: "uint256"}, {Name: "numLeaves", Type: "uint256"}}},
			}),
		},
	}

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

	return args.Pack(
		blobstreamAddr,
		nsNodeABI{Min: nsABI(nsNode.Min), Max: nsABI(nsNode.Max), Digest: nsNode.Digest},
		rowProofABI{SideNodes: rowProof.SideNodes, Key: rowProof.Key, NumLeaves: rowProof.NumLeaves},
		attProofABI{
			TupleRootNonce: attProof.TupleRootNonce,
			Tuple:          dataTupleABI{Height: attProof.Tuple.Height, DataRoot: attProof.Tuple.DataRoot},
			Proof:          rowProofABI{SideNodes: attProof.Proof.SideNodes, Key: attProof.Proof.Key, NumLeaves: attProof.Proof.NumLeaves},
		},
	)
}
