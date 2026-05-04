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

type namespaceABI struct {
	Version [1]byte
	Id      [28]byte
}

type namespaceNodeABI struct {
	Min    namespaceABI
	Max    namespaceABI
	Digest [32]byte
}

type binaryMerkleProofABI struct {
	SideNodes [][32]byte
	Key       *big.Int
	NumLeaves *big.Int
}

type namespaceMerkleMultiproofABI struct {
	BeginKey  *big.Int
	EndKey    *big.Int
	SideNodes []namespaceNodeABI
}

type dataRootTupleABI struct {
	Height   *big.Int
	DataRoot [32]byte
}

type attestationProofABI struct {
	TupleRootNonce *big.Int
	Tuple          dataRootTupleABI
	Proof          binaryMerkleProofABI
}

type sharesProofABI struct {
	Data             [][]byte
	ShareProofs      []namespaceMerkleMultiproofABI
	Namespace        namespaceABI
	RowRoots         []namespaceNodeABI
	RowProofs        []binaryMerkleProofABI
	AttestationProof attestationProofABI
}

var (
	namespaceABIComponents = []abi.ArgumentMarshaling{
		{Name: "version", Type: "bytes1"},
		{Name: "id", Type: "bytes28"},
	}
	namespaceNodeABIComponents = []abi.ArgumentMarshaling{
		{Name: "min", Type: "tuple", Components: namespaceABIComponents},
		{Name: "max", Type: "tuple", Components: namespaceABIComponents},
		{Name: "digest", Type: "bytes32"},
	}
	binaryMerkleProofABIComponents = []abi.ArgumentMarshaling{
		{Name: "sideNodes", Type: "bytes32[]"},
		{Name: "key", Type: "uint256"},
		{Name: "numLeaves", Type: "uint256"},
	}
	dataRootTupleABIComponents = []abi.ArgumentMarshaling{
		{Name: "height", Type: "uint256"},
		{Name: "dataRoot", Type: "bytes32"},
	}
	attestationProofABIComponents = []abi.ArgumentMarshaling{
		{Name: "tupleRootNonce", Type: "uint256"},
		{Name: "tuple", Type: "tuple", Components: dataRootTupleABIComponents},
		{Name: "proof", Type: "tuple", Components: binaryMerkleProofABIComponents},
	}
	namespaceMerkleMultiproofABIComponents = []abi.ArgumentMarshaling{
		{Name: "beginKey", Type: "uint256"},
		{Name: "endKey", Type: "uint256"},
		{Name: "sideNodes", Type: "tuple[]", Components: namespaceNodeABIComponents},
	}
	sharesProofABIComponents = []abi.ArgumentMarshaling{
		{Name: "data", Type: "bytes[]"},
		{Name: "shareProofs", Type: "tuple[]", Components: namespaceMerkleMultiproofABIComponents},
		{Name: "namespace", Type: "tuple", Components: namespaceABIComponents},
		{Name: "rowRoots", Type: "tuple[]", Components: namespaceNodeABIComponents},
		{Name: "rowProofs", Type: "tuple[]", Components: binaryMerkleProofABIComponents},
		{Name: "attestationProof", Type: "tuple", Components: attestationProofABIComponents},
	}
)

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
		TupleRootNonce: new(big.Int).SetUint64(nonce),
		Tuple: DataRootTuple{
			Height:   new(big.Int).SetUint64(height),
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
		Type: mustABIType("tuple", sharesProofABIComponents),
	},
}

var blobstreamProofArgs = abi.Arguments{
	{Name: "_blobstream", Type: mustABIType("address", nil)},
	{Name: "_rowRoot", Type: mustABIType("tuple", namespaceNodeABIComponents)},
	{Name: "_rowProof", Type: mustABIType("tuple", binaryMerkleProofABIComponents)},
	{Name: "_attestationProof", Type: mustABIType("tuple", attestationProofABIComponents)},
}

var validityProofArgs = abi.Arguments{
	{Name: "attestationProof", Type: mustABIType("tuple", attestationProofABIComponents)},
}

func mustABIType(t string, components []abi.ArgumentMarshaling) abi.Type {
	typ, err := abi.NewType(t, "", components)
	if err != nil {
		panic("invalid ABI type: " + t)
	}
	return typ
}

func toNamespaceABI(ns Namespace) namespaceABI {
	return namespaceABI{
		Version: ns.Version,
		Id:      ns.Id,
	}
}

func toNamespaceNodeABI(node NamespaceNode) namespaceNodeABI {
	return namespaceNodeABI{
		Min:    toNamespaceABI(node.Min),
		Max:    toNamespaceABI(node.Max),
		Digest: node.Digest,
	}
}

func toBinaryMerkleProofABI(proof BinaryMerkleProof) binaryMerkleProofABI {
	return binaryMerkleProofABI{
		SideNodes: proof.SideNodes,
		Key:       proof.Key,
		NumLeaves: proof.NumLeaves,
	}
}

func toNamespaceMerkleMultiproofABI(proof NamespaceMerkleMultiproof) namespaceMerkleMultiproofABI {
	sideNodes := make([]namespaceNodeABI, 0, len(proof.SideNodes))
	for _, node := range proof.SideNodes {
		sideNodes = append(sideNodes, toNamespaceNodeABI(node))
	}
	return namespaceMerkleMultiproofABI{
		BeginKey:  proof.BeginKey,
		EndKey:    proof.EndKey,
		SideNodes: sideNodes,
	}
}

func toDataRootTupleABI(tuple DataRootTuple) dataRootTupleABI {
	return dataRootTupleABI{
		Height:   tuple.Height,
		DataRoot: tuple.DataRoot,
	}
}

func toAttestationProofABI(proof AttestationProof) attestationProofABI {
	return attestationProofABI{
		TupleRootNonce: proof.TupleRootNonce,
		Tuple:          toDataRootTupleABI(proof.Tuple),
		Proof:          toBinaryMerkleProofABI(proof.Proof),
	}
}

func toSharesProofABI(proof SharesProof) sharesProofABI {
	shareProofs := make([]namespaceMerkleMultiproofABI, 0, len(proof.ShareProofs))
	for _, shareProof := range proof.ShareProofs {
		shareProofs = append(shareProofs, toNamespaceMerkleMultiproofABI(shareProof))
	}

	rowRoots := make([]namespaceNodeABI, 0, len(proof.RowRoots))
	for _, rowRoot := range proof.RowRoots {
		rowRoots = append(rowRoots, toNamespaceNodeABI(rowRoot))
	}

	rowProofs := make([]binaryMerkleProofABI, 0, len(proof.RowProofs))
	for _, rowProof := range proof.RowProofs {
		rowProofs = append(rowProofs, toBinaryMerkleProofABI(rowProof))
	}

	return sharesProofABI{
		Data:             proof.Data,
		ShareProofs:      shareProofs,
		Namespace:        toNamespaceABI(proof.Namespace),
		RowRoots:         rowRoots,
		RowProofs:        rowProofs,
		AttestationProof: toAttestationProofABI(proof.AttestationProof),
	}
}

func packSharesProof(blobstreamAddr common.Address, sharesProof SharesProof) ([]byte, error) {
	return sharesProofArgs.Pack(blobstreamAddr, toSharesProofABI(sharesProof))
}

// packBlobstreamProof keeps the legacy row-root-only proof packing used by GetProof.
func packBlobstreamProof(blobstreamAddr common.Address, nsNode NamespaceNode, rowProof BinaryMerkleProof, attProof AttestationProof) ([]byte, error) {
	return blobstreamProofArgs.Pack(
		blobstreamAddr,
		toNamespaceNodeABI(nsNode),
		toBinaryMerkleProofABI(rowProof),
		toAttestationProofABI(attProof),
	)
}

func packValidityProof(attProof AttestationProof) ([]byte, error) {
	return validityProofArgs.Pack(toAttestationProofABI(attProof))
}
