package das

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func sampleAttestationProof() AttestationProof {
	return AttestationProof{
		TupleRootNonce: big.NewInt(9),
		Tuple: DataRootTuple{
			Height:   big.NewInt(123),
			DataRoot: [32]byte{0xaa},
		},
		Proof: BinaryMerkleProof{
			SideNodes: [][32]byte{{0x01}, {0x02}},
			Key:       big.NewInt(4),
			NumLeaves: big.NewInt(8),
		},
	}
}

func sampleNamespaceNode(seed byte) NamespaceNode {
	return NamespaceNode{
		Min: Namespace{
			Version: [1]byte{seed},
			Id:      [28]byte{seed + 1},
		},
		Max: Namespace{
			Version: [1]byte{seed + 2},
			Id:      [28]byte{seed + 3},
		},
		Digest: [32]byte{seed + 4},
	}
}

func sampleSharesProof() SharesProof {
	return SharesProof{
		Data: [][]byte{
			[]byte("share-a"),
			[]byte("share-b"),
		},
		ShareProofs: []NamespaceMerkleMultiproof{
			{
				BeginKey:  big.NewInt(1),
				EndKey:    big.NewInt(3),
				SideNodes: []NamespaceNode{sampleNamespaceNode(0x10)},
			},
		},
		Namespace: Namespace{
			Version: [1]byte{0x20},
			Id:      [28]byte{0x21},
		},
		RowRoots: []NamespaceNode{
			sampleNamespaceNode(0x30),
		},
		RowProofs: []BinaryMerkleProof{
			{
				SideNodes: [][32]byte{{0x31}},
				Key:       big.NewInt(5),
				NumLeaves: big.NewInt(16),
			},
		},
		AttestationProof: sampleAttestationProof(),
	}
}

func unpackArgsInto[T any](t *testing.T, args abi.Arguments, packed []byte) T {
	t.Helper()

	vals, err := args.Unpack(packed)
	require.NoError(t, err)

	var out T
	require.NoError(t, args.Copy(&out, vals))
	return out
}

func TestPackValidityProof_RoundTrip(t *testing.T) {
	t.Parallel()

	attProof := sampleAttestationProof()
	packed, err := packValidityProof(attProof)
	require.NoError(t, err)

	type decoded struct {
		AttestationProof attestationProofABI `abi:"attestationProof"`
	}
	out := unpackArgsInto[decoded](t, validityProofArgs, packed)
	require.Equal(t, toAttestationProofABI(attProof), out.AttestationProof)
}

func TestPackBlobstreamProof_RoundTrip(t *testing.T) {
	t.Parallel()

	blobstreamAddr := common.HexToAddress("0x00000000000000000000000000000000000000AA")
	rowRoot := sampleNamespaceNode(0x40)
	rowProof := BinaryMerkleProof{
		SideNodes: [][32]byte{{0x41}},
		Key:       big.NewInt(6),
		NumLeaves: big.NewInt(32),
	}
	attProof := sampleAttestationProof()

	packed, err := packBlobstreamProof(blobstreamAddr, rowRoot, rowProof, attProof)
	require.NoError(t, err)

	type decoded struct {
		Blobstream       common.Address       `abi:"_blobstream"`
		RowRoot          namespaceNodeABI     `abi:"_rowRoot"`
		RowProof         binaryMerkleProofABI `abi:"_rowProof"`
		AttestationProof attestationProofABI  `abi:"_attestationProof"`
	}
	out := unpackArgsInto[decoded](t, blobstreamProofArgs, packed)
	require.Equal(t, blobstreamAddr, out.Blobstream)
	require.Equal(t, toNamespaceNodeABI(rowRoot), out.RowRoot)
	require.Equal(t, toBinaryMerkleProofABI(rowProof), out.RowProof)
	require.Equal(t, toAttestationProofABI(attProof), out.AttestationProof)
}

func TestPackSharesProof_RoundTrip(t *testing.T) {
	t.Parallel()

	blobstreamAddr := common.HexToAddress("0x00000000000000000000000000000000000000BB")
	sharesProof := sampleSharesProof()

	packed, err := packSharesProof(blobstreamAddr, sharesProof)
	require.NoError(t, err)

	type decoded struct {
		Blobstream  common.Address `abi:"blobstream"`
		SharesProof sharesProofABI `abi:"sharesProof"`
	}
	out := unpackArgsInto[decoded](t, sharesProofArgs, packed)
	require.Equal(t, blobstreamAddr, out.Blobstream)
	require.Equal(t, toSharesProofABI(sharesProof), out.SharesProof)
}
