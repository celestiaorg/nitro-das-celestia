package tree

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/tmhash"
)

func collectingRecorder() (func(common.Hash, []byte, arbutil.PreimageType), *map[common.Hash][]byte) {
	m := make(map[common.Hash][]byte)
	return func(h common.Hash, p []byte, _ arbutil.PreimageType) {
		cp := make([]byte, len(p))
		copy(cp, p)
		m[h] = cp
	}, &m
}

func TestHashFromByteSlices_EmptyInput(t *testing.T) {
	record, preimages := collectingRecorder()
	root := HashFromByteSlices(record, [][]byte{})

	expected := tmhash.Sum([]byte{})
	assert.Equal(t, expected, root)
	// The empty hash itself should be recorded
	assert.Contains(t, *preimages, common.BytesToHash(root))
}

func TestHashFromByteSlices_SingleLeaf(t *testing.T) {
	record, preimages := collectingRecorder()
	leaf := []byte("single leaf")
	root := HashFromByteSlices(record, [][]byte{leaf})

	expected := tmhash.Sum(append([]byte{0x00}, leaf...))
	assert.Equal(t, expected, root)
	assert.Contains(t, *preimages, common.BytesToHash(root))
}

func TestHashFromByteSlices_TwoLeaves(t *testing.T) {
	record, preimages := collectingRecorder()
	leaves := [][]byte{[]byte("left"), []byte("right")}
	root := HashFromByteSlices(record, leaves)

	leftHash := tmhash.Sum(append([]byte{0x00}, leaves[0]...))
	rightHash := tmhash.Sum(append([]byte{0x00}, leaves[1]...))
	preimage := make([]byte, 0, 1+len(leftHash)+len(rightHash))
	preimage = append(preimage, 0x01)
	preimage = append(preimage, leftHash...)
	preimage = append(preimage, rightHash...)
	expected := tmhash.Sum(preimage)
	assert.Equal(t, expected, root)
	// All 3 nodes should be recorded (2 leaves + 1 inner)
	assert.Len(t, *preimages, 3)
}

func TestHashFromByteSlices_FourLeaves(t *testing.T) {
	record, preimages := collectingRecorder()
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	root := HashFromByteSlices(record, leaves)

	require.NotNil(t, root)
	// 4 leaves + 2 inner + 1 root = 7 preimages
	assert.Len(t, *preimages, 7)
}

func TestHashFromByteSlices_Deterministic(t *testing.T) {
	leaves := [][]byte{[]byte("x"), []byte("y"), []byte("z")}
	r1 := HashFromByteSlices(noopRecord, leaves)
	r2 := HashFromByteSlices(noopRecord, leaves)
	assert.Equal(t, r1, r2)
}

func TestHashFromByteSlices_OrderMatters(t *testing.T) {
	r1 := HashFromByteSlices(noopRecord, [][]byte{[]byte("a"), []byte("b")})
	r2 := HashFromByteSlices(noopRecord, [][]byte{[]byte("b"), []byte("a")})
	assert.NotEqual(t, r1, r2)
}

func TestGetSplitPoint(t *testing.T) {
	cases := []struct {
		length int64
		want   int64
	}{
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 4},
		{8, 4},
		{9, 8},
		{16, 8},
		{17, 16},
		{100, 64},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("length=%d", tc.length), func(t *testing.T) {
			got := getSplitPoint(tc.length)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetSplitPoint_PanicsOnZero(t *testing.T) {
	assert.Panics(t, func() { getSplitPoint(0) })
}

func TestMerkleTreeContent_RoundTrips(t *testing.T) {
	record, preimages := collectingRecorder()
	leaves := [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma")}
	root := HashFromByteSlices(record, leaves)

	oracle := func(h common.Hash) ([]byte, error) {
		p, ok := (*preimages)[h]
		if !ok {
			return nil, fmt.Errorf("preimage not found for %s", h.Hex())
		}
		return p, nil
	}

	recovered, err := MerkleTreeContent(oracle, common.BytesToHash(root))
	require.NoError(t, err)
	require.Len(t, recovered, len(leaves))
	for i, leaf := range leaves {
		assert.Equal(t, leaf, recovered[i])
	}
}

func TestMerkleTreeContent_SingleLeaf(t *testing.T) {
	record, preimages := collectingRecorder()
	leaves := [][]byte{[]byte("only")}
	root := HashFromByteSlices(record, leaves)

	oracle := func(h common.Hash) ([]byte, error) {
		p, ok := (*preimages)[h]
		if !ok {
			return nil, fmt.Errorf("not found: %s", h.Hex())
		}
		return p, nil
	}

	recovered, err := MerkleTreeContent(oracle, common.BytesToHash(root))
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	assert.Equal(t, []byte("only"), recovered[0])
}

func TestMerkleTreeContent_OracleError(t *testing.T) {
	oracle := func(_ common.Hash) ([]byte, error) {
		return nil, fmt.Errorf("oracle failure")
	}
	_, err := MerkleTreeContent(oracle, common.BytesToHash(tmhash.Sum([]byte("x"))))
	require.ErrorContains(t, err, "oracle failure")
}
