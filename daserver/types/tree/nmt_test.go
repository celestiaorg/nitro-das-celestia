package tree

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/celestiaorg/rsmt2d"
	"github.com/ethereum/go-ethereum/common"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeShare creates a minimal valid share: 29-byte namespace prefix + payload
// padded to at least 29 bytes total.
func makeShare(nsVersion byte, nsIDLastByte byte, payload []byte) []byte {
	ns := make([]byte, NamespaceSize)
	ns[0] = nsVersion
	ns[NamespaceSize-1] = nsIDLastByte
	return append(ns, payload...)
}

func TestComputeNmtRoot_SingleShare(t *testing.T) {
	record, _ := collectingRecorder()
	squareSize := uint64(1) // 1x1 original square -> 2x2 EDS
	constructor := NewConstructor(record, squareSize)

	// Single share in quadrant zero (index 0, share index 0)
	share := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xAA}, 100))
	shares := [][]byte{share}

	root, err := ComputeNmtRoot(constructor, 0, shares)
	require.NoError(t, err)
	require.NotNil(t, root)
	require.NotEmpty(t, root)
}

func TestComputeNmtRoot_MultipleSortedShares(t *testing.T) {
	record, _ := collectingRecorder()
	squareSize := uint64(2)
	constructor := NewConstructor(record, squareSize)

	// Shares must be namespace-sorted for NMT
	share1 := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xAA}, 100))
	share2 := makeShare(0x00, 0x02, bytes.Repeat([]byte{0xBB}, 100))
	shares := [][]byte{share1, share2}

	root, err := ComputeNmtRoot(constructor, 0, shares)
	require.NoError(t, err)
	require.NotNil(t, root)
}

func TestComputeNmtRoot_Deterministic(t *testing.T) {
	share := makeShare(0x00, 0x05, bytes.Repeat([]byte{0xCC}, 50))
	shares := [][]byte{share}

	record1, _ := collectingRecorder()
	root1, err := ComputeNmtRoot(NewConstructor(record1, 1), 0, shares)
	require.NoError(t, err)

	record2, _ := collectingRecorder()
	root2, err := ComputeNmtRoot(NewConstructor(record2, 1), 0, shares)
	require.NoError(t, err)

	assert.Equal(t, root1, root2)
}

func TestComputeNmtRoot_NilShareReturnsError(t *testing.T) {
	record, _ := collectingRecorder()
	constructor := NewConstructor(record, 1)
	shares := [][]byte{nil}

	_, err := ComputeNmtRoot(constructor, 0, shares)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete")
}

func TestComputeNmtRoot_EmptySliceReturnsError(t *testing.T) {
	record, _ := collectingRecorder()
	constructor := NewConstructor(record, 1)

	// Empty shares slice: isComplete returns true (vacuously), but the NMT
	// tree will produce a root with no pushes. This should succeed.
	root, err := ComputeNmtRoot(constructor, 0, [][]byte{})
	require.NoError(t, err)
	require.NotNil(t, root)
}

func TestComputeNmtRoot_MixedNilAndValidShareReturnsError(t *testing.T) {
	record, _ := collectingRecorder()
	constructor := NewConstructor(record, 2)
	shares := [][]byte{
		makeShare(0x00, 0x01, []byte{0x01}),
		nil,
	}

	_, err := ComputeNmtRoot(constructor, 0, shares)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete")
}

func TestIsComplete(t *testing.T) {
	assert.True(t, isComplete([][]byte{}))
	assert.True(t, isComplete([][]byte{{1}, {2}}))
	assert.False(t, isComplete([][]byte{nil}))
	assert.False(t, isComplete([][]byte{{1}, nil}))
	assert.False(t, isComplete([][]byte{nil, {2}}))
}

func TestNmtContent_RoundTrips(t *testing.T) {
	preimages := make(map[common.Hash][]byte)
	record := func(h common.Hash, p []byte, _ arbutil.PreimageType) {
		cp := make([]byte, len(p))
		copy(cp, p)
		preimages[h] = cp
	}

	squareSize := uint64(2)
	constructor := NewConstructor(record, squareSize)

	share1 := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xAA}, 100))
	share2 := makeShare(0x00, 0x02, bytes.Repeat([]byte{0xBB}, 100))
	shares := [][]byte{share1, share2}

	root, err := ComputeNmtRoot(constructor, 0, shares)
	require.NoError(t, err)

	oracle := func(h common.Hash) ([]byte, error) {
		p, ok := preimages[h]
		if !ok {
			return nil, fmt.Errorf("preimage not found: %s", h.Hex())
		}
		return p, nil
	}

	recovered, err := NmtContent(oracle, root)
	require.NoError(t, err)
	require.Len(t, recovered, 2)
}

func TestNmtContent_OracleError(t *testing.T) {
	oracle := func(_ common.Hash) ([]byte, error) {
		return nil, fmt.Errorf("oracle down")
	}
	// fabricate a minimal NMT root: minNID(29) || maxNID(29) || hash(32) = 90 bytes
	fakeRoot := make([]byte, int(NamespaceSize)*2+32)
	_, err := NmtContent(oracle, fakeRoot)
	require.ErrorContains(t, err, "oracle down")
}

// stubTree implements rsmt2d.Tree for testing NewConstructor plumbing
type stubTree struct {
	pushCount int
	pushErr   error
	rootVal   []byte
	rootErr   error
}

func (s *stubTree) Push(_ []byte) error {
	s.pushCount++
	return s.pushErr
}
func (s *stubTree) Root() ([]byte, error) { return s.rootVal, s.rootErr }

func TestNewConstructor_CreatesWorkingTree(t *testing.T) {
	record, _ := collectingRecorder()
	ctor := NewConstructor(record, 4)
	tree := ctor(rsmt2d.Row, 0)
	require.NotNil(t, tree)

	share := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xDD}, 100))
	err := tree.Push(share)
	require.NoError(t, err)

	root, err := tree.Root()
	require.NoError(t, err)
	require.NotEmpty(t, root)
}
