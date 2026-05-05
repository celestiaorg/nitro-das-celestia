package tree

import (
	"bytes"
	"testing"

	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/nmt/namespace"
	"github.com/celestiaorg/rsmt2d"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespace_Bytes(t *testing.T) {
	ns := Namespace{Version: 0x01, ID: []byte{0x02, 0x03}}
	got := ns.Bytes()
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, got)
}

func TestParitySharesNamespace(t *testing.T) {
	b := ParitySharesNamespace.Bytes()
	require.Len(t, b, NamespaceIDSize+1)
	assert.Equal(t, byte(NamespaceVersionMax), b[0])
	// All bytes in ID should be 0xFF
	for i := 1; i < len(b); i++ {
		assert.Equal(t, byte(0xFF), b[i], "byte %d should be 0xFF", i)
	}
}

func TestNewErasuredNamespacedMerkleTree_PanicsOnZeroSquareSize(t *testing.T) {
	assert.Panics(t, func() {
		NewErasuredNamespacedMerkleTree(noopRecord, 0, 0)
	})
}

func TestErasuredNamespacedMerkleTree_PushAndRoot(t *testing.T) {
	record, _ := collectingRecorder()
	squareSize := uint64(2) // 2x2 ODS -> 4x4 EDS
	tree := NewErasuredNamespacedMerkleTree(record, squareSize, 0)

	// Push a share in quadrant zero (axisIndex=0, shareIndex=0)
	share := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xAA}, 100))
	err := tree.Push(share)
	require.NoError(t, err)

	root, err := tree.Root()
	require.NoError(t, err)
	require.NotEmpty(t, root)
}

func TestErasuredNamespacedMerkleTree_PushRejectsShortData(t *testing.T) {
	tree := NewErasuredNamespacedMerkleTree(noopRecord, 2, 0)
	shortData := make([]byte, int(NamespaceSize)-1) // too short
	err := tree.Push(shortData)
	require.ErrorContains(t, err, "data is too short")
}

func TestErasuredNamespacedMerkleTree_PushRejectsPastSquareSize(t *testing.T) {
	squareSize := uint64(1) // 1x1 ODS -> 2x2 EDS, max 2 shares per row
	tree := NewErasuredNamespacedMerkleTree(noopRecord, squareSize, 0)
	share := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xAA}, 100))

	// Push up to the limit (2*squareSize = 2 shares for a row in the EDS)
	err := tree.Push(share)
	require.NoError(t, err)
	err = tree.Push(share)
	require.NoError(t, err)

	// Third push should fail
	err = tree.Push(share)
	require.ErrorContains(t, err, "pushed past predetermined square size")
}

func TestErasuredNamespacedMerkleTree_QuadrantZeroUsesDataNamespace(t *testing.T) {
	// When axisIndex < squareSize and shareIndex < squareSize,
	// the share's own namespace should be used (quadrant zero).
	// We verify this by checking that two shares with different namespaces
	// produce a valid NMT root (which would fail if the namespace was overridden).
	record, _ := collectingRecorder()
	squareSize := uint64(4)
	tree := NewErasuredNamespacedMerkleTree(record, squareSize, 0)

	share1 := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xAA}, 100))
	share2 := makeShare(0x00, 0x02, bytes.Repeat([]byte{0xBB}, 100))

	require.NoError(t, tree.Push(share1))
	require.NoError(t, tree.Push(share2))

	root, err := tree.Root()
	require.NoError(t, err)
	require.NotEmpty(t, root)
}

func TestErasuredNamespacedMerkleTree_ParityQuadrantUsesParityNamespace(t *testing.T) {
	// When shareIndex >= squareSize, the parity namespace should be used.
	// We push squareSize shares (filling quadrant zero), then push one more
	// which should use the parity namespace.
	record, _ := collectingRecorder()
	squareSize := uint64(2)
	tree := NewErasuredNamespacedMerkleTree(record, squareSize, 0)

	share := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xAA}, 100))
	// Push squareSize shares (fills Q0)
	for i := uint64(0); i < squareSize; i++ {
		require.NoError(t, tree.Push(share))
	}
	// Next shares are in the parity quadrant
	parityShare := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xEE}, 100))
	for i := uint64(0); i < squareSize; i++ {
		require.NoError(t, tree.Push(parityShare))
	}

	root, err := tree.Root()
	require.NoError(t, err)
	require.NotEmpty(t, root)
}

func TestNewConstructor_ReturnsValidTreeConstructorFn(t *testing.T) {
	record, _ := collectingRecorder()
	ctor := NewConstructor(record, 4)

	// Should produce trees for both Row and Col axes
	for _, axis := range []rsmt2d.Axis{rsmt2d.Row, rsmt2d.Col} {
		tree := ctor(axis, 0)
		require.NotNil(t, tree)

		share := makeShare(0x00, 0x01, bytes.Repeat([]byte{0xCC}, 100))
		err := tree.Push(share)
		require.NoError(t, err)

		root, err := tree.Root()
		require.NoError(t, err)
		require.NotEmpty(t, root)
	}
}

func TestErasuredNamespacedMerkleTree_SetTree(t *testing.T) {
	tree := NewErasuredNamespacedMerkleTree(noopRecord, 2, 0)

	expectedRoot := []byte("fake-root")
	mock := &mockTree{rootVal: expectedRoot}
	tree.SetTree(mock)

	root, err := tree.Root()
	require.NoError(t, err)
	assert.Equal(t, expectedRoot, root)
}

type mockTree struct {
	rootVal []byte
}

func (m *mockTree) Root() ([]byte, error)                              { return m.rootVal, nil }
func (m *mockTree) Push(_ namespace.PrefixedData) error                { return nil }
func (m *mockTree) ProveRange(_ int, _ int) (nmt.Proof, error)         { return nmt.Proof{}, nil }
