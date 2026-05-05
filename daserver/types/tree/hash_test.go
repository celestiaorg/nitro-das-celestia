package tree

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/tmhash"
)

func noopRecord(_ common.Hash, _ []byte, _ arbutil.PreimageType) {}

func TestEmptyHash_ReturnsSha256OfEmpty(t *testing.T) {
	got := emptyHash()
	want := tmhash.Sum([]byte{})
	assert.Equal(t, want, got)
}

func TestLeafHash_ProducesCorrectHash(t *testing.T) {
	leaf := []byte("hello")
	got := leafHash(noopRecord, leaf)

	want := tmhash.Sum(append([]byte{0x00}, leaf...))
	assert.Equal(t, want, got)
}

func TestLeafHash_RecordsPreimage(t *testing.T) {
	leaf := []byte("test-leaf")
	var recorded []struct {
		hash     common.Hash
		preimage []byte
		typ      arbutil.PreimageType
	}
	record := func(h common.Hash, p []byte, t arbutil.PreimageType) {
		recorded = append(recorded, struct {
			hash     common.Hash
			preimage []byte
			typ      arbutil.PreimageType
		}{h, p, t})
	}

	hash := leafHash(record, leaf)
	require.Len(t, recorded, 1)
	assert.Equal(t, common.BytesToHash(hash), recorded[0].hash)
	assert.Equal(t, append([]byte{0x00}, leaf...), recorded[0].preimage)
	assert.Equal(t, arbutil.Sha2_256PreimageType, recorded[0].typ)
}

func TestLeafHash_DoesNotMutateGlobalPrefix(t *testing.T) {
	original := make([]byte, len(leafPrefix))
	copy(original, leafPrefix)

	leafHash(noopRecord, []byte("data1"))
	leafHash(noopRecord, []byte("data2"))

	assert.Equal(t, original, leafPrefix, "leafPrefix was mutated")
}

func TestInnerHash_ProducesCorrectHash(t *testing.T) {
	left := tmhash.Sum([]byte("left"))
	right := tmhash.Sum([]byte("right"))
	got := innerHash(noopRecord, left, right)

	preimage := make([]byte, 0, 1+len(left)+len(right))
	preimage = append(preimage, 0x01)
	preimage = append(preimage, left...)
	preimage = append(preimage, right...)
	want := tmhash.Sum(preimage)
	assert.Equal(t, want, got)
}

func TestInnerHash_RecordsPreimage(t *testing.T) {
	left := tmhash.Sum([]byte("L"))
	right := tmhash.Sum([]byte("R"))
	var recorded []struct {
		hash     common.Hash
		preimage []byte
		typ      arbutil.PreimageType
	}
	record := func(h common.Hash, p []byte, t arbutil.PreimageType) {
		recorded = append(recorded, struct {
			hash     common.Hash
			preimage []byte
			typ      arbutil.PreimageType
		}{h, p, t})
	}

	hash := innerHash(record, left, right)
	require.Len(t, recorded, 1)
	assert.Equal(t, common.BytesToHash(hash), recorded[0].hash)

	expectedPreimage := make([]byte, 0, 1+len(left)+len(right))
	expectedPreimage = append(expectedPreimage, 0x01)
	expectedPreimage = append(expectedPreimage, left...)
	expectedPreimage = append(expectedPreimage, right...)
	assert.Equal(t, expectedPreimage, recorded[0].preimage)
	assert.Equal(t, arbutil.Sha2_256PreimageType, recorded[0].typ)
}

func TestInnerHash_DoesNotMutateGlobalPrefix(t *testing.T) {
	original := make([]byte, len(innerPrefix))
	copy(original, innerPrefix)

	left := tmhash.Sum([]byte("a"))
	right := tmhash.Sum([]byte("b"))
	innerHash(noopRecord, left, right)
	innerHash(noopRecord, right, left)

	assert.Equal(t, original, innerPrefix, "innerPrefix was mutated")
}

func TestInnerHash_DoesNotMutateLeftArg(t *testing.T) {
	left := make([]byte, 32, 128) // spare capacity
	copy(left, tmhash.Sum([]byte("left"))[:32])
	leftCopy := make([]byte, len(left))
	copy(leftCopy, left)

	right := tmhash.Sum([]byte("right"))
	innerHash(noopRecord, left, right)

	assert.Equal(t, leftCopy, left, "left argument was mutated by innerHash")
}

func TestInnerHash_RecordedHashMatchesReturnedHash(t *testing.T) {
	left := tmhash.Sum([]byte("x"))
	right := tmhash.Sum([]byte("y"))

	var recordedHash common.Hash
	record := func(h common.Hash, _ []byte, _ arbutil.PreimageType) {
		recordedHash = h
	}

	returned := innerHash(record, left, right)
	assert.Equal(t, recordedHash, common.BytesToHash(returned),
		"recorded hash must match returned hash")
}

func TestLeafHash_DifferentLeavesProduceDifferentHashes(t *testing.T) {
	h1 := leafHash(noopRecord, []byte("a"))
	h2 := leafHash(noopRecord, []byte("b"))
	assert.NotEqual(t, h1, h2)
}

func TestLeafAndInnerHash_DomainSeparation(t *testing.T) {
	// A leaf "X" and an inner node with children that concatenate to "X"
	// must produce different hashes due to domain separation prefixes.
	data := []byte("some 32-byte-ish data to hash...")
	lh := leafHash(noopRecord, data)
	ih := innerHash(noopRecord, data[:16], data[16:])
	assert.NotEqual(t, lh, ih, "leaf and inner hashes must differ for same content")
}
