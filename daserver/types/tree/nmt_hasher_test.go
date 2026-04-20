package tree

import (
	"crypto/sha256"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNmtPreimageHasher_SumRecordsPreimage(t *testing.T) {
	var recorded []struct {
		hash     common.Hash
		preimage []byte
		typ      arbutil.PreimageType
	}
	record := func(h common.Hash, p []byte, typ arbutil.PreimageType) {
		recorded = append(recorded, struct {
			hash     common.Hash
			preimage []byte
			typ      arbutil.PreimageType
		}{h, p, typ})
	}

	hasher := newNmtPreimageHasher(record)
	data := []byte("hello world")
	_, err := hasher.Write(data)
	require.NoError(t, err)

	result := hasher.Sum(nil)
	require.Len(t, recorded, 1)

	expectedHash := sha256.Sum256(data)
	assert.Equal(t, expectedHash[:], result)
	assert.Equal(t, common.BytesToHash(expectedHash[:]), recorded[0].hash)
	assert.Equal(t, data, recorded[0].preimage)
	assert.Equal(t, arbutil.Sha2_256PreimageType, recorded[0].typ)
}

func TestNmtPreimageHasher_MultipleWrites(t *testing.T) {
	var recordedPreimage []byte
	record := func(_ common.Hash, p []byte, _ arbutil.PreimageType) {
		recordedPreimage = p
	}

	hasher := newNmtPreimageHasher(record)
	_, _ = hasher.Write([]byte("hello "))
	_, _ = hasher.Write([]byte("world"))
	hasher.Sum(nil)

	assert.Equal(t, []byte("hello world"), recordedPreimage)
}

func TestNmtPreimageHasher_ResetClearsData(t *testing.T) {
	var recordedPreimage []byte
	record := func(_ common.Hash, p []byte, _ arbutil.PreimageType) {
		recordedPreimage = p
	}

	hasher := newNmtPreimageHasher(record)
	_, _ = hasher.Write([]byte("first"))
	hasher.Reset()
	_, _ = hasher.Write([]byte("second"))
	hasher.Sum(nil)

	assert.Equal(t, []byte("second"), recordedPreimage)
}

func TestNmtPreimageHasher_SumDoesNotMutateRecordedPreimage(t *testing.T) {
	var recorded []byte
	record := func(_ common.Hash, p []byte, _ arbutil.PreimageType) {
		recorded = p
	}

	hasher := newNmtPreimageHasher(record)
	_, _ = hasher.Write([]byte("data"))
	hasher.Sum(nil)

	snapshot := make([]byte, len(recorded))
	copy(snapshot, recorded)

	// Reset and write different data
	hasher.Reset()
	_, _ = hasher.Write([]byte("other"))
	hasher.Sum(nil)

	// The first recorded preimage should not have been mutated
	// (because Sum copies h.data before recording)
	assert.Equal(t, snapshot, []byte("data"))
}

func TestNmtPreimageHasher_HashMatchesStandardSha256(t *testing.T) {
	hasher := newNmtPreimageHasher(noopRecord)
	data := []byte("test data for sha256")
	_, _ = hasher.Write(data)
	got := hasher.Sum(nil)

	expected := sha256.Sum256(data)
	assert.Equal(t, expected[:], got)
}

func TestNmtPreimageHasher_SumWithPrefix(t *testing.T) {
	hasher := newNmtPreimageHasher(noopRecord)
	_, _ = hasher.Write([]byte("abc"))
	result := hasher.Sum([]byte("prefix"))

	// Sum(b) should return append(b, hash...)
	expected := sha256.Sum256([]byte("abc"))
	assert.Equal(t, append([]byte("prefix"), expected[:]...), result)
}
