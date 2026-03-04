package das

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	validatorpkg "github.com/celestiaorg/nitro-das-celestia/daserver/validator"
	"github.com/stretchr/testify/require"
)

type fakeCelestiaReader struct {
	lastOffset uint64
	lastCert   *cert.CelestiaDACertV1
	readProof  []byte
	readErr    error
}

func (f *fakeCelestiaReader) Read(context.Context, *cert.CelestiaDACertV1) (*types.ReadResult, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeCelestiaReader) GetProof(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeCelestiaReader) GenerateReadPreimageProof(
	_ context.Context,
	offset uint64,
	certificate *cert.CelestiaDACertV1,
) ([]byte, error) {
	f.lastOffset = offset
	f.lastCert = certificate
	return f.readProof, f.readErr
}

func (f *fakeCelestiaReader) GenerateCertificateValidityProof(
	context.Context,
	*cert.CelestiaDACertV1,
) ([]byte, error) {
	return []byte{0x01, 0x01}, nil
}

func makeCertBytes(t *testing.T) []byte {
	t.Helper()
	var txCommitment [32]byte
	var dataRoot [32]byte
	txCommitment[0] = 0xAA
	dataRoot[0] = 0xBB
	c := cert.NewCelestiaCertificate(123, 10, 100, txCommitment, dataRoot)
	b, err := c.MarshalBinary()
	require.NoError(t, err)
	return b
}

func TestGenerateReadPreimageProof_DelegatesWithParsedCertificate(t *testing.T) {
	reader := &fakeCelestiaReader{readProof: []byte{0x02, 0x00}}
	v := validatorpkg.NewCelestiaValidator(reader)

	certBytes := makeCertBytes(t)
	res, err := v.GenerateReadPreimageProof(64, certBytes).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte{0x02, 0x00}, res.Proof)
	require.EqualValues(t, 64, reader.lastOffset)
	require.NotNil(t, reader.lastCert)
	require.EqualValues(t, 123, reader.lastCert.BlockHeight)
	require.EqualValues(t, 10, reader.lastCert.Start)
	require.EqualValues(t, 100, reader.lastCert.SharesLength)
}

func TestGenerateReadPreimageProof_InvalidCertificateReturnsError(t *testing.T) {
	reader := &fakeCelestiaReader{}
	v := validatorpkg.NewCelestiaValidator(reader)

	_, err := v.GenerateReadPreimageProof(0, []byte{0x01, 0x02}).Await(context.Background())
	require.Error(t, err)
}

func TestGenerateCertificateValidityProof_InvalidCertificateReturnsClaimedInvalid(t *testing.T) {
	reader := &fakeCelestiaReader{}
	v := validatorpkg.NewCelestiaValidator(reader)

	res, err := v.GenerateCertificateValidityProof([]byte{0x01, 0x02}).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x01}, res.Proof)
}

func TestBuildReadPreimageProofV1_Layout(t *testing.T) {
	offset := uint64(96)
	payloadSize := uint64(1536)
	chunkLen := uint8(32)
	firstShareIndex := uint64(25)
	shareCount := uint8(1)
	trailer := []byte{0xde, 0xad, 0xbe, 0xef}

	proof := buildReadPreimageProofV1(offset, payloadSize, chunkLen, firstShareIndex, shareCount, trailer)
	require.Len(t, proof, 1+8+8+1+8+1+len(trailer))

	pos := 0
	require.Equal(t, byte(0x01), proof[pos])
	pos++
	require.EqualValues(t, offset, binary.BigEndian.Uint64(proof[pos:pos+8]))
	pos += 8
	require.EqualValues(t, payloadSize, binary.BigEndian.Uint64(proof[pos:pos+8]))
	pos += 8
	require.Equal(t, chunkLen, proof[pos])
	pos++
	require.EqualValues(t, firstShareIndex, binary.BigEndian.Uint64(proof[pos:pos+8]))
	pos += 8
	require.Equal(t, shareCount, proof[pos])
	pos++
	require.Equal(t, trailer, proof[pos:])
}

func TestPayloadOffsetShareMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		offset        uint64
		wantShareRel  uint64
		wantShareBase uint64
		wantCap       uint64
	}{
		{offset: 0, wantShareRel: 0, wantShareBase: 0, wantCap: 478},
		{offset: 32, wantShareRel: 0, wantShareBase: 0, wantCap: 478},
		{offset: 448, wantShareRel: 0, wantShareBase: 0, wantCap: 478},
		{offset: 477, wantShareRel: 0, wantShareBase: 0, wantCap: 478},
		{offset: 478, wantShareRel: 1, wantShareBase: 478, wantCap: 482},
		{offset: 480, wantShareRel: 1, wantShareBase: 478, wantCap: 482},
		{offset: 512, wantShareRel: 1, wantShareBase: 478, wantCap: 482},
		{offset: 959, wantShareRel: 1, wantShareBase: 478, wantCap: 482},
		{offset: 960, wantShareRel: 2, wantShareBase: 960, wantCap: 482},
		{offset: 992, wantShareRel: 2, wantShareBase: 960, wantCap: 482},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(
			fmt.Sprintf("offset_%d", tc.offset),
			func(t *testing.T) {
				rel := payloadOffsetToShareRel(tc.offset)
				require.Equal(t, tc.wantShareRel, rel)
				require.Equal(t, tc.wantShareBase, payloadStartForShareRel(rel))
				require.Equal(t, tc.wantCap, payloadCapacityForShareRel(rel))
			},
		)
	}
}

func TestReadChunkShareSelectionMatrix(t *testing.T) {
	t.Parallel()

	chunkLenFor := func(offset, payloadSize uint64) uint64 {
		if offset >= payloadSize {
			return 0
		}
		rem := payloadSize - offset
		if rem > 32 {
			return 32
		}
		return rem
	}
	shareCountFor := func(offset, payloadSize uint64) uint64 {
		chunkLen := chunkLenFor(offset, payloadSize)
		if chunkLen == 0 {
			return 1
		}
		rel := payloadOffsetToShareRel(offset)
		base := payloadStartForShareRel(rel)
		cap := payloadCapacityForShareRel(rel)
		intra := offset - base
		if intra+chunkLen > cap {
			return 2
		}
		return 1
	}

	cases := []struct {
		name           string
		payloadSize    uint64
		offset         uint64
		wantShareRel   uint64
		wantShareCount uint64
		wantChunkLen   uint64
	}{
		{name: "size_478_off_448", payloadSize: 478, offset: 448, wantShareRel: 0, wantShareCount: 1, wantChunkLen: 30},
		{name: "size_479_off_448", payloadSize: 479, offset: 448, wantShareRel: 0, wantShareCount: 2, wantChunkLen: 31},
		{name: "size_480_off_448", payloadSize: 480, offset: 448, wantShareRel: 0, wantShareCount: 2, wantChunkLen: 32},
		{name: "size_511_off_480", payloadSize: 511, offset: 480, wantShareRel: 1, wantShareCount: 1, wantChunkLen: 31},
		{name: "size_512_off_480", payloadSize: 512, offset: 480, wantShareRel: 1, wantShareCount: 1, wantChunkLen: 32},
		{name: "size_513_off_480", payloadSize: 513, offset: 480, wantShareRel: 1, wantShareCount: 1, wantChunkLen: 32},
		{name: "size_560_off_544", payloadSize: 560, offset: 544, wantShareRel: 1, wantShareCount: 1, wantChunkLen: 16},
		{name: "size_961_off_960", payloadSize: 961, offset: 960, wantShareRel: 2, wantShareCount: 1, wantChunkLen: 1},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.wantShareRel, payloadOffsetToShareRel(tc.offset))
			require.Equal(t, tc.wantChunkLen, chunkLenFor(tc.offset, tc.payloadSize))
			require.Equal(t, tc.wantShareCount, shareCountFor(tc.offset, tc.payloadSize))
		})
	}
}
