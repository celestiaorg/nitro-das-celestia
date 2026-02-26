package das

import (
	"context"
	"encoding/binary"
	"errors"
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
