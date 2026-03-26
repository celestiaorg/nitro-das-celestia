package validator

import (
	"context"
	"errors"
	"testing"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/offchainlabs/nitro/daprovider"
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
	return []byte{0x01, 0x01, 0xaa}, nil
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
	v := NewCelestiaValidator(reader)

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
	v := NewCelestiaValidator(reader)

	_, err := v.GenerateReadPreimageProof(0, []byte{0x01, 0x02}).Await(context.Background())
	require.Error(t, err)
}

func TestGenerateReadPreimageProof_InvalidCertificateReturnsCertificateValidationError(t *testing.T) {
	reader := &fakeCelestiaReader{}
	v := NewCelestiaValidator(reader)

	validCert := makeCertBytes(t)
	cases := []struct {
		name         string
		certificate  []byte
		wantContains string
	}{
		{
			name:         "certificate_has_invalid_length",
			certificate:  []byte{0x01, 0x02},
			wantContains: "certificate validation failed",
		},
		{
			name: "invalid_certificate_header",
			certificate: func() []byte {
				mutated := append([]byte(nil), validCert...)
				mutated[0] = 0x00
				return mutated
			}(),
			wantContains: "certificate validation failed: invalid certificate header",
		},
		{
			name: "invalid_provider_type",
			certificate: func() []byte {
				mutated := append([]byte(nil), validCert...)
				mutated[1] = 0x00
				return mutated
			}(),
			wantContains: "certificate validation failed: invalid provider type",
		},
		{
			name: "unsupported_certificate_version",
			certificate: func() []byte {
				mutated := append([]byte(nil), validCert...)
				mutated[2] = 0x00
				mutated[3] = 0x02
				return mutated
			}(),
			wantContains: "certificate validation failed: unsupported certificate version",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.GenerateReadPreimageProof(0, tc.certificate).Await(context.Background())
			require.Error(t, err)
			require.ErrorContains(t, err, tc.wantContains)
			require.True(t, daprovider.IsCertificateValidationError(err))
		})
	}
}

func TestGenerateCertificateValidityProof_InvalidCertificateReturnsClaimedInvalid(t *testing.T) {
	reader := &fakeCelestiaReader{}
	v := NewCelestiaValidator(reader)

	res, err := v.GenerateCertificateValidityProof([]byte{0x01, 0x02}).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x01}, res.Proof)
}

func TestGenerateCertificateValidityProof_DelegatesProofPayload(t *testing.T) {
	reader := &fakeCelestiaReader{}
	v := NewCelestiaValidator(reader)

	res, err := v.GenerateCertificateValidityProof(makeCertBytes(t)).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x01, 0xaa}, res.Proof)
}
