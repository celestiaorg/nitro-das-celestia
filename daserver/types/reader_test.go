package types

import (
	"bytes"
	"context"
	"errors"
	"testing"

	appda "github.com/celestiaorg/celestia-app/v6/pkg/da"
	nodeblob "github.com/celestiaorg/celestia-node/blob"
	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/stretchr/testify/require"
)

type fakeReader struct {
	readResult *ReadResult
	readErr    error
	lastCert   *cert.CelestiaDACertV1
}

func (f *fakeReader) Read(_ context.Context, certificate *cert.CelestiaDACertV1) (*ReadResult, error) {
	f.lastCert = certificate
	return f.readResult, f.readErr
}

func (f *fakeReader) GetProof(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeReader) GenerateReadPreimageProof(context.Context, uint64, *cert.CelestiaDACertV1) ([]byte, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeReader) GenerateCertificateValidityProof(context.Context, *cert.CelestiaDACertV1) ([]byte, error) {
	return nil, errors.New("unused in this test")
}

func makeSequencerMessage(t *testing.T, certificate *cert.CelestiaDACertV1) []byte {
	t.Helper()

	certBytes, err := certificate.MarshalBinary()
	require.NoError(t, err)

	sequencerMsg := make([]byte, cert.SequencerMsgOffset+len(certBytes))
	copy(sequencerMsg[cert.SequencerMsgOffset:], certBytes)
	return sequencerMsg
}

func makeValidReadFixture(t *testing.T, message []byte) (*cert.CelestiaDACertV1, *ReadResult) {
	t.Helper()

	namespace, err := libshare.NewV0Namespace(bytes.Repeat([]byte{0x44}, libshare.NamespaceVersionZeroIDSize))
	require.NoError(t, err)

	blob, err := nodeblob.NewBlob(libshare.ShareVersionZero, namespace, message, nil)
	require.NoError(t, err)

	shares, err := nodeblob.BlobsToShares(blob)
	require.NoError(t, err)

	eds, err := appda.ExtendShares(libshare.ToBytes(shares))
	require.NoError(t, err)
	dah, err := appda.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	var dataRoot [32]byte
	copy(dataRoot[:], dah.Hash())

	certificate := cert.NewCelestiaCertificate(21, 0, uint64(len(shares)), [32]byte{0xaa}, dataRoot)
	result := &ReadResult{
		Message:     message,
		RowRoots:    dah.RowRoots,
		ColumnRoots: dah.ColumnRoots,
		Rows:        [][][]byte{eds.Row(0)},
		SquareSize:  uint64(len(dah.RowRoots)),
		StartRow:    0,
		EndRow:      0,
	}
	return certificate, result
}

func TestRecordPreimagesTo_NilMapReturnsNil(t *testing.T) {
	t.Parallel()

	require.Nil(t, RecordPreimagesTo(nil))
}

func TestRecordPreimagesTo_StoresEntries(t *testing.T) {
	t.Parallel()

	preimages := make(daprovider.PreimagesMap)
	recorder := RecordPreimagesTo(preimages)
	hash := common.HexToHash("0x01")
	value := []byte("payload")

	recorder(hash, value, arbutil.DACertificatePreimageType)

	require.Equal(t, value, preimages[arbutil.DACertificatePreimageType][hash])
}

func TestReaderForCelestia_HeaderByteSupport(t *testing.T) {
	t.Parallel()

	reader := NewReaderForCelestia(&fakeReader{})
	require.Equal(t, cert.CustomDAHeaderFlag, reader.HeaderByte())
	require.True(t, reader.IsValidHeaderByte(context.Background(), cert.CustomDAHeaderFlag))
	require.False(t, reader.IsValidHeaderByte(context.Background(), 0x00))
}

func TestRecoverPayloadFromCelestiaBatch_ReturnsPayloadWithoutPreimages(t *testing.T) {
	t.Parallel()

	message := []byte("recover payload")
	certificate, result := makeValidReadFixture(t, message)
	reader := &fakeReader{readResult: result}

	payload, preimages, err := RecoverPayloadFromCelestiaBatch(
		context.Background(),
		1,
		makeSequencerMessage(t, certificate),
		reader,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, message, payload)
	require.Nil(t, preimages)
	require.NotNil(t, reader.lastCert)
	require.Equal(t, certificate.BlockHeight, reader.lastCert.BlockHeight)
}

func TestRecoverPayloadFromCelestiaBatch_CollectsCertificatePreimage(t *testing.T) {
	t.Parallel()

	message := []byte("collect preimages")
	certificate, result := makeValidReadFixture(t, message)
	reader := &fakeReader{readResult: result}

	payload, preimages, err := RecoverPayloadFromCelestiaBatch(
		context.Background(),
		1,
		makeSequencerMessage(t, certificate),
		reader,
		true,
	)
	require.NoError(t, err)
	require.Equal(t, message, payload)
	require.NotNil(t, preimages)

	certBytes, err := certificate.MarshalBinary()
	require.NoError(t, err)
	certHash := crypto.Keccak256Hash(certBytes)
	require.Equal(t, message, preimages[arbutil.DACertificatePreimageType][certHash])
}

func TestRecoverPayloadFromCelestiaBatch_InvalidSequencerMessage(t *testing.T) {
	t.Parallel()

	_, _, err := RecoverPayloadFromCelestiaBatch(context.Background(), 1, []byte{0x01, 0x02}, &fakeReader{}, false)
	require.Error(t, err)
}

func TestRecoverPayloadFromCelestiaBatch_ReadError(t *testing.T) {
	t.Parallel()

	certificate, _ := makeValidReadFixture(t, []byte("payload"))
	reader := &fakeReader{readErr: errors.New("boom")}

	_, _, err := RecoverPayloadFromCelestiaBatch(
		context.Background(),
		1,
		makeSequencerMessage(t, certificate),
		reader,
		false,
	)
	require.ErrorContains(t, err, "boom")
}

func TestRecoverPayloadFromCelestiaBatch_CertificateValidationErrorPropagates(t *testing.T) {
	t.Parallel()

	certificate, _ := makeValidReadFixture(t, []byte("payload"))
	readErr := &daprovider.CertificateValidationError{Reason: "certificate validation failed: untrusted signer"}
	reader := &fakeReader{readErr: readErr}

	_, _, err := RecoverPayloadFromCelestiaBatch(
		context.Background(),
		1,
		makeSequencerMessage(t, certificate),
		reader,
		false,
	)
	require.ErrorIs(t, err, readErr)
	require.True(t, daprovider.IsCertificateValidationError(err))
}

func TestReaderForCelestia_RecoverPayload_PreservesCertificateValidationError(t *testing.T) {
	t.Parallel()

	certificate, _ := makeValidReadFixture(t, []byte("payload"))
	readErr := &daprovider.CertificateValidationError{Reason: "certificate validation failed: bad signature"}
	reader := NewReaderForCelestia(&fakeReader{readErr: readErr})

	_, err := reader.RecoverPayload(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.ErrorIs(t, err, readErr)
	require.True(t, daprovider.IsCertificateValidationError(err))
}

func TestReaderForCelestia_RecoverPayload_PropagatesInfrastructureError(t *testing.T) {
	t.Parallel()

	certificate, _ := makeValidReadFixture(t, []byte("payload"))
	readErr := errors.New("storage unavailable: database connection timeout")
	reader := NewReaderForCelestia(&fakeReader{readErr: readErr})

	_, err := reader.RecoverPayload(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.ErrorIs(t, err, readErr)
	require.False(t, daprovider.IsCertificateValidationError(err))
}

func TestRecoverPayloadFromCelestiaBatch_EmptyPayloadReturnsSuccess(t *testing.T) {
	t.Parallel()

	certificate, result := makeValidReadFixture(t, []byte("payload"))
	result.Message = nil
	reader := &fakeReader{readResult: result}

	payload, preimages, err := RecoverPayloadFromCelestiaBatch(
		context.Background(),
		1,
		makeSequencerMessage(t, certificate),
		reader,
		false,
	)
	require.NoError(t, err)
	require.Nil(t, payload)
	require.Nil(t, preimages)
}

func TestReaderForCelestia_RecoverPayload_EmptyBatchReturnsSuccess(t *testing.T) {
	t.Parallel()

	certificate, result := makeValidReadFixture(t, []byte("payload"))
	result.Message = []byte{}
	reader := NewReaderForCelestia(&fakeReader{readResult: result})

	res, err := reader.RecoverPayload(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.NoError(t, err)
	require.Empty(t, res.Payload)
}

func TestRecoverPayloadFromCelestiaBatch_RowRootMismatch(t *testing.T) {
	t.Parallel()

	certificate, result := makeValidReadFixture(t, []byte("payload"))
	result.RowRoots[0] = append([]byte(nil), result.RowRoots[0]...)
	result.RowRoots[0][0] ^= 0xff
	reader := &fakeReader{readResult: result}

	_, _, err := RecoverPayloadFromCelestiaBatch(
		context.Background(),
		1,
		makeSequencerMessage(t, certificate),
		reader,
		true,
	)
	require.ErrorContains(t, err, "row root mismatch")
}

func TestRecoverPayloadFromCelestiaBatch_DataRootMismatch(t *testing.T) {
	t.Parallel()

	certificate, result := makeValidReadFixture(t, []byte("payload"))
	certificate.DataRoot[0] ^= 0xff
	reader := &fakeReader{readResult: result}

	_, _, err := RecoverPayloadFromCelestiaBatch(
		context.Background(),
		1,
		makeSequencerMessage(t, certificate),
		reader,
		true,
	)
	require.ErrorContains(t, err, "data roots do not match")
}

func TestReaderForCelestia_RecoverPayloadAndPreimages(t *testing.T) {
	t.Parallel()

	message := []byte("payload and preimages")
	certificate, result := makeValidReadFixture(t, message)
	reader := NewReaderForCelestia(&fakeReader{readResult: result})

	res, err := reader.RecoverPayloadAndPreimages(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, message, res.Payload)
	require.NotNil(t, res.Preimages)
}

func TestReaderForCelestia_CollectPreimages(t *testing.T) {
	t.Parallel()

	message := []byte("just preimages")
	certificate, result := makeValidReadFixture(t, message)
	reader := NewReaderForCelestia(&fakeReader{readResult: result})

	res, err := reader.CollectPreimages(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res.Preimages)
}

func TestReaderForCelestia_CollectPreimages_PreservesCertificateValidationError(t *testing.T) {
	t.Parallel()

	certificate, _ := makeValidReadFixture(t, []byte("payload"))
	readErr := &daprovider.CertificateValidationError{Reason: "certificate validation failed: malformed certificate"}
	reader := NewReaderForCelestia(&fakeReader{readErr: readErr})

	_, err := reader.CollectPreimages(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.ErrorIs(t, err, readErr)
	require.True(t, daprovider.IsCertificateValidationError(err))
}

func TestReaderForCelestia_CollectPreimages_PropagatesInfrastructureError(t *testing.T) {
	t.Parallel()

	certificate, _ := makeValidReadFixture(t, []byte("payload"))
	readErr := errors.New("rpc timeout fetching batch data")
	reader := NewReaderForCelestia(&fakeReader{readErr: readErr})

	_, err := reader.CollectPreimages(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.ErrorIs(t, err, readErr)
	require.False(t, daprovider.IsCertificateValidationError(err))
}

func TestReaderForCelestia_CollectPreimages_EmptyBatchReturnsSuccess(t *testing.T) {
	t.Parallel()

	certificate, result := makeValidReadFixture(t, []byte("payload"))
	result.Message = []byte{}
	reader := NewReaderForCelestia(&fakeReader{readResult: result})

	res, err := reader.CollectPreimages(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res.Preimages)

	certBytes, marshalErr := certificate.MarshalBinary()
	require.NoError(t, marshalErr)
	certHash := crypto.Keccak256Hash(certBytes)
	require.Contains(t, res.Preimages[arbutil.DACertificatePreimageType], certHash)
	require.Empty(t, res.Preimages[arbutil.DACertificatePreimageType][certHash])
}

func TestReaderForCelestia_RecoverPayloadAndPreimages_PreservesCertificateValidationError(t *testing.T) {
	t.Parallel()

	certificate, _ := makeValidReadFixture(t, []byte("payload"))
	readErr := &daprovider.CertificateValidationError{Reason: "certificate validation failed: bad signature"}
	reader := NewReaderForCelestia(&fakeReader{readErr: readErr})

	_, err := reader.RecoverPayloadAndPreimages(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.ErrorIs(t, err, readErr)
	require.True(t, daprovider.IsCertificateValidationError(err))
}

func TestReaderForCelestia_RecoverPayloadAndPreimages_PropagatesInfrastructureError(t *testing.T) {
	t.Parallel()

	certificate, _ := makeValidReadFixture(t, []byte("payload"))
	readErr := errors.New("storage unavailable: backend offline")
	reader := NewReaderForCelestia(&fakeReader{readErr: readErr})

	_, err := reader.RecoverPayloadAndPreimages(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.ErrorIs(t, err, readErr)
	require.False(t, daprovider.IsCertificateValidationError(err))
}

func TestReaderForCelestia_RecoverPayloadAndPreimages_EmptyBatchReturnsSuccess(t *testing.T) {
	t.Parallel()

	certificate, result := makeValidReadFixture(t, []byte("payload"))
	result.Message = []byte{}
	reader := NewReaderForCelestia(&fakeReader{readResult: result})

	res, err := reader.RecoverPayloadAndPreimages(1, common.Hash{}, makeSequencerMessage(t, certificate)).Await(context.Background())
	require.NoError(t, err)
	require.Empty(t, res.Payload)
	require.NotNil(t, res.Preimages)

	certBytes, marshalErr := certificate.MarshalBinary()
	require.NoError(t, marshalErr)
	certHash := crypto.Keccak256Hash(certBytes)
	require.Contains(t, res.Preimages[arbutil.DACertificatePreimageType], certHash)
	require.Empty(t, res.Preimages[arbutil.DACertificatePreimageType][certHash])
}
