package das

import (
	"bytes"
	"testing"

	appda "github.com/celestiaorg/celestia-app/v6/pkg/da"
	nodeblob "github.com/celestiaorg/celestia-node/blob"
	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/stretchr/testify/require"
)

func TestBuildReadResultFromShares_IgnoresTxCommitmentMutation(t *testing.T) {
	namespace, err := libshare.NewV0Namespace(bytes.Repeat([]byte{0x42}, libshare.NamespaceVersionZeroIDSize))
	require.NoError(t, err)

	message := []byte("txCommitment should not affect recovery")
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
	certificate := cert.NewCelestiaCertificate(
		11,
		0,
		uint64(len(shares)),
		[32]byte{0xde, 0xad, 0xbe, 0xef},
		dataRoot,
	)

	result, err := buildReadResultFromShares(
		certificate,
		readResultShares{
			RowRoots:    dah.RowRoots,
			ColumnRoots: dah.ColumnRoots,
			Shares:      shares,
			Rows:        [][][]byte{eds.Row(0)},
		},
	)
	require.NoError(t, err)
	require.Equal(t, message, result.Message)
	require.NoError(t, validateReadResult(result, certificate))
}

func TestBuildReadResultFromShares_RejectsWrongShareCount(t *testing.T) {
	namespace, err := libshare.NewV0Namespace(bytes.Repeat([]byte{0x24}, libshare.NamespaceVersionZeroIDSize))
	require.NoError(t, err)

	blob, err := nodeblob.NewBlob(libshare.ShareVersionZero, namespace, []byte("share count mismatch"), nil)
	require.NoError(t, err)

	shares, err := nodeblob.BlobsToShares(blob)
	require.NoError(t, err)

	eds, err := appda.ExtendShares(libshare.ToBytes(shares))
	require.NoError(t, err)
	dah, err := appda.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	var dataRoot [32]byte
	copy(dataRoot[:], dah.Hash())
	certificate := cert.NewCelestiaCertificate(12, 0, uint64(len(shares))+1, [32]byte{0xaa}, dataRoot)

	_, err = buildReadResultFromShares(
		certificate,
		readResultShares{
			RowRoots:    dah.RowRoots,
			ColumnRoots: dah.ColumnRoots,
			Shares:      shares,
			Rows:        [][][]byte{eds.Row(0)},
		},
	)
	require.ErrorContains(t, err, "share length mismatch")
}

func TestValidateReadResult_RejectsMutatedDataRoot(t *testing.T) {
	namespace, err := libshare.NewV0Namespace(bytes.Repeat([]byte{0x73}, libshare.NamespaceVersionZeroIDSize))
	require.NoError(t, err)

	message := []byte("mutated data root should fail validation")
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
	certificate := cert.NewCelestiaCertificate(13, 0, uint64(len(shares)), [32]byte{0xbb}, dataRoot)

	result, err := buildReadResultFromShares(
		certificate,
		readResultShares{
			RowRoots:    dah.RowRoots,
			ColumnRoots: dah.ColumnRoots,
			Shares:      shares,
			Rows:        [][][]byte{eds.Row(0)},
		},
	)
	require.NoError(t, err)

	certificate.DataRoot[0] ^= 0xff
	err = validateReadResult(result, certificate)
	require.ErrorContains(t, err, "data root mismatch")
	require.True(t, daprovider.IsCertificateValidationError(err))
}

func TestValidateReadResult_RejectsIncompleteRowAsCertificateValidationError(t *testing.T) {
	namespace, err := libshare.NewV0Namespace(bytes.Repeat([]byte{0x39}, libshare.NamespaceVersionZeroIDSize))
	require.NoError(t, err)

	message := []byte("incomplete rows should fail certificate validation")
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
	certificate := cert.NewCelestiaCertificate(14, 0, uint64(len(shares)), [32]byte{0xcc}, dataRoot)

	result, err := buildReadResultFromShares(
		certificate,
		readResultShares{
			RowRoots:    dah.RowRoots,
			ColumnRoots: dah.ColumnRoots,
			Shares:      shares,
			Rows:        [][][]byte{eds.Row(0)},
		},
	)
	require.NoError(t, err)

	result.Rows[0][0] = nil
	err = validateReadResult(result, certificate)
	require.ErrorContains(t, err, "failed to compute row root")
	require.True(t, daprovider.IsCertificateValidationError(err))
}

func TestValidateReadResult_RejectsNilCertificate(t *testing.T) {
	t.Parallel()

	err := validateReadResult(&types.ReadResult{}, nil)
	require.ErrorContains(t, err, "nil certificate")
	require.True(t, daprovider.IsCertificateValidationError(err))
}
