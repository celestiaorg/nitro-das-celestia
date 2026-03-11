package das

import (
	"bytes"
	"testing"

	appda "github.com/celestiaorg/celestia-app/v6/pkg/da"
	nodeblob "github.com/celestiaorg/celestia-node/blob"
	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
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
