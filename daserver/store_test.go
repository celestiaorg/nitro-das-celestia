package das

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	appda "github.com/celestiaorg/celestia-app/v7/pkg/da"
	txclient "github.com/celestiaorg/celestia-node/api/client"
	node "github.com/celestiaorg/celestia-node/api/rpc/client"
	nodeblob "github.com/celestiaorg/celestia-node/blob"
	nodeheader "github.com/celestiaorg/celestia-node/header"
	blobapi "github.com/celestiaorg/celestia-node/nodebuilder/blob"
	headerapi "github.com/celestiaorg/celestia-node/nodebuilder/header"
	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

func blobWithIndex(t *testing.T, namespace libshare.Namespace, message []byte, index int) *nodeblob.Blob {
	t.Helper()

	blob, err := nodeblob.NewBlobV0(namespace, message)
	require.NoError(t, err)

	raw, err := blob.MarshalJSON()
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	decoded["index"] = float64(index)

	withIndexRaw, err := json.Marshal(decoded)
	require.NoError(t, err)

	var withIndex nodeblob.Blob
	require.NoError(t, withIndex.UnmarshalJSON(withIndexRaw))
	require.Equal(t, index, withIndex.Index())

	return &withIndex
}

func makeStoreFixture(t *testing.T, message []byte, blobIndex int) (*CelestiaDA, *nodeblob.Blob, *nodeheader.ExtendedHeader) {
	t.Helper()

	namespace, err := libshare.NewV0Namespace(bytes.Repeat([]byte{0x31}, libshare.NamespaceVersionZeroIDSize))
	require.NoError(t, err)

	blob := blobWithIndex(t, namespace, message, blobIndex)
	shares, err := nodeblob.BlobsToShares(blob)
	require.NoError(t, err)

	eds, err := appda.ExtendShares(libshare.ToBytes(shares))
	require.NoError(t, err)

	dah, err := appda.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	header := &nodeheader.ExtendedHeader{
		RawHeader: tmtypes.Header{DataHash: dah.Hash()},
		DAH:       &dah,
	}

	writeClient := &node.Client{}
	writeClient.Blob.Internal.Submit = func(context.Context, []*nodeblob.Blob, *nodeblob.SubmitOptions) (uint64, error) {
		return 77, nil
	}

	blobAPI := &blobapi.API{}
	blobAPI.Internal.Get = func(context.Context, uint64, libshare.Namespace, nodeblob.Commitment) (*nodeblob.Blob, error) {
		return blob, nil
	}

	headerAPI := &headerapi.API{}
	headerAPI.Internal.GetByHeight = func(context.Context, uint64) (*nodeheader.ExtendedHeader, error) {
		return header, nil
	}

	readClient := &txclient.ReadClient{
		Blob:   blobAPI,
		Header: headerAPI,
	}

	da := &CelestiaDA{
		Cfg: &DAConfig{
			WithWriter: true,
			RetryConfig: RetryBackoffConfig{
				MaxRetries:     3,
				InitialBackoff: time.Millisecond,
				MaxBackoff:     2 * time.Millisecond,
				BackoffFactor:  1,
			},
		},
		Client:     writeClient,
		ReadClient: readClient,
		Namespace:  &namespace,
	}
	return da, blob, header
}

func TestStore_AllowsBlobIndexZero(t *testing.T) {
	t.Parallel()

	da, _, _ := makeStoreFixture(t, []byte("index zero should be valid"), 0)

	certBytes, err := da.Store(context.Background(), []byte("index zero should be valid"))
	require.NoError(t, err)

	parsed, err := cert.ParseCelestiaCertificate(certBytes)
	require.NoError(t, err)
	require.EqualValues(t, 0, parsed.Start)
}

func TestStore_ReturnsCertificateMatchingBlobAndHeader(t *testing.T) {
	t.Parallel()

	message := []byte("store should return exact blob/header certificate fields")
	da, blob, header := makeStoreFixture(t, message, 3)

	certBytes, err := da.Store(context.Background(), message)
	require.NoError(t, err)

	parsed, err := cert.ParseCelestiaCertificate(certBytes)
	require.NoError(t, err)
	require.EqualValues(t, 77, parsed.BlockHeight)
	require.EqualValues(t, 2, parsed.Start)

	sharesLength, err := blob.Length()
	require.NoError(t, err)
	require.EqualValues(t, sharesLength, parsed.SharesLength)

	var wantCommitment [32]byte
	copy(wantCommitment[:], blob.Commitment)
	require.Equal(t, wantCommitment, parsed.TxCommitment)

	var wantDataRoot [32]byte
	copy(wantDataRoot[:], header.DataHash)
	require.Equal(t, wantDataRoot, parsed.DataRoot)
}

func TestStore_RetriesBlobGetAfterSuccessfulSubmit(t *testing.T) {
	t.Parallel()

	message := []byte("store should retry blob get after submit")
	da, _, _ := makeStoreFixture(t, message, 3)

	calls := 0
	originalGet := da.ReadClient.Blob.Get
	blobAPI := &blobapi.API{}
	blobAPI.Internal.Get = func(ctx context.Context, h uint64, ns libshare.Namespace, c nodeblob.Commitment) (*nodeblob.Blob, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("transient blob get failure")
		}
		return originalGet(ctx, h, ns, c)
	}
	da.ReadClient.Blob = blobAPI

	certBytes, err := da.Store(context.Background(), message)
	require.NoError(t, err)
	require.NotEmpty(t, certBytes)
	require.Equal(t, 2, calls)
}

func TestStore_RetriesHeaderGetAfterSuccessfulSubmit(t *testing.T) {
	t.Parallel()

	message := []byte("store should retry header get after submit")
	da, _, _ := makeStoreFixture(t, message, 3)

	calls := 0
	originalGetByHeight := da.ReadClient.Header.GetByHeight
	headerAPI := &headerapi.API{}
	headerAPI.Internal.GetByHeight = func(ctx context.Context, h uint64) (*nodeheader.ExtendedHeader, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("transient header get failure")
		}
		return originalGetByHeight(ctx, h)
	}
	da.ReadClient.Header = headerAPI

	certBytes, err := da.Store(context.Background(), message)
	require.NoError(t, err)
	require.NotEmpty(t, certBytes)
	require.Equal(t, 2, calls)
}
