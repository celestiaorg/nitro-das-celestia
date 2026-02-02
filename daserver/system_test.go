package das

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/stretchr/testify/require"
)

func getAuthToken(t *testing.T, network string) string {
	cmd := exec.Command("celestia", "light", "auth", "admin", "--p2p.network", network)
	output, err := cmd.Output()
	require.NoError(t, err, "Failed to get auth token")
	return strings.TrimSpace(string(output))
}

func setupTestEnvironment(t *testing.T) (*CelestiaDA, string, func()) {
	// Get auth token from CLI
	authToken := getAuthToken(t, "mocha")
	require.NotEmpty(t, authToken, "Auth token should not be empty")

	// Generate namespace ID
	namespaceID := "000008e5f679bf7116cb"
	require.NotEmpty(t, namespaceID, "Namespace ID should not be empty")

	// Create CelestiaDA instance connected to local node
	cfg := &DAConfig{
		Rpc:              "http://localhost:26658", // Default Celestia light node RPC port
		ReadRpc:          "http://localhost:26658",
		NamespaceId:      namespaceID,
		AuthToken:        authToken,
		CacheCleanupTime: time.Minute,
		WithWriter:       true,
		// Add validator config and other nec
	}

	celestiaDA, err := NewCelestiaDA(cfg)
	require.NoError(t, err)

	// Find an available port for our RPC server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// RPC server timeouts
	timeouts := genericconf.HTTPServerTimeoutConfig{
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
	}

	// Start the RPC server
	ctx, cancel := context.WithCancel(context.Background())
	server, err := StartCelestiaDASRPCServerOnListener(
		ctx,
		listener,
		timeouts,
		1024*1024*2, // 2MB body limit
		celestiaDA,
		celestiaDA,
		nil,
		false,
	)
	require.NoError(t, err)

	endpoint := "http://" + listener.Addr().String()

	cleanup := func() {
		cancel()
		server.Close()
		if celestiaDA != nil {
			celestiaDA.Stop()
		}
	}

	return celestiaDA, endpoint, cleanup
}

func certToBlobPointer(c *cert.CelestiaDACertV1) types.BlobPointer {
	return types.BlobPointer{
		BlockHeight:  c.BlockHeight,
		Start:        c.Start,
		SharesLength: c.SharesLength,
		TxCommitment: c.TxCommitment,
		DataRoot:     c.DataRoot,
	}
}

func TestCelestiaIntegration(t *testing.T) {
	celestiaDA, endpoint, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create RPC client
	client, err := rpc.Dial(endpoint)
	require.NoError(t, err)
	defer client.Close()

	t.Run("Store and Read Flow", func(t *testing.T) {
		// Test data
		message := []byte("test message for celestia integration " + time.Now().String())

		// Store through RPC
		var storedBytes []byte
		err = client.Call(&storedBytes, "celestia_store", hexutil.Bytes(message))
		require.NoError(t, err)
		require.NotNil(t, storedBytes)

		// Check header flag and length
		require.Equal(t, cert.CustomDAHeaderFlag, storedBytes[0])
		require.Equal(t, cert.CelestiaDACertV1Len, len(storedBytes))

		// Parse certificate
		parsedCert := &cert.CelestiaDACertV1{}
		err = parsedCert.UnmarshalBinary(storedBytes)
		require.NoError(t, err)

		blobPointer := certToBlobPointer(parsedCert)

		// Read through RPC
		var readResult types.ReadResult
		err = client.Call(&readResult, "celestia_read", &blobPointer)
		require.NoError(t, err)
		require.NotNil(t, readResult)

		// Verify message
		require.Equal(t, message, readResult.Message)

		// Verify proof data is present
		require.NotEmpty(t, readResult.RowRoots)
		require.NotEmpty(t, readResult.ColumnRoots)
		require.NotEmpty(t, readResult.Rows)
	})

	t.Run("Multiple Messages", func(t *testing.T) {
		messages := [][]byte{
			[]byte("first message " + time.Now().String()),
			[]byte("second message " + time.Now().String()),
			[]byte("third message " + time.Now().String()),
		}

		for _, msg := range messages {
			var storedBytes []byte
			err = client.Call(&storedBytes, "celestia_store", hexutil.Bytes(msg))
			require.NoError(t, err)

			parsedCert := &cert.CelestiaDACertV1{}
			err = parsedCert.UnmarshalBinary(storedBytes)
			require.NoError(t, err)

			blobPointer := certToBlobPointer(parsedCert)
			var readResult types.ReadResult
			err = client.Call(&readResult, "celestia_read", &blobPointer)
			require.NoError(t, err)
			require.Equal(t, msg, readResult.Message)
		}
	})

	t.Run("Get Proof", func(t *testing.T) {
		if celestiaDA.Cfg.ValidatorConfig.EthClient == "" {
			t.Skip("Skipping proof test - no validator config")
			return
		}

		message := []byte("message for proof test " + time.Now().String())

		// Store message
		var storedBytes []byte
		err = client.Call(&storedBytes, "celestia_store", hexutil.Bytes(message))
		require.NoError(t, err)

		// Get proof
		var proofBytes []byte
		err = client.Call(&proofBytes, "celestia_getProof", storedBytes)
		require.NoError(t, err)
		require.NotNil(t, proofBytes)
	})

	t.Run("Certificate Format", func(t *testing.T) {
		message := []byte("cert format test " + time.Now().String())

		var storedBytes []byte
		err = client.Call(&storedBytes, "celestia_store", hexutil.Bytes(message))
		require.NoError(t, err)

		// Verify cert structure
		require.Equal(t, cert.CelestiaDACertV1Len, len(storedBytes), "cert should be exactly 92 bytes")
		require.Equal(t, cert.CustomDAHeaderFlag, storedBytes[0], "first byte should be custom DA header")
		require.Equal(t, cert.CelestiaProviderTag, storedBytes[1], "second byte should be provider tag")

		// Verify round-trip
		parsedCert := &cert.CelestiaDACertV1{}
		err = parsedCert.UnmarshalBinary(storedBytes)
		require.NoError(t, err)
		require.NotZero(t, parsedCert.BlockHeight)
		require.NotZero(t, parsedCert.TxCommitment)
		require.NotZero(t, parsedCert.DataRoot)
	})

	t.Run("Error Cases", func(t *testing.T) {
		// Try to read non-existent block
		invalidPointer := &types.BlobPointer{
			BlockHeight:  999999999, // Very high block number
			Start:        0,
			SharesLength: 1,
		}

		var readResult types.ReadResult
		err = client.Call(&readResult, "celestia_read", invalidPointer)
		require.Error(t, err)

		// Try to store empty message
		var storedBytes []byte
		err = client.Call(&storedBytes, "celestia_store", hexutil.Bytes([]byte{}))
		require.Error(t, err)
	})

	t.Run("Cache Behavior", func(t *testing.T) {
		message := []byte("cached message " + time.Now().String())

		// First store
		var firstStore []byte
		err = client.Call(&firstStore, "celestia_store", hexutil.Bytes(message))
		require.NoError(t, err)

		// Immediate second store of same message
		var secondStore []byte
		err = client.Call(&secondStore, "celestia_store", hexutil.Bytes(message))
		require.NoError(t, err)

		// Should get same blob pointer from cache
		require.Equal(t, firstStore, secondStore)

		if celestiaDA.Cfg.CacheCleanupTime > 0 {
			// Wait for cache cleanup
			time.Sleep(celestiaDA.Cfg.CacheCleanupTime * 2)

			// Store again after cache clear
			var thirdStore []byte
			err = client.Call(&thirdStore, "celestia_store", hexutil.Bytes(message))
			require.NoError(t, err)

			// Should get different blob pointer after cache clear
			require.NotEqual(t, firstStore, thirdStore)
		}
	})
}
