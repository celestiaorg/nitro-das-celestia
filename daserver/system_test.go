package das

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/stretchr/testify/require"
)

func getAuthToken(t *testing.T, network string) string {
	if token := os.Getenv("CELESTIA_AUTH_TOKEN"); token != "" {
		return strings.TrimSpace(token)
	}
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
	namespaceID := os.Getenv("NAMESPACE")
	if namespaceID == "" {
		namespaceID = "000008e5f679bf7116cb"
	}
	require.NotEmpty(t, namespaceID, "Namespace ID should not be empty")

	// Create CelestiaDA instance connected to local node
	cfg := &DAConfig{
		Rpc:              "http://localhost:26658", // Default Celestia light node RPC port
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
		ReadTimeout:       5 * time.Minute,
		ReadHeaderTimeout: 5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       5 * time.Minute,
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

		// Read through RPC
		var readResult types.ReadResult
		err = client.Call(&readResult, "celestia_read", parsedCert)
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

			var readResult types.ReadResult
			err = client.Call(&readResult, "celestia_read", parsedCert)
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
		require.Equal(t, cert.CelestiaMessageHeaderFlag, storedBytes[1], "second byte should be provider tag")

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

	t.Run("Multiple Messages With Binary Payload", func(t *testing.T) {
		payloads := [][]byte{
			[]byte("alpha: " + time.Now().Format(time.RFC3339Nano)),
			[]byte("beta: the quick brown fox jumps over the lazy dog"),
			make([]byte, 256), // binary blob
		}
		// fill binary blob with a repeating byte pattern
		for i := range payloads[2] {
			payloads[2][i] = byte(i % 256)
		}

		for i, msg := range payloads {
			t.Run(fmt.Sprintf("blob_%d", i), func(t *testing.T) {
				var certBytes []byte
				err := client.Call(&certBytes, "celestia_store", hexutil.Bytes(msg))
				require.NoError(t, err, "store failed for blob %d", i)
				require.Len(t, certBytes, cert.CelestiaDACertV1Len)

				parsedCert := &cert.CelestiaDACertV1{}
				require.NoError(t, parsedCert.UnmarshalBinary(certBytes))

				var result types.ReadResult
				err = client.Call(&result, "celestia_read", parsedCert)
				require.NoError(t, err, "read failed for blob %d", i)
				require.Equal(t, msg, result.Message, "payload mismatch for blob %d", i)
			})
		}
	})
}

// TestDAProviderAPI exercises the daprovider_* namespace:
// store via celestia_store, then recover via daprovider_recoverPayload.
func TestDAProviderAPI(t *testing.T) {
	_, endpoint, cleanup := setupTestEnvironment(t)
	defer cleanup()

	client, err := rpc.Dial(endpoint)
	require.NoError(t, err)
	defer client.Close()

	message := []byte("daprovider api test " + time.Now().Format(time.RFC3339Nano))

	// Store using the celestia namespace
	var certBytes []byte
	err = client.Call(&certBytes, "celestia_store", hexutil.Bytes(message))
	require.NoError(t, err, "celestia_store failed")
	require.Len(t, certBytes, cert.CelestiaDACertV1Len)

	t.Logf("Stored cert: 0x%s", hex.EncodeToString(certBytes))

	// Build a synthetic sequencer message: 40-byte header + cert bytes.
	// The daserver reads the cert starting at offset 40 (cert.SequencerMsgOffset).
	seqHeader := make([]byte, 40)
	seqHeader[40-2] = cert.CustomDAHeaderFlag        // byte[38]
	seqHeader[40-1] = cert.CelestiaMessageHeaderFlag // byte[39]
	seqMsg := append(seqHeader, certBytes...)

	type PayloadResult struct {
		Payload []byte `json:"Payload"`
	}
	var payloadResult PayloadResult
	err = client.Call(
		&payloadResult,
		"daprovider_recoverPayload",
		hexutil.Uint64(1),     // batchNum
		common.Hash{},         // batchBlockHash (zero hash)
		hexutil.Bytes(seqMsg), // sequencerMsg
	)
	require.NoError(t, err, "daprovider_recoverPayload failed")
	require.Equal(t, message, []byte(payloadResult.Payload), "recovered payload mismatch")

	t.Logf("daprovider_recoverPayload returned %d bytes: %q", len(payloadResult.Payload), payloadResult.Payload)
}

// TestGenerateCertificateValidityProof stores a blob and calls
// daprovider_generateCertificateValidityProof, verifying the proof claims valid.
func TestGenerateCertificateValidityProof(t *testing.T) {
	_, endpoint, cleanup := setupTestEnvironment(t)
	defer cleanup()

	client, err := rpc.Dial(endpoint)
	require.NoError(t, err)
	defer client.Close()

	message := []byte("validity proof test " + time.Now().Format(time.RFC3339Nano))

	var certBytes []byte
	err = client.Call(&certBytes, "celestia_store", hexutil.Bytes(message))
	require.NoError(t, err, "celestia_store failed")

	type ValidityProofResult struct {
		Proof hexutil.Bytes `json:"Proof"`
	}
	var result ValidityProofResult
	err = client.Call(
		&result,
		"daprovider_generateCertificateValidityProof",
		hexutil.Bytes(certBytes),
	)
	require.NoError(t, err, "daprovider_generateCertificateValidityProof failed")
	require.NotEmpty(t, result.Proof, "validity proof must not be empty")

	// First byte: 0x01 = claimed valid, 0x00 = invalid
	claimedValid := result.Proof[0]
	t.Logf("Validity proof (%d bytes): claimedValid=0x%02x", len(result.Proof), claimedValid)
	require.Equal(t, byte(0x01), claimedValid, "cert should be claimed valid")
}

// TestReadInvalidCertFastFail verifies that reading a cert with a bogus block
// height returns an error quickly using a minimal retry config.
func TestReadInvalidCertFastFail(t *testing.T) {
	authToken := getAuthToken(t, "mocha")
	namespaceID := os.Getenv("NAMESPACE")
	if namespaceID == "" {
		namespaceID = "000008e5f679bf7116cb"
	}

	fastFail := RetryBackoffConfig{
		MaxRetries:     1,
		InitialBackoff: 500 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
		BackoffFactor:  1.0,
	}

	cfg := &DAConfig{
		Rpc:              "http://localhost:26658",
		NamespaceId:      namespaceID,
		AuthToken:        authToken,
		CacheCleanupTime: time.Minute,
		WithWriter:       true,
		RetryConfig:      fastFail,
	}

	celestiaDA, err := NewCelestiaDA(cfg)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	timeouts := genericconf.HTTPServerTimeoutConfig{
		ReadTimeout:       5 * time.Minute,
		ReadHeaderTimeout: 5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       5 * time.Minute,
	}

	ctx, cancel := context.WithCancel(context.Background())
	server, err := StartCelestiaDASRPCServerOnListener(ctx, listener, timeouts, 1024*1024*2, celestiaDA, celestiaDA)
	require.NoError(t, err)
	defer func() {
		cancel()
		server.Close()
		celestiaDA.Stop()
	}()

	client, err := rpc.Dial("http://" + listener.Addr().String())
	require.NoError(t, err)
	defer client.Close()

	badCert := cert.NewCelestiaCertificate(
		999_999_999, // block height far in the future
		0,
		1,
		[32]byte{0xde, 0xad, 0xbe, 0xef},
		[32]byte{0xca, 0xfe, 0xba, 0xbe},
	)

	var readResult types.ReadResult
	err = client.Call(&readResult, "celestia_read", badCert)
	require.Error(t, err, "reading an invalid cert should return an error")
	t.Logf("invalid cert correctly returned error: %v", err)
}
