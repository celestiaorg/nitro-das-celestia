package das

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/offchainlabs/nitro/daprovider/server_api"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Shared setup helpers
// ---------------------------------------------------------------------------

// setupValidatorTest creates a CelestiaDA instance wired to a local Celestia
// light node and starts an RPC server.  It is intentionally separate from
// setupNetworkTest so the validator tests can carry their own ValidatorConfig.
//
// Required environment variables (test skipped if absent):
//
//	NAMESPACE  – hex namespace ID (no 0x prefix), e.g. "000008e5f679bf7116cb"
//	CELESTIA_AUTH_TOKEN or the celestia CLI must be available
//
// Optional (needed by Blobstream-related subtests):
//
//	ETH_RPC         – JSON-RPC endpoint of an EVM node, e.g. "https://eth-sepolia.g.alchemy.com/v2/..."
//	BLOBSTREAM_ADDR – deployed SP1-Blobstream contract address (0x…)
func setupValidatorTest(t *testing.T) (*CelestiaDA, *rpc.Client, func()) {
	t.Helper()

	namespaceID := os.Getenv("NAMESPACE")
	if namespaceID == "" {
		t.Skip("NAMESPACE not set – skipping validator integration test")
	}

	authToken := getAuthToken(t, "celestia")
	require.NotEmpty(t, authToken, "auth token must not be empty")

	cfg := &DAConfig{
		Rpc:              "http://localhost:26658",
		NamespaceId:      namespaceID,
		AuthToken:        authToken,
		CacheCleanupTime: time.Minute,
		WithWriter:       true,
		ValidatorConfig: ValidatorConfig{
			EthClient:      os.Getenv("ETH_RPC"),
			BlobstreamAddr: os.Getenv("BLOBSTREAM_ADDR"),
		},
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
	server, err := StartCelestiaDASRPCServerOnListener(
		ctx,
		listener,
		timeouts,
		4*1024*1024,
		celestiaDA,
		celestiaDA,
	)
	require.NoError(t, err)

	client, err := rpc.Dial("http://" + listener.Addr().String())
	require.NoError(t, err)

	cleanup := func() {
		client.Close()
		cancel()
		server.Close()
		celestiaDA.Stop()
	}

	return celestiaDA, client, cleanup
}

// certFromEnv builds a CelestiaDACertV1 from the well-known env-var set used
// by the blobstream_test.go suite (HEIGHT, COMMITMENT, BLOB_DATA, NAMESPACE).
// Returns nil if any required variable is missing.
func certFromEnv(t *testing.T, celestiaDA *CelestiaDA) *cert.CelestiaDACertV1 {
	t.Helper()

	heightStr := os.Getenv("HEIGHT")
	commitmentB64 := os.Getenv("COMMITMENT")
	blobDataB64 := os.Getenv("BLOB_DATA")

	if heightStr == "" || commitmentB64 == "" || blobDataB64 == "" {
		return nil
	}

	height, err := strconv.ParseUint(heightStr, 10, 64)
	require.NoError(t, err)

	commitment, err := base64.StdEncoding.DecodeString(commitmentB64)
	require.NoError(t, err)

	nsBytes, err := hex.DecodeString(celestiaDA.Cfg.NamespaceId)
	require.NoError(t, err)

	namespace, err := libshare.NewV0Namespace(nsBytes)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	header, err := celestiaDA.ReadClient.Header.GetByHeight(ctx, height)
	if err != nil {
		if strings.Contains(err.Error(), "syncing") || strings.Contains(err.Error(), "future") {
			t.Skipf("celestia node not synced to height %d: %v", height, err)
		}
		require.NoError(t, err)
	}
	if header == nil {
		t.Skipf("nil header at height %d", height)
	}

	dataBlob, err := celestiaDA.ReadClient.Blob.Get(ctx, height, namespace, commitment)
	if err != nil {
		if strings.Contains(err.Error(), "syncing") || strings.Contains(err.Error(), "future") {
			t.Skipf("celestia node not synced to height %d: %v", height, err)
		}
		require.NoError(t, err)
	}

	sharesLength, err := dataBlob.Length()
	require.NoError(t, err)
	require.NotZero(t, sharesLength)

	squareSize := uint64(len(header.DAH.RowRoots))
	odsSize := squareSize / 2
	blobIndex := uint64(dataBlob.Index())
	startRow := blobIndex / squareSize
	startIndexOds := blobIndex - odsSize*startRow

	var txCommitment, dataRoot [32]byte
	copy(txCommitment[:], dataBlob.Commitment)
	copy(dataRoot[:], header.DataHash)

	return cert.NewCelestiaCertificate(
		height,
		startIndexOds,
		uint64(sharesLength),
		txCommitment,
		dataRoot,
	)
}

// ---------------------------------------------------------------------------
// Helper: parse the read-preimage proof format and return its sections.
//
// Expected layout:
//
//	[certSize  (8 bytes, big-endian uint64)]
//	[certificate (certSize bytes)          ]
//	[version   (1 byte) = 0x01             ]
//	[preimSize (8 bytes, big-endian uint64)]
//	[preimage  (preimSize bytes)           ]
//	[blobstreamProofData (remainder)       ]
type parsedReadPreimageProof struct {
	certSize        uint64
	certificate     []byte
	version         byte
	preimageSize    uint64
	preimage        []byte
	blobstreamProof []byte
}

func parseReadPreimageProof(t *testing.T, proof []byte) parsedReadPreimageProof {
	t.Helper()

	require.GreaterOrEqual(t, len(proof), 8, "proof must be at least 8 bytes (certSize field)")

	var p parsedReadPreimageProof

	pos := 0
	p.certSize = binary.BigEndian.Uint64(proof[pos : pos+8])
	pos += 8

	require.GreaterOrEqual(t, len(proof), pos+int(p.certSize),
		"proof truncated before end of certificate")
	p.certificate = proof[pos : pos+int(p.certSize)]
	pos += int(p.certSize)

	require.GreaterOrEqual(t, len(proof), pos+1, "proof truncated before version byte")
	p.version = proof[pos]
	pos++

	require.GreaterOrEqual(t, len(proof), pos+8, "proof truncated before preimageSize field")
	p.preimageSize = binary.BigEndian.Uint64(proof[pos : pos+8])
	pos += 8

	require.GreaterOrEqual(t, len(proof), pos+int(p.preimageSize),
		"proof truncated before end of preimage")
	p.preimage = proof[pos : pos+int(p.preimageSize)]
	pos += int(p.preimageSize)

	p.blobstreamProof = proof[pos:]

	return p
}

// ---------------------------------------------------------------------------
// Helper: parse the certificate-validity proof format.
//
// Expected layout:
//
//	[certSize    (8 bytes, big-endian uint64)]
//	[certificate (certSize bytes)            ]
//	[claimedValid (1 byte): 0x01 or 0x00    ]
type parsedValidityProof struct {
	certSize     uint64
	certificate  []byte
	claimedValid byte
}

func parseValidityProof(t *testing.T, proof []byte) parsedValidityProof {
	t.Helper()

	require.GreaterOrEqual(t, len(proof), 8, "validity proof must be at least 8 bytes")

	var p parsedValidityProof

	pos := 0
	p.certSize = binary.BigEndian.Uint64(proof[pos : pos+8])
	pos += 8

	require.GreaterOrEqual(t, len(proof), pos+int(p.certSize),
		"validity proof truncated before end of certificate")
	p.certificate = proof[pos : pos+int(p.certSize)]
	pos += int(p.certSize)

	require.GreaterOrEqual(t, len(proof), pos+1, "validity proof truncated before claimedValid byte")
	p.claimedValid = proof[pos]

	return p
}

// ---------------------------------------------------------------------------
// TestGenerateCertificateValidityProof_InvalidCert
//
// Verifies that feeding a syntactically invalid certificate (all-zero 92 bytes
// with the right header bytes but a zero blockHeight) causes the method to
// return a proof with claimedValid=0x00 and NO error.
//
// Does NOT require ETH_RPC or BLOBSTREAM_ADDR – only a running Celestia node.
// ---------------------------------------------------------------------------
func TestGenerateCertificateValidityProof_InvalidCert(t *testing.T) {
	_, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	// Build a structurally parseable but semantically invalid cert:
	// blockHeight = 0 causes validateCertificate to return false immediately.
	badCert := make([]byte, cert.CelestiaDACertV1Len)
	badCert[0] = cert.CustomDAHeaderFlag
	badCert[1] = cert.CelestiaMessageHeaderFlag
	binary.BigEndian.PutUint16(badCert[2:4], uint16(cert.CelestiaCertVersion))
	// blockHeight[4..11] left as 0 → invalid

	var result server_api.GenerateCertificateValidityProofResult
	err := client.Call(&result, "daprovider_generateCertificateValidityProof", hexutil.Bytes(badCert))
	require.NoError(t, err, "invalid cert must not return an RPC error – only claimedValid=0x00")
	require.NotEmpty(t, result.Proof, "proof must not be empty even for an invalid cert")

	parsed := parseValidityProof(t, result.Proof)

	require.EqualValues(t, cert.CelestiaDACertV1Len, parsed.certSize,
		"certSize field must equal %d", cert.CelestiaDACertV1Len)
	require.Len(t, parsed.certificate, cert.CelestiaDACertV1Len,
		"certificate section must be exactly %d bytes", cert.CelestiaDACertV1Len)
	require.Equal(t, badCert, parsed.certificate,
		"certificate bytes in proof must match the input certificate")
	require.EqualValues(t, 0x00, parsed.claimedValid,
		"claimedValid must be 0x00 for a cert with blockHeight=0")
}

// ---------------------------------------------------------------------------
// TestGenerateCertificateValidityProof_MalformedCert
//
// Verifies that a cert whose UnmarshalBinary fails (wrong header byte) causes
// the validator to return claimedValid=0x00 and no error.
// ---------------------------------------------------------------------------
func TestGenerateCertificateValidityProof_MalformedCert(t *testing.T) {
	_, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	// Cert with wrong header byte – UnmarshalBinary in validator will fail,
	// which should surface as claimedValid=0x00, not an RPC error.
	malformed := make([]byte, cert.CelestiaDACertV1Len)
	malformed[0] = 0xAA // not CustomDAHeaderFlag
	malformed[1] = cert.CelestiaMessageHeaderFlag
	binary.BigEndian.PutUint16(malformed[2:4], uint16(cert.CelestiaCertVersion))
	binary.BigEndian.PutUint64(malformed[4:12], 12345) // non-zero blockHeight
	binary.BigEndian.PutUint64(malformed[20:28], 1)    // non-zero sharesLength

	var result server_api.GenerateCertificateValidityProofResult
	err := client.Call(&result, "daprovider_generateCertificateValidityProof", hexutil.Bytes(malformed))
	// The validator layer returns {Proof: []byte{0}} for unmarshal failures,
	// not an error.  The RPC result itself is nil-error.
	require.NoError(t, err, "malformed cert must not return an RPC error")
	require.NotEmpty(t, result.Proof)
	// The proof from a parse failure is {0x00} (single byte) since the cert
	// could not be marshalled back; accept anything with last byte == 0.
	require.EqualValues(t, 0x00, result.Proof[len(result.Proof)-1],
		"last byte of proof must be 0x00 for a cert that fails to unmarshal")
}

// ---------------------------------------------------------------------------
// TestGenerateCertificateValidityProof_ValidCert
//
// Stores a blob, then verifies the validity proof contains the expected
// structure and claimedValid=0x01.
//
// Required env vars (in addition to NAMESPACE):
//
//	HEIGHT, COMMITMENT, BLOB_DATA  (same as blobstream_test.go)
//
// ---------------------------------------------------------------------------
func TestGenerateCertificateValidityProof_ValidCert(t *testing.T) {
	celestiaDA, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	daeCert := certFromEnv(t, celestiaDA)
	if daeCert == nil {
		t.Skip("HEIGHT, COMMITMENT, BLOB_DATA not set – skipping valid-cert subtest")
	}

	certBytes, err := daeCert.MarshalBinary()
	require.NoError(t, err)

	var result server_api.GenerateCertificateValidityProofResult
	err = client.Call(&result, "daprovider_generateCertificateValidityProof", hexutil.Bytes(certBytes))
	require.NoError(t, err)
	require.NotEmpty(t, result.Proof)

	parsed := parseValidityProof(t, result.Proof)

	require.EqualValues(t, cert.CelestiaDACertV1Len, parsed.certSize,
		"certSize field must equal %d", cert.CelestiaDACertV1Len)
	require.Len(t, parsed.certificate, cert.CelestiaDACertV1Len)
	require.Equal(t, certBytes, parsed.certificate,
		"certificate bytes in proof must match the input")

	// The claimedValid byte indicates whether the blob is live on Celestia.
	// For a freshly stored blob it must be 0x01.
	require.EqualValues(t, 0x01, parsed.claimedValid,
		"claimedValid must be 0x01 for a live Celestia blob")

	// Also verify that the embedded certificate round-trips cleanly.
	roundTripped := &cert.CelestiaDACertV1{}
	require.NoError(t, roundTripped.UnmarshalBinary(parsed.certificate))
	require.Equal(t, daeCert.BlockHeight, roundTripped.BlockHeight)
	require.Equal(t, daeCert.DataRoot, roundTripped.DataRoot)
	require.Equal(t, daeCert.TxCommitment, roundTripped.TxCommitment)
}

// ---------------------------------------------------------------------------
// TestGenerateReadPreimageProof_Structure
//
// Stores a blob, calls GenerateReadPreimageProof at offset 0, and verifies
// the byte-level layout of the returned proof without performing Blobstream
// on-chain verification (that requires ETH_RPC + BLOBSTREAM_ADDR).
//
// Required env vars: NAMESPACE, HEIGHT, COMMITMENT, BLOB_DATA
// Also required: ETH_RPC, BLOBSTREAM_ADDR (for the Blobstream proof portion)
// ---------------------------------------------------------------------------
func TestGenerateReadPreimageProof_Structure(t *testing.T) {
	celestiaDA, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	if celestiaDA.Cfg.ValidatorConfig.EthClient == "" ||
		celestiaDA.Cfg.ValidatorConfig.BlobstreamAddr == "" {
		t.Skip("ETH_RPC and BLOBSTREAM_ADDR must be set for read-preimage proof tests")
	}

	daeCert := certFromEnv(t, celestiaDA)
	if daeCert == nil {
		t.Skip("HEIGHT, COMMITMENT, BLOB_DATA not set – skipping read-preimage proof test")
	}

	certBytes, err := daeCert.MarshalBinary()
	require.NoError(t, err)

	var result server_api.GenerateReadPreimageProofResult
	err = client.Call(&result, "daprovider_generateReadPreimageProof",
		hexutil.Uint64(0), hexutil.Bytes(certBytes))
	require.NoError(t, err)
	require.NotEmpty(t, result.Proof, "proof must not be empty")

	// ------------------------------------------------------------------
	// Parse and validate the proof structure:
	//   [certSize(8)][certificate][version(1)=0x01][preimageSize(8)][preimage][blobstreamProof]
	// ------------------------------------------------------------------
	p := parseReadPreimageProof(t, result.Proof)

	t.Logf("certSize=%d version=0x%02x preimageSize=%d blobstreamProofLen=%d",
		p.certSize, p.version, p.preimageSize, len(p.blobstreamProof))

	// 1. certSize must equal the constant CelestiaDACertV1Len.
	require.EqualValues(t, cert.CelestiaDACertV1Len, p.certSize,
		"certSize field must be %d (CelestiaDACertV1Len)", cert.CelestiaDACertV1Len)

	// 2. Certificate section must be exactly certSize bytes.
	require.Len(t, p.certificate, cert.CelestiaDACertV1Len,
		"certificate section length mismatch")

	// 3. Certificate must round-trip cleanly.
	roundTripped := &cert.CelestiaDACertV1{}
	require.NoError(t, roundTripped.UnmarshalBinary(p.certificate),
		"embedded certificate must unmarshal without error")
	require.Equal(t, daeCert.BlockHeight, roundTripped.BlockHeight,
		"embedded cert blockHeight must match original")
	require.Equal(t, daeCert.DataRoot, roundTripped.DataRoot,
		"embedded cert dataRoot must match original")

	// 4. Version byte must be 0x01.
	require.EqualValues(t, 0x01, p.version, "proof version byte must be 0x01")

	// 5. preimageSize must be non-zero.
	require.NotZero(t, p.preimageSize, "preimageSize must be non-zero")

	// 6. Preimage must match preimageSize.
	require.Len(t, p.preimage, int(p.preimageSize),
		"preimage section length must equal preimageSize")

	// 7. Blobstream proof section must be non-empty (ABI-encoded proof data).
	require.NotEmpty(t, p.blobstreamProof,
		"blobstream proof data section must be non-empty")

	// 8. First 32 bytes of preimage must equal the first chunk returned at offset 0.
	//    Re-call with offset=0 via the legacy celestia_getProof route is not
	//    needed here; instead verify that the preimage is consistent with the
	//    blob we can read back directly.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	readResult, err := celestiaDA.Read(ctx, daeCert)
	require.NoError(t, err)
	require.NotEmpty(t, readResult.Message)
	require.Equal(t, readResult.Message, p.preimage,
		"preimage in proof must equal the blob payload returned by Read")
}

// ---------------------------------------------------------------------------
// TestGenerateReadPreimageProof_MultipleOffsets
//
// Calls GenerateReadPreimageProof at several 32-byte-aligned offsets and
// verifies that:
//   - Each returned proof has the correct structure
//   - The certificate is the same across all offsets (it's embedded per-call)
//   - The preimage is identical across all offsets (the full payload is always
//     embedded; the offset only affects what the Solidity contract returns)
//
// ---------------------------------------------------------------------------
func TestGenerateReadPreimageProof_MultipleOffsets(t *testing.T) {
	celestiaDA, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	if celestiaDA.Cfg.ValidatorConfig.EthClient == "" ||
		celestiaDA.Cfg.ValidatorConfig.BlobstreamAddr == "" {
		t.Skip("ETH_RPC and BLOBSTREAM_ADDR must be set for multi-offset proof tests")
	}

	daeCert := certFromEnv(t, celestiaDA)
	if daeCert == nil {
		t.Skip("HEIGHT, COMMITMENT, BLOB_DATA not set")
	}

	certBytes, err := daeCert.MarshalBinary()
	require.NoError(t, err)

	// Read the actual payload so we know how many 32-byte chunks there are.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	readResult, err := celestiaDA.Read(ctx, daeCert)
	require.NoError(t, err)
	require.NotEmpty(t, readResult.Message)

	payloadLen := uint64(len(readResult.Message))
	offsets := []uint64{0}
	if payloadLen > 32 {
		offsets = append(offsets, 32)
	}
	if payloadLen > 64 {
		offsets = append(offsets, 64)
	}
	// Last valid 32-byte-aligned offset
	lastOffset := (payloadLen - 1) &^ 31
	if lastOffset != 0 && lastOffset != 32 && lastOffset != 64 {
		offsets = append(offsets, lastOffset)
	}

	var firstProof []byte

	for _, offset := range offsets {
		t.Run("offset="+strconv.FormatUint(offset, 10), func(t *testing.T) {
			var result server_api.GenerateReadPreimageProofResult
			err := client.Call(&result, "daprovider_generateReadPreimageProof",
				hexutil.Uint64(offset), hexutil.Bytes(certBytes))
			require.NoError(t, err)
			require.NotEmpty(t, result.Proof)

			p := parseReadPreimageProof(t, result.Proof)

			require.EqualValues(t, cert.CelestiaDACertV1Len, p.certSize)
			require.Len(t, p.certificate, cert.CelestiaDACertV1Len)
			require.EqualValues(t, 0x01, p.version)
			require.EqualValues(t, payloadLen, p.preimageSize,
				"all offsets must embed the same full preimage")
			require.Equal(t, readResult.Message, p.preimage,
				"preimage must equal the full payload regardless of offset")
			require.NotEmpty(t, p.blobstreamProof)

			if offset == 0 {
				firstProof = result.Proof
			} else {
				// The proofs at different offsets should be identical because
				// the proof format encodes the FULL preimage and does not vary
				// by offset (offset is a parameter to the Solidity verifier).
				require.Equal(t, firstProof, result.Proof,
					"proof bytes must be identical across different offsets (offset is a verifier param, not encoded)")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestGenerateReadPreimageProof_OutOfBoundsOffset
//
// Verifies that an out-of-bounds offset returns an RPC error (not a panic).
// ---------------------------------------------------------------------------
func TestGenerateReadPreimageProof_OutOfBoundsOffset(t *testing.T) {
	celestiaDA, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	if celestiaDA.Cfg.ValidatorConfig.EthClient == "" ||
		celestiaDA.Cfg.ValidatorConfig.BlobstreamAddr == "" {
		t.Skip("ETH_RPC and BLOBSTREAM_ADDR must be set")
	}

	daeCert := certFromEnv(t, celestiaDA)
	if daeCert == nil {
		t.Skip("HEIGHT, COMMITMENT, BLOB_DATA not set")
	}

	certBytes, err := daeCert.MarshalBinary()
	require.NoError(t, err)

	// Use an impossibly large offset.
	var result server_api.GenerateReadPreimageProofResult
	err = client.Call(&result, "daprovider_generateReadPreimageProof",
		hexutil.Uint64(1<<40), hexutil.Bytes(certBytes))
	require.Error(t, err, "out-of-bounds offset must return an RPC error")
}

// ---------------------------------------------------------------------------
// TestGenerateReadPreimageProof_MismatchedOffsetAlignment
//
// Verifies that a non-32-byte-aligned offset returns an RPC error.
// ---------------------------------------------------------------------------
func TestGenerateReadPreimageProof_MismatchedOffsetAlignment(t *testing.T) {
	_, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	// We only need a parseable cert, not a live one.
	fakeCert := cert.NewCelestiaCertificate(
		1000,
		0,
		16,
		[32]byte{1},
		[32]byte{2},
	)
	certBytes, err := fakeCert.MarshalBinary()
	require.NoError(t, err)

	var result server_api.GenerateReadPreimageProofResult
	err = client.Call(&result, "daprovider_generateReadPreimageProof",
		hexutil.Uint64(7), // not 32-byte aligned
		hexutil.Bytes(certBytes),
	)
	require.Error(t, err, "non-aligned offset must return an RPC error")
}

// ---------------------------------------------------------------------------
// TestValidatorProofLayout_ByteAudit
//
// A pure unit-level structural test (no live node required) that verifies the
// byte layout constants are internally consistent:
//
//	cert.CelestiaDACertV1Len is stable
//	MarshalBinary produces exactly cert.CelestiaDACertV1Len bytes
//	parseReadPreimageProof correctly extracts every section from a
//	hand-constructed byte slice
//
// This test runs without any environment variables.
// ---------------------------------------------------------------------------
func TestValidatorProofLayout_ByteAudit(t *testing.T) {
	// ------------------------------------------------------------------
	// 1. Verify cert constants.
	// ------------------------------------------------------------------
	require.Equal(t, 92, cert.CelestiaDACertV1Len, "CelestiaDACertV1Len must be 92")

	fakeCert := cert.NewCelestiaCertificate(
		42, // blockHeight
		3,  // start
		8,  // sharesLength
		[32]byte{0xAB},
		[32]byte{0xCD},
	)
	certBytes, err := fakeCert.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, certBytes, cert.CelestiaDACertV1Len, "MarshalBinary length mismatch")

	// Spot-check the header bytes.
	require.Equal(t, cert.CustomDAHeaderFlag, certBytes[0])
	require.Equal(t, cert.CelestiaMessageHeaderFlag, certBytes[1])

	// ------------------------------------------------------------------
	// 2. Hand-build a read-preimage proof and verify parseReadPreimageProof.
	// ------------------------------------------------------------------
	preimage := []byte("the quick brown fox jumps over the lazy dog --- some extra padding --")
	fakeProofData := []byte("ABI-ENCODED-BLOBSTREAM-PROOF-PLACEHOLDER")

	// Build: [certSize(8)][certificate][version(1)][preimageSize(8)][preimage][proofData]
	hand := make([]byte, 8+len(certBytes)+1+8+len(preimage)+len(fakeProofData))
	pos := 0
	binary.BigEndian.PutUint64(hand[pos:], uint64(len(certBytes)))
	pos += 8
	copy(hand[pos:], certBytes)
	pos += len(certBytes)
	hand[pos] = 0x01
	pos++
	binary.BigEndian.PutUint64(hand[pos:], uint64(len(preimage)))
	pos += 8
	copy(hand[pos:], preimage)
	pos += len(preimage)
	copy(hand[pos:], fakeProofData)

	p := parseReadPreimageProof(t, hand)

	require.EqualValues(t, cert.CelestiaDACertV1Len, p.certSize)
	require.Equal(t, certBytes, p.certificate)
	require.EqualValues(t, 0x01, p.version)
	require.EqualValues(t, uint64(len(preimage)), p.preimageSize)
	require.Equal(t, preimage, p.preimage)
	require.Equal(t, fakeProofData, p.blobstreamProof)

	// ------------------------------------------------------------------
	// 3. Hand-build a validity proof and verify parseValidityProof.
	// ------------------------------------------------------------------
	validHand := make([]byte, 8+cert.CelestiaDACertV1Len+1)
	binary.BigEndian.PutUint64(validHand[:8], uint64(len(certBytes)))
	copy(validHand[8:], certBytes)
	validHand[8+cert.CelestiaDACertV1Len] = 0x01

	vp := parseValidityProof(t, validHand)
	require.EqualValues(t, cert.CelestiaDACertV1Len, vp.certSize)
	require.Equal(t, certBytes, vp.certificate)
	require.EqualValues(t, 0x01, vp.claimedValid)

	// And for the invalid case.
	invalidHand := make([]byte, 8+cert.CelestiaDACertV1Len+1)
	binary.BigEndian.PutUint64(invalidHand[:8], uint64(len(certBytes)))
	copy(invalidHand[8:], certBytes)
	invalidHand[8+cert.CelestiaDACertV1Len] = 0x00

	ivp := parseValidityProof(t, invalidHand)
	require.EqualValues(t, 0x00, ivp.claimedValid)

	// ------------------------------------------------------------------
	// 4. Verify that Go-side encoding matches what the Solidity contract
	//    expects for the cert bytes embedded in both proof types:
	//      cert[0] == 0x01 (CustomDAHeaderFlag)
	//      cert[1] == 0x63 (CelestiaMessageHeaderFlag)
	//      cert[2..3] == 0x0001 (version = 1, big-endian)
	//      cert.length == 92
	// ------------------------------------------------------------------
	require.Equal(t, byte(0x01), p.certificate[0], "cert[0] must be 0x01")
	require.Equal(t, byte(0x63), p.certificate[1], "cert[1] must be 0x63")
	require.Equal(t, byte(0x00), p.certificate[2], "cert[2] must be 0x00 (version high)")
	require.Equal(t, byte(0x01), p.certificate[3], "cert[3] must be 0x01 (version low)")
	require.EqualValues(t, 42, binary.BigEndian.Uint64(p.certificate[4:12]),
		"blockHeight must round-trip through MarshalBinary")
}

// ---------------------------------------------------------------------------
// TestGenerateCertificateValidityProof_RoundTripViaRPC
//
// Stores a blob via the celestia_store RPC, then calls
// daprovider_generateCertificateValidityProof on the returned cert and
// verifies the proof structure.
//
// Required: NAMESPACE (+ live node); does NOT need ETH_RPC or BLOBSTREAM_ADDR.
// ---------------------------------------------------------------------------
func TestGenerateCertificateValidityProof_RoundTripViaRPC(t *testing.T) {
	_, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	// Store a small payload.
	payload := []byte("validator-round-trip-test-" + time.Now().String())
	var storedCertBytes hexutil.Bytes
	err := client.Call(&storedCertBytes, "celestia_store", hexutil.Bytes(payload))
	require.NoError(t, err)
	require.Len(t, []byte(storedCertBytes), cert.CelestiaDACertV1Len,
		"stored cert must be exactly 92 bytes")

	// Verify the cert round-trips.
	parsedCert := &cert.CelestiaDACertV1{}
	require.NoError(t, parsedCert.UnmarshalBinary(storedCertBytes))

	// Generate the validity proof for the freshly stored cert.
	var result server_api.GenerateCertificateValidityProofResult
	err = client.Call(&result, "daprovider_generateCertificateValidityProof",
		hexutil.Bytes(storedCertBytes))
	require.NoError(t, err)
	require.NotEmpty(t, result.Proof)

	vp := parseValidityProof(t, result.Proof)

	require.EqualValues(t, cert.CelestiaDACertV1Len, vp.certSize)
	require.Len(t, vp.certificate, cert.CelestiaDACertV1Len)

	// The cert embedded in the proof must equal the one returned by Store.
	require.Equal(t, []byte(storedCertBytes), vp.certificate,
		"certificate embedded in validity proof must match the stored cert")

	// For a freshly stored blob the node must see it as valid.
	require.EqualValues(t, 0x01, vp.claimedValid,
		"freshly stored blob must have claimedValid=0x01")

	// Also ensure the embedded cert parses correctly.
	embeddedCert := &cert.CelestiaDACertV1{}
	require.NoError(t, embeddedCert.UnmarshalBinary(vp.certificate))
	require.Equal(t, parsedCert.BlockHeight, embeddedCert.BlockHeight)
	require.Equal(t, parsedCert.DataRoot, embeddedCert.DataRoot)
}

// ---------------------------------------------------------------------------
// TestGenerateReadPreimageProof_RoundTripViaRPC
//
// Stores a blob, then generates a read-preimage proof at offset=0 and verifies
// the full structure including that the embedded preimage matches the stored
// payload.
//
// Required: NAMESPACE (+ live node) + ETH_RPC + BLOBSTREAM_ADDR
// ---------------------------------------------------------------------------
func TestGenerateReadPreimageProof_RoundTripViaRPC(t *testing.T) {
	celestiaDA, client, cleanup := setupValidatorTest(t)
	defer cleanup()

	if celestiaDA.Cfg.ValidatorConfig.EthClient == "" ||
		celestiaDA.Cfg.ValidatorConfig.BlobstreamAddr == "" {
		t.Skip("ETH_RPC and BLOBSTREAM_ADDR must be set for read-preimage round-trip test")
	}

	// Store a small payload.
	payload := []byte("read-preimage-round-trip-" + time.Now().String())
	var storedCertBytes hexutil.Bytes
	err := client.Call(&storedCertBytes, "celestia_store", hexutil.Bytes(payload))
	require.NoError(t, err)
	require.Len(t, []byte(storedCertBytes), cert.CelestiaDACertV1Len)

	// Read the payload back via Read so we can compare with the proof preimage.
	parsedCert := &cert.CelestiaDACertV1{}
	require.NoError(t, parsedCert.UnmarshalBinary(storedCertBytes))

	var readResult types.ReadResult
	err = client.Call(&readResult, "celestia_read", parsedCert)
	require.NoError(t, err)
	require.NotEmpty(t, readResult.Message)

	// Generate the read-preimage proof.
	var result server_api.GenerateReadPreimageProofResult
	err = client.Call(&result, "daprovider_generateReadPreimageProof",
		hexutil.Uint64(0),
		hexutil.Bytes(storedCertBytes),
	)
	require.NoError(t, err)
	require.NotEmpty(t, result.Proof)

	p := parseReadPreimageProof(t, result.Proof)

	// ------------------------------------------------------------------
	// Structure checks
	// ------------------------------------------------------------------
	require.EqualValues(t, cert.CelestiaDACertV1Len, p.certSize)
	require.Len(t, p.certificate, cert.CelestiaDACertV1Len)
	require.Equal(t, []byte(storedCertBytes), p.certificate,
		"certificate embedded in read-preimage proof must match the stored cert")
	require.EqualValues(t, 0x01, p.version)
	require.EqualValues(t, uint64(len(readResult.Message)), p.preimageSize,
		"preimageSize must equal the full payload length")
	require.Equal(t, readResult.Message, p.preimage,
		"embedded preimage must equal the payload returned by Read")
	require.NotEmpty(t, p.blobstreamProof,
		"blobstream proof section must be present")

	// ------------------------------------------------------------------
	// Content check: the first 32 bytes of the preimage must equal the
	// first 32 bytes of the original payload (or the full payload if
	// shorter than 32 bytes).
	// ------------------------------------------------------------------
	chunkLen := 32
	if len(readResult.Message) < 32 {
		chunkLen = len(readResult.Message)
	}
	require.Equal(t, readResult.Message[:chunkLen], p.preimage[:chunkLen],
		"first chunk of embedded preimage must match payload")

	t.Logf("proof OK: certSize=%d preimageSize=%d blobstreamProofLen=%d",
		p.certSize, p.preimageSize, len(p.blobstreamProof))
}
