package das

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/celestiagen"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/joho/godotenv"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/stretchr/testify/require"
)

func init() {
	godotenv.Load()
}

// The following test assumes that you have a running celestia light node

func setupNetworkTest(t *testing.T) (*CelestiaDA, string, func(), context.Context) {
	// Get auth token from CLI
	// pass "celestia" for mainnet and "mocha" for mocha and so on
	authToken := getAuthToken(t, "celestia")
	require.NotEmpty(t, authToken, "Auth token should not be empty")

	// Generate namespace ID
	namespaceID := os.Getenv("NAMESPACE")
	if namespaceID == "" {
		t.Skip("NAMESPACE not set")
	}

	// Create CelestiaDA instance connected to local node
	cfg := &DAConfig{
		Rpc:              "http://localhost:26658", // Default Celestia light node RPC port
		ReadRpc:          "http://localhost:26658",
		NamespaceId:      namespaceID,
		AuthToken:        authToken,
		CacheCleanupTime: time.Minute,
		ValidatorConfig: ValidatorConfig{
			EthClient:      os.Getenv("ETH_RPC"),
			BlobstreamAddr: os.Getenv("BLOBSTREAM_ADDR"),
		},
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
		nil,
		false,
	)
	require.NoError(t, err)

	endpoint := "http://" + listener.Addr().String()

	cleanup := func() {
		cancel()
		server.Close()
		celestiaDA.Stop()
	}

	return celestiaDA, endpoint, cleanup, ctx
}

func TestGetProofVerification(t *testing.T) {
	if os.Getenv("NAMESPACE") == "" || os.Getenv("ETH_RPC") == "" || os.Getenv("BLOBSTREAM_ADDR") == "" {
		t.Skip("NAMESPACE, ETH_RPC, and BLOBSTREAM_ADDR must be set")
	}
	celestiaDA, endpoint, cleanup, ctx := setupNetworkTest(t)
	defer cleanup()

	// Create RPC client
	client, err := rpc.Dial(endpoint)
	require.NoError(t, err)
	defer client.Close()

	message, err := base64.StdEncoding.DecodeString(os.Getenv("BLOB_DATA"))
	require.NoError(t, err)

	nsBytes, err := hex.DecodeString(celestiaDA.Cfg.NamespaceId)
	require.NoError(t, err)

	namespace, err := libshare.NewV0Namespace(nsBytes)
	require.NoError(t, err)

	height, err := strconv.ParseUint(os.Getenv("HEIGHT"), 10, 64)
	require.NoError(t, err)

	commitment, err := base64.StdEncoding.DecodeString(os.Getenv("COMMITMENT"))
	require.NoError(t, err)

	header, _ := celestiaDA.Client.Header.GetByHeight(ctx, height)

	dataBlob, err := celestiaDA.Client.Blob.Get(ctx, height, namespace, commitment)
	require.NoError(t, err)

	txCommitment, dataRoot := [32]byte{}, [32]byte{}
	copy(txCommitment[:], dataBlob.Commitment)

	copy(dataRoot[:], header.DataHash)

	// Row roots give us the length of the EDS
	squareSize := uint64(len(header.DAH.RowRoots))
	// ODS size
	odsSize := squareSize / 2

	blobIndex := uint64(dataBlob.Index())
	// startRow
	startRow := blobIndex / squareSize

	sharesLength, err := dataBlob.Length()
	if err != nil || sharesLength == 0 {
		celestiaFailureCounter.Inc(1)
		log.Warn("could not get shares length for blob", "err", err)
		if err == nil {
			err = fmt.Errorf("blob found, but has shares length zero")
		}
		require.NoError(t, err)
	}

	startIndexOds := blobIndex - odsSize*startRow

	blobPointer := types.BlobPointer{
		BlockHeight:  height,
		Start:        uint64(startIndexOds),
		SharesLength: uint64(sharesLength),
		DataRoot:     dataRoot,
	}

	t.Run("Read Message BlobPointer", func(t *testing.T) {
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

	t.Run("Get Proof e2e", func(t *testing.T) {

		blobBytes, err := blobPointer.MarshalBinary()
		require.NoError(t, err)
		// Read through RPC
		var proofResult []byte
		err = client.Call(&proofResult, "celestia_getProof", &blobBytes)
		require.NoError(t, err)
		require.NotNil(t, proofResult)

		// Get the ABI for "verifyProof"

		celestiaVerifierAbi, err := celestiagen.CelestiaBatchVerifierMetaData.GetAbi()
		require.NoError(t, err)

		verifyProofABI := celestiaVerifierAbi.Methods["verifyProof"]

		// First unpack into interface slice
		values, err := verifyProofABI.Inputs.Unpack(proofResult)
		require.NoError(t, err)

		// Define types to match the ABI exactly
		type NamespaceInfo struct {
			Version [1]byte  `abi:"Version"`
			Id      [28]byte `abi:"Id"`
		}

		type RowRoot struct {
			Min    NamespaceInfo `abi:"Min"`
			Max    NamespaceInfo `abi:"Max"`
			Digest [32]byte      `abi:"Digest"`
		}

		type RowProof struct {
			SideNodes [][32]byte `abi:"SideNodes"`
			Key       *big.Int   `abi:"Key"`
			NumLeaves *big.Int   `abi:"NumLeaves"`
		}

		type DataRootTuple struct {
			Height   *big.Int `abi:"Height"`
			DataRoot [32]byte `abi:"DataRoot"`
		}

		type AttestationProof struct {
			TupleRootNonce *big.Int      `abi:"TupleRootNonce"`
			Tuple          DataRootTuple `abi:"Tuple"`
			Proof          RowProof      `abi:"Proof"`
		}

		type Args struct {
			Blobstream       common.Address   `abi:"_blobstream"`
			RowRoot          RowRoot          `abi:"_rowRoot"`
			RowProof         RowProof         `abi:"_rowProof"`
			AttestationProof AttestationProof `abi:"_attestationProof"`
		}

		var args Args

		// Copy the unpacked values into our struct
		err = verifyProofABI.Inputs.Copy(&args, values)
		require.NoError(t, err)

		ethRpc, err := ethclient.Dial(celestiaDA.Cfg.ValidatorConfig.EthClient)
		require.NoError(t, err)

		packedData, _ := verifyProofABI.Inputs.Pack(
			args.Blobstream,
			celestiagen.NamespaceNode{
				Min:    celestiagen.Namespace(args.RowRoot.Min),
				Max:    celestiagen.Namespace(args.RowRoot.Max),
				Digest: args.RowRoot.Digest,
			},
			celestiagen.BinaryMerkleProof{
				SideNodes: args.RowProof.SideNodes,
				Key:       args.RowProof.Key,
				NumLeaves: args.RowProof.NumLeaves,
			},
			celestiagen.AttestationProof{
				TupleRootNonce: args.AttestationProof.TupleRootNonce,
				Tuple:          celestiagen.DataRootTuple(args.AttestationProof.Tuple),
				Proof: celestiagen.BinaryMerkleProof{
					SideNodes: args.AttestationProof.Proof.SideNodes,
					Key:       args.AttestationProof.Proof.Key,
					NumLeaves: args.AttestationProof.Proof.NumLeaves,
				},
			},
		)

		// Convert into calldata
		methodID := verifyProofABI.ID
		callData := append(methodID[:], packedData...)
		// Printing out calldata in case user wants to use `cast` to see a trace
		// Sadly such features are not available in Go to the developers knowldege :(
		t.Logf("Calldata for \"verifyProof\" on : %v", hex.EncodeToString(callData))

		verifierAbi, err := celestiagen.CelestiaBatchVerifierMetaData.GetAbi()
		require.NoError(t, err)

		// NOTE: We are using the celestiagen.CelestiaBatchVerifierMetaData ABI
		// bute here we are calling a wrapper contract that uses the library
		// trying to call a library purely wont work, wrapper contract and deployment scripts are on test folder
		verifierWrapperAddress := common.HexToAddress(os.Getenv("VERIFIER_WRAPPER"))

		// Create call message
		msg := ethereum.CallMsg{
			To:   &verifierWrapperAddress,
			Data: callData,
		}

		// Execute eth_call
		result, err := ethRpc.CallContract(context.Background(), msg, nil)
		require.NoError(t, err)

		// Decode result
		results, err := verifierAbi.Methods["verifyProof"].Outputs.Unpack(result)
		require.NoError(t, err)

		fmt.Printf("Results: %+v\n", results)
	})
}
