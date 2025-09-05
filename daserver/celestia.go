package das

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	txclient "github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/blob"
	"github.com/celestiaorg/celestia-node/nodebuilder/p2p"
	"github.com/celestiaorg/celestia-node/state"
	libshare "github.com/celestiaorg/go-square/v2/share"
	"github.com/celestiaorg/nitro-das-celestia/celestiagen"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/spf13/pflag"

	blobstreamx "github.com/succinctlabs/sp1-blobstream/bindings"
)

type DAConfig struct {
	WithWriter         bool            `koanf:"with-writer"`
	GasPrice           float64         `koanf:"gas-price" reload:"hot"`
	GasMultiplier      float64         `koanf:"gas-multiplier" reload:"hot"`
	Rpc                string          `koanf:"rpc" reload:"hot"`
	ReadRpc            string          `koanf:"read-rpc" reload:"hot"`
	NamespaceId        string          `koanf:"namespace-id" `
	AuthToken          string          `koanf:"auth-token" reload:"hot"`
	ReadAuthToken      string          `koanf:"read-auth-token" reload:"hot"`
	CoreToken          string          `koanf:"core-token" reload:"hot"`
	CoreURL            string          `koanf:"core-url" reload:"hot"`
	CoreNetwork        string          `koanf:"core-network" reload:"hot"`
	KeyName            string          `koanf:"key-name" reload:"hot"`
	KeyPath            string          `koanf:"key-path" reload:"hot"`
	BackendName        string          `koanf:"backend-name" reload:"hot"`
	NoopWriter         bool            `koanf:"noop-writer" reload:"hot"`
	EnableDATLS        bool            `koanf:"enable-da-tls" reload:"hot"`
	EnableCoreTLS      bool            `koanf:"enable-core-tls" reload:"hot"`
	ValidatorConfig    ValidatorConfig `koanf:"validator-config" reload:"hot"`
	ReorgOnReadFailure bool            `koanf:"dangerous-reorg-on-read-failure"`
	CacheCleanupTime   time.Duration   `koanf:"cache-time"`
}

type ValidatorConfig struct {
	EthClient      string `koanf:"eth-rpc" reload:"hot"`
	BlobstreamAddr string `koanf:"blobstream" reload:"hot"`
	SleepTime      int    `koanf:"sleep-time" reload:"hot"`
}

var (
	celestiaDALastSuccesfulActionGauge = metrics.NewRegisteredGauge("celestia/action/last_success", nil)
	celestiaLastNonDefaultGasprice     = metrics.NewRegisteredGaugeFloat64("celestia/last_gas_price", nil)
	celestiaSuccessCounter             = metrics.NewRegisteredCounter("celestia/action/celestia_success", nil)
	celestiaFailureCounter             = metrics.NewRegisteredCounter("celestia/action/celestia_failure", nil)
	celestiaGasRetries                 = metrics.NewRegisteredCounter("celestia/action/gas_retries", nil)

	celestiaValidationLastSuccesfulActionGauge = metrics.NewRegisteredGauge("celestia/validation/last_success", nil)
	celestiaValidationSuccessCounter           = metrics.NewRegisteredCounter("celestia/validation/blobstream_success", nil)
	celestiaValidationFailureCounter           = metrics.NewRegisteredCounter("celestia/validation/blobstream_failure", nil)
)

var (
	// ErrTxTimedout is the error message returned by the DA when mempool is congested
	ErrTxTimedout = errors.New("timed out waiting for tx to be included in a block")

	// ErrTxAlreadyInMempool is  the error message returned by the DA when tx is already in mempool
	ErrTxAlreadyInMempool = errors.New("tx already in mempool")

	// ErrTxIncorrectAccountSequence is the error message returned by the DA when tx has incorrect sequence
	ErrTxIncorrectAccountSequence = errors.New("incorrect account sequence")
)

// CelestiaMessageHeaderFlag indicates that this data is a Blob Pointer
// which will be used to retrieve data from Celestia
const CelestiaMessageHeaderFlag byte = 0x63

func hasBits(checking byte, bits byte) bool {
	return (checking & bits) == bits
}

func IsCelestiaMessageHeaderByte(header byte) bool {
	return hasBits(header, CelestiaMessageHeaderFlag)
}

type CelestiaDA struct {
	Cfg        *DAConfig
	Client     *txclient.Client
	ReadClient *txclient.ReadClient

	Namespace *libshare.Namespace

	messageCache sync.Map
}

func CelestiaDAConfigAddOptions(prefix string, f *pflag.FlagSet) {
	f.Bool(prefix+".with-writer", false, "Enable using the DA Server for writing data to Celestia")
	f.Float64(prefix+".gas-price", 0.01, "Gas for retrying Celestia transactions")
	f.Float64(prefix+".gas-multiplier", 1.01, "Gas multiplier for Celestia transactions")
	f.String(prefix+".rpc", "", "Rpc endpoint for celestia-node")
	f.String(prefix+".read-rpc", "", "separate celestia RPC endpoint for reads")
	f.String(prefix+".namespace-id", "", "Celestia Namespace to post data to")
	f.String(prefix+".auth-token", "", "Auth token for Celestia Node")
	f.String(prefix+".read-auth-token", "", "Auth token for Celestia Node")
	f.String(prefix+".core-token", "", "Auth token for Core Celestia Node Endpoint")
	f.String(prefix+".core-url", "", "URL to Celestia Core endpoint")
	f.String(prefix+".core-network", "celestia", "Celestia Network to use")
	f.String(prefix+".key-name", "my_celes_key", "key name to use")
	f.String(prefix+".key-path", "", "key path to use")
	f.String(prefix+".backend-name", "test", "keyring backend to use")
	f.Bool(prefix+".enable-da-tls", false, "enable TLS for DA node")
	f.Bool(prefix+".enable-core-tls", false, "enable TLS for Core node")
	f.Bool(prefix+".noop-writer", false, "Noop writer (disable posting to celestia)")
	f.String(prefix+".validator-config"+".eth-rpc", "", "Parent chain connection, only used for validation")
	f.String(prefix+".validator-config"+".blobstream", "", "Blobstream address, only used for validation")
	f.Int(prefix+".validator-config"+".sleep-time", 3600, "How many seconds to wait before initiating another filtering loop for Blobstream events")
	f.Bool(prefix+".dangerous-reorg-on-read-failure", false, "DANGEROUS: reorg if any error during reads from celestia node")
	f.Duration(prefix+".cache-time", time.Hour/2, "how often to clean the in memory cache")
}

// DefaultKeyringPath constructs the default keyring path using the given
// node type and network.
var DefaultKeyringPath = func(tp string, network string) (string, error) {
	home := os.Getenv("CELESTIA_HOME")
	if home != "" {
		return home, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if network == "mainnet" {
		return fmt.Sprintf("%s/.celestia-%s/keys", home, strings.ToLower(tp)), nil
	}
	// only include network name in path for testnets and custom networks
	return fmt.Sprintf(
		"%s/.celestia-%s-%s/keys",
		home,
		strings.ToLower(tp),
		strings.ToLower(network),
	), nil
}

func NewCelestiaDA(cfg *DAConfig) (*CelestiaDA, error) {
	if cfg == nil {
		return nil, errors.New("celestia cfg cannot be blank")
	}

	var readClient *txclient.ReadClient
	var writeClient *txclient.Client
	if cfg.WithWriter {
		var err error
		if cfg.KeyPath == "" {
			cfg.KeyPath, err = DefaultKeyringPath("light", cfg.CoreNetwork)
		}

		log.Info("Key path", "path", cfg.KeyPath)
		// Create a keyring
		kr, err := txclient.KeyringWithNewKey(txclient.KeyringConfig{
			KeyName:     cfg.KeyName,
			BackendName: cfg.BackendName,
		}, cfg.KeyPath)
		if err != nil {
			log.Error("failed to create keyring")
			return nil, err
		}

		if cfg.CoreURL == "" {
			cfg.CoreURL = cfg.Rpc
		}

		log.Info("Core URL: ", "url", cfg.CoreURL)

		// Configure the client
		clientCfg := txclient.Config{
			ReadConfig: txclient.ReadConfig{
				BridgeDAAddr: cfg.Rpc,
				DAAuthToken:  cfg.AuthToken,
				EnableDATLS:  cfg.EnableDATLS,
			},
			SubmitConfig: txclient.SubmitConfig{
				DefaultKeyName: cfg.KeyName,
				Network:        p2p.Network(cfg.CoreNetwork),
				CoreGRPCConfig: txclient.CoreGRPCConfig{
					Addr:       cfg.CoreURL,
					TLSEnabled: cfg.EnableCoreTLS,
					AuthToken:  cfg.CoreToken,
				},
			},
		}

		writeClient, err = txclient.New(context.Background(), clientCfg, kr)
		if err != nil {
			log.Error("failed to initialize client", "err", err)
			return nil, err
		}

		var readConfig txclient.ReadConfig
		if cfg.ReadRpc != "" && cfg.ReadAuthToken != "" {
			readConfig = txclient.ReadConfig{
				BridgeDAAddr: cfg.ReadRpc,
				DAAuthToken:  cfg.ReadAuthToken,
				EnableDATLS:  cfg.EnableDATLS,
			}
		} else {
			readConfig = txclient.ReadConfig{
				BridgeDAAddr: cfg.Rpc,
				DAAuthToken:  cfg.AuthToken,
				EnableDATLS:  cfg.EnableDATLS,
			}
		}

		readClient, err = txclient.NewReadClient(context.Background(), readConfig)
		if err != nil {
			log.Error("error initializing read client", "err", err)
			return nil, err
		}

		log.Info("Succesfully initialized write and read client", "writeRpc", cfg.CoreURL, "readRpc", readConfig.BridgeDAAddr)
	} else {
		readClientCfg := txclient.ReadConfig{
			BridgeDAAddr: cfg.ReadRpc,
			DAAuthToken:  cfg.ReadAuthToken,
			EnableDATLS:  cfg.EnableDATLS,
		}

		var err error
		readClient, err = txclient.NewReadClient(context.Background(), readClientCfg)
		if err != nil {
		}
		log.Info("Succesfully initialized read only client", "rpc", cfg.ReadRpc)
	}

	if cfg.NamespaceId == "" {
		return nil, errors.New("namespace id cannot be blank")
	}
	nsBytes, err := hex.DecodeString(cfg.NamespaceId)
	if err != nil {
		return nil, err
	}

	namespace, err := libshare.NewV0Namespace(nsBytes)
	if err != nil {
		return nil, err
	}

	da := &CelestiaDA{
		Cfg:        cfg,
		Client:     writeClient,
		ReadClient: readClient,
		Namespace:  &namespace,
	}

	da.StartCacheCleanup(cfg.CacheCleanupTime)

	return da, nil
}

func (c *CelestiaDA) Stop() error {
	c.Client.Close()
	return nil
}

func (c *CelestiaDA) StartCacheCleanup(cleanupInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			// Clear the entire cache periodically
			c.messageCache = sync.Map{}
		}
	}()
}

func (c *CelestiaDA) Store(ctx context.Context, message []byte) ([]byte, error) {
	if c.Cfg.NoopWriter {
		log.Warn("NoopWriter enabled, falling back", "c.Cfg.NoopWriter", c.Cfg.NoopWriter)
		celestiaFailureCounter.Inc(1)
		return nil, errors.New("NoopWriter enabled")
	}

	// Create hash of message to use as cache key
	msgHash := crypto.Keccak256(message)
	msgHashHex := hex.EncodeToString(msgHash)

	// Check cache first
	if pointer, ok := c.messageCache.Load(msgHashHex); ok {
		log.Info("Retrieved blob pointer from cache", "msgHash", msgHashHex)
		return pointer.([]byte), nil
	}

	// set a 5 minute timeout context on submissions
	// if it takes longer than that to succesfully submit and verify a blob,
	// then there's an issue with the connection to the celestia node
	ctx, cancel := context.WithTimeout(ctx, time.Duration(time.Minute*5))
	defer cancel()
	dataBlob, err := blob.NewBlobV0(*c.Namespace, message)
	if err != nil {
		celestiaFailureCounter.Inc(1)
		log.Warn("Error creating blob", "err", err)
		return nil, err
	}

	height := uint64(0)
	submitted := false
	// this will trigger node to use the default gas price from celestia app
	gasPrice := -1.0
	for !submitted {
		// add submit options
		submitOptions := &blob.SubmitOptions{}
		state.WithGasPrice(gasPrice)(submitOptions)
		height, err = c.Client.Blob.Submit(ctx, []*blob.Blob{dataBlob}, submitOptions)
		if err != nil {
			switch {
			case strings.Contains(err.Error(), ErrTxTimedout.Error()), strings.Contains(err.Error(), ErrTxAlreadyInMempool.Error()), strings.Contains(err.Error(), ErrTxIncorrectAccountSequence.Error()):
				log.Warn("Failed to submit blob, bumping gas price and retrying...", "err", err)
				if gasPrice == -1.0 {
					gasPrice = c.Cfg.GasPrice
				} else {
					gasPrice = gasPrice * c.Cfg.GasMultiplier
				}

				celestiaGasRetries.Inc(1)
				continue
			default:
				celestiaFailureCounter.Inc(1)
				log.Warn("Blob Submission error", "err", err)
				return nil, err
			}
		}

		if height == 0 {
			celestiaFailureCounter.Inc(1)
			log.Warn("Unexpected height from blob response", "height", height)
			return nil, errors.New("unexpected response code")
		}

		submitted = true

		celestiaLastNonDefaultGasprice.Update(gasPrice)
	}

	log.Info("Succesfully posted blob", "height", height, "commitment", hex.EncodeToString(dataBlob.Commitment))

	// we fetch the blob so that we can get the correct start index in the square
	dataBlob, err = c.ReadClient.Blob.Get(ctx, height, *c.Namespace, dataBlob.Commitment)
	if err != nil {
		log.Warn("could not fetch blob", "err", err)
		celestiaFailureCounter.Inc(1)
		return nil, err
	}

	if dataBlob.Index() <= 0 {
		celestiaFailureCounter.Inc(1)
		log.Warn("Unexpected index from blob response", "index", dataBlob.Index())
		return nil, errors.New("unexpected response code")
	}

	header, err := c.ReadClient.Header.GetByHeight(ctx, height)
	if err != nil {
		celestiaFailureCounter.Inc(1)
		log.Warn("Header retrieval error", "err", err)
		return nil, err
	}

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
	if odsSize*startRow > blobIndex {
		celestiaFailureCounter.Inc(1)
		// return an empty batch
		return nil, fmt.Errorf("storing Celestia information, odsSize*startRow=%v was larger than blobIndex=%v", odsSize*startRow, dataBlob.Index())
	}

	sharesLength, err := dataBlob.Length()
	if err != nil || sharesLength == 0 {
		celestiaFailureCounter.Inc(1)
		log.Warn("could not get shares length for blob", "err", err)
		if err == nil {
			err = fmt.Errorf("blob found, but has shares length zero")
		}
		return nil, err
	}

	startIndexOds := blobIndex - odsSize*startRow
	blobPointer := types.BlobPointer{
		BlockHeight:  height,
		Start:        startIndexOds,
		SharesLength: uint64(sharesLength),
		TxCommitment: txCommitment,
		DataRoot:     dataRoot,
	}
	log.Info("Posted blob to height and dataRoot", "height", blobPointer.BlockHeight, "dataRoot", hex.EncodeToString(blobPointer.DataRoot[:]))

	blobPointerData, err := blobPointer.MarshalBinary()
	if err != nil {
		celestiaFailureCounter.Inc(1)
		log.Warn("BlobPointer MashalBinary error", "err", err)
		return nil, err
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, CelestiaMessageHeaderFlag)
	if err != nil {
		celestiaFailureCounter.Inc(1)
		log.Warn("batch type byte serialization failed", "err", err)
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, blobPointerData)
	if err != nil {
		celestiaFailureCounter.Inc(1)
		log.Warn("blob pointer data serialization failed", "err", err)
		return nil, err
	}

	serializedBlobPointerData := buf.Bytes()

	c.messageCache.Store(msgHashHex, serializedBlobPointerData)

	celestiaSuccessCounter.Inc(1)
	celestiaDALastSuccesfulActionGauge.Update(time.Now().Unix())

	return serializedBlobPointerData, nil
}

func (c *CelestiaDA) Read(ctx context.Context, blobPointer *types.BlobPointer) (*types.ReadResult, error) {
	header, err := c.ReadClient.Header.GetByHeight(ctx, blobPointer.BlockHeight)
	if err != nil {
		log.Error("could not fetch header", "err", err)
		return nil, err
	}

	headerDataHash := [32]byte{}
	copy(headerDataHash[:], header.DataHash)
	if headerDataHash != blobPointer.DataRoot {
		return c.returnErrorHelper(fmt.Errorf("data Root mismatch, header.DataHash=%v, blobPointer.DataRoot=%v", header.DataHash, hex.EncodeToString(blobPointer.DataRoot[:])))
	}

	var blobData []byte
	var sharesLength int
BlobLoop:
	for {
		select {
		case <-ctx.Done():
			return c.returnErrorHelper(fmt.Errorf("context cancelled or deadline exceeded"))
		default:
			blob, err := c.ReadClient.Blob.Get(ctx, blobPointer.BlockHeight, *c.Namespace, blobPointer.TxCommitment[:])
			if err != nil {
				log.Warn("failed to read blob, retrying...", "err", err)
				continue
			}
			blob.Index()
			blob.Length()
			blobData = blob.Data()
			length, err := blob.Length()
			if err != nil || length == 0 {
				celestiaFailureCounter.Inc(1)
				log.Warn("could not get shares length for blob", "err", err)
				if err == nil {
					err = fmt.Errorf("blob found, but has shares length zero")
				}
				return nil, err
			}
			sharesLength = length
			break BlobLoop
		}
	}

	extendedSquare, err := c.ReadClient.Share.GetEDS(ctx, blobPointer.BlockHeight)
	if err != nil {
		return c.returnErrorHelper(fmt.Errorf("failed to get EDS, height=%v, err=%v", blobPointer.BlockHeight, err))
	}

	squareSize := uint64(len(header.DAH.RowRoots))
	odsSize := squareSize / 2

	startRow := blobPointer.Start / odsSize

	if blobPointer.Start >= odsSize*odsSize {
		return c.returnErrorHelper(fmt.Errorf("startIndexOds >= odsSize*odsSize, startIndexOds=%v, odsSize*odsSize=%v", blobPointer.Start, odsSize*odsSize))
	}

	if blobPointer.Start+blobPointer.SharesLength < 1 {
		return c.returnErrorHelper(fmt.Errorf("startIndexOds+blobPointer.SharesLength < 1, startIndexOds+blobPointer.SharesLength=%v", blobPointer.Start+blobPointer.SharesLength))
	}

	endIndexOds := blobPointer.Start + blobPointer.SharesLength - 1
	if endIndexOds >= odsSize*odsSize {
		return c.returnErrorHelper(fmt.Errorf("endIndexOds >= odsSize*odsSize, endIndexOds=%v, odsSize*odsSize=%v", endIndexOds, odsSize*odsSize))
	}

	endRow := endIndexOds / odsSize

	if endRow >= odsSize || startRow >= odsSize {
		return c.returnErrorHelper(fmt.Errorf("endRow >= odsSize || startRow >= odsSize, endRow=%v, startRow=%v, odsSize=%v", endRow, startRow, odsSize))
	}

	startColumn := blobPointer.Start % odsSize
	endColumn := endIndexOds % odsSize

	if startRow == endRow && startColumn > endColumn {
		return c.returnErrorHelper(fmt.Errorf("start and end row are the same and startColumn >= endColumn, startColumn=%v, endColumn+1=%v", startColumn, endColumn+1))
	}

	if uint64(sharesLength) != blobPointer.SharesLength || sharesLength == 0 {
		celestiaFailureCounter.Inc(1)
		return c.returnErrorHelper(fmt.Errorf("share length mismatch, sharesLength=%v, blobPointer.SharesLength=%v", sharesLength, blobPointer.SharesLength))
	}

	rows := [][][]byte{}
	for i := startRow; i <= endRow; i++ {
		rows = append(rows, extendedSquare.Row(uint(i)))
	}

	return &types.ReadResult{
		Message:     blobData,
		RowRoots:    header.DAH.RowRoots,
		ColumnRoots: header.DAH.ColumnRoots,
		Rows:        rows,
		SquareSize:  squareSize,
		StartRow:    startRow,
		EndRow:      endRow,
	}, nil

}

func (c *CelestiaDA) GetProof(ctx context.Context, msg []byte) ([]byte, error) {
	if c.Cfg.ValidatorConfig.EthClient == "" || c.Cfg.ValidatorConfig.BlobstreamAddr == "" {
		celestiaValidationFailureCounter.Inc(1)
		return nil, fmt.Errorf("no celestia prover config")
	}

	ethRpc, err := ethclient.Dial(c.Cfg.ValidatorConfig.EthClient)
	if err != nil {
		celestiaValidationFailureCounter.Inc(1)
		log.Error("Couldn't dial to eth rpc for Blobstream proof", "rpcAddr", c.Cfg.ValidatorConfig.EthClient, "err", err)
		return nil, err
	}

	blobstream, err := blobstreamx.NewBindings(common.HexToAddress(c.Cfg.ValidatorConfig.BlobstreamAddr), ethRpc)
	if err != nil {
		celestiaValidationFailureCounter.Inc(1)
		log.Error("Couldn't instantiate client for blobstream", "rpcAddr", c.Cfg.ValidatorConfig.EthClient, "blobstreamAddr", common.HexToAddress(c.Cfg.ValidatorConfig.BlobstreamAddr), "err", err)
		return nil, err
	}

	fmt.Printf("Inbox Message: %v\n", msg)
	buf := bytes.NewBuffer(msg)
	// msgLength := uint32(len(msg) + 1)
	blobPointer := types.BlobPointer{}
	blobBytes := buf.Bytes()
	err = blobPointer.UnmarshalBinary(blobBytes)
	if err != nil {
		celestiaValidationFailureCounter.Inc(1)
		log.Error("Couldn't unmarshal Celestia blob pointer", "err", err)
		return nil, err
	}

	// Get data root from a celestia node
	header, err := c.ReadClient.Header.GetByHeight(ctx, blobPointer.BlockHeight)
	if err != nil {
		celestiaValidationFailureCounter.Inc(1)
		log.Warn("Header retrieval error", "err", err)
		return nil, err
	}

	latestBlockNumber, err := ethRpc.BlockNumber(context.Background())
	if err != nil {
		log.Warn("could not fetch latest L1 block", "err", err)
		celestiaValidationFailureCounter.Inc(1)
		return nil, err
	}

	// check the latest celestia block on the Blobstream contract
	latestCelestiaBlock, err := blobstream.LatestBlock(&bind.CallOpts{
		Pending:     false,
		BlockNumber: big.NewInt(int64(latestBlockNumber)),
		Context:     ctx,
	})
	if err != nil {
		log.Warn("could not fetch latestBlock on BlobstreamX", "err", err)
		celestiaValidationFailureCounter.Inc(1)
		return nil, err
	}

	fmt.Printf("Blob Pointer Height: %v\n", blobPointer.BlockHeight)
	fmt.Printf("Latest Blobstream Height: %v\n", latestCelestiaBlock)

	var backwards bool
	if blobPointer.BlockHeight < latestCelestiaBlock {
		backwards = true
	} else {
		backwards = false
	}

	var event *blobstreamx.BindingsDataCommitmentStored

	event, err = c.filter(ctx, ethRpc, blobstream, latestBlockNumber, blobPointer.BlockHeight, backwards)
	if err != nil {
		log.Warn("event filtering error", "err", err)
		celestiaValidationFailureCounter.Inc(1)
		return nil, err
	}

	// get the block data root inclusion proof to the data root tuple root
	dataRootProof, err := c.ReadClient.Blobstream.GetDataRootTupleInclusionProof(ctx, blobPointer.BlockHeight, event.StartBlock, event.EndBlock)
	if err != nil {
		log.Warn("could not get data root proof", "err", err)
		celestiaValidationFailureCounter.Inc(1)
		return nil, err
	}

	sideNodes := make([][32]byte, len((*dataRootProof).Aunts))
	for i, aunt := range (*dataRootProof).Aunts {
		sideNodes[i] = *(*[32]byte)(aunt)
	}

	tuple := blobstreamx.DataRootTuple{
		Height:   big.NewInt(int64(blobPointer.BlockHeight)),
		DataRoot: [32]byte(header.DataHash),
	}

	proof := blobstreamx.BinaryMerkleProof{
		SideNodes: sideNodes,
		Key:       big.NewInt((*dataRootProof).Index),
		NumLeaves: big.NewInt((*dataRootProof).Total),
	}

	valid, err := blobstream.VerifyAttestation(
		&bind.CallOpts{},
		event.ProofNonce,
		tuple,
		proof,
	)
	if err != nil {
		log.Warn("could not verify attestation", "err", err)
		celestiaValidationFailureCounter.Inc(1)
		return nil, err
	}

	log.Info("Verified Celestia Attestation", "height", blobPointer.BlockHeight, "valid", valid)

	if valid {
		rangeResult, err := c.Client.Share.GetRange(ctx, blobPointer.BlockHeight, int(blobPointer.Start), int(blobPointer.Start+blobPointer.SharesLength))
		if err != nil {
			celestiaValidationFailureCounter.Inc(1)
			log.Error("Unable to get ShareProof", "err", err)
			return nil, err
		}

		sharesProof := rangeResult.Proof

		namespaceNode := toNamespaceNode(sharesProof.RowProof.RowRoots[0])
		rowProof := toRowProofs((sharesProof.RowProof.Proofs[0]))
		attestationProof := toAttestationProof(event.ProofNonce.Uint64(), blobPointer.BlockHeight, blobPointer.DataRoot, dataRootProof)

		celestiaVerifierAbi, err := celestiagen.CelestiaBatchVerifierMetaData.GetAbi()
		if err != nil {
			celestiaValidationFailureCounter.Inc(1)
			log.Error("Could not get ABI for Celestia Batch Verifier", "err", err)
			return nil, err
		}

		verifyProofABI := celestiaVerifierAbi.Methods["verifyProof"]

		proofData, err := verifyProofABI.Inputs.Pack(
			common.HexToAddress(c.Cfg.ValidatorConfig.BlobstreamAddr), namespaceNode, rowProof, attestationProof,
		)
		if err != nil {
			celestiaValidationFailureCounter.Inc(1)
			log.Error("Could not pack structs into ABI", "err", err)
			return nil, err
		}

		celestiaValidationSuccessCounter.Inc(1)
		celestiaValidationLastSuccesfulActionGauge.Update(time.Now().Unix())
		ethRpc.Close()
		return proofData, nil
	}

	celestiaValidationFailureCounter.Inc(1)
	ethRpc.Close()
	return nil, err
}

func (c *CelestiaDA) filter(ctx context.Context, ethRpc *ethclient.Client,
	blobstream *blobstreamx.Bindings, latestBlock uint64, celestiaHeight uint64, backwards bool) (*blobstreamx.BindingsDataCommitmentStored, error) {
	// Geth has a default of 5000 block limit for filters
	start := uint64(0)
	if latestBlock > 5000 {
		start = latestBlock - 5000
	}
	end := latestBlock

	for {
		// Check context before each iteration
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context cancelled or deadline exceeded: %w", err)
		}
		eventsIterator, err := blobstream.FilterDataCommitmentStored(
			&bind.FilterOpts{
				Context: ctx,
				Start:   start,
				End:     &end,
			},
			nil,
			nil,
			nil,
		)
		if err != nil {
			log.Error("Error creating event iterator", "err", err)
			return nil, err
		}

		var event *blobstreamx.BindingsDataCommitmentStored
		for eventsIterator.Next() {
			e := eventsIterator.Event
			if e.StartBlock <= celestiaHeight && celestiaHeight < e.EndBlock {
				event = &blobstreamx.BindingsDataCommitmentStored{
					ProofNonce:     e.ProofNonce,
					StartBlock:     e.StartBlock,
					EndBlock:       e.EndBlock,
					DataCommitment: e.DataCommitment,
				}
				break
			}
		}
		if err := eventsIterator.Error(); err != nil {
			return nil, err
		}
		err = eventsIterator.Close()
		if err != nil {
			return nil, err
		}
		if event != nil {
			log.Info("Found Data Root submission event", "proof_nonce", event.ProofNonce, "start", event.StartBlock, "end", event.EndBlock)
			return event, nil
		}

		if backwards {
			if start >= 5000 {
				start -= 5000
			} else {
				start = 0
			}
			if end < 5000 {
				end = start + 1000
			} else {
				end -= 5000
			}
		} else {
			// Make the sleep cancellable with context
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second * time.Duration(c.Cfg.ValidatorConfig.SleepTime)):
			}

			latestBlockNumber, err := ethRpc.BlockNumber(context.Background())
			if err != nil {
				return nil, err
			}

			start = end
			end = latestBlockNumber
		}
	}
}

func (c *CelestiaDA) returnErrorHelper(err error) (*types.ReadResult, error) {
	log.Error(err.Error())

	if c.Cfg.ReorgOnReadFailure {
		return &types.ReadResult{Message: []byte{}}, nil
	}

	return nil, err
}
