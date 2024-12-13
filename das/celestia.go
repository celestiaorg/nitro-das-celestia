package das

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"

	node "github.com/celestiaorg/celestia-node/api/rpc/client"
	"github.com/celestiaorg/celestia-node/blob"
	eds "github.com/celestiaorg/celestia-node/share/eds"
	"github.com/celestiaorg/celestia-node/state"
	libshare "github.com/celestiaorg/go-square/v2/share"
	"github.com/celestiaorg/nitro-das-celestia/celestiagen"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/spf13/pflag"

	blobstreamx "github.com/succinctlabs/blobstreamx/bindings"
)

type DAConfig struct {
	Enable             bool             `koanf:"enable"`
	GasPrice           float64          `koanf:"gas-price" reload:"hot"`
	GasMultiplier      float64          `koanf:"gas-multiplier" reload:"hot"`
	Rpc                string           `koanf:"rpc" reload:"hot"`
	ReadRpc            string           `koanf:"read-rpc" reload:"hot"`
	NamespaceId        string           `koanf:"namespace-id" `
	AuthToken          string           `koanf:"auth-token" reload:"hot"`
	ReadAuthToken      string           `koanf:"read-auth-token" reload:"hot"`
	KeyName            string           `koanf:"keyname" reload:"hot"`
	NoopWriter         bool             `koanf:"noop-writer" reload:"hot"`
	ValidatorConfig    *ValidatorConfig `koanf:"validator-config"`
	ReorgOnReadFailure bool             `koanf:"dangerous-reorg-on-read-failure"`
	CacheCleanupTime   time.Duration    `koanf:"cache-time"`
}

type ValidatorConfig struct {
	EthClient      string `koanf:"eth-rpc" reload:"hot"`
	BlobstreamAddr string `koanf:"blobstream"`
}

var (
	celestiaDALastSuccesfulActionGauge = metrics.NewRegisteredGauge("celestia/action/last_success", nil)
	celestiaLastNonDefaultGasprice     = metrics.NewRegisteredGaugeFloat64("celestia/last_gas_price", nil)
	celestiaSuccessCounter             = metrics.NewRegisteredCounter("celestia/action/celestia_success", nil)
	celestiaFailureCounter             = metrics.NewRegisteredCounter("celestia/action/celestia_failure", nil)
	celestiaGasRetries                 = metrics.NewRegisteredCounter("celestia/action/gas_retries", nil)
	celestiaBlobInclusionRetries       = metrics.NewRegisteredCounter("celestia/action/inclusion_retries", nil)

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
	Client     *node.Client
	ReadClient *node.Client

	Namespace *libshare.Namespace
	Prover    *CelestiaProver
	KeyName   string

	messageCache sync.Map
}

type CelestiaProver struct {
	EthClient   *ethclient.Client
	BlobstreamX *blobstreamx.BlobstreamX
}

func CelestiaDAConfigAddOptions(prefix string, f *pflag.FlagSet) {
	f.Bool(prefix+".enable", false, "Enable Celestia DA")
	f.Float64(prefix+".gas-price", 0.01, "Gas for retrying Celestia transactions")
	f.Float64(prefix+".gas-multiplier", 1.01, "Gas multiplier for Celestia transactions")
	f.String(prefix+".rpc", "", "Rpc endpoint for celestia-node")
	f.String(prefix+".read-rpc", "", "separate celestia RPC endpoint for reads")
	f.String(prefix+".namespace-id", "", "Celestia Namespace to post data to")
	f.String(prefix+".auth-token", "", "Auth token for Celestia Node")
	f.String(prefix+".read-auth-token", "", "Auth token for Celestia Node")
	f.String(prefix+".keyname", "my_cel_key", "Keyring keyname for Celestia Node for blobs submission")
	f.Bool(prefix+".noop-writer", false, "Noop writer (disable posting to celestia)")
	f.String(prefix+".validator-config"+".eth-rpc", "", "Parent chain connection, only used for validation")
	f.String(prefix+".validator-config"+".blobstream", "", "Blobstream address, only used for validation")
	f.Bool(prefix+".dangerous-reorg-on-read-failure", false, "DANGEROUS: reorg if any error during reads from celestia node")
	f.Duration(prefix+".cache-time", time.Hour/2, "how often to clean the in memory cache")
}

func NewCelestiaDA(cfg *DAConfig, ethClient *ethclient.Client) (*CelestiaDA, error) {
	if cfg == nil {
		return nil, errors.New("celestia cfg cannot be blank")
	}
	daClient, err := node.NewClient(context.Background(), cfg.Rpc, cfg.AuthToken)
	if err != nil {
		return nil, err
	}

	var readClient *node.Client
	if cfg.ReadRpc != "" && cfg.ReadAuthToken != "" {
		readClient, err = node.NewClient(context.Background(), cfg.ReadRpc, cfg.ReadAuthToken)
		if err != nil {
			return nil, err
		}
	} else {
		readClient = daClient
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

	if cfg.KeyName == "" {
		return nil, errors.New("keyring keyname cannot be blank")
	}
	if !isValidKeyName(cfg.KeyName) {
		return nil, fmt.Errorf("invalid keyring keyname format: %s", cfg.KeyName)
	}

	if cfg.ValidatorConfig != nil {

		var ethRpc *ethclient.Client
		if ethClient != nil {
			ethRpc = ethClient
		} else if len(cfg.ValidatorConfig.EthClient) > 0 {
			ethRpc, err = ethclient.Dial(cfg.ValidatorConfig.EthClient)
			if err != nil {
				return nil, err
			}
		}

		blobstreamx, err := blobstreamx.NewBlobstreamX(common.HexToAddress(cfg.ValidatorConfig.BlobstreamAddr), ethClient)
		if err != nil {
			return nil, err
		}

		da := &CelestiaDA{
			Cfg:        cfg,
			Client:     daClient,
			ReadClient: readClient,
			Namespace:  &namespace,
			KeyName:    cfg.KeyName,
			Prover: &CelestiaProver{
				EthClient:   ethRpc,
				BlobstreamX: blobstreamx,
			},
		}

		da.StartCacheCleanup(cfg.CacheCleanupTime)

		return da, nil

	}

	da := &CelestiaDA{
		Cfg:        cfg,
		Client:     daClient,
		ReadClient: readClient,
		Namespace:  &namespace,
	}

	da.StartCacheCleanup(cfg.CacheCleanupTime)

	return da, nil
}

func (c *CelestiaDA) Stop() error {
	c.Prover.EthClient.Close()
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

	proofs, err := c.ReadClient.Blob.GetProof(ctx, height, *c.Namespace, dataBlob.Commitment)
	if err != nil {
		celestiaFailureCounter.Inc(1)
		log.Warn("Error retrieving proof", "err", err)
		return nil, err
	}

	proofRetries := 0
	for proofs == nil {
		log.Warn("Retrieved empty proof from GetProof, fetching again...", "proofRetries", proofRetries)
		time.Sleep(time.Millisecond * 100)
		proofs, err = c.ReadClient.Blob.GetProof(ctx, height, *c.Namespace, dataBlob.Commitment)
		if err != nil {
			celestiaFailureCounter.Inc(1)
			log.Warn("Error retrieving proof", "err", err)
			return nil, err
		}
		proofRetries++
		celestiaBlobInclusionRetries.Inc(1)
	}

	included, err := c.ReadClient.Blob.Included(ctx, height, *c.Namespace, proofs, dataBlob.Commitment)
	if err != nil || !included {
		celestiaFailureCounter.Inc(1)
		log.Warn("Error checking for inclusion", "err", err, "proof", proofs)
		return nil, err
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
	blobPointer := BlobPointer{
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

func (c *CelestiaDA) Read(ctx context.Context, blobPointer *BlobPointer) (*ReadResult, error) {
	// Wait until our client is synced
	err := c.ReadClient.Header.SyncWait(ctx)
	if err != nil {
		log.Error("trouble with client sync", "err", err)
		return nil, err
	}

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

	return &ReadResult{
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
	if c.Prover == nil {
		celestiaValidationFailureCounter.Inc(1)
		return nil, fmt.Errorf("no celestia prover config found")
	}

	fmt.Printf("Inbox Message: %v\n", msg)
	buf := bytes.NewBuffer(msg)
	// msgLength := uint32(len(msg) + 1)
	blobPointer := BlobPointer{}
	blobBytes := buf.Bytes()
	err := blobPointer.UnmarshalBinary(blobBytes)
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

	latestBlockNumber, err := c.Prover.EthClient.BlockNumber(context.Background())
	if err != nil {
		log.Warn("could not fetch latest L1 block", "err", err)
		celestiaValidationFailureCounter.Inc(1)
		return nil, err
	}

	// check the latest celestia block on the Blobstream contract
	latestCelestiaBlock, err := c.Prover.BlobstreamX.LatestBlock(&bind.CallOpts{
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

	var event *blobstreamx.BlobstreamXDataCommitmentStored

	event, err = c.filter(ctx, latestBlockNumber, blobPointer.BlockHeight, backwards)
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

	valid, err := c.Prover.BlobstreamX.VerifyAttestation(
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
		extendedSquare, err := c.Client.Share.GetEDS(ctx, blobPointer.BlockHeight)
		if err != nil {
			celestiaValidationFailureCounter.Inc(1)
			log.Error("Unable to get ShareProof", "err", err)
			return nil, err
		}
		sharesProof, err := eds.ProveShares(extendedSquare, int(blobPointer.Start), int(blobPointer.Start+blobPointer.SharesLength))
		if err != nil {
			celestiaValidationFailureCounter.Inc(1)
			log.Error("Unable to get ShareProof", "err", err)
			return nil, err
		}

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
		return proofData, nil
	}

	celestiaValidationFailureCounter.Inc(1)
	return nil, err
}

func (c *CelestiaDA) filter(ctx context.Context, latestBlock uint64, celestiaHeight uint64, backwards bool) (*blobstreamx.BlobstreamXDataCommitmentStored, error) {
	// Geth has a default of 5000 block limit for filters
	start := uint64(0)
	if latestBlock > 5000 {
		start = latestBlock - 5000
	}
	end := latestBlock

	for attempt := 0; attempt < 11; attempt++ {
		eventsIterator, err := c.Prover.BlobstreamX.FilterDataCommitmentStored(
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

		var event *blobstreamx.BlobstreamXDataCommitmentStored
		for eventsIterator.Next() {
			e := eventsIterator.Event
			if e.StartBlock <= celestiaHeight && celestiaHeight < e.EndBlock {
				event = &blobstreamx.BlobstreamXDataCommitmentStored{
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
			time.Sleep(time.Second * 3600)
			latestBlockNumber, err := c.Prover.EthClient.BlockNumber(context.Background())
			if err != nil {
				return nil, err
			}

			start = end
			end = latestBlockNumber
		}
	}

	return nil, fmt.Errorf("unable to find Data Commitment Stored event in Blobstream")
}

func (c *CelestiaDA) returnErrorHelper(err error) (*ReadResult, error) {
	log.Error(err.Error())

	if c.Cfg.ReorgOnReadFailure {
		return &ReadResult{Message: []byte{}}, nil
	}

	return nil, err
}

// Validate that the KeyName is a alphanumeric string of length > 0
func isValidKeyName(name string) bool {
	return len(name) > 0 && regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(name)
}
