package das

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	awskeyring "github.com/celestiaorg/aws-kms-keyring"
	"github.com/celestiaorg/celestia-app/v6/pkg/appconsts"
	txclient "github.com/celestiaorg/celestia-node/api/client"
	node "github.com/celestiaorg/celestia-node/api/rpc/client"
	"github.com/celestiaorg/celestia-node/blob"
	"github.com/celestiaorg/celestia-node/header"
	"github.com/celestiaorg/celestia-node/nodebuilder/p2p"
	"github.com/celestiaorg/celestia-node/state"
	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/celestiagen"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/celestiaorg/rsmt2d"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
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
	WithWriter                  bool               `koanf:"with-writer"`
	GasPrice                    float64            `koanf:"gas-price" reload:"hot"`
	GasMultiplier               float64            `koanf:"gas-multiplier" reload:"hot"`
	Rpc                         string             `koanf:"rpc" reload:"hot"`
	ReadRpc                     string             `koanf:"read-rpc" reload:"hot"`
	NamespaceId                 string             `koanf:"namespace-id" `
	AuthToken                   string             `koanf:"auth-token" reload:"hot"`
	ReadAuthToken               string             `koanf:"read-auth-token" reload:"hot"`
	CoreToken                   string             `koanf:"core-token" reload:"hot"`
	CoreURL                     string             `koanf:"core-url" reload:"hot"`
	CoreNetwork                 string             `koanf:"core-network" reload:"hot"`
	KeyName                     string             `koanf:"key-name" reload:"hot"`
	KeyPath                     string             `koanf:"key-path" reload:"hot"`
	BackendName                 string             `koanf:"backend-name" reload:"hot"`
	NoopWriter                  bool               `koanf:"noop-writer" reload:"hot"`
	EnableDATLS                 bool               `koanf:"enable-da-tls" reload:"hot"`
	EnableCoreTLS               bool               `koanf:"enable-core-tls" reload:"hot"`
	ValidatorConfig             ValidatorConfig    `koanf:"validator-config" reload:"hot"`
	CacheCleanupTime            time.Duration      `koanf:"cache-time"`
	ExperimentalTxClient        bool               `koanf:"experimental-tx-client"`
	DangerousReorgOnReadFailure bool               `koanf:"dangerous-reorg-on-read-failure"`
	RetryConfig                 RetryBackoffConfig `koanf:"retry-config"`
	AWSKMSConfig                AWSKMSConfig       `koanf:"aws-kms-config"`
}

// AWSKMSConfig configures the AWS KMS backend for signing Celestia transactions.
type AWSKMSConfig struct {
	Region        string `koanf:"region"`
	Endpoint      string `koanf:"endpoint"`
	AliasPrefix   string `koanf:"alias-prefix"`
	AutoCreate    bool   `koanf:"auto-create"`
	ImportKeyName string `koanf:"import-key-name"`
	ImportKeyHex  string `koanf:"import-key-hex"`
}

// ToKeyringConfig converts to awskeyring.Config
func (c *AWSKMSConfig) ToKeyringConfig() *awskeyring.Config {
	return &awskeyring.Config{
		Region:        c.Region,
		Endpoint:      c.Endpoint,
		AliasPrefix:   c.AliasPrefix,
		AutoCreate:    c.AutoCreate,
		ImportKeyName: c.ImportKeyName,
		ImportKeyHex:  c.ImportKeyHex,
	}
}

type RetryBackoffConfig struct {
	MaxRetries     int           `koanf:"max-retries"`
	InitialBackoff time.Duration `koanf:"initial-backoff"`
	MaxBackoff     time.Duration `koanf:"max-backoff"`
	BackoffFactor  float64       `koanf:"backoff-factor"`
}

func CelestiaRetryConfigAddOptions(prefix string, f *pflag.FlagSet) {
	f.Int(prefix+".max-retries", DefaultCelestiaRetryConfig.MaxRetries, "maximum number of retry attempts")
	f.Duration(prefix+".initial-backoff", DefaultCelestiaRetryConfig.InitialBackoff, "initial backoff duration for retries")
	f.Duration(prefix+".max-backoff", DefaultCelestiaRetryConfig.MaxBackoff, "maximum backoff duration for retries")
	f.Float64(prefix+".backoff-factor", DefaultCelestiaRetryConfig.BackoffFactor, "exponential backoff multiplier")
}

var DefaultCelestiaRetryConfig = RetryBackoffConfig{
	MaxRetries:     5,
	InitialBackoff: 10 * time.Second,
	MaxBackoff:     120 * time.Second,
	BackoffFactor:  2.0,
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

func hasBits(checking byte, bits byte) bool {
	return (checking & bits) == bits
}

// NOTE: this method should be renamed, it matches the custom DA header flag
func IsCelestiaMessageHeaderByte(header byte) bool {
	return hasBits(header, cert.CustomDAHeaderFlag)
}

type CelestiaDA struct {
	Cfg        *DAConfig
	Client     *node.Client
	TxClient   *txclient.Client
	ReadClient *txclient.ReadClient

	Namespace *libshare.Namespace

	messageCache sync.Map
}

func (c *CelestiaDA) MaxMessageSize(ctx context.Context) (int, error) {
	// Celestia's max blob size is not exposed via ReadClient in v0.28.2.
	// Use the default max blob size from the Celestia app constants.
	return int(appconsts.DefaultMaxBytes), nil
}

func CelestiaDAConfigAddOptions(prefix string, f *pflag.FlagSet) {
	f.Bool(prefix+".with-writer", false, "Enable using the DA Server for writing data to Celestia")
	f.Bool(prefix+".experimental-tx-client", false, "Enable using the DA Server for writing data to Celestia")
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
	f.String(prefix+".backend-name", "test", "keyring backend to use (test, file, os, kwallet, pass, keychain, memory, awskms)")
	f.Bool(prefix+".enable-da-tls", false, "enable TLS for DA node")
	f.Bool(prefix+".enable-core-tls", false, "enable TLS for Core node")
	f.Bool(prefix+".noop-writer", false, "Noop writer (disable posting to celestia)")
	f.String(prefix+".validator-config"+".eth-rpc", "", "Parent chain connection, only used for validation")
	f.String(prefix+".validator-config"+".blobstream", "", "Blobstream address, only used for validation")
	f.Int(prefix+".validator-config"+".sleep-time", 3600, "How many seconds to wait before initiating another filtering loop for Blobstream events")
	f.Duration(prefix+".cache-time", time.Hour/2, "how often to clean the in memory cache")
	CelestiaRetryConfigAddOptions(prefix+".retry-config", f)
	CelestiaAWSKMSConfigAddOptions(prefix+".aws-kms-config", f)
}

func CelestiaAWSKMSConfigAddOptions(prefix string, f *pflag.FlagSet) {
	f.String(prefix+".region", "us-east-1", "AWS region for KMS")
	f.String(prefix+".endpoint", "", "AWS KMS endpoint (use http://localhost:4566 for localstack)")
	f.String(prefix+".alias-prefix", "alias/nitro-das-celestia/", "Prefix for KMS key aliases")
	f.Bool(prefix+".auto-create", false, "Automatically create KMS keys if they don't exist")
	f.String(prefix+".import-key-name", "", "Name for imported key (requires import-key-hex)")
	f.String(prefix+".import-key-hex", "", "Hex-encoded private key to import into KMS (32 bytes)")
}

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

func initKeyring(ctx context.Context, cfg *DAConfig) (keyring.Keyring, error) {
	keyname := cfg.KeyName
	if keyname == "" {
		keyname = "my_celes_key"
	}

	backend := cfg.BackendName
	if backend == "" {
		backend = keyring.BackendTest
	}

	var kr keyring.Keyring
	var err error
	switch backend {
	case "awskms":
		if cfg.AWSKMSConfig.Region == "" {
			return nil, fmt.Errorf("AWS KMS region is required when using awskms backend")
		}
		kmsConfig := cfg.AWSKMSConfig.ToKeyringConfig()
		kr, err = awskeyring.NewKMSKeyring(ctx, keyname, *kmsConfig)
	default:
		kr, err = txclient.KeyringWithNewKey(txclient.KeyringConfig{
			KeyName:     keyname,
			BackendName: backend,
		}, cfg.KeyPath)
	}
	return kr, err
}

func NewCelestiaDA(cfg *DAConfig) (*CelestiaDA, error) {
	if cfg == nil {
		return nil, errors.New("celestia cfg cannot be blank")
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

	var readClient *txclient.ReadClient
	var writeClient *txclient.Client
	var daClient *node.Client

	// use dedicated read rpc or use the same as the da-client
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

	if cfg.WithWriter {
		// compatibility to connect with a light node / bridge node without grpc
		// grpc client currently under "experimental"
		if cfg.ExperimentalTxClient {
			var err error
			if cfg.KeyPath == "" {
				cfg.KeyPath, err = DefaultKeyringPath("light", cfg.CoreNetwork)
			}

			log.Info("Key path", "path", cfg.KeyPath)
			// Create a keyring
			kr, err := initKeyring(context.Background(), cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize keyring: %w", err)
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

			log.Info("Succesfully initialized write (experimental) txclient", "writeRpc", cfg.CoreURL)
		} else {
			daClient, err = node.NewClient(context.Background(), cfg.Rpc, cfg.AuthToken)
			if err != nil {
				log.Error("could not initialize node client for da rpc", "err", err)
				return nil, err
			}
			log.Info("Succesfully initialized node da client", "writeRpc", cfg.Rpc)
		}
	}

	readClient, err = txclient.NewReadClient(context.Background(), readConfig)
	if err != nil {
		log.Error("could not initialize txclient.ReadClient", "err", err)
		return nil, err
	}
	log.Info("Succesfully initialized read client", "readRpc", readConfig.BridgeDAAddr)

	da := &CelestiaDA{
		Cfg:        cfg,
		Client:     daClient,
		TxClient:   writeClient,
		ReadClient: readClient,
		Namespace:  &namespace,
	}

	da.StartCacheCleanup(cfg.CacheCleanupTime)

	return da, nil
}

func (c *CelestiaDA) Stop() error {
	c.Client.Close()
	c.ReadClient.Close()
	if c.Cfg.ExperimentalTxClient {
		c.TxClient.Close()
	}
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

	if !c.Cfg.WithWriter {
		log.Warn("Attempted to call Store() without writer enabled", "cfg.with-writer", c.Cfg.WithWriter)
		return nil, errors.New("writer not enabled")
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
		if c.Cfg.ExperimentalTxClient {
			height, err = c.TxClient.Blob.Submit(ctx, []*blob.Blob{dataBlob}, submitOptions)

		} else {
			height, err = c.Client.Blob.Submit(ctx, []*blob.Blob{dataBlob}, submitOptions)
		}
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
				log.Error("Blob Submission error", "err", err)
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

	certificate := cert.NewCelestiaCertificate(
		height,
		startIndexOds,
		uint64(sharesLength),
		txCommitment,
		dataRoot,
	)
	
	serializedCert, err := certificate.MarshalBinary()
	if err != nil {
		celestiaFailureCounter.Inc(1)
		log.Warn("certificate serialization failed", "err", err)
		return nil, err
	}
	log.Info("Posted blob to height and dataRoot", "height", certificate.BlockHeight, "dataRoot", hex.EncodeToString(certificate.DataRoot[:]))

	c.messageCache.Store(msgHashHex, certificate)

	celestiaSuccessCounter.Inc(1)
	celestiaDALastSuccesfulActionGauge.Update(time.Now().Unix())

	return serializedCert, nil
}

func (c *CelestiaDA) Read(ctx context.Context, certificate *cert.CelestiaDACertV1) (*types.ReadResult, error) {

	log.Info("reading blob pointer",
		"blockHeight", certificate.BlockHeight,
		"start", certificate.Start,
		"sharesLength", certificate.SharesLength,
		"dataRoot", hex.EncodeToString(certificate.DataRoot[:]),
		"txCommitment", hex.EncodeToString(certificate.TxCommitment[:]),
	)

	// Add timeout to the context
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// Helper function for retrying with exponential backoff
	retryWithBackoff := func(operation func() error) error {
		backoff := c.Cfg.RetryConfig.InitialBackoff
		for attempt := 0; attempt < c.Cfg.RetryConfig.MaxRetries; attempt++ {
			err := operation()
			if err == nil {
				return nil
			}

			// Check if context is cancelled
			if ctx.Err() != nil {
				return fmt.Errorf("context cancelled: %w", ctx.Err())
			}

			// Last attempt, don't wait
			if attempt == c.Cfg.RetryConfig.MaxRetries-1 {
				return fmt.Errorf("max retries exceeded: %w", err)
			}

			log.Warn("operation failed, retrying...", "attempt", attempt+1, "backoff", backoff, "err", err)

			// Wait with backoff
			select {
			case <-time.After(backoff):
				// Exponential backoff with jitter
				backoff = time.Duration(float64(backoff) * c.Cfg.RetryConfig.BackoffFactor)
				if backoff > c.Cfg.RetryConfig.MaxBackoff {
					backoff = c.Cfg.RetryConfig.MaxBackoff
				}
				// Add jitter (±20%)
				jitter := time.Duration(rand.Float64()*0.4*float64(backoff)) - time.Duration(0.2*float64(backoff))
				backoff += jitter
			case <-ctx.Done():
				return fmt.Errorf("context cancelled during backoff: %w", ctx.Err())
			}
		}
		return fmt.Errorf("unexpected retry loop exit")
	}

	// Fetch header with retry
	var header *header.ExtendedHeader
	err := retryWithBackoff(func() error {
		var err error
		header, err = c.ReadClient.Header.GetByHeight(ctx, certificate.BlockHeight)
		if err != nil {
			log.Warn("could not fetch header", "height", certificate.BlockHeight, "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch header after retries: %w", err)
	}

	// Validate data root
	headerDataHash := [32]byte{}
	copy(headerDataHash[:], header.DataHash)
	if headerDataHash != certificate.DataRoot {
		return nil, fmt.Errorf("data Root mismatch, header.DataHash=%v, blobPointer.DataRoot=%v", header.DataHash, hex.EncodeToString(certificate.DataRoot[:]))
	}

	// Fetch blob with retry
	var blobData []byte
	var sharesLength int
	err = retryWithBackoff(func() error {
		blob, err := c.ReadClient.Blob.Get(ctx, certificate.BlockHeight, *c.Namespace, certificate.TxCommitment[:])
		if err != nil {
			return err
		}

		blob.Index()
		blobData = blob.Data()
		length, err := blob.Length()
		if err != nil {
			return fmt.Errorf("could not get shares length: %w", err)
		}
		if length == 0 {
			return fmt.Errorf("blob found, but has shares length zero")
		}
		sharesLength = length
		return nil
	})
	if err != nil {
		celestiaFailureCounter.Inc(1)
		return nil, fmt.Errorf("failed to read blob after retries: %w", err)
	}

	// Fetch EDS with retry
	var extendedSquare *rsmt2d.ExtendedDataSquare
	err = retryWithBackoff(func() error {
		var err error
		extendedSquare, err = c.ReadClient.Share.GetEDS(ctx, certificate.BlockHeight)
		if err != nil {
			return fmt.Errorf("failed to get EDS, height=%v: %w", certificate.BlockHeight, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Validation logic (no changes needed here)
	squareSize := uint64(len(header.DAH.RowRoots))
	odsSize := squareSize / 2
	startRow := certificate.Start / odsSize

	if certificate.Start >= odsSize*odsSize {
		return nil, fmt.Errorf("startIndexOds >= odsSize*odsSize, startIndexOds=%v, odsSize*odsSize=%v", certificate.Start, odsSize*odsSize)
	}

	if certificate.Start+certificate.SharesLength < 1 {
		return nil, fmt.Errorf("startIndexOds+blobPointer.SharesLength < 1, startIndexOds+blobPointer.SharesLength=%v", certificate.Start+certificate.SharesLength)
	}

	endIndexOds := certificate.Start + certificate.SharesLength - 1
	if endIndexOds >= odsSize*odsSize {
		return nil, fmt.Errorf("endIndexOds >= odsSize*odsSize, endIndexOds=%v, odsSize*odsSize=%v", endIndexOds, odsSize*odsSize)
	}

	endRow := endIndexOds / odsSize

	if endRow >= odsSize || startRow >= odsSize {
		return nil, fmt.Errorf("endRow >= odsSize || startRow >= odsSize, endRow=%v, startRow=%v, odsSize=%v", endRow, startRow, odsSize)
	}

	startColumn := certificate.Start % odsSize
	endColumn := endIndexOds % odsSize

	if startRow == endRow && startColumn > endColumn {
		return nil, fmt.Errorf("start and end row are the same and startColumn >= endColumn, startColumn=%v, endColumn+1=%v", startColumn, endColumn+1)
	}

	if uint64(sharesLength) != certificate.SharesLength || sharesLength == 0 {
		celestiaFailureCounter.Inc(1)
		return nil, fmt.Errorf("share length mismatch, sharesLength=%v, blobPointer.SharesLength=%v", sharesLength, certificate.SharesLength)
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

func (c *CelestiaDA) GetNamespace() *libshare.Namespace {
	return c.Namespace
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
		rangeResult, err := c.ReadClient.Share.GetRange(ctx, blobPointer.BlockHeight, int(blobPointer.Start), int(blobPointer.Start+blobPointer.SharesLength))
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
