package das

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appda "github.com/celestiaorg/celestia-app/v7/pkg/da"
	appproof "github.com/celestiaorg/celestia-app/v7/pkg/proof"
	txclient "github.com/celestiaorg/celestia-node/api/client"
	nodeblob "github.com/celestiaorg/celestia-node/blob"
	nodeheader "github.com/celestiaorg/celestia-node/header"
	blobstreamapi "github.com/celestiaorg/celestia-node/nodebuilder/blobstream"
	nodebuildershare "github.com/celestiaorg/celestia-node/nodebuilder/share"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libhead "github.com/celestiaorg/go-header"
	headersync "github.com/celestiaorg/go-header/sync"
	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	validatorpkg "github.com/celestiaorg/nitro-das-celestia/daserver/validator"
	"github.com/celestiaorg/rsmt2d"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"
)

var (
	latestBlockSelector       = "0x07e2da96"
	verifyAttestationSelector = "0x1f3302a9"
	dataCommitmentStoredTopic = crypto.Keccak256Hash([]byte("DataCommitmentStored(uint256,uint64,uint64,bytes32)"))
)

type fakeCelestiaReader struct {
	lastOffset uint64
	lastCert   *cert.CelestiaDACertV1
	readProof  []byte
	readErr    error
}

func (f *fakeCelestiaReader) Read(context.Context, *cert.CelestiaDACertV1) (*types.ReadResult, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeCelestiaReader) GetProof(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeCelestiaReader) GenerateReadPreimageProof(
	_ context.Context,
	offset uint64,
	certificate *cert.CelestiaDACertV1,
) ([]byte, error) {
	f.lastOffset = offset
	f.lastCert = certificate
	return f.readProof, f.readErr
}

func (f *fakeCelestiaReader) GenerateCertificateValidityProof(
	context.Context,
	*cert.CelestiaDACertV1,
) ([]byte, error) {
	return []byte{0x01, 0x01, 0xaa}, nil
}

func makeCertBytes(t *testing.T) []byte {
	t.Helper()
	var txCommitment [32]byte
	var dataRoot [32]byte
	txCommitment[0] = 0xAA
	dataRoot[0] = 0xBB
	c := cert.NewCelestiaCertificate(123, 10, 100, txCommitment, dataRoot)
	b, err := c.MarshalBinary()
	require.NoError(t, err)
	return b
}

func TestGenerateReadPreimageProof_DelegatesWithParsedCertificate(t *testing.T) {
	reader := &fakeCelestiaReader{readProof: []byte{0x02, 0x00}}
	v := validatorpkg.NewCelestiaValidator(reader)

	certBytes := makeCertBytes(t)
	res, err := v.GenerateReadPreimageProof(64, certBytes).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte{0x02, 0x00}, res.Proof)
	require.EqualValues(t, 64, reader.lastOffset)
	require.NotNil(t, reader.lastCert)
	require.EqualValues(t, 123, reader.lastCert.BlockHeight)
	require.EqualValues(t, 10, reader.lastCert.Start)
	require.EqualValues(t, 100, reader.lastCert.SharesLength)
}

func TestGenerateReadPreimageProof_InvalidCertificateReturnsError(t *testing.T) {
	reader := &fakeCelestiaReader{}
	v := validatorpkg.NewCelestiaValidator(reader)

	_, err := v.GenerateReadPreimageProof(0, []byte{0x01, 0x02}).Await(context.Background())
	require.Error(t, err)
}

func TestGenerateCertificateValidityProof_InvalidCertificateReturnsClaimedInvalid(t *testing.T) {
	reader := &fakeCelestiaReader{}
	v := validatorpkg.NewCelestiaValidator(reader)

	res, err := v.GenerateCertificateValidityProof([]byte{0x01, 0x02}).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x01}, res.Proof)
}

func TestGenerateCertificateValidityProof_DelegatesProofPayload(t *testing.T) {
	reader := &fakeCelestiaReader{}
	v := validatorpkg.NewCelestiaValidator(reader)

	res, err := v.GenerateCertificateValidityProof(makeCertBytes(t)).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x01, 0xaa}, res.Proof)
}

func TestBuildReadPreimageProofV1_Layout(t *testing.T) {
	offset := uint64(96)
	payloadSize := uint64(1536)
	chunkLen := uint8(32)
	firstShareIndex := uint64(25)
	shareCount := uint8(1)
	trailer := []byte{0xde, 0xad, 0xbe, 0xef}

	proof := buildReadPreimageProofV1(offset, payloadSize, chunkLen, firstShareIndex, shareCount, trailer)
	require.Len(t, proof, 1+8+8+1+8+1+len(trailer))

	pos := 0
	require.Equal(t, byte(0x01), proof[pos])
	pos++
	require.EqualValues(t, offset, binary.BigEndian.Uint64(proof[pos:pos+8]))
	pos += 8
	require.EqualValues(t, payloadSize, binary.BigEndian.Uint64(proof[pos:pos+8]))
	pos += 8
	require.Equal(t, chunkLen, proof[pos])
	pos++
	require.EqualValues(t, firstShareIndex, binary.BigEndian.Uint64(proof[pos:pos+8]))
	pos += 8
	require.Equal(t, shareCount, proof[pos])
	pos++
	require.Equal(t, trailer, proof[pos:])
}

func TestPayloadOffsetShareMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		offset        uint64
		wantShareRel  uint64
		wantShareBase uint64
		wantCap       uint64
	}{
		{offset: 0, wantShareRel: 0, wantShareBase: 0, wantCap: 478},
		{offset: 32, wantShareRel: 0, wantShareBase: 0, wantCap: 478},
		{offset: 448, wantShareRel: 0, wantShareBase: 0, wantCap: 478},
		{offset: 477, wantShareRel: 0, wantShareBase: 0, wantCap: 478},
		{offset: 478, wantShareRel: 1, wantShareBase: 478, wantCap: 482},
		{offset: 480, wantShareRel: 1, wantShareBase: 478, wantCap: 482},
		{offset: 512, wantShareRel: 1, wantShareBase: 478, wantCap: 482},
		{offset: 959, wantShareRel: 1, wantShareBase: 478, wantCap: 482},
		{offset: 960, wantShareRel: 2, wantShareBase: 960, wantCap: 482},
		{offset: 992, wantShareRel: 2, wantShareBase: 960, wantCap: 482},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(
			fmt.Sprintf("offset_%d", tc.offset),
			func(t *testing.T) {
				rel := payloadOffsetToShareRel(tc.offset)
				require.Equal(t, tc.wantShareRel, rel)
				require.Equal(t, tc.wantShareBase, payloadStartForShareRel(rel))
				require.Equal(t, tc.wantCap, payloadCapacityForShareRel(rel))
			},
		)
	}
}

func TestReadChunkShareSelectionMatrix(t *testing.T) {
	t.Parallel()

	chunkLenFor := func(offset, payloadSize uint64) uint64 {
		if offset >= payloadSize {
			return 0
		}
		rem := payloadSize - offset
		if rem > 32 {
			return 32
		}
		return rem
	}
	shareCountFor := func(offset, payloadSize uint64) uint64 {
		chunkLen := chunkLenFor(offset, payloadSize)
		if chunkLen == 0 {
			return 1
		}
		rel := payloadOffsetToShareRel(offset)
		base := payloadStartForShareRel(rel)
		cap := payloadCapacityForShareRel(rel)
		intra := offset - base
		if intra+chunkLen > cap {
			return 2
		}
		return 1
	}

	cases := []struct {
		name           string
		payloadSize    uint64
		offset         uint64
		wantShareRel   uint64
		wantShareCount uint64
		wantChunkLen   uint64
	}{
		{name: "size_478_off_448", payloadSize: 478, offset: 448, wantShareRel: 0, wantShareCount: 1, wantChunkLen: 30},
		{name: "size_479_off_448", payloadSize: 479, offset: 448, wantShareRel: 0, wantShareCount: 2, wantChunkLen: 31},
		{name: "size_480_off_448", payloadSize: 480, offset: 448, wantShareRel: 0, wantShareCount: 2, wantChunkLen: 32},
		{name: "size_511_off_480", payloadSize: 511, offset: 480, wantShareRel: 1, wantShareCount: 1, wantChunkLen: 31},
		{name: "size_512_off_480", payloadSize: 512, offset: 480, wantShareRel: 1, wantShareCount: 1, wantChunkLen: 32},
		{name: "size_513_off_480", payloadSize: 513, offset: 480, wantShareRel: 1, wantShareCount: 1, wantChunkLen: 32},
		{name: "size_560_off_544", payloadSize: 560, offset: 544, wantShareRel: 1, wantShareCount: 1, wantChunkLen: 16},
		{name: "size_961_off_960", payloadSize: 961, offset: 960, wantShareRel: 2, wantShareCount: 1, wantChunkLen: 1},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.wantShareRel, payloadOffsetToShareRel(tc.offset))
			require.Equal(t, tc.wantChunkLen, chunkLenFor(tc.offset, tc.payloadSize))
			require.Equal(t, tc.wantShareCount, shareCountFor(tc.offset, tc.payloadSize))
		})
	}
}

type fakeBlobstreamReadModule struct {
	proof *blobstreamapi.DataRootTupleInclusionProof
	err   error
}

type fakeHeaderModule struct {
	header *nodeheader.ExtendedHeader
	err    error
}

type fakeShareModule struct {
	t                 *testing.T
	namespace         libshare.Namespace
	eds               *rsmt2d.ExtendedDataSquare
	shares            []libshare.Share
	getRangeCalls     int
	getRangeErrOnCall map[int]error
}

type readPreimageFixture struct {
	celestiaDA   *CelestiaDA
	certificate  *cert.CelestiaDACertV1
	contractAddr common.Address
	server       *httptest.Server
	rpcServer    *fakeEthRPCServer
	shareModule  *fakeShareModule
}

func (f *fakeBlobstreamReadModule) GetDataRootTupleRoot(
	context.Context,
	uint64,
	uint64,
) (blobstreamapi.DataRootTupleRoot, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeBlobstreamReadModule) GetDataRootTupleInclusionProof(
	context.Context,
	uint64,
	uint64,
	uint64,
) (*blobstreamapi.DataRootTupleInclusionProof, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.proof, nil
}

func (f *fakeHeaderModule) LocalHead(context.Context) (*nodeheader.ExtendedHeader, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeHeaderModule) GetByHash(context.Context, libhead.Hash) (*nodeheader.ExtendedHeader, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeHeaderModule) GetRangeByHeight(context.Context, *nodeheader.ExtendedHeader, uint64) ([]*nodeheader.ExtendedHeader, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeHeaderModule) GetByHeight(context.Context, uint64) (*nodeheader.ExtendedHeader, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.header, nil
}

func (f *fakeHeaderModule) WaitForHeight(context.Context, uint64) (*nodeheader.ExtendedHeader, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeHeaderModule) SyncState(context.Context) (headersync.State, error) {
	return headersync.State{}, errors.New("unused in this test")
}

func (f *fakeHeaderModule) SyncWait(context.Context) error {
	return errors.New("unused in this test")
}

func (f *fakeHeaderModule) NetworkHead(context.Context) (*nodeheader.ExtendedHeader, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeHeaderModule) Tail(context.Context) (*nodeheader.ExtendedHeader, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeHeaderModule) Subscribe(context.Context) (<-chan *nodeheader.ExtendedHeader, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeShareModule) SharesAvailable(context.Context, uint64) error {
	return errors.New("unused in this test")
}

func (f *fakeShareModule) GetShare(context.Context, uint64, int, int) (libshare.Share, error) {
	return libshare.Share{}, errors.New("unused in this test")
}

func (f *fakeShareModule) GetSamples(context.Context, uint64, []shwap.SampleCoords) ([]shwap.Sample, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeShareModule) GetEDS(context.Context, uint64) (*rsmt2d.ExtendedDataSquare, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeShareModule) GetRow(_ context.Context, _ uint64, rowIdx int) (shwap.Row, error) {
	return shwap.RowFromEDS(f.eds, rowIdx, shwap.Both)
}

func (f *fakeShareModule) GetNamespaceData(context.Context, uint64, libshare.Namespace) (shwap.NamespaceData, error) {
	return nil, errors.New("unused in this test")
}

func (f *fakeShareModule) GetRange(_ context.Context, _ uint64, start, end int) (*nodebuildershare.GetRangeResult, error) {
	f.getRangeCalls++
	if err := f.getRangeErrOnCall[f.getRangeCalls]; err != nil {
		return nil, err
	}
	proof, err := appproof.NewShareInclusionProofFromEDS(f.eds, f.namespace, libshare.NewRange(start, end))
	if err != nil {
		return nil, err
	}
	proofBytes, err := proof.Marshal()
	if err != nil {
		return nil, err
	}
	var protoProof tmproto.ShareProof
	if err := protoProof.Unmarshal(proofBytes); err != nil {
		return nil, err
	}
	coreProof, err := tmtypes.ShareProofFromProto(protoProof)
	if err != nil {
		return nil, err
	}
	return &nodebuildershare.GetRangeResult{
		Shares: f.shares[start:end],
		Proof:  &coreProof,
	}, nil
}

type fakeEthRPCServer struct {
	t                   *testing.T
	contractAddr        common.Address
	latestL1Block       uint64
	latestL1BlockErr    *jsonRPCError
	latestCelestiaBlock uint64
	latestBlockErr      *jsonRPCError
	logs                []ethLogResult
	logsErr             *jsonRPCError
	verifyAttestation   bool
	verifyErr           *jsonRPCError
}

type jsonRPCRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ethCallArg struct {
	To    string `json:"to"`
	Data  string `json:"data"`
	Input string `json:"input"`
}

type ethGetLogsArg struct {
	FromBlock string  `json:"fromBlock"`
	ToBlock   string  `json:"toBlock"`
	Address   any     `json:"address"`
	Topics    [][]any `json:"topics"`
}

type ethLogResult struct {
	Address          string   `json:"address"`
	Topics           []string `json:"topics"`
	Data             string   `json:"data"`
	BlockNumber      string   `json:"blockNumber"`
	TransactionHash  string   `json:"transactionHash"`
	TransactionIndex string   `json:"transactionIndex"`
	BlockHash        string   `json:"blockHash"`
	LogIndex         string   `json:"logIndex"`
	Removed          bool     `json:"removed"`
}

func (s *fakeEthRPCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req jsonRPCRequest
	require.NoError(s.t, json.NewDecoder(r.Body).Decode(&req))

	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "eth_blockNumber":
		if s.latestL1BlockErr != nil {
			resp.Error = s.latestL1BlockErr
			break
		}
		resp.Result = hexutil.EncodeUint64(s.latestL1Block)
	case "eth_call":
		var arg ethCallArg
		require.NoError(s.t, json.Unmarshal(req.Params[0], &arg))
		callData := arg.Data
		if callData == "" {
			callData = arg.Input
		}
		switch selector(callData) {
		case latestBlockSelector:
			if s.latestBlockErr != nil {
				resp.Error = s.latestBlockErr
				break
			}
			resp.Result = encodeUint64Return(s.latestCelestiaBlock)
		case verifyAttestationSelector:
			if s.verifyErr != nil {
				resp.Error = s.verifyErr
				break
			}
			resp.Result = encodeBoolReturn(s.verifyAttestation)
		default:
			s.t.Fatalf("unexpected eth_call selector: %q", selector(callData))
		}
	case "eth_getLogs":
		var arg ethGetLogsArg
		require.NoError(s.t, json.Unmarshal(req.Params[0], &arg))
		if s.logsErr != nil {
			resp.Error = s.logsErr
			break
		}
		fromBlock := decodeHexUint64(s.t, arg.FromBlock)
		toBlock := s.latestL1Block
		if arg.ToBlock != "" && arg.ToBlock != "latest" {
			toBlock = decodeHexUint64(s.t, arg.ToBlock)
		}
		result := make([]ethLogResult, 0)
		for _, log := range s.logs {
			blockNumber := decodeHexUint64(s.t, log.BlockNumber)
			if fromBlock <= blockNumber && blockNumber <= toBlock {
				result = append(result, log)
			}
		}
		resp.Result = result
	case "eth_chainId":
		resp.Result = "0x1"
	default:
		s.t.Fatalf("unexpected RPC method: %s", req.Method)
	}

	w.Header().Set("Content-Type", "application/json")
	require.NoError(s.t, json.NewEncoder(w).Encode(resp))
}

func selector(data string) string {
	if len(data) < len(latestBlockSelector) {
		return data
	}
	return data[:len(latestBlockSelector)]
}

func encodeUint64Return(v uint64) string {
	return hexutil.Encode(common.LeftPadBytes(new(big.Int).SetUint64(v).Bytes(), 32))
}

func encodeBoolReturn(v bool) string {
	if v {
		return hexutil.Encode(common.LeftPadBytes([]byte{1}, 32))
	}
	return hexutil.Encode(make([]byte, 32))
}

func decodeHexUint64(t *testing.T, raw string) uint64 {
	t.Helper()
	if raw == "" || raw == "latest" {
		return 0
	}
	value, err := hexutil.DecodeUint64(raw)
	require.NoError(t, err)
	return value
}

func makeStandaloneCert() *cert.CelestiaDACertV1 {
	var txCommitment [32]byte
	var dataRoot [32]byte
	txCommitment[0] = 0xAA
	dataRoot[0] = 0xBB
	return cert.NewCelestiaCertificate(123, 10, 100, txCommitment, dataRoot)
}

func makeStandaloneDataRootProof() *blobstreamapi.DataRootTupleInclusionProof {
	return &blobstreamapi.DataRootTupleInclusionProof{
		Total: 1,
		Index: 0,
		Aunts: nil,
	}
}

func makeCommitmentStoredLog(
	contractAddr common.Address,
	blockNumber uint64,
	proofNonce uint64,
	startBlock uint64,
	endBlock uint64,
	dataCommitment [32]byte,
) ethLogResult {
	return ethLogResult{
		Address: contractAddr.Hex(),
		Topics: []string{
			dataCommitmentStoredTopic.Hex(),
			common.BigToHash(new(big.Int).SetUint64(startBlock)).Hex(),
			common.BigToHash(new(big.Int).SetUint64(endBlock)).Hex(),
			common.BytesToHash(dataCommitment[:]).Hex(),
		},
		Data:             hexutil.Encode(common.LeftPadBytes(new(big.Int).SetUint64(proofNonce).Bytes(), 32)),
		BlockNumber:      hexutil.EncodeUint64(blockNumber),
		TransactionHash:  common.BigToHash(big.NewInt(int64(blockNumber + 1))).Hex(),
		TransactionIndex: "0x0",
		BlockHash:        common.BigToHash(big.NewInt(int64(blockNumber + 2))).Hex(),
		LogIndex:         "0x0",
		Removed:          false,
	}
}

func newStandaloneCelestiaDA(
	t *testing.T,
	server *httptest.Server,
	contractAddr common.Address,
	readModule blobstreamapi.Module,
) *CelestiaDA {
	t.Helper()

	ethRPC, err := ethclient.Dial(server.URL)
	require.NoError(t, err)
	t.Cleanup(ethRPC.Close)

	return &CelestiaDA{
		Cfg: &DAConfig{
			RetryConfig: DefaultCelestiaRetryConfig,
			ValidatorConfig: ValidatorConfig{
				EthClient:      "mock",
				BlobstreamAddr: contractAddr.Hex(),
				SleepTime:      0,
			},
			L1ClientOverride: ethRPC,
		},
		ReadClient: &txclient.ReadClient{Blobstream: readModule},
	}
}

func newReadPreimageFixture(t *testing.T) *readPreimageFixture {
	t.Helper()

	return newReadPreimageFixtureWithMessage(t, []byte("read preimage regression payload"))
}

func newReadPreimageFixtureWithMessage(t *testing.T, message []byte) *readPreimageFixture {
	t.Helper()

	namespace, err := libshare.NewV0Namespace(bytes.Repeat([]byte{0x42}, libshare.NamespaceVersionZeroIDSize))
	require.NoError(t, err)

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
		123,
		0,
		uint64(len(shares)),
		[32]byte{0xAA},
		dataRoot,
	)

	header := &nodeheader.ExtendedHeader{
		RawHeader: tmtypes.Header{DataHash: dah.Hash()},
		DAH:       &dah,
	}

	shareModule := &fakeShareModule{
		t:                 t,
		namespace:         namespace,
		eds:               eds,
		shares:            shares,
		getRangeErrOnCall: map[int]error{},
	}

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000C0")
	rpcServer := &fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
		logs: []ethLogResult{
			makeCommitmentStoredLog(contractAddr, 11_000, 7, 100, 200, [32]byte{}),
		},
		verifyAttestation: true,
	}
	server := httptest.NewServer(rpcServer)
	t.Cleanup(server.Close)

	da := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{proof: makeStandaloneDataRootProof()})
	da.ReadClient.Header = &fakeHeaderModule{header: header}
	da.ReadClient.Share = shareModule
	da.Namespace = &namespace

	return &readPreimageFixture{
		celestiaDA:   da,
		certificate:  certificate,
		contractAddr: contractAddr,
		server:       server,
		rpcServer:    rpcServer,
		shareModule:  shareModule,
	}
}

func TestGenerateCertificateValidityProof_NoBlobstreamEventClaimsInvalid(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000AA")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	valid, _, err := celestiaDA.generateCertificateValidityProof(ctx, makeStandaloneCert())
	require.NoError(t, err)
	require.False(t, valid)
}

func TestGenerateCertificateValidityProof_NoBlobstreamEventReturnsInvalidProofBytes(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000B1")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	proof, err := celestiaDA.GenerateCertificateValidityProof(ctx, makeStandaloneCert())
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x01}, proof)
}

func TestGenerateCertificateValidityProof_L1BlockNumberErrorPropagates(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000AB")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:            t,
		contractAddr: contractAddr,
		latestL1BlockErr: &jsonRPCError{
			Code:    -32000,
			Message: "block number failed",
		},
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{})

	_, _, err := celestiaDA.generateCertificateValidityProof(context.Background(), makeStandaloneCert())
	require.ErrorContains(t, err, "block number failed")
}

func TestGenerateCertificateValidityProof_LatestBlobstreamBlockErrorPropagates(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000AE")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:             t,
		contractAddr:  contractAddr,
		latestL1Block: 12_000,
		latestBlockErr: &jsonRPCError{
			Code:    -32000,
			Message: "latest block failed",
		},
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{})

	_, _, err := celestiaDA.generateCertificateValidityProof(context.Background(), makeStandaloneCert())
	require.ErrorContains(t, err, "latest block failed")
}

func TestGenerateCertificateValidityProof_UncommittedHeightClaimsInvalid(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000AC")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: makeStandaloneCert().BlockHeight,
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	valid, _, err := celestiaDA.generateCertificateValidityProof(ctx, makeStandaloneCert())
	require.NoError(t, err)
	require.False(t, valid)
}

func TestGenerateCertificateValidityProof_GetLogsErrorPropagates(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000AF")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
		logsErr: &jsonRPCError{
			Code:    -32000,
			Message: "get logs failed",
		},
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{})

	_, _, err := celestiaDA.generateCertificateValidityProof(context.Background(), makeStandaloneCert())
	require.ErrorContains(t, err, "get logs failed")
}

func TestGenerateCertificateValidityProof_InclusionProofErrorPropagates(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000BB")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
		logs: []ethLogResult{
			makeCommitmentStoredLog(contractAddr, 11_000, 7, 100, 200, [32]byte{}),
		},
	})
	defer server.Close()

	readErr := errors.New("proof backend failed")
	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{err: readErr})

	_, _, err := celestiaDA.generateCertificateValidityProof(context.Background(), makeStandaloneCert())
	require.ErrorIs(t, err, readErr)
}

func TestGenerateCertificateValidityProof_VerifyAttestationFalseClaimsInvalid(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000B0")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
		logs: []ethLogResult{
			makeCommitmentStoredLog(contractAddr, 11_000, 7, 100, 200, [32]byte{}),
		},
		verifyAttestation: false,
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{proof: makeStandaloneDataRootProof()})

	valid, _, err := celestiaDA.generateCertificateValidityProof(context.Background(), makeStandaloneCert())
	require.NoError(t, err)
	require.False(t, valid)
}

func TestGenerateCertificateValidityProof_VerifyAttestationErrorPropagates(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000AD")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
		logs: []ethLogResult{
			makeCommitmentStoredLog(contractAddr, 11_000, 7, 100, 200, [32]byte{}),
		},
		verifyErr: &jsonRPCError{
			Code:    -32000,
			Message: "verify failed",
		},
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{proof: makeStandaloneDataRootProof()})

	_, _, err := celestiaDA.generateCertificateValidityProof(context.Background(), makeStandaloneCert())
	require.ErrorContains(t, err, "verify failed")
}

func TestGenerateCertificateValidityProof_VerifyAttestationTrueReturnsValidProofBytes(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
		logs: []ethLogResult{
			makeCommitmentStoredLog(contractAddr, 11_000, 7, 100, 200, [32]byte{}),
		},
		verifyAttestation: true,
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{proof: makeStandaloneDataRootProof()})

	proof, err := celestiaDA.GenerateCertificateValidityProof(context.Background(), makeStandaloneCert())
	require.NoError(t, err)
	require.Greater(t, len(proof), 2)
	require.Equal(t, byte(0x01), proof[0])
	require.Equal(t, byte(0x01), proof[1])
}

func TestGenerateCertificateValidityProof_NonAttestableCertClaimsInvalid(t *testing.T) {
	t.Parallel()

	t.Run("zero shares length", func(t *testing.T) {
		t.Parallel()

		cert := makeStandaloneCert()
		cert.SharesLength = 0

		valid, _, err := (&CelestiaDA{}).generateCertificateValidityProof(context.Background(), cert)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("zero data root", func(t *testing.T) {
		t.Parallel()

		cert := makeStandaloneCert()
		cert.DataRoot = [32]byte{}

		valid, _, err := (&CelestiaDA{}).generateCertificateValidityProof(context.Background(), cert)
		require.NoError(t, err)
		require.False(t, valid)
	})
}

func TestValidateCertificate_NonAttestableCertClaimsInvalid(t *testing.T) {
	t.Parallel()

	t.Run("zero shares length", func(t *testing.T) {
		t.Parallel()

		cert := makeStandaloneCert()
		cert.SharesLength = 0

		valid, err := (&CelestiaDA{}).validateCertificate(context.Background(), cert)
		require.NoError(t, err)
		require.False(t, valid)
	})

	t.Run("zero data root", func(t *testing.T) {
		t.Parallel()

		cert := makeStandaloneCert()
		cert.DataRoot = [32]byte{}

		valid, err := (&CelestiaDA{}).validateCertificate(context.Background(), cert)
		require.NoError(t, err)
		require.False(t, valid)
	})
}

func TestValidateCertificate_NoBlobstreamEventClaimsInvalid(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000C1")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	valid, err := celestiaDA.validateCertificate(ctx, makeStandaloneCert())
	require.NoError(t, err)
	require.False(t, valid)
}

func TestValidateCertificate_UncommittedHeightClaimsInvalid(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000C2")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: makeStandaloneCert().BlockHeight,
	})
	defer server.Close()

	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	valid, err := celestiaDA.validateCertificate(ctx, makeStandaloneCert())
	require.NoError(t, err)
	require.False(t, valid)
}

func TestValidateCertificate_InclusionProofErrorPropagates(t *testing.T) {
	t.Parallel()

	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000C3")
	server := httptest.NewServer(&fakeEthRPCServer{
		t:                   t,
		contractAddr:        contractAddr,
		latestL1Block:       12_000,
		latestCelestiaBlock: 200,
		logs: []ethLogResult{
			makeCommitmentStoredLog(contractAddr, 11_000, 7, 100, 200, [32]byte{}),
		},
		verifyAttestation: true,
	})
	defer server.Close()

	readErr := context.DeadlineExceeded
	celestiaDA := newStandaloneCelestiaDA(t, server, contractAddr, &fakeBlobstreamReadModule{err: readErr})

	_, err := celestiaDA.validateCertificate(context.Background(), makeStandaloneCert())
	require.ErrorIs(t, err, readErr)
}

func TestGenerateReadPreimageProof_NoBlobstreamEventReturnsError(t *testing.T) {
	t.Parallel()

	fixture := newReadPreimageFixture(t)
	fixture.rpcServer.logs = nil

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := fixture.celestiaDA.GenerateReadPreimageProof(ctx, 0, fixture.certificate)
	require.Error(t, err)
}

func TestGenerateReadPreimageProof_VerifyAttestationFalseReturnsError(t *testing.T) {
	t.Parallel()

	fixture := newReadPreimageFixture(t)
	fixture.rpcServer.verifyAttestation = false

	_, err := fixture.celestiaDA.GenerateReadPreimageProof(context.Background(), 0, fixture.certificate)
	require.ErrorContains(t, err, "certificate validation failed")
}

func TestGenerateReadPreimageProof_HeaderDataRootMismatchReturnsError(t *testing.T) {
	t.Parallel()

	fixture := newReadPreimageFixture(t)
	fixture.certificate.DataRoot[0] ^= 0xFF

	_, err := fixture.celestiaDA.GenerateReadPreimageProof(context.Background(), 0, fixture.certificate)
	require.ErrorContains(t, err, "data root mismatch")
}

func TestGenerateReadPreimageProof_InclusionProofErrorReturnsError(t *testing.T) {
	t.Parallel()

	fixture := newReadPreimageFixture(t)
	readErr := errors.New("proof backend failed")
	fixture.celestiaDA.ReadClient.Blobstream = &fakeBlobstreamReadModule{err: readErr}

	_, err := fixture.celestiaDA.GenerateReadPreimageProof(context.Background(), 0, fixture.certificate)
	require.ErrorIs(t, err, readErr)
}

func TestGenerateReadPreimageProof_ShareRangeProofRetrievalErrorReturnsError(t *testing.T) {
	t.Parallel()

	fixture := newReadPreimageFixture(t)
	fixture.shareModule.getRangeErrOnCall[2] = errors.New("share range proof failed")

	_, err := fixture.celestiaDA.GenerateReadPreimageProof(context.Background(), 0, fixture.certificate)
	require.ErrorContains(t, err, "failed to fetch share range proof")
}

func TestGenerateReadPreimageProof_SuccessLayoutBoundaries(t *testing.T) {
	t.Parallel()

	fixture := newReadPreimageFixtureWithMessage(t, bytes.Repeat([]byte("a"), 1456))
	cases := []struct {
		name           string
		offset         uint64
		wantChunkLen   uint8
		wantShareIndex uint64
		wantShareCount uint8
	}{
		{name: "offset_0", offset: 0, wantChunkLen: 32, wantShareIndex: fixture.certificate.Start, wantShareCount: 1},
		{name: "offset_448", offset: 448, wantChunkLen: 32, wantShareIndex: fixture.certificate.Start, wantShareCount: 2},
		{name: "offset_480", offset: 480, wantChunkLen: 32, wantShareIndex: fixture.certificate.Start + 1, wantShareCount: 1},
		{name: "offset_1440", offset: 1440, wantChunkLen: 16, wantShareIndex: fixture.certificate.Start + 2, wantShareCount: 2},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			proof, err := fixture.celestiaDA.GenerateReadPreimageProof(context.Background(), tc.offset, fixture.certificate)
			require.NoError(t, err)
			require.Greater(t, len(proof), 27)
			require.Equal(t, byte(0x01), proof[0])
			require.EqualValues(t, tc.offset, binary.BigEndian.Uint64(proof[1:9]))
			require.EqualValues(t, 1456, binary.BigEndian.Uint64(proof[9:17]))
			require.Equal(t, tc.wantChunkLen, proof[17])
			require.EqualValues(t, tc.wantShareIndex, binary.BigEndian.Uint64(proof[18:26]))
			require.Equal(t, tc.wantShareCount, proof[26])
		})
	}
}

func TestGenerateReadPreimageProof_UnalignedOffsetReturnsError(t *testing.T) {
	t.Parallel()

	fixture := newReadPreimageFixture(t)

	_, err := fixture.celestiaDA.GenerateReadPreimageProof(context.Background(), 1, fixture.certificate)
	require.ErrorContains(t, err, "offset must be 32-byte aligned")
}

func TestGenerateReadPreimageProof_OffsetOutOfBoundsReturnsError(t *testing.T) {
	t.Parallel()

	fixture := newReadPreimageFixtureWithMessage(t, []byte("short payload"))

	_, err := fixture.celestiaDA.GenerateReadPreimageProof(context.Background(), 32, fixture.certificate)
	require.ErrorContains(t, err, "offset out of bounds")
}
