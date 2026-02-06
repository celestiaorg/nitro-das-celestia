package das

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/util/pretty"

	"github.com/offchainlabs/nitro/daprovider/data_streaming"
	"github.com/offchainlabs/nitro/daprovider/server_api"

	"github.com/ethereum/go-ethereum/rpc"
)

var (
	rpcStoreRequestGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/store/requests", nil)
	rpcStoreSuccessGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/store/success", nil)
	rpcStoreFailureGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/store/failure", nil)
	rpcStoreStoredBytesGauge  = metrics.NewRegisteredGauge("celestia/das/rpc/store/bytes", nil)
	rpcStoreDurationHistogram = metrics.NewRegisteredHistogram("celestia/das/rpc/store/duration", nil, metrics.NewExpDecaySample(1024, 0.015))

	rpcReadRequestGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/read/requests", nil)
	rpcReadSuccessGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/read/success", nil)
	rpcReadFailureGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/read/failure", nil)
	rpcReadReadBytesGauge    = metrics.NewRegisteredGauge("celestia/das/rpc/read/bytes", nil)
	rpcReadDurationHistogram = metrics.NewRegisteredHistogram("celestia/das/rpc/read/duration", nil, metrics.NewExpDecaySample(1024, 0.015))

	rpcProofRequestGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/proof/requests", nil)
	rpcProofSuccessGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/proof/success", nil)
	rpcProofFailureGauge      = metrics.NewRegisteredGauge("celestia/das/rpc/proof/failure", nil)
	rpcProofBytesGauge        = metrics.NewRegisteredGauge("celestia/das/rpc/proof/bytes", nil)
	rpcProofDurationHistogram = metrics.NewRegisteredHistogram("celestia/das/rpc/proof/duration", nil, metrics.NewExpDecaySample(1024, 0.015))
)

type DaClientServer struct {
	reader       types.Reader
	writer       types.Writer
	dataReceiver *data_streaming.DataStreamReceiver
	headerBytes  []byte // supported header bytes (TODO: Cleanup)
}

type CelestiaDASRPCServer struct {
	celestiaReader types.CelestiaReader
	celestiaWriter types.CelestiaWriter
}

func StartDASRPCServer(ctx context.Context, addr string, portNum uint64, rpcServerTimeouts genericconf.HTTPServerTimeoutConfig, rpcServerBodyLimit int, celestiaReader types.CelestiaReader, celestiaWriter types.CelestiaWriter) (*http.Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, portNum))
	if err != nil {
		return nil, err
	}
	return StartCelestiaDASRPCServerOnListener(ctx, listener, rpcServerTimeouts, rpcServerBodyLimit, celestiaReader, celestiaWriter)
}

func StartCelestiaDASRPCServerOnListener(ctx context.Context, listener net.Listener, rpcServerTimeouts genericconf.HTTPServerTimeoutConfig, rpcServerBodyLimit int, celestiaReader types.CelestiaReader, celestiaWriter types.CelestiaWriter) (*http.Server, error) {
	if celestiaWriter == nil {
		return nil, errors.New("no writer backend was configured for Celestia DAS RPC server. Please setup a node and ensure a connections is being established")
	}
	rpcServer := rpc.NewServer()
	if rpcServerBodyLimit > 0 {
		rpcServer.SetHTTPBodyLimit(rpcServerBodyLimit)
	}
	// pass components needed to setup new da provider api
	// build read / write / validator components separetely
	err := rpcServer.RegisterName("celestia", &CelestiaDASRPCServer{
		celestiaReader: celestiaReader,
		celestiaWriter: celestiaWriter,
	})

	if err != nil {
		return nil, err
	}

	var dataStreamReceiver *data_streaming.DataStreamReceiver
	if celestiaWriter != nil {
		dataStreamReceiver = data_streaming.NewDefaultDataStreamReceiver(data_streaming.PayloadCommitmentVerifier())
		dataStreamReceiver.Start(ctx)
	}

	// // NOTICE: DA VALIDATOR NOT IMPLEMENTED
	// // Currently the server will handle any da proofs through the GetProof call established in the celestia nitro integration
	// providerServer, err := dapserver.NewServerWithDAPProvider(ctx, nil, types.NewReaderForCelestia(celestiaReader), types.NewWriterForCelestia(celestiaWriter), nil, []byte{CelestiaMessageHeaderFlag}, data_streaming.PayloadCommitmentVerifier())
	// if err != nil {
	// 	return nil, err
	// }

	// TODO: use NewServerWithDAPProvider and add "validator" for the custom da proofs for Nitro
	server := &DaClientServer{
		reader:       types.NewReaderForCelestia(celestiaReader),
		writer:       types.NewWriterForCelestia(celestiaWriter),
		dataReceiver: dataStreamReceiver,
		headerBytes:  []byte{CelestiaMessageHeaderFlag},
	}

	err = rpcServer.RegisterName("daprovider", server)

	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Handler:           rpcServer,
		ReadTimeout:       rpcServerTimeouts.ReadTimeout,
		ReadHeaderTimeout: rpcServerTimeouts.ReadHeaderTimeout,
		WriteTimeout:      rpcServerTimeouts.WriteTimeout,
		IdleTimeout:       rpcServerTimeouts.IdleTimeout,
	}

	go func() {
		err := srv.Serve(listener)
		if err != nil {
			return
		}
	}()
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	return srv, nil
}

func (serv *CelestiaDASRPCServer) Store(ctx context.Context, message hexutil.Bytes) ([]byte, error) {
	log.Trace("celestiaDasRpc.CelestiaDASRPCServer.Store", "message", pretty.FirstFewBytes(message), "message length", len(message), "this", serv)
	rpcStoreRequestGauge.Inc(1)
	start := time.Now()
	success := false
	defer func() {
		if success {
			rpcStoreSuccessGauge.Inc(1)
		} else {
			rpcStoreFailureGauge.Inc(1)
		}
		rpcStoreDurationHistogram.Update(time.Since(start).Nanoseconds())
	}()

	result, err := serv.celestiaWriter.Store(ctx, message)
	if err != nil {
		return nil, err
	}
	rpcStoreStoredBytesGauge.Inc(int64(len(message)))
	success = true
	return result, nil
}

func (serv *CelestiaDASRPCServer) Read(ctx context.Context, blobPointer *types.BlobPointer) (*types.ReadResult, error) {
	log.Info("CelestiaDASRPCServer.Read",
		"blockHeight", blobPointer.BlockHeight,
		"start", blobPointer.Start,
		"sharesLength", blobPointer.SharesLength,
		"dataRoot", hex.EncodeToString(blobPointer.DataRoot[:]),
		"txCommitment", hex.EncodeToString(blobPointer.TxCommitment[:]),
	)
	rpcReadRequestGauge.Inc(1)
	start := time.Now()
	success := false
	defer func() {
		if success {
			rpcReadSuccessGauge.Inc(1)
		} else {
			rpcReadFailureGauge.Inc(1)
		}
		rpcReadDurationHistogram.Update(time.Since(start).Nanoseconds())
	}()

	result, err := serv.celestiaReader.Read(ctx, blobPointer)
	if err != nil {
		return nil, err
	}
	rpcReadReadBytesGauge.Inc(int64(len(result.Message)))
	success = true
	return result, nil
}

func (serv *CelestiaDASRPCServer) GetProof(ctx context.Context, msg []byte) ([]byte, error) {
	log.Trace("celestiaDasRpc.CelestiaDASRPCServer.GetProof", "message", pretty.FirstFewBytes(msg), "message length", len(msg), "this", serv)
	rpcProofRequestGauge.Inc(1)
	start := time.Now()
	success := false
	defer func() {
		if success {
			rpcProofSuccessGauge.Inc(1)
		} else {
			rpcProofFailureGauge.Inc(1)
		}
		rpcProofDurationHistogram.Update(time.Since(start).Nanoseconds())
	}()

	proof, err := serv.celestiaReader.GetProof(ctx, msg)
	if err != nil {
		return nil, err
	}
	rpcProofBytesGauge.Inc(int64(len(proof)))
	success = true
	return proof, nil
}

// TODO: Add metrics to the new DA API methods

func (serv *DaClientServer) RecoverPayload(
	ctx context.Context,
	batchNum hexutil.Uint64,
	batchBlockHash common.Hash,
	sequencerMsg hexutil.Bytes,
) (*daprovider.PayloadResult, error) {
	log.Info("CelestiaDASRPCServer.RecoverPayload",
		"batchNum", batchNum,
		"batchBlockHash", batchBlockHash,
		"sequencerMsg", sequencerMsg,
	)
	// check the header byte before sending out the call
	headerByte := sequencerMsg[40]
	if IsCelestiaMessageHeaderByte(headerByte) {
		log.Info("CelestiaDASRPCServer.RecoverPayload", "celestiaHeaderByte", headerByte)
		promise := serv.reader.RecoverPayload(uint64(batchNum), batchBlockHash, sequencerMsg)
		result, err := promise.Await(ctx)
		if err != nil {
			log.Error("failed to recover payload from Celestia batch",
				"batchNum", batchNum,
				"batchBlockHash", batchBlockHash,
				"sequencerMsg", sequencerMsg,
				"err", err)
			return nil, err
		}
		log.Info("Recovered Payload from Celestia batch", "len(result.Payload)", len(result.Payload))
		return &result, nil
	}

	return nil, errors.New("unknown batch header byte")
}

func (serv *DaClientServer) CollectPreimages(
	ctx context.Context,
	batchNum hexutil.Uint64,
	batchBlockHash common.Hash,
	sequencerMsg hexutil.Bytes,
) (*daprovider.PreimagesResult, error) {
	promise := serv.reader.CollectPreimages(uint64(batchNum), batchBlockHash, sequencerMsg)
	result, err := promise.Await(ctx)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (serv *DaClientServer) Store(
	message hexutil.Bytes,
	timeout hexutil.Uint64,
) (*server_api.StoreResult, error) {
	cert, err := serv.writer.Store(message, uint64(timeout)).Await(context.Background())
	if err != nil {
		// check if theres an error to log out on the da server
		log.Error("daprovider_store: error storing data on celestia", "err", err)
	}
	// will return the appropirate rpc result and error if any
	return &server_api.StoreResult{SerializedDACert: cert}, err
}

func (serv *DaClientServer) GetSupportedHeaderBytes(ctx context.Context) (*server_api.SupportedHeaderBytesResult, error) {
	return &server_api.SupportedHeaderBytesResult{
		HeaderBytes: serv.headerBytes,
	}, nil
}

// WriterServer methods (Data Stream API)

func (s *DaClientServer) StartChunkedStore(ctx context.Context, timestamp, nChunks, chunkSize, totalSize, timeout hexutil.Uint64, sig hexutil.Bytes) (*data_streaming.StartStreamingResult, error) {
	return s.dataReceiver.StartReceiving(ctx, uint64(timestamp), uint64(nChunks), uint64(chunkSize), uint64(totalSize), uint64(timeout), sig)
}

func (s *DaClientServer) SendChunk(ctx context.Context, messageId, chunkId hexutil.Uint64, chunk hexutil.Bytes, sig hexutil.Bytes) error {
	return s.dataReceiver.ReceiveChunk(ctx, data_streaming.MessageId(messageId), uint64(chunkId), chunk, sig)
}

func (s *DaClientServer) CommitChunkedStore(ctx context.Context, messageId hexutil.Uint64, sig hexutil.Bytes) (*server_api.StoreResult, error) {
	message, timeout, _, err := s.dataReceiver.FinalizeReceiving(ctx, data_streaming.MessageId(messageId), sig)
	if err != nil {
		return nil, err
	}

	// Use Store with fallback
	serializedDACert, err := s.writer.Store(message, timeout).Await(ctx)
	if err != nil {
		log.Error("Found error when trying to store chunk", "err", err)
		return nil, err
	}
	log.Info("Certificate and error", "cert", serializedDACert, "err", err)
	return &server_api.StoreResult{SerializedDACert: serializedDACert}, err
}

// TODO: Add
// func (s *ValidatorServer) GenerateReadPreimageProof(ctx context.Context, certHash common.Hash, offset hexutil.Uint64, certificate hexutil.Bytes) (*server_api.GenerateReadPreimageProofResult, error) {
// 	// #nosec G115
// 	promise := s.validator.GenerateReadPreimageProof(certHash, uint64(offset), certificate)
// 	result, err := promise.Await(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &server_api.GenerateReadPreimageProofResult{Proof: hexutil.Bytes(result.Proof)}, nil
// }

// func (s *ValidatorServer) GenerateCertificateValidityProof(ctx context.Context, certificate hexutil.Bytes) (*server_api.GenerateCertificateValidityProofResult, error) {
// 	// #nosec G115
// 	promise := s.validator.GenerateCertificateValidityProof(certificate)
// 	result, err := promise.Await(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &server_api.GenerateCertificateValidityProofResult{Proof: hexutil.Bytes(result.Proof)}, nil
// }
