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
	"github.com/offchainlabs/nitro/util/containers"
	"github.com/offchainlabs/nitro/util/pretty"

	"github.com/offchainlabs/nitro/daprovider/daclient"
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
	reader      types.Reader
	writer      types.Writer
	dasClient   *daclient.Client
	headerBytes []byte // supported header bytes
	fallback    bool
}

type CelestiaDASRPCServer struct {
	celestiaReader types.CelestiaReader
	celestiaWriter types.CelestiaWriter
}

func StartDASRPCServer(ctx context.Context, addr string, portNum uint64, rpcServerTimeouts genericconf.HTTPServerTimeoutConfig, rpcServerBodyLimit int, celestiaReader types.CelestiaReader, celestiaWriter types.CelestiaWriter, dasClient *daclient.Client, fallbackEnabled bool) (*http.Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, portNum))
	if err != nil {
		return nil, err
	}
	return StartCelestiaDASRPCServerOnListener(ctx, listener, rpcServerTimeouts, rpcServerBodyLimit, celestiaReader, celestiaWriter, dasClient, fallbackEnabled)
}

func StartCelestiaDASRPCServerOnListener(ctx context.Context, listener net.Listener, rpcServerTimeouts genericconf.HTTPServerTimeoutConfig, rpcServerBodyLimit int, celestiaReader types.CelestiaReader, celestiaWriter types.CelestiaWriter, dasClient *daclient.Client, fallbackEnabled bool) (*http.Server, error) {
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

	// // NOTICE: DA VALIDATOR NOT IMPLEMENTED
	// // Currently the server will handle any da proofs through the GetProof call established in the celestia nitro integration
	// providerServer, err := dapserver.NewServerWithDAPProvider(ctx, nil, types.NewReaderForCelestia(celestiaReader), types.NewWriterForCelestia(celestiaWriter), nil, []byte{CelestiaMessageHeaderFlag}, data_streaming.PayloadCommitmentVerifier())
	// if err != nil {
	// 	return nil, err
	// }

	// TODO: use NewServerWithDAPProvider and add "validator" for the custom da proofs for Nitro
	server := &DaClientServer{
		reader:      types.NewReaderForCelestia(celestiaReader),
		writer:      types.NewWriterForCelestia(celestiaWriter),
		dasClient:   dasClient,
		headerBytes: []byte{CelestiaMessageHeaderFlag, daprovider.DASMessageHeaderFlag},
		fallback:    fallbackEnabled,
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
	} else if daprovider.IsDASMessageHeaderByte(headerByte) {
		log.Info("CelestiaDASRPCServer.RecoverPayload", "dasHeaderByte", headerByte)
		if serv.dasClient == nil {
			return nil, fmt.Errorf("found DAS Message header Byte, but das client for fallback not enabled on server")
		}
		promise := serv.dasClient.RecoverPayload(uint64(batchNum), batchBlockHash, sequencerMsg)
		result, err := promise.Await(ctx)
		if err != nil {
			log.Error("failed to recover payload from DAS batch",
				"batchNum", batchNum,
				"batchBlockHash", batchBlockHash,
				"sequencerMsg", sequencerMsg,
				"err", err)
			return nil, err
		}
		log.Info("Recovered Payload from DAS batch", "len(payload)", len(result.Payload))
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
	log.Info("CelestiaDASRPCServer.CollectPreimages",
		"batchNum", batchNum,
		"batchBlockHash", batchBlockHash,
		"sequencerMsg", sequencerMsg,
	)
	// check the header byte before sending out the call
	headerByte := sequencerMsg[40]
	if IsCelestiaMessageHeaderByte(headerByte) {
		log.Info("CelestiaDASRPCServer.RecoverPayloadFromBatch", "celestiaHeaderByte", headerByte)
		promise := serv.reader.CollectPreimages(uint64(batchNum), batchBlockHash, sequencerMsg)
		result, err := promise.Await(ctx)
		if err != nil {
			log.Error("failed to recover payload from Celestia batch",
				"batchNum", batchNum,
				"batchBlockHash", batchBlockHash,
				"sequencerMsg", sequencerMsg,
				"err", err)
			return nil, err
		}
		log.Info("Recovered Payload from Celestia batch", "len(result.Preimages)", len(result.Preimages))
		return &result, nil
	} else if daprovider.IsDASMessageHeaderByte(headerByte) {
		log.Info("CelestiaDASRPCServer.RecoverPayloadFromBatch", "dasHeaderByte", headerByte)
		if serv.dasClient == nil {
			return nil, fmt.Errorf("found DAS Message header Byte, but das client for fallback not enabled on server")
		}
		promise := serv.dasClient.CollectPreimages(uint64(batchNum), batchBlockHash, sequencerMsg)
		result, err := promise.Await(ctx)
		if err != nil {
			log.Error("failed to recover payload from DAS batch",
				"batchNum", batchNum,
				"batchBlockHash", batchBlockHash,
				"sequencerMsg", sequencerMsg,
				"err", err)
			return nil, err
		}
		log.Info("Recovered Payload from DAS batch", "len(payload)", len(result.Preimages))
		return &result, nil
	}

	return nil, errors.New("unknown batch header byte")
}

func (serv *DaClientServer) Store(
	message hexutil.Bytes,
	timeout hexutil.Uint64,
) containers.PromiseInterface[[]byte] {
	promise, ctx := containers.NewPromiseWithContext[[]byte](context.Background())
	go func() {
		cert, err := serv.writer.Store(message, uint64(timeout)).Await(ctx)
		if err != nil {
			if serv.fallback && serv.dasClient != nil {
				log.Info("Falling back to write data to Anytrust DAS")
				cert, err = serv.dasClient.Store(message, uint64(timeout)).Await(ctx)
				if err != nil {
					promise.ProduceError(err)
				}
				log.Info("Succesfully wrote data to anytrust daprovider", "result", cert)
			} else {
				promise.ProduceError(err)
			}
			promise.ProduceError(err)
		} else {
			log.Info("Succesfully wrote data to Celestia", "result", cert)
			promise.Produce(cert)
		}
	}()
	return promise
}

func (serv *DaClientServer) GetSupportedHeaderBytes(ctx context.Context) (*server_api.SupportedHeaderBytesResult, error) {
	return &server_api.SupportedHeaderBytesResult{
		HeaderBytes: serv.headerBytes,
	}, nil
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
