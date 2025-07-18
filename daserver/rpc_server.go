package das

import (
	"context"
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

	"github.com/offchainlabs/nitro/daprovider/daclient"

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
	reader    types.Reader
	writer    types.Writer
	dasClient *daclient.Client
	fallback  bool
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
	err := rpcServer.RegisterName("celestia", &CelestiaDASRPCServer{
		celestiaReader: celestiaReader,
		celestiaWriter: celestiaWriter,
	})

	if err != nil {
		return nil, err
	}

	server := &DaClientServer{
		reader:    types.NewReaderForCelestia(celestiaReader),
		writer:    types.NewWriterForCelestia(celestiaWriter),
		dasClient: dasClient,
		fallback:  fallbackEnabled,
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
	log.Trace("celestiaDasRpc.CelestiaDASRPCServer.Read", "blob pointer", blobPointer, "this", serv)
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

func (serv *DaClientServer) RecoverPayloadFromBatch(
	ctx context.Context,
	batchNum hexutil.Uint64,
	batchBlockHash common.Hash,
	sequencerMsg hexutil.Bytes,
	preimages daprovider.PreimagesMap,
	validateSeqMsg bool,
) (*types.RecoverPayloadFromBatchResult, error) {
	// check the header byte before sending out the call

	headerByte := sequencerMsg[40]
	if IsCelestiaMessageHeaderByte(headerByte) {
		payload, preimages, err := serv.reader.RecoverPayloadFromBatch(ctx, uint64(batchNum), batchBlockHash, sequencerMsg, preimages, validateSeqMsg)
		if err != nil {
			return nil, err
		}
		return &types.RecoverPayloadFromBatchResult{
			Payload:   payload,
			Preimages: preimages,
		}, nil
	} else if daprovider.IsDASMessageHeaderByte(headerByte) {
		payload, preimages, err := serv.dasClient.RecoverPayloadFromBatch(ctx, uint64(batchNum), batchBlockHash, sequencerMsg, preimages, validateSeqMsg)
		if err != nil {
			return nil, err
		}
		return &types.RecoverPayloadFromBatchResult{
			Payload:   payload,
			Preimages: preimages,
		}, nil
	}

	return nil, errors.New("unknown batch header byte")
}

func (serv *DaClientServer) IsValidHeaderByte(ctx context.Context, headerByte byte) (*types.IsValidHeaderByteResult, error) {
	return &types.IsValidHeaderByteResult{IsValid: serv.reader.IsValidHeaderByte(ctx, headerByte) || serv.dasClient.IsValidHeaderByte(ctx, headerByte)}, nil
}

func (serv *DaClientServer) Store(
	ctx context.Context,
	message hexutil.Bytes,
	timeout hexutil.Uint64,
	disableFallbackStoreDataOnChain bool,
) (*types.StoreResult, error) {
	result, err := serv.writer.Store(ctx, message, uint64(timeout), disableFallbackStoreDataOnChain)
	if err != nil {
		// fallback to das
		if serv.fallback {
			log.Info("Falling back to write data to Anytrust DAS")
			result, err = serv.dasClient.Store(ctx, message, uint64(timeout), disableFallbackStoreDataOnChain)
			if err != nil {
				return nil, err
			}
			log.Info("Succesfully wrote data to anytrust daprovider", "result", result)
		} else {
			return nil, err
		}
	}
	return &types.StoreResult{SerializedResult: result}, nil
}
