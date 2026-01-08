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
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/offchainlabs/nitro/util/pretty"
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

// DAProviderServer implements the Nitro v3.9.0+ External DA Provider interface
type DAProviderServer struct {
	celestiaReader types.CelestiaReader
	celestiaWriter types.CelestiaWriter
}

// CelestiaDASRPCServer provides low-level Celestia RPC methods (celestia namespace)
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
	rpcServer := rpc.NewServer()
	if rpcServerBodyLimit > 0 {
		rpcServer.SetHTTPBodyLimit(rpcServerBodyLimit)
	}

	// Register celestia namespace (low-level Celestia operations)
	celestiaServer := &CelestiaDASRPCServer{
		celestiaReader: celestiaReader,
		celestiaWriter: celestiaWriter,
	}
	if err := rpcServer.RegisterName("celestia", celestiaServer); err != nil {
		return nil, err
	}

	// Register daprovider namespace (Nitro v3.9.0+ interface)
	daProviderServer := &DAProviderServer{
		celestiaReader: celestiaReader,
		celestiaWriter: celestiaWriter,
	}
	if err := rpcServer.RegisterName("daprovider", daProviderServer); err != nil {
		return nil, err
	}

	// Create HTTP mux with health check and RPC handler
	mux := http.NewServeMux()

	// Health check endpoint for Docker/K8s
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// RPC handler for all other requests
	mux.Handle("/", rpcServer)

	srv := &http.Server{
		Handler:           mux,
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

// =============================================================================
// Nitro v3.9.0+ DA Provider Interface (daprovider namespace)
// =============================================================================

// GetSupportedHeaderBytes returns the header byte(s) that identify this DA provider's certificates
func (s *DAProviderServer) GetSupportedHeaderBytes(ctx context.Context) (*types.SupportedHeaderBytesResult, error) {
	log.Debug("daprovider.GetSupportedHeaderBytes called")
	return &types.SupportedHeaderBytesResult{
		HeaderBytes: []byte{types.CelestiaMessageHeaderFlag},
	}, nil
}

// GetMaxMessageSize returns the maximum message size this DA provider can accept
func (s *DAProviderServer) GetMaxMessageSize(ctx context.Context) (*types.MaxMessageSizeResult, error) {
	log.Debug("daprovider.GetMaxMessageSize called")
	return &types.MaxMessageSizeResult{
		MaxSize: CelestiaMaxBlobSize,
	}, nil
}

// Store stores batch data to Celestia and returns a serialized DA certificate
func (s *DAProviderServer) Store(
	ctx context.Context,
	message hexutil.Bytes,
	timeout hexutil.Uint64,
) (*types.StoreResult, error) {
	log.Info("daprovider.Store", "messageLen", len(message), "timeout", timeout)
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

	if s.celestiaWriter == nil {
		return nil, errors.New("writer not configured")
	}

	// Check message size - use exact error string that Nitro matches for batch resize
	if len(message) > CelestiaMaxBlobSize {
		log.Warn("daprovider.Store message too large", "size", len(message), "max", CelestiaMaxBlobSize)
		return nil, errors.New("message too large for current DA backend")
	}

	// Store to Celestia - returns certificate with header byte prepended
	cert, err := s.celestiaWriter.Store(ctx, message)
	if err != nil {
		log.Error("daprovider.Store failed", "err", err)
		// Use exact error string that Nitro matches for fallback to next writer
		return nil, fmt.Errorf("DA provider requests fallback to next writer: %w", err)
	}

	rpcStoreStoredBytesGauge.Inc(int64(len(message)))
	success = true

	log.Info("daprovider.Store success", "certLen", len(cert))
	return &types.StoreResult{
		SerializedDACert: cert,
	}, nil
}

// RecoverPayload recovers the original batch payload from a DA certificate
func (s *DAProviderServer) RecoverPayload(
	ctx context.Context,
	batchNum hexutil.Uint64,
	batchBlockHash common.Hash,
	sequencerMsg hexutil.Bytes,
) (*types.PayloadResult, error) {
	log.Info("daprovider.RecoverPayload",
		"batchNum", batchNum,
		"batchBlockHash", batchBlockHash.Hex(),
		"sequencerMsgLen", len(sequencerMsg),
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

	payload, err := types.RecoverPayloadFromCelestia(ctx, sequencerMsg, s.celestiaReader)
	if err != nil {
		log.Error("daprovider.RecoverPayload failed", "err", err)
		return nil, err
	}

	rpcReadReadBytesGauge.Inc(int64(len(payload)))
	success = true

	log.Info("daprovider.RecoverPayload success", "payloadLen", len(payload))
	return &types.PayloadResult{
		Payload: payload,
	}, nil
}

// CollectPreimages collects preimages needed for fraud proofs from the batch data
func (s *DAProviderServer) CollectPreimages(
	ctx context.Context,
	batchNum hexutil.Uint64,
	batchBlockHash common.Hash,
	sequencerMsg hexutil.Bytes,
) (*types.PreimagesResult, error) {
	log.Info("daprovider.CollectPreimages",
		"batchNum", batchNum,
		"batchBlockHash", batchBlockHash.Hex(),
		"sequencerMsgLen", len(sequencerMsg),
	)

	preimages, err := types.CollectPreimagesFromCelestia(ctx, sequencerMsg, s.celestiaReader)
	if err != nil {
		log.Error("daprovider.CollectPreimages failed", "err", err)
		return nil, err
	}

	log.Info("daprovider.CollectPreimages success", "preimageTypes", len(preimages))
	return &types.PreimagesResult{
		Preimages: preimages,
	}, nil
}

// GenerateReadPreimageProof generates a proof for reading a specific preimage at a given offset
func (s *DAProviderServer) GenerateReadPreimageProof(
	ctx context.Context,
	offset hexutil.Uint64,
	certificate hexutil.Bytes,
) (*types.ReadPreimageProofResult, error) {
	log.Info("daprovider.GenerateReadPreimageProof",
		"offset", offset,
		"certLen", len(certificate),
	)
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

	// Parse the certificate to get blob pointer
	if len(certificate) < 1 {
		return nil, errors.New("certificate too short")
	}

	// Skip header byte and parse blob pointer
	blobPointer := types.BlobPointer{}
	if err := blobPointer.UnmarshalBinary(certificate[1:]); err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Get proof using existing GetProof infrastructure
	// The offset parameter indicates which share we need the proof for
	proof, err := s.celestiaReader.GetProof(ctx, certificate)
	if err != nil {
		log.Error("daprovider.GenerateReadPreimageProof failed", "err", err)
		return nil, err
	}

	rpcProofBytesGauge.Inc(int64(len(proof)))
	success = true

	log.Info("daprovider.GenerateReadPreimageProof success", "proofLen", len(proof))
	return &types.ReadPreimageProofResult{
		Proof: proof,
	}, nil
}

// GenerateCertificateValidityProof generates a proof that the DA certificate is valid
func (s *DAProviderServer) GenerateCertificateValidityProof(
	ctx context.Context,
	certificate hexutil.Bytes,
) (*types.CertificateValidityProofResult, error) {
	log.Info("daprovider.GenerateCertificateValidityProof", "certLen", len(certificate))
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

	// Use existing GetProof which generates Blobstream inclusion proof
	proof, err := s.celestiaReader.GetProof(ctx, certificate)
	if err != nil {
		log.Error("daprovider.GenerateCertificateValidityProof failed", "err", err)
		return nil, err
	}

	rpcProofBytesGauge.Inc(int64(len(proof)))
	success = true

	log.Info("daprovider.GenerateCertificateValidityProof success", "proofLen", len(proof))
	return &types.CertificateValidityProofResult{
		Proof: proof,
	}, nil
}

// =============================================================================
// Low-level Celestia RPC methods (celestia namespace)
// =============================================================================

func (serv *CelestiaDASRPCServer) Store(ctx context.Context, message hexutil.Bytes) ([]byte, error) {
	log.Trace("celestia.Store", "message", pretty.FirstFewBytes(message), "messageLen", len(message))
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

	if serv.celestiaWriter == nil {
		return nil, errors.New("writer not configured")
	}

	result, err := serv.celestiaWriter.Store(ctx, message)
	if err != nil {
		return nil, err
	}
	rpcStoreStoredBytesGauge.Inc(int64(len(message)))
	success = true
	return result, nil
}

func (serv *CelestiaDASRPCServer) Read(ctx context.Context, blobPointer *types.BlobPointer) (*types.ReadResult, error) {
	log.Info("celestia.Read",
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
	log.Trace("celestia.GetProof", "message", pretty.FirstFewBytes(msg), "messageLen", len(msg))
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

