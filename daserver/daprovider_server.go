package das

import (
	"context"
	"errors"

	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/celestiaorg/nitro-das-celestia/daserver/validator"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/daprovider/daclient"
)

type DaproviderServer struct {
	reader         types.Reader
	writer         types.Writer
	validator      *validator.CelestiaValidator
	dupeDAS        *daclient.Client
	useDASFallback bool
}

type payloadResult struct {
	Payload hexutil.Bytes `json:"payload,omitempty"`
}

type preimagesResult struct {
	Preimages daprovider.PreimagesMap `json:"preimages,omitempty"`
}

type payloadAndPreimagesResult struct {
	Payload   hexutil.Bytes           `json:"payload,omitempty"`
	Preimages daprovider.PreimagesMap `json:"preimages,omitempty"`
}

type supportedHeaderBytesResult struct {
	HeaderBytes hexutil.Bytes `json:"headerBytes,omitempty"`
}

type maxMessageSizeResult struct {
	MaxSize int `json:"maxSize"`
}

type storeResult struct {
	SerializedDACert hexutil.Bytes `json:"serialized-da-cert,omitempty"`
}

type preimageProofResult struct {
	Proof hexutil.Bytes `json:"proof,omitempty"`
}

type validityProofResult struct {
	Proof hexutil.Bytes `json:"proof,omitempty"`
}

func (s *DaproviderServer) GetSupportedHeaderBytes(ctx context.Context) (*supportedHeaderBytesResult, error) {
	if s.reader == nil {
		return nil, errors.New("reader not configured")
	}
	return &supportedHeaderBytesResult{HeaderBytes: hexutil.Bytes{s.reader.HeaderByte()}}, nil
}

func (s *DaproviderServer) RecoverPayload(ctx context.Context, batchNum hexutil.Uint64, batchBlockHash common.Hash, sequencerMsg hexutil.Bytes) (*payloadResult, error) {
	payload, _, err := s.reader.RecoverPayloadFromBatch(ctx, uint64(batchNum), batchBlockHash, sequencerMsg, nil, true)
	if err != nil {
		return nil, err
	}
	return &payloadResult{Payload: payload}, nil
}

func (s *DaproviderServer) CollectPreimages(ctx context.Context, batchNum hexutil.Uint64, batchBlockHash common.Hash, sequencerMsg hexutil.Bytes) (*preimagesResult, error) {
	_, preimages, err := s.reader.RecoverPayloadFromBatch(ctx, uint64(batchNum), batchBlockHash, sequencerMsg, make(daprovider.PreimagesMap), true)
	if err != nil {
		return nil, err
	}
	return &preimagesResult{Preimages: preimages}, nil
}

func (s *DaproviderServer) RecoverPayloadAndPreimages(ctx context.Context, batchNum hexutil.Uint64, batchBlockHash common.Hash, sequencerMsg hexutil.Bytes) (*payloadAndPreimagesResult, error) {
	payload, preimages, err := s.reader.RecoverPayloadFromBatch(ctx, uint64(batchNum), batchBlockHash, sequencerMsg, make(daprovider.PreimagesMap), true)
	if err != nil {
		return nil, err
	}
	return &payloadAndPreimagesResult{Payload: payload, Preimages: preimages}, nil
}

func (s *DaproviderServer) GenerateReadPreimageProof(ctx context.Context, offset hexutil.Uint64, certificate hexutil.Bytes) (*preimageProofResult, error) {
	if s.validator == nil {
		return nil, errors.New("validator not configured")
	}
	res, err := s.validator.GenerateReadPreimageProof(uint64(offset), certificate).Await(ctx)
	if err != nil {
		return nil, err
	}
	return &preimageProofResult{Proof: hexutil.Bytes(res.Proof)}, nil
}

func (s *DaproviderServer) GenerateCertificateValidityProof(ctx context.Context, certificate hexutil.Bytes) (*validityProofResult, error) {
	if s.validator == nil {
		return nil, errors.New("validator not configured")
	}
	res, err := s.validator.GenerateCertificateValidityProof(certificate).Await(ctx)
	if err != nil {
		return nil, err
	}
	return &validityProofResult{Proof: hexutil.Bytes(res.Proof)}, nil
}

func (s *DaproviderServer) Store(ctx context.Context, message hexutil.Bytes, timeout hexutil.Uint64) (*storeResult, error) {
	if s.writer == nil {
		return nil, errors.New("writer not configured")
	}
	result, err := s.writer.Store(ctx, message, uint64(timeout))
	if err != nil {
		if s.useDASFallback && s.dupeDAS != nil {
			log.Info("Falling back to AnyTrust DAS store")
			fallback, fbErr := s.dupeDAS.Store(ctx, message, uint64(timeout), false)
			if fbErr != nil {
				return nil, fbErr
			}
			return &storeResult{SerializedDACert: fallback}, nil
		}
		return nil, err
	}
	return &storeResult{SerializedDACert: result}, nil
}

func (s *DaproviderServer) GetMaxMessageSize(ctx context.Context) (*maxMessageSizeResult, error) {
	if s.writer == nil {
		return nil, errors.New("writer not configured")
	}
	maxSize, err := s.writer.GetMaxMessageSize(ctx)
	if err != nil {
		return nil, err
	}
	return &maxMessageSizeResult{MaxSize: maxSize}, nil
}

// NewDaproviderServer constructs a Custom DA provider server that reuses existing Celestia reader/writer.
func NewDaproviderServer(reader types.Reader, writer types.Writer, validator *validator.CelestiaValidator, dasClient *daclient.Client, fallback bool) *DaproviderServer {
	return &DaproviderServer{
		reader:         reader,
		writer:         writer,
		validator:      validator,
		dupeDAS:        dasClient,
		useDASFallback: fallback,
	}
}
