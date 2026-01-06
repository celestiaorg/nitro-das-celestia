package types

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/offchainlabs/nitro/daprovider"
)

// SupportedHeaderBytesResult is returned by getSupportedHeaderBytes
type SupportedHeaderBytesResult struct {
	HeaderBytes hexutil.Bytes `json:"headerBytes"`
}

// MaxMessageSizeResult is returned by getMaxMessageSize
type MaxMessageSizeResult struct {
	MaxSize int `json:"maxSize"`
}

// StoreResult is returned by store
type StoreResult struct {
	SerializedDACert hexutil.Bytes `json:"serialized-da-cert"`
}

// PayloadResult is returned by recoverPayload
type PayloadResult struct {
	Payload hexutil.Bytes `json:"Payload"`
}

// PreimagesResult is returned by collectPreimages
type PreimagesResult struct {
	Preimages daprovider.PreimagesMap `json:"Preimages"`
}

// ReadPreimageProofResult is returned by generateReadPreimageProof
type ReadPreimageProofResult struct {
	Proof hexutil.Bytes `json:"proof"`
}

// CertificateValidityProofResult is returned by generateCertificateValidityProof
type CertificateValidityProofResult struct {
	Proof hexutil.Bytes `json:"proof"`
}
