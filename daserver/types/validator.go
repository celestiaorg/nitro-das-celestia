package types

import (
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/util/containers"
)

// Validator defines the interface for custom data availability systems.
// This interface is used to generate proofs for DACertificate certificates and preimages.
type Validator interface {
	// GenerateReadPreimageProof generates a proof for a specific preimage at a given offset.
	// The proof format depends on the implementation and must be compatible with the Solidity
	// IDACertificateValidator contract.
	GenerateReadPreimageProof(offset uint64, certificate []byte) containers.PromiseInterface[daprovider.PreimageProofResult]

	// GenerateCertificateValidityProof returns a proof of whether the certificate
	// is valid according to your DA system's rules.
	GenerateCertificateValidityProof(certificate []byte) containers.PromiseInterface[daprovider.ValidityProofResult]
}
