package validator

import (
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/util/containers"
)

// CelestiaValidator generates proof payloads for the on-chain Custom DA validator.
// It uses the proof bytes embedded in the certificate.
type CelestiaValidator struct{}

func NewCelestiaValidator() *CelestiaValidator {
	return &CelestiaValidator{}
}

func (v *CelestiaValidator) GenerateReadPreimageProof(offset uint64, certificate []byte) containers.PromiseInterface[daprovider.PreimageProofResult] {
	parsed := &cert.CelestiaDACertV1{}
	if err := parsed.UnmarshalBinary(certificate); err != nil {
		return containers.NewReadyPromise(daprovider.PreimageProofResult{}, err)
	}
	// For Celestia, we return an empty proof since the actual verification
	// is done via the GetProof method which generates Celestia-specific proofs
	// The proof enhancer will handle the certificate and offset
	return containers.NewReadyPromise(daprovider.PreimageProofResult{Proof: []byte{}}, nil)
}

func (v *CelestiaValidator) GenerateCertificateValidityProof(certificate []byte) containers.PromiseInterface[daprovider.ValidityProofResult] {
	parsed := &cert.CelestiaDACertV1{}
	if err := parsed.UnmarshalBinary(certificate); err != nil {
		// Invalid certificate format - return invalid proof (claimedValid=0)
		// Per DA API spec, we should NOT return an error for invalid certificates
		return containers.NewReadyPromise(daprovider.ValidityProofResult{Proof: []byte{0, 0x01}}, nil)
	}
	// TODO: This currently only validates certificate format.
	// A certificate should only be considered valid (claimedValid=1) if:
	// - The block height exists on Celestia
	// - The data root matches Celestia's header at that height
	// - The tx commitment is valid
	// TODO: This should query Celestia to verify data actually exists
	// before returning claimedValid=1. Currently returns valid for any well-formed cert.
	return containers.NewReadyPromise(daprovider.ValidityProofResult{Proof: []byte{1, 0x01}}, nil)
}
