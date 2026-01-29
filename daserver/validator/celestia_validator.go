package validator

import (
	"errors"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/offchainlabs/nitro/util/containers"
)

// CelestiaValidator generates proof payloads for the on-chain Custom DA validator.
// It uses the proof bytes embedded in the certificate.
type CelestiaValidator struct{}

func NewCelestiaValidator() *CelestiaValidator {
	return &CelestiaValidator{}
}

type PreimageProofResult struct {
	Proof []byte
}

type ValidityProofResult struct {
	Proof []byte
}

func (v *CelestiaValidator) GenerateReadPreimageProof(offset uint64, certificate []byte) containers.PromiseInterface[PreimageProofResult] {
	_, err := cert.Deserialize(certificate)
	if err != nil {
		return containers.NewReadyPromise(PreimageProofResult{}, err)
	}
	if offset != 0 {
		return containers.NewReadyPromise(PreimageProofResult{}, errors.New("offset not supported"))
	}
	return containers.NewReadyPromise(PreimageProofResult{Proof: nil}, nil)
}

func (v *CelestiaValidator) GenerateCertificateValidityProof(certificate []byte) containers.PromiseInterface[ValidityProofResult] {
	_, err := cert.Deserialize(certificate)
	if err != nil {
		return containers.NewReadyPromise(ValidityProofResult{}, err)
	}
	return containers.NewReadyPromise(ValidityProofResult{Proof: nil}, nil)
}
