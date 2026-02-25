package validator

import (
	"context"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/util/containers"
)

type CelestiaValidator struct {
	reader types.CelestiaReader
}

func NewCelestiaValidator(reader types.CelestiaReader) *CelestiaValidator {
	return &CelestiaValidator{reader: reader}
}

func (v *CelestiaValidator) GenerateReadPreimageProof(offset uint64, certificate []byte) containers.PromiseInterface[daprovider.PreimageProofResult] {
	return containers.DoPromise(context.Background(), func(ctx context.Context) (daprovider.PreimageProofResult, error) {
		parsed := &cert.CelestiaDACertV1{}
		if err := parsed.UnmarshalBinary(certificate); err != nil {
			return daprovider.PreimageProofResult{Proof: []byte{}}, err
		}

		proof, err := v.reader.GenerateReadPreimageProof(ctx, offset, parsed)
		if err != nil {
			return daprovider.PreimageProofResult{Proof: []byte{}}, err
		}

		return daprovider.PreimageProofResult{Proof: proof}, nil
	})
}

func (v *CelestiaValidator) GenerateCertificateValidityProof(certificate []byte) containers.PromiseInterface[daprovider.ValidityProofResult] {
	return containers.DoPromise(context.Background(), func(ctx context.Context) (daprovider.ValidityProofResult, error) {
		parsed := &cert.CelestiaDACertV1{}
		if err := parsed.UnmarshalBinary(certificate); err != nil {
			return daprovider.ValidityProofResult{Proof: []byte{0, 0x01}}, nil
		}

		proof, err := v.reader.GenerateCertificateValidityProof(ctx, parsed)
		if err != nil {
			return daprovider.ValidityProofResult{Proof: []byte{}}, err
		}

		return daprovider.ValidityProofResult{Proof: proof}, nil
	})
}
