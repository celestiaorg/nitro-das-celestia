package validator

import (
	"context"
	"encoding/binary"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/util/containers"
)

const ProofVersion = 1

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

		readResult, err := v.reader.Read(ctx, parsed)
		if err != nil {
			return daprovider.PreimageProofResult{Proof: []byte{}}, err
		}

		if len(readResult.Message) == 0 {
			return daprovider.PreimageProofResult{Proof: []byte{}}, nil
		}

		data := readResult.Message

		if offset >= uint64(len(data)) {
			return daprovider.PreimageProofResult{Proof: []byte{}}, nil
		}

		endOffset := offset + 32
		if endOffset > uint64(len(data)) {
			endOffset = uint64(len(data))
		}

		chunk := data[offset:endOffset]

		proof := make([]byte, 1+8+len(chunk))
		proof[0] = ProofVersion
		binary.BigEndian.PutUint64(proof[1:9], uint64(len(chunk)))
		copy(proof[9:], chunk)

		return daprovider.PreimageProofResult{Proof: proof}, nil
	})
}

func (v *CelestiaValidator) GenerateCertificateValidityProof(certificate []byte) containers.PromiseInterface[daprovider.ValidityProofResult] {
	return containers.DoPromise(context.Background(), func(ctx context.Context) (daprovider.ValidityProofResult, error) {
		parsed := &cert.CelestiaDACertV1{}
		if err := parsed.UnmarshalBinary(certificate); err != nil {
			return daprovider.ValidityProofResult{Proof: []byte{0, ProofVersion}}, nil
		}

		readResult, err := v.reader.Read(ctx, parsed)
		if err != nil {
			return daprovider.ValidityProofResult{Proof: []byte{0, ProofVersion}}, nil
		}

		if len(readResult.Message) == 0 {
			return daprovider.ValidityProofResult{Proof: []byte{0, ProofVersion}}, nil
		}

		return daprovider.ValidityProofResult{Proof: []byte{1, ProofVersion}}, nil
	})
}
