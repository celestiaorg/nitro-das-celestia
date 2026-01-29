package types

import (
	"errors"

	"github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
)

func BuildCelestiaCertificate(pointer BlobPointer, namespace []byte, proof []byte) ([]byte, error) {
	if len(namespace) < share.NamespaceSize {
		return nil, errors.New("namespace too short")
	}
	var ns [32]byte
	copy(ns[:], namespace[:share.NamespaceSize])

	certData := &cert.CelestiaDACertV1{
		DataRoot:     pointer.DataRoot,
		Namespace:    ns,
		Height:       pointer.BlockHeight,
		ShareStart:   pointer.Start,
		ShareLen:     pointer.SharesLength,
		TxCommitment: pointer.TxCommitment,
		Proof:        proof,
	}
	return cert.Serialize(certData), nil
}
