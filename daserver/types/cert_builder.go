package types

import (
	"errors"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
)

func BuildCelestiaCertificate(pointer BlobPointer, namespace []byte, _ []byte) ([]byte, error) {
	if len(namespace) < 10 {
		return nil, errors.New("namespace too short")
	}
	var ns [10]byte
	copy(ns[:], namespace[len(namespace)-10:])

	certData := &cert.CelestiaDACertV1{
		DataRoot:     pointer.DataRoot,
		Namespace:    ns,
		Height:       pointer.BlockHeight,
		ShareStart:   pointer.Start,
		ShareLen:     pointer.SharesLength,
		TxCommitment: pointer.TxCommitment,
	}
	return cert.Serialize(certData), nil
}
