package types

import (
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
)

func BuildCelestiaCertificate(pointer BlobPointer, _ []byte, _ []byte) ([]byte, error) {
	certData := &cert.CelestiaDACertV1{
		BlockHeight:  pointer.BlockHeight,
		Start:        pointer.Start,
		SharesLength: pointer.SharesLength,
		TxCommitment: pointer.TxCommitment,
		DataRoot:     pointer.DataRoot,
	}
	return certData.MarshalBinary()
}
