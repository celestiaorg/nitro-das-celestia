package types

import (
	"bytes"
	"context"
	"errors"

	"github.com/celestiaorg/celestia-node/blob"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types/tree"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/offchainlabs/nitro/daprovider"
)

type Reader interface {
	// IsValidHeaderByte returns true if the given headerByte has bits corresponding to the DA provider
	IsValidHeaderByte(ctx context.Context, headerByte byte) bool

	// HeaderByte returns the primary header byte for this provider
	HeaderByte() byte

	// RecoverPayloadFromBatch fetches the underlying payload and a map of preimages from the DA provider given the batch header information
	RecoverPayloadFromBatch(
		ctx context.Context,
		batchNum uint64,
		batchBlockHash common.Hash,
		sequencerMsg []byte,
		preimages daprovider.PreimagesMap,
		validateSeqMsg bool,
	) ([]byte, daprovider.PreimagesMap, error)
}

// RecordPreimagesTo takes in preimages map and returns a function that can be used
// In recording (hash,preimage) key value pairs into preimages map, when fetching payload through RecoverPayloadFromBatch
func RecordPreimagesTo(preimages daprovider.PreimagesMap) daprovider.PreimageRecorder {
	if preimages == nil {
		return nil
	}
	return func(key common.Hash, value []byte, ty arbutil.PreimageType) {
		if preimages[ty] == nil {
			preimages[ty] = make(map[common.Hash][]byte)
		}
		preimages[ty][key] = value
	}
}

func NewReaderForCelestia(celestiaReader CelestiaReader) *readerForCelestia {
	return &readerForCelestia{celestiaReader: celestiaReader}
}

type readerForCelestia struct {
	celestiaReader CelestiaReader
}

func (c *readerForCelestia) IsValidHeaderByte(_ context.Context, headerByte byte) bool {
	return headerByte == cert.CustomDAHeaderFlag
}

func (c *readerForCelestia) HeaderByte() byte {
	return cert.CustomDAHeaderFlag
}

func (c *readerForCelestia) GetProof(ctx context.Context, msg []byte) ([]byte, error) {
	return c.celestiaReader.GetProof(ctx, msg)
}

func (c *readerForCelestia) RecoverPayloadFromBatch(
	ctx context.Context,
	_ uint64,
	_ common.Hash,
	sequencerMsg []byte,
	preimages daprovider.PreimagesMap,
	_ bool,
) ([]byte, daprovider.PreimagesMap, error) {
	if len(sequencerMsg) < cert.SequencerMsgOffset+cert.CelestiaDACertV1Len {
		return nil, nil, errors.New("sequencer message too short")
	}
	var preimageRecorder daprovider.PreimageRecorder
	if preimages != nil {
		preimageRecorder = RecordPreimagesTo(preimages)
	}
	parsed := &cert.CelestiaDACertV1{}
	if err := parsed.UnmarshalBinary(sequencerMsg[cert.SequencerMsgOffset:]); err != nil {
		return nil, nil, err
	}

	blobPointer := BlobPointer{
		BlockHeight:  parsed.BlockHeight,
		Start:        parsed.Start,
		SharesLength: parsed.SharesLength,
		TxCommitment: parsed.TxCommitment,
		DataRoot:     parsed.DataRoot,
	}

	result, err := c.celestiaReader.Read(ctx, &blobPointer)
	if err != nil {
		log.Error("Failed to resolve blob pointer from celestia", "err", err)
		return nil, nil, err
	}

	if len(result.Message) == 0 {
		return nil, nil, errors.New("empty payload returned from Celestia")
	}

	if preimageRecorder != nil {

		odsSize := result.SquareSize / 2
		rowIndex := result.StartRow
		for _, row := range result.Rows {
			treeConstructor := tree.NewConstructor(preimageRecorder, odsSize)
			root, err := tree.ComputeNmtRoot(treeConstructor, uint(rowIndex), row)
			if err != nil {
				log.Error("Failed to compute row root", "err", err)
				return nil, nil, err
			}

			if !bytes.Equal(result.RowRoots[rowIndex], root) {
				log.Error("Row root mismatch", "rowIndex", rowIndex)
				return nil, nil, errors.New("row root mismatch")
			}
			rowIndex++
		}

		rowsCount := len(result.RowRoots)
		slices := make([][]byte, rowsCount+rowsCount)
		copy(slices[0:rowsCount], result.RowRoots)
		copy(slices[rowsCount:], result.ColumnRoots)

		dataRoot := tree.HashFromByteSlices(preimageRecorder, slices)

		dataRootMatches := bytes.Equal(dataRoot, blobPointer.DataRoot[:])
		if !dataRootMatches {
			log.Error("Data Root do not match", "blobPointer data root", blobPointer.DataRoot, "calculated", dataRoot)
			return nil, nil, errors.New("data roots do not match")
		}
	}

	namespace := c.celestiaReader.GetNamespace()
	if namespace == nil {
		return nil, nil, errors.New("namespace not configured")
	}
	computedBlob, err := blob.NewBlobV0(*namespace, result.Message)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(computedBlob.Commitment, parsed.TxCommitment[:]) {
		return nil, nil, errors.New("txCommitment mismatch")
	}

	return result.Message, preimages, nil
}
