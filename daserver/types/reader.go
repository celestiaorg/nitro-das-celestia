package types

import (
	"bytes"
	"context"
	"errors"

	"github.com/celestiaorg/celestia-node/blob"
	libshare "github.com/celestiaorg/go-square/v3/share"
	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types/tree"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
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

// RecoverPayloadFromBatchResult is the result struct that data availability providers should use to respond with underlying payload and updated preimages map to a RecoverPayloadFromBatch fetch request
type RecoverPayloadFromBatchResult struct {
	Payload   hexutil.Bytes           `json:"payload,omitempty"`
	Preimages daprovider.PreimagesMap `json:"preimages,omitempty"`
}

type IsValidHeaderByteResult struct {
	IsValid bool `json:"is-valid,omitempty"`
}

func NewReaderForCelestia(celestiaReader CelestiaReader) *readerForCelestia {
	return &readerForCelestia{celestiaReader: celestiaReader}
}

type readerForCelestia struct {
	celestiaReader CelestiaReader
}

func (c *readerForCelestia) IsValidHeaderByte(ctx context.Context, headerByte byte) bool {
	return IsCelestiaMessageHeaderByte(headerByte)
}

func (c *readerForCelestia) HeaderByte() byte {
	return cert.CustomDAHeaderFlag
}

func IsCelestiaMessageHeaderByte(header byte) bool {
	return header == cert.CustomDAHeaderFlag
}

func (c *readerForCelestia) GetProof(ctx context.Context, msg []byte) ([]byte, error) {
	return c.celestiaReader.GetProof(ctx, msg)
}

func (c *readerForCelestia) RecoverPayloadFromBatch(
	ctx context.Context,
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
	preimages daprovider.PreimagesMap,
	validateSeqMsg bool,
) ([]byte, daprovider.PreimagesMap, error) {
	return RecoverPayloadFromCelestiaBatch(ctx, batchNum, sequencerMsg, c.celestiaReader, preimages, validateSeqMsg)
}

func RecoverPayloadFromCelestiaBatch(
	ctx context.Context,
	batchNum uint64,
	sequencerMsg []byte,
	celestiaReader CelestiaReader,
	preimages daprovider.PreimagesMap,
	validateSeqMsg bool,
) ([]byte, daprovider.PreimagesMap, error) {
	var preimageRecorder daprovider.PreimageRecorder
	if preimages != nil {
		preimageRecorder = RecordPreimagesTo(preimages)
	}
	certBytes := sequencerMsg[40:]
	if len(certBytes) == 0 {
		return nil, nil, errors.New("sequencer message missing certificate")
	}
	if !IsCelestiaMessageHeaderByte(certBytes[0]) {
		return nil, nil, errors.New("invalid certificate header byte")
	}
	parsed, err := cert.Deserialize(certBytes)
	if err != nil {
		return nil, nil, err
	}

	blobPointer := BlobPointer{
		BlockHeight:  parsed.Height,
		Start:        parsed.ShareStart,
		SharesLength: parsed.ShareLen,
		TxCommitment: parsed.TxCommitment,
		DataRoot:     parsed.DataRoot,
	}

	result, err := celestiaReader.Read(ctx, &blobPointer)
	if err != nil {
		log.Error("Failed to resolve blob pointer from celestia", "err", err)
		return nil, nil, err
	}

	// we read a batch that is to be discarded, so we return the empty batch
	if len(result.Message) == 0 {
		return nil, nil, errors.New("tried to deserialize a message that doesn't have the Celestia header")
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

			rowRootMatches := bytes.Equal(result.RowRoots[rowIndex], root)
			if !rowRootMatches {
				log.Error("Row roots do not match", "eds row root", result.RowRoots[rowIndex], "calculated", root)
				log.Error("Row roots", "row_roots", result.RowRoots)
				return nil, nil, err
			}
			rowIndex += 1
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

	namespace, err := libshare.NewV0Namespace(parsed.Namespace[:])
	if err != nil {
		return nil, nil, err
	}
	computedBlob, err := blob.NewBlobV0(namespace, result.Message)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(computedBlob.Commitment, parsed.TxCommitment[:]) {
		return nil, nil, errors.New("txCommitment mismatch")
	}

	return result.Message, preimages, nil
}
