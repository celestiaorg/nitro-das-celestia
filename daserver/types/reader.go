package types

import (
	"bytes"
	"context"
	"errors"

	"github.com/celestiaorg/nitro-das-celestia/daserver/types/tree"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/offchainlabs/nitro/daprovider"
	"github.com/offchainlabs/nitro/util/containers"
)

type Reader interface {
	// NOTICE: The below are DA API methods for v3.8.0 and above
	// RecoverPayload fetches the underlying payload from the DA provider given the batch header information
	RecoverPayload(
		batchNum uint64,
		batchBlockHash common.Hash,
		sequencerMsg []byte,
	) containers.PromiseInterface[daprovider.PayloadResult]

	// CollectPreimages collects preimages from the DA provider given the batch header information
	CollectPreimages(
		batchNum uint64,
		batchBlockHash common.Hash,
		sequencerMsg []byte,
	) containers.PromiseInterface[daprovider.PreimagesResult]
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

// CelestiaMessageHeaderFlag indicates that this data is a Blob Pointer
// which will be used to retrieve data from Celestia
const CelestiaMessageHeaderFlag byte = 0x63

func hasBits(checking byte, bits byte) bool {
	return (checking & bits) == bits
}

func IsCelestiaMessageHeaderByte(header byte) bool {
	return hasBits(header, CelestiaMessageHeaderFlag)
}

func (c *readerForCelestia) GetProof(ctx context.Context, msg []byte) ([]byte, error) {
	return c.celestiaReader.GetProof(ctx, msg)
}

func (c *readerForCelestia) RecoverPayload(
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
) containers.PromiseInterface[daprovider.PayloadResult] {
	promise, ctx := containers.NewPromiseWithContext[daprovider.PayloadResult](context.Background())
	go func() {
		payload, _, err := RecoverPayloadFromCelestiaBatch(ctx, batchNum, sequencerMsg, c.celestiaReader, false)
		if err != nil {
			promise.ProduceError(err)
		} else {
			promise.Produce(daprovider.PayloadResult{Payload: payload})
		}
	}()
	return promise
}

// CollectPreimages collects preimages from the DA provider given the batch header information
func (c *readerForCelestia) CollectPreimages(
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
) containers.PromiseInterface[daprovider.PreimagesResult] {
	return containers.DoPromise(context.Background(), func(ctx context.Context) (daprovider.PreimagesResult, error) {
		_, preimages, err := RecoverPayloadFromCelestiaBatch(ctx, batchNum, sequencerMsg, c.celestiaReader, true)
		return daprovider.PreimagesResult{Preimages: preimages}, err
	})
}

func RecoverPayloadFromCelestiaBatch(
	ctx context.Context,
	batchNum uint64,
	sequencerMsg []byte,
	celestiaReader CelestiaReader,
	needPreimages bool,
) ([]byte, daprovider.PreimagesMap, error) {
	var preimages daprovider.PreimagesMap
	var preimageRecorder daprovider.PreimageRecorder
	if needPreimages {
		preimages = make(daprovider.PreimagesMap)
		preimageRecorder = daprovider.RecordPreimagesTo(preimages)
	}
	buf := bytes.NewBuffer(sequencerMsg[40:])

	header, err := buf.ReadByte()
	if err != nil {
		log.Error("Couldn't deserialize Celestia header byte", "err", err)
		return nil, nil, errors.New("tried to deserialize a message that doesn't have the Celestia header")
	}
	if !IsCelestiaMessageHeaderByte(header) {
		log.Error("Couldn't deserialize Celestia header byte", "err", errors.New("tried to deserialize a message that doesn't have the Celestia header"))
		return nil, nil, errors.New("tried to deserialize a message that doesn't have the Celestia header")
	}

	blobPointer := BlobPointer{}
	blobBytes := buf.Bytes()
	err = blobPointer.UnmarshalBinary(blobBytes)
	if err != nil {
		return nil, nil, err
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

	return result.Message, preimages, nil
}
