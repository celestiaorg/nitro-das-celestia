package types

import (
	"bytes"
	"context"
	"errors"

	"github.com/celestiaorg/nitro-das-celestia/daserver/cert"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types/tree"
	"github.com/ethereum/go-ethereum/common"
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

	// RecoverPayloadAndPreimages recovers payload and collects preimages in a single call
	RecoverPayloadAndPreimages(
		batchNum uint64,
		batchBlockHash common.Hash,
		sequencerMsg []byte,
	) containers.PromiseInterface[daprovider.PayloadAndPreimagesResult]
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

func hasBits(checking byte, bits byte) bool {
	return (checking & bits) == bits
}

func IsCustomDAHeaderByte(header byte) bool {
	return hasBits(header, cert.CustomDAHeaderFlag)
}

func (c *readerForCelestia) IsValidHeaderByte(_ context.Context, headerByte byte) bool {
	return IsCustomDAHeaderByte(headerByte)
}

func (c *readerForCelestia) HeaderByte() byte {
	return cert.CustomDAHeaderFlag
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

// RecoverPayloadAndPreimages recovers payload and collects preimages from the DA provider given the batch header information
func (c *readerForCelestia) RecoverPayloadAndPreimages(
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
) containers.PromiseInterface[daprovider.PayloadAndPreimagesResult] {
	return containers.DoPromise(context.Background(), func(ctx context.Context) (daprovider.PayloadAndPreimagesResult, error) {
		payload, preimages, err := RecoverPayloadFromCelestiaBatch(ctx, batchNum, sequencerMsg, c.celestiaReader, true)
		return daprovider.PayloadAndPreimagesResult{
			Payload:   payload,
			Preimages: preimages,
		}, err
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

	certificate, err := cert.ExtractFromSequencerMessage(sequencerMsg)
	if err != nil {
		return nil, nil, err
	}

	result, err := celestiaReader.Read(ctx, certificate)
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

		dataRootMatches := bytes.Equal(dataRoot, certificate.DataRoot[:])
		if !dataRootMatches {
			log.Error("Data Root do not match", "blobPointer data root", certificate.DataRoot, "calculated", dataRoot)
			return nil, nil, errors.New("data roots do not match")
		}
	}

	return result.Message, preimages, nil
}
