package types

import (
	"bytes"
	"context"
	"errors"

	"github.com/celestiaorg/nitro-das-celestia/daserver/types/tree"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/arbutil"
	"github.com/offchainlabs/nitro/daprovider"
)

// CelestiaMessageHeaderFlag is the header byte for Celestia DA certificates.
// This matches CUSTOM_DA_MESSAGE_HEADER_FLAG (0x01) in Nitro's SequencerInbox contract.
// Note: Previously was 0x63 for the Celestia fork of Nitro, but official Nitro v3.9.x uses 0x01.
const CelestiaMessageHeaderFlag byte = 0x01

// IsCelestiaMessageHeaderByte checks if a header byte indicates Celestia DA
func IsCelestiaMessageHeaderByte(header byte) bool {
	return header == CelestiaMessageHeaderFlag
}

// =============================================================================
// Nitro v3.9.0+ DA Provider Functions
// =============================================================================

// RecoverPayloadFromCelestia recovers the original batch payload from a sequencer message
// This is the simplified version for Nitro v3.9.0+ that only returns the payload
func RecoverPayloadFromCelestia(
	ctx context.Context,
	sequencerMsg []byte,
	celestiaReader CelestiaReader,
) ([]byte, error) {
	blobPointer, err := extractBlobPointerFromSequencerMsg(sequencerMsg)
	if err != nil {
		return nil, err
	}

	result, err := celestiaReader.Read(ctx, blobPointer)
	if err != nil {
		log.Error("Failed to resolve blob pointer from Celestia", "err", err)
		return nil, err
	}

	if len(result.Message) == 0 {
		return nil, errors.New("empty message retrieved from Celestia")
	}

	return result.Message, nil
}

// CollectPreimagesFromCelestia collects preimages needed for fraud proofs
// This is separate from RecoverPayload for Nitro v3.9.0+
func CollectPreimagesFromCelestia(
	ctx context.Context,
	sequencerMsg []byte,
	celestiaReader CelestiaReader,
) (daprovider.PreimagesMap, error) {
	blobPointer, err := extractBlobPointerFromSequencerMsg(sequencerMsg)
	if err != nil {
		return nil, err
	}

	result, err := celestiaReader.Read(ctx, blobPointer)
	if err != nil {
		log.Error("Failed to resolve blob pointer from Celestia", "err", err)
		return nil, err
	}

	if len(result.Message) == 0 {
		return nil, errors.New("empty message retrieved from Celestia")
	}

	// Build preimages map
	preimages := make(daprovider.PreimagesMap)
	preimageRecorder := RecordPreimagesTo(preimages)

	// Compute NMT roots and record preimages
	odsSize := result.SquareSize / 2
	rowIndex := result.StartRow
	for _, row := range result.Rows {
		treeConstructor := tree.NewConstructor(preimageRecorder, odsSize)
		root, err := tree.ComputeNmtRoot(treeConstructor, uint(rowIndex), row)
		if err != nil {
			log.Error("Failed to compute row root", "err", err)
			return nil, err
		}

		rowRootMatches := bytes.Equal(result.RowRoots[rowIndex], root)
		if !rowRootMatches {
			log.Error("Row roots do not match", "eds row root", result.RowRoots[rowIndex], "calculated", root)
			return nil, errors.New("row roots do not match")
		}
		rowIndex++
	}

	// Compute data root from row and column roots
	rowsCount := len(result.RowRoots)
	slices := make([][]byte, rowsCount+rowsCount)
	copy(slices[0:rowsCount], result.RowRoots)
	copy(slices[rowsCount:], result.ColumnRoots)

	dataRoot := tree.HashFromByteSlices(preimageRecorder, slices)

	dataRootMatches := bytes.Equal(dataRoot, blobPointer.DataRoot[:])
	if !dataRootMatches {
		log.Error("Data root does not match", "blobPointer", blobPointer.DataRoot, "calculated", dataRoot)
		return nil, errors.New("data roots do not match")
	}

	return preimages, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// extractBlobPointerFromSequencerMsg extracts the BlobPointer from a sequencer message
func extractBlobPointerFromSequencerMsg(sequencerMsg []byte) (*BlobPointer, error) {
	// Sequencer message format:
	// Bytes 0-39: Batch header (40 bytes)
	// Byte 40: DA type header (0x01 for external/custom DA)
	// Bytes 41+: BlobPointer data

	if len(sequencerMsg) < 41 {
		return nil, errors.New("sequencer message too short")
	}

	buf := bytes.NewBuffer(sequencerMsg[40:])

	header, err := buf.ReadByte()
	if err != nil {
		log.Error("Couldn't read Celestia header byte", "err", err)
		return nil, errors.New("failed to read header byte from sequencer message")
	}

	if !IsCelestiaMessageHeaderByte(header) {
		log.Error("Invalid header byte", "header", header, "expected", CelestiaMessageHeaderFlag)
		return nil, errors.New("message does not have Celestia header")
	}

	blobPointer := &BlobPointer{}
	if err := blobPointer.UnmarshalBinary(buf.Bytes()); err != nil {
		return nil, err
	}

	return blobPointer, nil
}

// RecordPreimagesTo takes in preimages map and returns a function that can be used
// to record (hash,preimage) key value pairs into the preimages map
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
