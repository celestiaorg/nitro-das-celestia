package types

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Writer interface {
	// Store posts the batch data to the invoking DA provider
	// And returns sequencerMsg which is later used to retrieve the batch data
	Store(
		ctx context.Context,
		message []byte,
		timeout uint64,
		disableFallbackStoreDataOnChain bool,
	) ([]byte, error)
}

func NewWriterForCelestia(celestiaWriter CelestiaWriter) *writerForCelestia {
	return &writerForCelestia{celestiaWriter: celestiaWriter}
}

type writerForCelestia struct {
	celestiaWriter CelestiaWriter
}

type StoreResult struct {
	SerializedResult hexutil.Bytes `json:"serialized-da-cert,omitempty"`
}

func (c *writerForCelestia) Store(ctx context.Context, message []byte, timeout uint64, disableFallbackStoreDataOnChain bool) ([]byte, error) {
	msg, err := c.celestiaWriter.Store(ctx, message)
	if err != nil {
		if disableFallbackStoreDataOnChain {
			return nil, errors.New("unable to batch to Celestia and fallback storing data on chain is disabled")
		}
		return nil, err
	}
	message = msg
	return message, nil
}

func (d *writerForCelestia) Type() string {
	return "celestia"
}
