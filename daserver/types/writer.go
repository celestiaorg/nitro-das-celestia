package types

import (
	"context"

	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/util/containers"
)

type OldWriter interface {
	// Store posts the batch data to the invoking DA provider
	// And returns sequencerMsg which is later used to retrieve the batch data
	Store(
		ctx context.Context,
		message []byte,
		timeout uint64,
	) ([]byte, error)

	// GetMaxMessageSize returns the maximum message size the writer can accept.
	GetMaxMessageSize(ctx context.Context) (int, error)
}

// New Writer interface from v3.8.0
type Writer interface {
	// Store posts the batch data to the invoking DA provider
	// And returns sequencerMsg which is later used to retrieve the batch data
	Store(
		message []byte,
		timeout uint64,
	) containers.PromiseInterface[[]byte]

	// GetMaxMessageSize returns the maximum message size the writer can accept.
	GetMaxMessageSize() containers.PromiseInterface[int]
}

func NewWriterForCelestia(celestiaWriter CelestiaWriter) *writerForCelestia {
	return &writerForCelestia{celestiaWriter: celestiaWriter}
}

type writerForCelestia struct {
	celestiaWriter CelestiaWriter
}

// DA Provider Store method from Nitro v3.8.0
func (c *writerForCelestia) Store(
	message []byte,
	timeout uint64,
) containers.PromiseInterface[[]byte] {
	return containers.DoPromise(context.Background(), func(ctx context.Context) ([]byte, error) {
		cert, err := c.celestiaWriter.Store(context.Background(), message)
		if err != nil {
			log.Error("Returning error from Celestia writer", "err", err)
			return nil, err
		}
		return cert, nil
	})
}

func (c *writerForCelestia) GetMaxMessageSize() containers.PromiseInterface[int] {
	return containers.DoPromise(context.Background(), func(ctx context.Context) (int, error) {
		return c.celestiaWriter.MaxMessageSize(ctx)
	})
}

func (d *writerForCelestia) Type() string {
	return "celestia"
}
