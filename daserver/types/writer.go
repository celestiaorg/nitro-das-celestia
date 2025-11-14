package types

import (
	"context"

	"github.com/offchainlabs/nitro/util/containers"
)

type OldWriter interface {
	// Store posts the batch data to the invoking DA provider
	// And returns sequencerMsg which is later used to retrieve the batch data
	Store(
		ctx context.Context,
		message []byte,
		timeout uint64,
		disableFallbackStoreDataOnChain bool,
	) ([]byte, error)
}

// New Writer interface from v3.8.0
type Writer interface {
	// Store posts the batch data to the invoking DA provider
	// And returns sequencerMsg which is later used to retrieve the batch data
	Store(
		message []byte,
		timeout uint64,
	) containers.PromiseInterface[[]byte]
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
	promise, ctx := containers.NewPromiseWithContext[[]byte](context.Background())
	go func() {
		cert, err := c.celestiaWriter.Store(ctx, message)
		if err != nil {
			promise.ProduceError(err)
		} else {
			promise.Produce(cert)
		}
	}()

	return promise
}

func (d *writerForCelestia) Type() string {
	return "celestia"
}
