package types

import (
	"context"
	"errors"
)

type Writer interface {
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

func NewWriterForCelestia(celestiaWriter CelestiaWriter) *writerForCelestia {
	return &writerForCelestia{celestiaWriter: celestiaWriter}
}

type writerForCelestia struct {
	celestiaWriter CelestiaWriter
}

func (c *writerForCelestia) Store(ctx context.Context, message []byte, timeout uint64) ([]byte, error) {
	msg, err := c.celestiaWriter.Store(ctx, message)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (c *writerForCelestia) GetMaxMessageSize(ctx context.Context) (int, error) {
	if maxer, ok := c.celestiaWriter.(interface {
		MaxMessageSize(context.Context) (int, error)
	}); ok {
		return maxer.MaxMessageSize(ctx)
	}
	return 0, errors.New("max message size not supported")
}

func (d *writerForCelestia) Type() string {
	return "celestia"
}
