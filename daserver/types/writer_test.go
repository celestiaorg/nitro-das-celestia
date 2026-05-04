package types

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeWriter struct {
	storeFn          func(context.Context, []byte) ([]byte, error)
	maxMessageSizeFn func(context.Context) (int, error)
}

func (f *fakeWriter) Store(ctx context.Context, message []byte) ([]byte, error) {
	if f.storeFn == nil {
		return nil, errors.New("unexpected Store call")
	}
	return f.storeFn(ctx, message)
}

func (f *fakeWriter) MaxMessageSize(ctx context.Context) (int, error) {
	if f.maxMessageSizeFn == nil {
		return 0, errors.New("unexpected MaxMessageSize call")
	}
	return f.maxMessageSizeFn(ctx)
}

func TestWriterForCelestia_StoreReturnsCertificate(t *testing.T) {
	t.Parallel()

	writer := NewWriterForCelestia(&fakeWriter{
		storeFn: func(ctx context.Context, message []byte) ([]byte, error) {
			require.Equal(t, []byte("payload"), message)
			return []byte("cert"), nil
		},
	})

	result, err := writer.Store([]byte("payload"), 0).Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("cert"), result)
}

func TestWriterForCelestia_StorePropagatesCancellationToUnderlyingWriter(t *testing.T) {
	t.Parallel()

	writerCtxCanceled := make(chan struct{})
	writer := NewWriterForCelestia(&fakeWriter{
		storeFn: func(ctx context.Context, message []byte) ([]byte, error) {
			<-ctx.Done()
			close(writerCtxCanceled)
			return nil, ctx.Err()
		},
	})

	promise := writer.Store([]byte("payload"), 0)
	awaitCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := promise.Await(awaitCtx)
	require.ErrorIs(t, err, context.Canceled)

	select {
	case <-writerCtxCanceled:
	case <-time.After(time.Second):
		t.Fatal("underlying writer context was not canceled")
	}
}

func TestWriterForCelestia_GetMaxMessageSize(t *testing.T) {
	t.Parallel()

	writer := NewWriterForCelestia(&fakeWriter{
		maxMessageSizeFn: func(ctx context.Context) (int, error) {
			return 1234, nil
		},
	})

	maxSize, err := writer.GetMaxMessageSize().Await(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1234, maxSize)
}
