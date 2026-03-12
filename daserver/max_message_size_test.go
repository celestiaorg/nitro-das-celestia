package das

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

type rpcRequest struct {
	ID     json.RawMessage   `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newETHRPCServer(t *testing.T, maxMessageSize *big.Int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var req rpcRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		resp := rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
		}

		switch req.Method {
		case "eth_call":
			encoded := make([]byte, 32)
			maxMessageSize.FillBytes(encoded)
			resp.Result = hexutil.Encode(encoded)
		default:
			resp.Error = &rpcError{
				Code:    -32601,
				Message: "method not found",
			}
		}

		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
}

func TestMaxMessageSize_DefaultWithoutProofValidatorConfig(t *testing.T) {
	t.Parallel()

	da := &CelestiaDA{Cfg: &DAConfig{}}
	maxSize, err := da.MaxMessageSize(context.Background())
	require.NoError(t, err)
	require.Equal(t, celestiaDefaultMaxBytes, maxSize)
}

func TestMaxMessageSize_FallsBackOnRPCDialFailure(t *testing.T) {
	t.Parallel()

	da := &CelestiaDA{
		Cfg: &DAConfig{
			ValidatorConfig: ValidatorConfig{
				EthClient:          "http://127.0.0.1:0",
				ProofValidatorAddr: "0x00000000000000000000000000000000000000AA",
			},
		},
	}

	maxSize, err := da.MaxMessageSize(context.Background())
	require.NoError(t, err)
	require.Equal(t, celestiaDefaultMaxBytes, maxSize)
}

func TestMaxMessageSize_ReadsConfiguredProofValidator(t *testing.T) {
	t.Parallel()

	want := big.NewInt(123456)
	server := newETHRPCServer(t, want)
	defer server.Close()

	da := &CelestiaDA{
		Cfg: &DAConfig{
			ValidatorConfig: ValidatorConfig{
				EthClient:          server.URL,
				ProofValidatorAddr: "0x00000000000000000000000000000000000000AA",
			},
		},
	}

	maxSize, err := da.MaxMessageSize(context.Background())
	require.NoError(t, err)
	require.Equal(t, int(want.Int64()), maxSize)
}
