package das

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/gorilla/websocket"
	"github.com/knadh/koanf"
	"github.com/spf13/pflag"
)

// generatec interface for the DAS DAProvider to avoid depdency issues from importing nitro

// Client provides a standalone interface to communicate with DA provider RPC service
type Client struct {
	rpcURL    string
	client    *http.Client
	wsConn    *websocket.Conn
	useWS     bool
	requestID int64
}

// ClientConfig holds configuration for the standalone client
type ClientConfig struct {
	RPCURL            string        `koanf:"rpc-url"`
	UseWebSocket      bool          `koanf:"use-websocket"`
	RequestTimeout    time.Duration `koanf:"request-timeout"`
	MaxMessageSize    int64         `koanf:"max-message-size"`
	ConnectionRetries int           `koanf:"connection-retries"`
	EnableFallback    bool          `koanf:"enable-fallback"`
}

// DefaultConfig provides sensible defaults
var DefaultConfig = ClientConfig{
	RPCURL:            "http://localhost:8547", // Adjust as needed
	UseWebSocket:      false,
	RequestTimeout:    30 * time.Second,
	MaxMessageSize:    256 * 1024 * 1024, // 256MB
	ConnectionRetries: 3,
	EnableFallback:    true,
}

// ClientConfigAddOptions adds configuration options to pflag
func ClientConfigAddOptions(prefix string, f *pflag.FlagSet) {
	f.String(prefix+".rpc-url", DefaultConfig.RPCURL, "RPC URL for the DA provider service")
	f.Bool(prefix+".use-websocket", DefaultConfig.UseWebSocket, "use WebSocket connection instead of HTTP")
	f.Duration(prefix+".request-timeout", DefaultConfig.RequestTimeout, "timeout for RPC requests")
	f.Int64(prefix+".max-message-size", DefaultConfig.MaxMessageSize, "maximum message size for WebSocket connections")
	f.Int(prefix+".connection-retries", DefaultConfig.ConnectionRetries, "number of connection retries")
	f.Bool(prefix+".enable-fallback", DefaultConfig.EnableFallback, "enable falling back to an anytrust DAC")
}

// LoadConfigFromKoanf loads configuration from koanf instance
func LoadConfigFromKoanf(k *koanf.Koanf, prefix string) (ClientConfig, error) {
	var config ClientConfig
	if err := k.Unmarshal(prefix, &config); err != nil {
		return ClientConfig{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return config, nil
}

// NewClient creates a new standalone DA provider client
func NewClient(config ClientConfig) (*Client, error) {
	client := &Client{
		rpcURL: config.RPCURL,
		client: &http.Client{
			Timeout: config.RequestTimeout,
		},
		useWS: config.UseWebSocket,
	}

	if config.UseWebSocket {
		if err := client.connectWebSocket(); err != nil {
			return nil, fmt.Errorf("failed to establish websocket connection: %w", err)
		}
	}

	return client, nil
}

// connectWebSocket establishes a websocket connection
func (c *Client) connectWebSocket() error {
	u, err := url.Parse(c.rpcURL)
	if err != nil {
		return err
	}

	// Convert HTTP URL to WebSocket URL
	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else if u.Scheme == "https" {
		u.Scheme = "wss"
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	c.wsConn = conn
	return nil
}

// Close closes the client connection
func (c *Client) Close() error {
	if c.wsConn != nil {
		return c.wsConn.Close()
	}
	return nil
}

// RPCRequest represents a JSON-RPC request
type RPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int64         `json:"id"`
}

// RPCResponse represents a JSON-RPC response
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// RPCError represents a JSON-RPC error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// callRPC makes an RPC call and unmarshals the result
func (c *Client) callRPC(ctx context.Context, method string, params []interface{}, result interface{}) error {
	c.requestID++

	request := RPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      c.requestID,
	}

	if c.useWS && c.wsConn != nil {
		return c.callWebSocket(request, result)
	}
	return c.callHTTP(ctx, request, result)
}

// callHTTP makes an HTTP RPC call
func (c *Client) callHTTP(ctx context.Context, request RPCRequest, result interface{}) error {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.rpcURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	var rpcResp RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if rpcResp.Error != nil {
		return rpcResp.Error
	}

	if result != nil && rpcResp.Result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return fmt.Errorf("failed to unmarshal result: %w", err)
		}
	}

	return nil
}

// callWebSocket makes a WebSocket RPC call
func (c *Client) callWebSocket(request RPCRequest, result interface{}) error {
	if err := c.wsConn.WriteJSON(request); err != nil {
		return fmt.Errorf("failed to send websocket message: %w", err)
	}

	var rpcResp RPCResponse
	if err := c.wsConn.ReadJSON(&rpcResp); err != nil {
		return fmt.Errorf("failed to read websocket response: %w", err)
	}

	if rpcResp.Error != nil {
		return rpcResp.Error
	}

	if result != nil && rpcResp.Result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return fmt.Errorf("failed to unmarshal result: %w", err)
		}
	}

	return nil
}

// IsValidHeaderByteResult represents the response for header byte validation
type IsValidHeaderByteResult struct {
	IsValid bool `json:"is-valid,omitempty"`
}

const DASMessageHeaderFlag byte = 0x80

func IsDASMessageHeaderByte(header byte) bool {
	return hasBits(header, DASMessageHeaderFlag)
}

// IsValidHeaderByte checks if a header byte is valid for the DA service
func (c *Client) IsValidHeaderByte(ctx context.Context, headerByte byte) (bool, error) {
	// re-implmenting since current anytrust binary does not expose the daprovider interface
	return IsDASMessageHeaderByte(headerByte), nil
}

// RecoverPayloadFromBatchResult represents the response for payload recovery
type RecoverPayloadFromBatchResult struct {
	Payload   hexutil.Bytes      `json:"payload,omitempty"`
	Preimages types.PreimagesMap `json:"preimages,omitempty"`
}

// RecoverPayloadFromBatch recovers payload from a batch
func (c *Client) RecoverPayloadFromBatch(
	ctx context.Context,
	batchNum uint64,
	batchBlockHash common.Hash,
	sequencerMsg []byte,
	preimages types.PreimagesMap,
	validateSeqMsg bool,
) ([]byte, types.PreimagesMap, error) {
	params := []interface{}{
		hexutil.Uint64(batchNum),
		batchBlockHash,
		hexutil.Bytes(sequencerMsg),
		preimages,
		validateSeqMsg,
	}

	var result RecoverPayloadFromBatchResult
	err := c.callRPC(ctx, "daprovider_recoverPayloadFromBatch", params, &result)
	if err != nil {
		return nil, nil, fmt.Errorf("daprovider_recoverPayloadFromBatch failed: %w", err)
	}

	return result.Payload, result.Preimages, nil
}

// StoreResult represents the response for store operations
type StoreResult struct {
	SerializedDACert hexutil.Bytes `json:"serialized-da-cert,omitempty"`
}

// Store stores data in the DA service and returns a commitment
func (c *Client) Store(
	ctx context.Context,
	message []byte,
	timeout uint64,
	disableFallbackStoreDataOnChain bool,
) ([]byte, error) {
	params := []interface{}{
		hexutil.Bytes(message),
		hexutil.Uint64(timeout),
		disableFallbackStoreDataOnChain,
	}

	var result StoreResult
	err := c.callRPC(ctx, "daprovider_store", params, &result)
	if err != nil {
		return nil, fmt.Errorf("daprovider_store failed: %w", err)
	}

	return result.SerializedDACert, nil
}
