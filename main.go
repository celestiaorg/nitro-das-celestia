package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	types "github.com/celestiaorg/nitro-das-celestia/daserver/types"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      int             `json:"id"`
}

// JSONRPCError represents a JSON-RPC error
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	serverURL := "http://localhost:26657"
	hexMessage := "00000000007eb2280000000000000009000000000000000108e6994426b20503f8aeca285d469de69f10f9223b5ee8fb149d624bc0dfe0c96545d874e51c449616e700bf102444d8bdad08bf1759b35b0e083cbc21cb910c"

	// Decode hex string to bytes
	blobBytes, err := hex.DecodeString(hexMessage)
	if err != nil {
		fmt.Printf("Failed to decode hex: %v\n", err)
		return
	}

	// Unmarshal into BlobPointer
	blobPointer := types.BlobPointer{}
	err = blobPointer.UnmarshalBinary(blobBytes)
	if err != nil {
		fmt.Printf("Failed to unmarshal: %v\n", err)
		return
	}

	// Print what we're sending
	fmt.Printf("=== BlobPointer Details ===\n")
	fmt.Printf("Block Height: %d\n", blobPointer.BlockHeight)
	fmt.Printf("Start: %d\n", blobPointer.Start)
	fmt.Printf("Shares Length: %d\n", blobPointer.SharesLength)
	fmt.Printf("TX Commitment: 0x%x\n", blobPointer.TxCommitment)
	fmt.Printf("Data Root: 0x%x\n\n", blobPointer.DataRoot)

	// Make the request
	result, err := celestiaRead(serverURL, blobPointer)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("\nSuccess! Result: %s\n", string(result))
}

// celestiaRead makes a celestia_read RPC call with a BlobPointer
func celestiaRead(serverURL string, blobPointer types.BlobPointer) (json.RawMessage, error) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "celestia_read",
		Params:  []interface{}{blobPointer},
		ID:      1,
	}

	// Marshal request to JSON
	reqBody, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	fmt.Printf("Request:\n%s\n\n", string(reqBody))

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	fmt.Printf("Response:\n%s\n", string(respBody))

	// Parse JSON-RPC response
	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for errors
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error (code %d): %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}
