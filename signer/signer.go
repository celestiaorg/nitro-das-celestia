package signer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	txclient "github.com/celestiaorg/celestia-node/api/client"

	"github.com/celestiaorg/nitro-das-celestia/config"

	popsigner "github.com/Bidon15/popsigner/sdk-go"
)

// SignerType represents the type of signer
type SignerType string

const (
	SignerTypeLocal  SignerType = "local"
	SignerTypeRemote SignerType = "remote"
)

// NewKeyring creates a keyring based on the signer configuration.
// For local signers, it uses the celestia-node txclient keyring.
// For remote signers, it uses popsigner's remote signing infrastructure.
func NewKeyring(cfg *config.SignerConfig, network string) (keyring.Keyring, error) {
	switch SignerType(cfg.Type) {
	case SignerTypeLocal:
		return newLocalKeyring(&cfg.Local, network)
	case SignerTypeRemote:
		return newRemoteKeyring(&cfg.Remote)
	default:
		return nil, fmt.Errorf("unknown signer type: %s", cfg.Type)
	}
}

// newLocalKeyring creates a local keyring using celestia-node's txclient
func newLocalKeyring(cfg *config.LocalSignerConfig, network string) (keyring.Keyring, error) {
	keyPath := cfg.KeyPath
	if keyPath == "" {
		var err error
		keyPath, err = defaultKeyringPath("light", network)
		if err != nil {
			return nil, fmt.Errorf("failed to determine default key path: %w", err)
		}
	}

	// Expand ~ in path
	if strings.HasPrefix(keyPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home dir: %w", err)
		}
		keyPath = filepath.Join(home, keyPath[2:])
	}

	kr, err := txclient.KeyringWithNewKey(txclient.KeyringConfig{
		KeyName:     cfg.KeyName,
		BackendName: cfg.Backend,
	}, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create local keyring: %w", err)
	}

	return kr, nil
}

// newRemoteKeyring creates a remote keyring using popsigner
func newRemoteKeyring(cfg *config.RemoteSignerConfig) (keyring.Keyring, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("api_key is required for remote signer")
	}
	if cfg.KeyID == "" {
		return nil, fmt.Errorf("key_id is required for remote signer")
	}

	opts := []popsigner.CelestiaKeyringOption{}
	if cfg.BaseURL != "" {
		opts = append(opts, popsigner.WithCelestiaBaseURL(cfg.BaseURL))
	}

	kr, err := popsigner.NewCelestiaKeyring(cfg.APIKey, cfg.KeyID, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create remote keyring: %w", err)
	}

	return kr, nil
}

// defaultKeyringPath returns the default keyring path for a given node type and network
func defaultKeyringPath(nodeType string, network string) (string, error) {
	// Check CELESTIA_HOME environment variable first
	home := os.Getenv("CELESTIA_HOME")
	if home != "" {
		return home, nil
	}

	// Fall back to default path based on network
	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home dir: %w", err)
	}

	// Normalize network name
	network = strings.ToLower(network)
	nodeType = strings.ToLower(nodeType)

	// For mainnet, the path is ~/.celestia-light/keys
	// For other networks, it's ~/.celestia-light-{network}/keys
	if network == "mainnet" || network == "celestia" || network == "" {
		return filepath.Join(userHome, fmt.Sprintf(".celestia-%s", nodeType), "keys"), nil
	}

	return filepath.Join(userHome, fmt.Sprintf(".celestia-%s-%s", nodeType, network), "keys"), nil
}

// GetKeyName returns the key name from the signer configuration
func GetKeyName(cfg *config.SignerConfig) string {
	switch SignerType(cfg.Type) {
	case SignerTypeLocal:
		return cfg.Local.KeyName
	case SignerTypeRemote:
		// For remote signers, the key_id serves as the key name
		return cfg.Remote.KeyID
	default:
		return ""
	}
}
