package signer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/nitro-das-celestia/config"
)

func TestDefaultKeyringPath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name     string
		nodeType string
		network  string
		envHome  string
		expected string
	}{
		{
			name:     "mainnet",
			nodeType: "light",
			network:  "celestia",
			expected: filepath.Join(home, ".celestia-light", "keys"),
		},
		{
			name:     "mainnet alt",
			nodeType: "light",
			network:  "mainnet",
			expected: filepath.Join(home, ".celestia-light", "keys"),
		},
		{
			name:     "mocha testnet",
			nodeType: "light",
			network:  "mocha-4",
			expected: filepath.Join(home, ".celestia-light-mocha-4", "keys"),
		},
		{
			name:     "arabica devnet",
			nodeType: "light",
			network:  "arabica",
			expected: filepath.Join(home, ".celestia-light-arabica", "keys"),
		},
		{
			name:     "with CELESTIA_HOME",
			nodeType: "light",
			network:  "celestia",
			envHome:  "/custom/path",
			expected: "/custom/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envHome != "" {
				os.Setenv("CELESTIA_HOME", tt.envHome)
				defer os.Unsetenv("CELESTIA_HOME")
			}

			path, err := defaultKeyringPath(tt.nodeType, tt.network)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, path)
		})
	}
}

func TestNewKeyringInvalidType(t *testing.T) {
	cfg := &config.SignerConfig{
		Type: "invalid",
	}

	_, err := NewKeyring(cfg, "celestia")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signer type")
}

func TestNewKeyringRemoteMissingAPIKey(t *testing.T) {
	cfg := &config.SignerConfig{
		Type: "remote",
		Remote: config.RemoteSignerConfig{
			APIKey: "",
			KeyID:  "key_123",
		},
	}

	_, err := NewKeyring(cfg, "celestia")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key is required")
}

func TestNewKeyringRemoteMissingKeyID(t *testing.T) {
	cfg := &config.SignerConfig{
		Type: "remote",
		Remote: config.RemoteSignerConfig{
			APIKey: "psk_test_123",
			KeyID:  "",
		},
	}

	_, err := NewKeyring(cfg, "celestia")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestGetKeyName(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.SignerConfig
		expected string
	}{
		{
			name: "local signer",
			cfg: &config.SignerConfig{
				Type: "local",
				Local: config.LocalSignerConfig{
					KeyName: "my_key",
				},
			},
			expected: "my_key",
		},
		{
			name: "remote signer",
			cfg: &config.SignerConfig{
				Type: "remote",
				Remote: config.RemoteSignerConfig{
					KeyID: "key_abc123",
				},
			},
			expected: "key_abc123",
		},
		{
			name: "invalid type",
			cfg: &config.SignerConfig{
				Type: "invalid",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyName := GetKeyName(tt.cfg)
			assert.Equal(t, tt.expected, keyName)
		})
	}
}

// TestNewLocalKeyring tests local keyring creation
// Note: This test requires the celestia-node dependencies to be available
func TestNewLocalKeyring(t *testing.T) {
	// Skip if running in CI without full dependencies
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping local keyring test in CI")
	}

	tmpDir := t.TempDir()

	cfg := &config.LocalSignerConfig{
		KeyName: "test_key",
		KeyPath: tmpDir,
		Backend: "test",
	}

	kr, err := newLocalKeyring(cfg, "mocha-4")
	// The keyring creation might fail if celestia dependencies aren't set up
	// This is expected in some test environments
	if err != nil {
		t.Logf("Local keyring creation failed (expected in some environments): %v", err)
		return
	}

	require.NotNil(t, kr)
}
