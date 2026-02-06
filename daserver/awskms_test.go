package das

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// isLocalStackRunning checks if LocalStack is accessible on the given endpoint
func isLocalStackRunning(endpoint string) bool {
	conn, err := net.DialTimeout("tcp", "localhost:4566", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func TestInitKeyringAWSKMS(t *testing.T) {
	if !isLocalStackRunning("http://localhost:4566") {
		t.Skip("LocalStack not running, skipping AWS KMS test")
	}

	// Set AWS credentials for LocalStack (it doesn't validate them)
	os.Setenv("AWS_ACCESS_KEY_ID", "test")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	defer func() {
		os.Unsetenv("AWS_ACCESS_KEY_ID")
		os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	}()

	ctx := context.Background()

	t.Run("Create keyring with auto-create", func(t *testing.T) {
		cfg := &DAConfig{
			KeyName:     "test_key_" + time.Now().Format("20060102150405"),
			BackendName: "awskms",
			AWSKMSConfig: AWSKMSConfig{
				Region:      "us-east-1",
				Endpoint:    "http://localhost:4566",
				AliasPrefix: "alias/nitro-das-test/",
				AutoCreate:  true,
			},
		}

		kr, err := initKeyring(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, kr)

		// Verify we can get the key info
		keyInfo, err := kr.Key(cfg.KeyName)
		require.NoError(t, err)
		require.NotNil(t, keyInfo)
		require.Equal(t, cfg.KeyName, keyInfo.Name)
	})

	t.Run("Create keyring with imported key", func(t *testing.T) {
		// Test private key (32 bytes hex-encoded)
		// This is a test key - DO NOT USE IN PRODUCTION
		testPrivKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		cfg := &DAConfig{
			KeyName:     "imported_key_" + time.Now().Format("20060102150405"),
			BackendName: "awskms",
			AWSKMSConfig: AWSKMSConfig{
				Region:        "us-east-1",
				Endpoint:      "http://localhost:4566",
				AliasPrefix:   "alias/nitro-das-test/",
				AutoCreate:    true,
				ImportKeyName: "imported_key_" + time.Now().Format("20060102150405"),
				ImportKeyHex:  testPrivKeyHex,
			},
		}

		kr, err := initKeyring(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, kr)

		// Verify we can get the key info
		keyInfo, err := kr.Key(cfg.KeyName)
		require.NoError(t, err)
		require.NotNil(t, keyInfo)
	})

	t.Run("Error without region", func(t *testing.T) {
		cfg := &DAConfig{
			KeyName:     "test_key",
			BackendName: "awskms",
			AWSKMSConfig: AWSKMSConfig{
				Region:      "", // Missing region
				Endpoint:    "http://localhost:4566",
				AliasPrefix: "alias/nitro-das-test/",
				AutoCreate:  true,
			},
		}

		_, err := initKeyring(ctx, cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "region is required")
	})

	t.Run("Error without auto-create when key doesn't exist", func(t *testing.T) {
		cfg := &DAConfig{
			KeyName:     "nonexistent_key_" + time.Now().Format("20060102150405"),
			BackendName: "awskms",
			AWSKMSConfig: AWSKMSConfig{
				Region:      "us-east-1",
				Endpoint:    "http://localhost:4566",
				AliasPrefix: "alias/nitro-das-test/",
				AutoCreate:  false, // Don't auto-create
			},
		}

		_, err := initKeyring(ctx, cfg)
		require.Error(t, err)
	})
}

func TestAWSKMSConfigToKeyringConfig(t *testing.T) {
	cfg := AWSKMSConfig{
		Region:        "us-west-2",
		Endpoint:      "http://localhost:4566",
		AliasPrefix:   "alias/test/",
		AutoCreate:    true,
		ImportKeyName: "my_key",
		ImportKeyHex:  "deadbeef",
	}

	kmsConfig := cfg.ToKeyringConfig()

	require.Equal(t, cfg.Region, kmsConfig.Region)
	require.Equal(t, cfg.Endpoint, kmsConfig.Endpoint)
	require.Equal(t, cfg.AliasPrefix, kmsConfig.AliasPrefix)
	require.Equal(t, cfg.AutoCreate, kmsConfig.AutoCreate)
	require.Equal(t, cfg.ImportKeyName, kmsConfig.ImportKeyName)
	require.Equal(t, cfg.ImportKeyHex, kmsConfig.ImportKeyHex)
}
