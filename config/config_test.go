package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	content := `
[server]
rpc_addr = "0.0.0.0"
rpc_port = 9876

[celestia]
namespace_id = "000008e5f679bf7116cb"
network = "mocha-4"
gas_price = 0.02
gas_multiplier = 1.05

[celestia.reader]
rpc = "http://localhost:26658"
auth_token = "test_token"

[celestia.writer]
core_grpc = "localhost:9090"

[celestia.signer]
type = "local"

[celestia.signer.local]
key_name = "test_key"
backend = "test"
`

	tmpfile, err := os.CreateTemp("", "config*.toml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	tmpfile.Close()

	cfg, err := LoadConfig(tmpfile.Name())
	require.NoError(t, err)

	assert.Equal(t, "000008e5f679bf7116cb", cfg.Celestia.NamespaceID)
	assert.Equal(t, "mocha-4", cfg.Celestia.Network)
	assert.Equal(t, 0.02, cfg.Celestia.GasPrice)
	assert.Equal(t, 1.05, cfg.Celestia.GasMultiplier)
	assert.Equal(t, "local", cfg.Celestia.Signer.Type)
	assert.Equal(t, "test_key", cfg.Celestia.Signer.Local.KeyName)
	assert.Equal(t, "http://localhost:26658", cfg.Celestia.Reader.RPC)
}

func TestLoadConfigWithEnvVars(t *testing.T) {
	os.Setenv("TEST_AUTH_TOKEN", "secret_token_value")
	os.Setenv("TEST_API_KEY", "psk_live_12345")
	defer os.Unsetenv("TEST_AUTH_TOKEN")
	defer os.Unsetenv("TEST_API_KEY")

	content := `
[server]
rpc_addr = "0.0.0.0"
rpc_port = 9876

[celestia]
namespace_id = "000008e5f679bf7116cb"

[celestia.reader]
rpc = "http://localhost:26658"
auth_token = "${TEST_AUTH_TOKEN}"

[celestia.writer]
core_grpc = "localhost:9090"

[celestia.signer]
type = "remote"

[celestia.signer.remote]
api_key = "${TEST_API_KEY}"
key_id = "key_test"
`

	tmpfile, err := os.CreateTemp("", "config*.toml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	tmpfile.Close()

	cfg, err := LoadConfig(tmpfile.Name())
	require.NoError(t, err)

	assert.Equal(t, "secret_token_value", cfg.Celestia.Reader.AuthToken)
	assert.Equal(t, "psk_live_12345", cfg.Celestia.Signer.Remote.APIKey)
}

func TestValidateConfig(t *testing.T) {
	t.Run("missing namespace", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Celestia.NamespaceID = ""
		cfg.Celestia.Reader.RPC = "http://localhost:26658"

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace_id")
	})

	t.Run("missing reader rpc", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Celestia.NamespaceID = "test"
		cfg.Celestia.Reader.RPC = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reader.rpc")
	})

	t.Run("writer enabled but missing core grpc", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Celestia.NamespaceID = "test"
		cfg.Celestia.Reader.RPC = "http://localhost:26658"
		cfg.Celestia.WithWriter = true
		cfg.Celestia.Writer.CoreGRPC = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "core_grpc")
	})

	t.Run("invalid signer type", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Celestia.NamespaceID = "test"
		cfg.Celestia.Reader.RPC = "http://localhost:26658"
		cfg.Celestia.WithWriter = true
		cfg.Celestia.Writer.CoreGRPC = "localhost:9090"
		cfg.Celestia.Signer.Type = "invalid"

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signer type")
	})

	t.Run("remote signer missing api key", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Celestia.NamespaceID = "test"
		cfg.Celestia.Reader.RPC = "http://localhost:26658"
		cfg.Celestia.WithWriter = true
		cfg.Celestia.Writer.CoreGRPC = "localhost:9090"
		cfg.Celestia.Signer.Type = "remote"
		cfg.Celestia.Signer.Remote.APIKey = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key")
	})

	t.Run("valid local signer config", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Celestia.NamespaceID = "test"
		cfg.Celestia.Reader.RPC = "http://localhost:26658"
		cfg.Celestia.WithWriter = true
		cfg.Celestia.Writer.CoreGRPC = "localhost:9090"
		cfg.Celestia.Signer.Type = "local"
		cfg.Celestia.Signer.Local.KeyName = "my_key"

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid remote signer config", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Celestia.NamespaceID = "test"
		cfg.Celestia.Reader.RPC = "http://localhost:26658"
		cfg.Celestia.WithWriter = true
		cfg.Celestia.Writer.CoreGRPC = "localhost:9090"
		cfg.Celestia.Signer.Type = "remote"
		cfg.Celestia.Signer.Remote.APIKey = "psk_live_xxx"
		cfg.Celestia.Signer.Remote.KeyID = "key_xxx"

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid cache time duration", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Celestia.NamespaceID = "test"
		cfg.Celestia.Reader.RPC = "http://localhost:26658"
		cfg.Celestia.CacheTime = "invalid"

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cache_time")
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "0.0.0.0", cfg.Server.RPCAddr)
	assert.Equal(t, uint64(9876), cfg.Server.RPCPort)
	assert.Equal(t, 0.01, cfg.Celestia.GasPrice)
	assert.Equal(t, 1.01, cfg.Celestia.GasMultiplier)
	assert.Equal(t, "celestia", cfg.Celestia.Network)
	assert.Equal(t, "local", cfg.Celestia.Signer.Type)
	assert.Equal(t, "my_celes_key", cfg.Celestia.Signer.Local.KeyName)
	assert.Equal(t, 5, cfg.Celestia.Retry.MaxRetries)
	assert.Equal(t, "INFO", cfg.Logging.Level)
}

func TestMaskSecret(t *testing.T) {
	assert.Equal(t, "", maskSecret(""))
	assert.Equal(t, "****", maskSecret("short"))
	assert.Equal(t, "long****cret", maskSecret("longsecret"))
	assert.Equal(t, "this****ring", maskSecret("this_is_a_very_long_secret_string"))
}

func TestPrintConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Celestia.NamespaceID = "test_namespace"
	cfg.Celestia.Reader.RPC = "http://localhost:26658"
	cfg.Celestia.Reader.AuthToken = "very_secret_token"

	output := cfg.PrintConfig()

	assert.Contains(t, output, "test_namespace")
	assert.Contains(t, output, "http://localhost:26658")
	assert.Contains(t, output, "very****oken") // masked
	assert.NotContains(t, output, "very_secret_token")
}

func TestGetDurations(t *testing.T) {
	cfg := DefaultConfig()

	cacheTime := cfg.Celestia.GetCacheTimeDuration()
	assert.Equal(t, 30*60*1000000000, int(cacheTime.Nanoseconds())) // 30 minutes

	initialBackoff := cfg.Celestia.Retry.GetInitialBackoffDuration()
	assert.Equal(t, 10*1000000000, int(initialBackoff.Nanoseconds())) // 10 seconds

	maxBackoff := cfg.Celestia.Retry.GetMaxBackoffDuration()
	assert.Equal(t, 120*1000000000, int(maxBackoff.Nanoseconds())) // 120 seconds
}
