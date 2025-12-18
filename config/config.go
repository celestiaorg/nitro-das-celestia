package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config is the root configuration structure
type Config struct {
	Server   ServerConfig   `toml:"server"`
	Celestia CelestiaConfig `toml:"celestia"`
	Fallback FallbackConfig `toml:"fallback"`
	Logging  LoggingConfig  `toml:"logging"`
	Metrics  MetricsConfig  `toml:"metrics"`
}

// ServerConfig contains RPC server settings
type ServerConfig struct {
	RPCAddr           string `toml:"rpc_addr"`
	RPCPort           uint64 `toml:"rpc_port"`
	RPCBodyLimit      int    `toml:"rpc_body_limit"`
	ReadTimeout       string `toml:"read_timeout"`
	ReadHeaderTimeout string `toml:"read_header_timeout"`
	WriteTimeout      string `toml:"write_timeout"`
	IdleTimeout       string `toml:"idle_timeout"`
}

// CelestiaConfig contains all Celestia-related settings
type CelestiaConfig struct {
	NamespaceID   string          `toml:"namespace_id"`
	GasPrice      float64         `toml:"gas_price"`
	GasMultiplier float64         `toml:"gas_multiplier"`
	Network       string          `toml:"network"`
	WithWriter    bool            `toml:"with_writer"`
	NoopWriter    bool            `toml:"noop_writer"`
	CacheTime     string          `toml:"cache_time"`
	Reader        ReaderConfig    `toml:"reader"`
	Writer        WriterConfig    `toml:"writer"`
	Signer        SignerConfig    `toml:"signer"`
	Validator     ValidatorConfig `toml:"validator"`
	Retry         RetryConfig     `toml:"retry"`

	DangerousReorgOnReadFailure bool `toml:"dangerous_reorg_on_read_failure"`
}

// ReaderConfig contains DA Bridge node connection settings for reading
type ReaderConfig struct {
	RPC       string `toml:"rpc"`
	AuthToken string `toml:"auth_token"`
	EnableTLS bool   `toml:"enable_tls"`
}

// WriterConfig contains Core gRPC settings for blob submission
type WriterConfig struct {
	CoreGRPC  string `toml:"core_grpc"`
	CoreToken string `toml:"core_token"`
	EnableTLS bool   `toml:"enable_tls"`
}

// SignerConfig contains keyring configuration
type SignerConfig struct {
	Type   string             `toml:"type"` // "local" or "remote"
	Local  LocalSignerConfig  `toml:"local"`
	Remote RemoteSignerConfig `toml:"remote"`
}

// LocalSignerConfig contains settings for local keyring signing
type LocalSignerConfig struct {
	KeyName string `toml:"key_name"`
	KeyPath string `toml:"key_path"`
	Backend string `toml:"backend"`
}

// RemoteSignerConfig contains settings for remote signing via popsigner
type RemoteSignerConfig struct {
	APIKey  string `toml:"api_key"`
	KeyID   string `toml:"key_id"`
	BaseURL string `toml:"base_url"`
}

// ValidatorConfig contains Blobstream validation settings
type ValidatorConfig struct {
	EthRPC         string `toml:"eth_rpc"`
	BlobstreamAddr string `toml:"blobstream_addr"`
	SleepTime      int    `toml:"sleep_time"`
}

// RetryConfig contains retry backoff settings
type RetryConfig struct {
	MaxRetries     int     `toml:"max_retries"`
	InitialBackoff string  `toml:"initial_backoff"`
	MaxBackoff     string  `toml:"max_backoff"`
	BackoffFactor  float64 `toml:"backoff_factor"`
}

// FallbackConfig contains AnyTrust DAS fallback settings
type FallbackConfig struct {
	Enabled bool   `toml:"enabled"`
	DASRPC  string `toml:"das_rpc"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level string `toml:"level"`
	Type  string `toml:"type"`
}

// MetricsConfig contains metrics and profiling settings
type MetricsConfig struct {
	Enabled   bool   `toml:"enabled"`
	Addr      string `toml:"addr"`
	Port      int    `toml:"port"`
	PProf     bool   `toml:"pprof"`
	PProfAddr string `toml:"pprof_addr"`
	PProfPort int    `toml:"pprof_port"`
}

// LoadConfig loads configuration from a TOML file
func LoadConfig(path string) (*Config, error) {
	// Expand ~ in path
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home dir: %w", err)
		}
		path = filepath.Join(home, path[2:])
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in the TOML content
	content := expandEnvVars(string(data))

	cfg := DefaultConfig()
	if err := toml.Unmarshal([]byte(content), cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// expandEnvVars replaces ${VAR} or $VAR with environment variable values
func expandEnvVars(content string) string {
	// Match ${VAR} pattern
	re := regexp.MustCompile(`\$\{([^}]+)\}`)
	content = re.ReplaceAllStringFunc(content, func(match string) string {
		varName := match[2 : len(match)-1] // Remove ${ and }
		if val := os.Getenv(varName); val != "" {
			return val
		}
		return match // Keep original if env var not set
	})

	// Match $VAR pattern (simple form)
	re2 := regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	content = re2.ReplaceAllStringFunc(content, func(match string) string {
		varName := match[1:] // Remove $
		if val := os.Getenv(varName); val != "" {
			return val
		}
		return match // Keep original if env var not set
	})

	return content
}

// Validate performs validation on the configuration
func (c *Config) Validate() error {
	if c.Celestia.NamespaceID == "" {
		return fmt.Errorf("celestia.namespace_id is required")
	}

	if c.Celestia.Reader.RPC == "" {
		return fmt.Errorf("celestia.reader.rpc is required")
	}

	if c.Celestia.WithWriter && !c.Celestia.NoopWriter {
		if c.Celestia.Writer.CoreGRPC == "" {
			return fmt.Errorf("celestia.writer.core_grpc is required when with_writer is true")
		}

		switch c.Celestia.Signer.Type {
		case "local":
			if c.Celestia.Signer.Local.KeyName == "" {
				return fmt.Errorf("celestia.signer.local.key_name is required for local signer")
			}
		case "remote":
			if c.Celestia.Signer.Remote.APIKey == "" {
				return fmt.Errorf("celestia.signer.remote.api_key is required for remote signer")
			}
			if c.Celestia.Signer.Remote.KeyID == "" {
				return fmt.Errorf("celestia.signer.remote.key_id is required for remote signer")
			}
		default:
			return fmt.Errorf("invalid signer type: %s (must be 'local' or 'remote')", c.Celestia.Signer.Type)
		}
	}

	// Validate duration strings
	if c.Celestia.CacheTime != "" {
		if _, err := time.ParseDuration(c.Celestia.CacheTime); err != nil {
			return fmt.Errorf("invalid celestia.cache_time duration: %w", err)
		}
	}

	if c.Celestia.Retry.InitialBackoff != "" {
		if _, err := time.ParseDuration(c.Celestia.Retry.InitialBackoff); err != nil {
			return fmt.Errorf("invalid celestia.retry.initial_backoff duration: %w", err)
		}
	}

	if c.Celestia.Retry.MaxBackoff != "" {
		if _, err := time.ParseDuration(c.Celestia.Retry.MaxBackoff); err != nil {
			return fmt.Errorf("invalid celestia.retry.max_backoff duration: %w", err)
		}
	}

	return nil
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			RPCAddr:           "0.0.0.0",
			RPCPort:           9876,
			RPCBodyLimit:      0,
			ReadTimeout:       "30s",
			ReadHeaderTimeout: "10s",
			WriteTimeout:      "30s",
			IdleTimeout:       "120s",
		},
		Celestia: CelestiaConfig{
			GasPrice:      0.01,
			GasMultiplier: 1.01,
			Network:       "celestia",
			CacheTime:     "30m",
			Signer: SignerConfig{
				Type: "local",
				Local: LocalSignerConfig{
					KeyName: "my_celes_key",
					Backend: "test",
				},
			},
			Retry: RetryConfig{
				MaxRetries:     5,
				InitialBackoff: "10s",
				MaxBackoff:     "120s",
				BackoffFactor:  2.0,
			},
			Validator: ValidatorConfig{
				SleepTime: 3600,
			},
		},
		Logging: LoggingConfig{
			Level: "INFO",
			Type:  "plaintext",
		},
		Metrics: MetricsConfig{
			Enabled:   false,
			Addr:      "127.0.0.1",
			Port:      6060,
			PProfAddr: "127.0.0.1",
			PProfPort: 6061,
		},
	}
}

// PrintConfig prints the configuration with sensitive values masked
func (c *Config) PrintConfig() string {
	var sb strings.Builder

	sb.WriteString("=== Configuration ===\n")
	sb.WriteString(fmt.Sprintf("[server]\n"))
	sb.WriteString(fmt.Sprintf("  rpc_addr = %q\n", c.Server.RPCAddr))
	sb.WriteString(fmt.Sprintf("  rpc_port = %d\n", c.Server.RPCPort))
	sb.WriteString(fmt.Sprintf("  rpc_body_limit = %d\n", c.Server.RPCBodyLimit))

	sb.WriteString(fmt.Sprintf("\n[celestia]\n"))
	sb.WriteString(fmt.Sprintf("  namespace_id = %q\n", c.Celestia.NamespaceID))
	sb.WriteString(fmt.Sprintf("  gas_price = %f\n", c.Celestia.GasPrice))
	sb.WriteString(fmt.Sprintf("  gas_multiplier = %f\n", c.Celestia.GasMultiplier))
	sb.WriteString(fmt.Sprintf("  network = %q\n", c.Celestia.Network))
	sb.WriteString(fmt.Sprintf("  with_writer = %t\n", c.Celestia.WithWriter))
	sb.WriteString(fmt.Sprintf("  noop_writer = %t\n", c.Celestia.NoopWriter))
	sb.WriteString(fmt.Sprintf("  cache_time = %q\n", c.Celestia.CacheTime))

	sb.WriteString(fmt.Sprintf("\n[celestia.reader]\n"))
	sb.WriteString(fmt.Sprintf("  rpc = %q\n", c.Celestia.Reader.RPC))
	sb.WriteString(fmt.Sprintf("  auth_token = %q\n", maskSecret(c.Celestia.Reader.AuthToken)))
	sb.WriteString(fmt.Sprintf("  enable_tls = %t\n", c.Celestia.Reader.EnableTLS))

	sb.WriteString(fmt.Sprintf("\n[celestia.writer]\n"))
	sb.WriteString(fmt.Sprintf("  core_grpc = %q\n", c.Celestia.Writer.CoreGRPC))
	sb.WriteString(fmt.Sprintf("  core_token = %q\n", maskSecret(c.Celestia.Writer.CoreToken)))
	sb.WriteString(fmt.Sprintf("  enable_tls = %t\n", c.Celestia.Writer.EnableTLS))

	sb.WriteString(fmt.Sprintf("\n[celestia.signer]\n"))
	sb.WriteString(fmt.Sprintf("  type = %q\n", c.Celestia.Signer.Type))

	if c.Celestia.Signer.Type == "local" {
		sb.WriteString(fmt.Sprintf("\n[celestia.signer.local]\n"))
		sb.WriteString(fmt.Sprintf("  key_name = %q\n", c.Celestia.Signer.Local.KeyName))
		sb.WriteString(fmt.Sprintf("  key_path = %q\n", c.Celestia.Signer.Local.KeyPath))
		sb.WriteString(fmt.Sprintf("  backend = %q\n", c.Celestia.Signer.Local.Backend))
	} else if c.Celestia.Signer.Type == "remote" {
		sb.WriteString(fmt.Sprintf("\n[celestia.signer.remote]\n"))
		sb.WriteString(fmt.Sprintf("  api_key = %q\n", maskSecret(c.Celestia.Signer.Remote.APIKey)))
		sb.WriteString(fmt.Sprintf("  key_id = %q\n", c.Celestia.Signer.Remote.KeyID))
		sb.WriteString(fmt.Sprintf("  base_url = %q\n", c.Celestia.Signer.Remote.BaseURL))
	}

	sb.WriteString(fmt.Sprintf("\n[celestia.retry]\n"))
	sb.WriteString(fmt.Sprintf("  max_retries = %d\n", c.Celestia.Retry.MaxRetries))
	sb.WriteString(fmt.Sprintf("  initial_backoff = %q\n", c.Celestia.Retry.InitialBackoff))
	sb.WriteString(fmt.Sprintf("  max_backoff = %q\n", c.Celestia.Retry.MaxBackoff))
	sb.WriteString(fmt.Sprintf("  backoff_factor = %f\n", c.Celestia.Retry.BackoffFactor))

	sb.WriteString(fmt.Sprintf("\n[celestia.validator]\n"))
	sb.WriteString(fmt.Sprintf("  eth_rpc = %q\n", c.Celestia.Validator.EthRPC))
	sb.WriteString(fmt.Sprintf("  blobstream_addr = %q\n", c.Celestia.Validator.BlobstreamAddr))
	sb.WriteString(fmt.Sprintf("  sleep_time = %d\n", c.Celestia.Validator.SleepTime))

	sb.WriteString(fmt.Sprintf("\n[fallback]\n"))
	sb.WriteString(fmt.Sprintf("  enabled = %t\n", c.Fallback.Enabled))
	sb.WriteString(fmt.Sprintf("  das_rpc = %q\n", c.Fallback.DASRPC))

	sb.WriteString(fmt.Sprintf("\n[logging]\n"))
	sb.WriteString(fmt.Sprintf("  level = %q\n", c.Logging.Level))
	sb.WriteString(fmt.Sprintf("  type = %q\n", c.Logging.Type))

	sb.WriteString(fmt.Sprintf("\n[metrics]\n"))
	sb.WriteString(fmt.Sprintf("  enabled = %t\n", c.Metrics.Enabled))
	sb.WriteString(fmt.Sprintf("  addr = %q\n", c.Metrics.Addr))
	sb.WriteString(fmt.Sprintf("  port = %d\n", c.Metrics.Port))
	sb.WriteString(fmt.Sprintf("  pprof = %t\n", c.Metrics.PProf))

	sb.WriteString("=====================\n")

	return sb.String()
}

// maskSecret masks a secret string, showing only first and last 4 chars
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// GetCacheTimeDuration parses and returns the cache time as a Duration
func (c *CelestiaConfig) GetCacheTimeDuration() time.Duration {
	d, err := time.ParseDuration(c.CacheTime)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// GetInitialBackoffDuration parses and returns the initial backoff as a Duration
func (r *RetryConfig) GetInitialBackoffDuration() time.Duration {
	d, err := time.ParseDuration(r.InitialBackoff)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// GetMaxBackoffDuration parses and returns the max backoff as a Duration
func (r *RetryConfig) GetMaxBackoffDuration() time.Duration {
	d, err := time.ParseDuration(r.MaxBackoff)
	if err != nil {
		return 120 * time.Second
	}
	return d
}
