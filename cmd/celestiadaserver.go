package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	gethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/metrics/exp"

	"github.com/offchainlabs/nitro/cmd/genericconf"

	"github.com/celestiaorg/nitro-das-celestia/config"
	das "github.com/celestiaorg/nitro-das-celestia/daserver"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
	"github.com/celestiaorg/nitro-das-celestia/signer"
)

func main() {
	if err := startup(); err != nil {
		gethlog.Error("Error running CelestiaDAServer", "err", err)
		os.Exit(1)
	}
}

func printUsage(progname string) {
	fmt.Printf("\nUsage: %s --config <path/to/config.toml>\n", progname)
	fmt.Printf("\nCelestia DAS Server - Data Availability Server for Arbitrum Nitro\n")
	fmt.Printf("\nOptions:\n")
	fmt.Printf("  --config string    Path to TOML configuration file (required)\n")
	fmt.Printf("  --help             Show this help message\n")
	fmt.Printf("  --version          Show version information\n")
	fmt.Printf("\nExample:\n")
	fmt.Printf("  %s --config /path/to/config.toml\n", progname)
	fmt.Printf("\nFor config file format, see config.example.toml\n")
}

func parseArgs() (string, error) {
	f := flag.NewFlagSet("celestia-das-server", flag.ContinueOnError)
	configPath := f.String("config", "", "Path to TOML configuration file (required)")
	help := f.Bool("help", false, "Show help")
	version := f.Bool("version", false, "Show version")

	// Parse flags
	if err := f.Parse(os.Args[1:]); err != nil {
		return "", err
	}

	if *help {
		printUsage(os.Args[0])
		os.Exit(0)
	}

	if *version {
		fmt.Println("Celestia DAS Server v0.7.0")
		os.Exit(0)
	}

	if *configPath == "" {
		return "", fmt.Errorf("--config flag is required")
	}

	return *configPath, nil
}

// startMetrics starts metrics and pprof servers if enabled
func startMetrics(cfg *config.Config) error {
	if cfg.Metrics.Enabled && cfg.Metrics.PProf {
		mAddr := fmt.Sprintf("%s:%d", cfg.Metrics.Addr, cfg.Metrics.Port)
		pAddr := fmt.Sprintf("%s:%d", cfg.Metrics.PProfAddr, cfg.Metrics.PProfPort)
		if mAddr == pAddr {
			return fmt.Errorf("metrics and pprof cannot be enabled on the same address:port: %s", mAddr)
		}
	}

	if cfg.Metrics.Enabled {
		mAddr := fmt.Sprintf("%s:%d", cfg.Metrics.Addr, cfg.Metrics.Port)
		go metrics.CollectProcessMetrics(3 * time.Second)
		exp.Setup(mAddr)
		gethlog.Info("Metrics server started", "addr", mAddr)
	}

	if cfg.Metrics.PProf {
		pAddr := fmt.Sprintf("%s:%d", cfg.Metrics.PProfAddr, cfg.Metrics.PProfPort)
		genericconf.StartPprof(pAddr)
		gethlog.Info("PProf server started", "addr", pAddr)
	}

	return nil
}

// parseTimeouts converts config timeout strings to HTTPServerTimeoutConfig
func parseTimeouts(cfg *config.Config) genericconf.HTTPServerTimeoutConfig {
	readTimeout, _ := time.ParseDuration(cfg.Server.ReadTimeout)
	readHeaderTimeout, _ := time.ParseDuration(cfg.Server.ReadHeaderTimeout)
	writeTimeout, _ := time.ParseDuration(cfg.Server.WriteTimeout)
	idleTimeout, _ := time.ParseDuration(cfg.Server.IdleTimeout)

	// Use defaults if parsing fails
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	if readHeaderTimeout == 0 {
		readHeaderTimeout = 10 * time.Second
	}
	if writeTimeout == 0 {
		writeTimeout = 30 * time.Second
	}
	if idleTimeout == 0 {
		idleTimeout = 120 * time.Second
	}

	return genericconf.HTTPServerTimeoutConfig{
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

func startup() error {
	// Parse command line arguments
	configPath, err := parseArgs()
	if err != nil {
		printUsage(os.Args[0])
		return err
	}

	// Load configuration from TOML file
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup logging first
	logLevel, err := genericconf.ToSlogLevel(cfg.Logging.Level)
	if err != nil {
		return fmt.Errorf("invalid log level %q: %w", cfg.Logging.Level, err)
	}

	handler, err := genericconf.HandlerFromLogType(cfg.Logging.Type, io.Writer(os.Stderr))
	if err != nil {
		return fmt.Errorf("error creating log handler: %w", err)
	}
	glogger := gethlog.NewGlogHandler(handler)
	glogger.Verbosity(logLevel)
	gethlog.SetDefault(gethlog.NewLogger(glogger))

	// Print configuration with masked secrets
	gethlog.Info("Starting Celestia DAS Server")
	fmt.Print(cfg.PrintConfig())

	// Start metrics if enabled
	if err := startMetrics(cfg); err != nil {
		return err
	}

	// Setup signal handling
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create keyring if writer is enabled
	var kr keyring.Keyring
	if cfg.Celestia.WithWriter && !cfg.Celestia.NoopWriter {
		if cfg.Celestia.Signer.Type == string(signer.SignerTypeRemote) {
			kr, err = signer.NewKeyring(&cfg.Celestia.Signer, cfg.Celestia.Network)
			if err != nil {
				return fmt.Errorf("failed to create signer keyring: %w", err)
			}
			gethlog.Info("Keyring initialized", "type", cfg.Celestia.Signer.Type)
		} else {
			gethlog.Info("Using local signer configuration", "backend", cfg.Celestia.Signer.Local.Backend)
		}
	}

	// Create DAConfig from TOML config
	daCfg, err := das.NewDAConfigFromTOML(cfg, kr)
	if err != nil {
		return fmt.Errorf("failed to create DA config: %w", err)
	}

	// Create CelestiaDA instance
	celestiaDA, err := das.NewCelestiaDA(daCfg)
	if err != nil {
		return fmt.Errorf("failed to create CelestiaDA: %w", err)
	}
	defer celestiaDA.Stop()

	var celestiaReader types.CelestiaReader = celestiaDA
	var celestiaWriter types.CelestiaWriter = celestiaDA
	var rpcServer *http.Server

	// Parse HTTP server timeouts
	timeouts := parseTimeouts(cfg)

	// Keep config-level fallback settings visible even though this server currently
	// starts a single DAS RPC backend.
	if cfg.Fallback.Enabled && cfg.Fallback.DASRPC != "" {
		gethlog.Warn("fallback DAS RPC configured but not enabled in current RPC startup path", "dasRpc", cfg.Fallback.DASRPC)
	}
	rpcServer, err = das.StartDASRPCServer(
		ctx,
		cfg.Server.RPCAddr,
		cfg.Server.RPCPort,
		timeouts,
		cfg.Server.RPCBodyLimit,
		celestiaReader,
		celestiaWriter,
	)
	if err != nil {
		return fmt.Errorf("failed to start RPC server: %w", err)
	}

	gethlog.Info("CelestiaDA Server started",
		"addr", cfg.Server.RPCAddr,
		"port", cfg.Server.RPCPort,
		"writer", cfg.Celestia.WithWriter,
		"network", cfg.Celestia.Network,
		"namespace", cfg.Celestia.NamespaceID,
	)

	// Wait for shutdown signal
	<-sigint
	gethlog.Info("Shutting down...")

	if rpcServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		err = rpcServer.Shutdown(shutdownCtx)
	}

	return err
}
