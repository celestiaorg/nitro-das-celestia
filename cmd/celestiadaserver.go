package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	flag "github.com/spf13/pflag"

	gethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/metrics/exp"

	"github.com/offchainlabs/nitro/cmd/genericconf"
	"github.com/offchainlabs/nitro/cmd/util/confighelpers"
	"github.com/offchainlabs/nitro/util/headerreader"

	das "github.com/celestiaorg/nitro-das-celestia/daserver"
	"github.com/celestiaorg/nitro-das-celestia/daserver/types"
)

type CelestiaDAServerConfig struct {
	EnableRPC          bool                                `koanf:"enable-rpc"`
	RPCAddr            string                              `koanf:"rpc-addr"`
	RPCPort            uint64                              `koanf:"rpc-port"`
	RPCServerTimeouts  genericconf.HTTPServerTimeoutConfig `koanf:"rpc-server-timeouts"`
	RPCServerBodyLimit int                                 `koanf:"rpc-server-body-limit"`

	CelestiaDa das.DAConfig `koanf:"celestia"`

	LogLevel string `koanf:"log-level"`
	LogType  string `koanf:"log-type"`

	Metrics       bool                            `koanf:"metrics"`
	MetricsServer genericconf.MetricsServerConfig `koanf:"metrics-server"`
	PProf         bool                            `koanf:"pprof"`
	PprofCfg      genericconf.PProf               `koanf:"pprof-cfg"`
}

var DefaultCelestiaDAServerConfig = CelestiaDAServerConfig{
	EnableRPC:          true,
	RPCAddr:            "localhost",
	RPCPort:            9876,
	RPCServerTimeouts:  genericconf.HTTPServerTimeoutConfigDefault,
	RPCServerBodyLimit: genericconf.HTTPServerBodyLimitDefault,
	LogLevel:           "INFO",
	LogType:            "plaintext",
	Metrics:            false,
	MetricsServer:      genericconf.MetricsServerConfigDefault,
	PProf:              false,
	PprofCfg:           genericconf.PProfDefault,
}

func main() {
	if err := startup(); err != nil {
		gethlog.Error("Error running CelestiaDAServer", "err", err)
	}
}

func printSampleUsage(progname string) {
	fmt.Printf("\n")
	fmt.Printf("Sample usage:                  %s --help \n", progname)
}

func parseDAServer(args []string) (*CelestiaDAServerConfig, error) {
	f := flag.NewFlagSet("daserver", flag.ContinueOnError)
	f.Bool("enable-rpc", DefaultCelestiaDAServerConfig.EnableRPC, "enable the HTTP-RPC server listening on rpc-addr and rpc-port")
	f.String("rpc-addr", DefaultCelestiaDAServerConfig.RPCAddr, "HTTP-RPC server listening interface")
	f.Uint64("rpc-port", DefaultCelestiaDAServerConfig.RPCPort, "HTTP-RPC server listening port")
	f.Int("rpc-server-body-limit", DefaultCelestiaDAServerConfig.RPCServerBodyLimit, "HTTP-RPC server maximum request body size in bytes; the default (0) uses geth's 5MB limit")
	genericconf.HTTPServerTimeoutConfigAddOptions("rpc-server-timeouts", f)

	f.Bool("metrics", DefaultCelestiaDAServerConfig.Metrics, "enable metrics")
	genericconf.MetricsServerAddOptions("metrics-server", f)

	f.Bool("pprof", DefaultCelestiaDAServerConfig.PProf, "enable pprof")
	genericconf.PProfAddOptions("pprof-cfg", f)

	f.String("log-level", DefaultCelestiaDAServerConfig.LogLevel, "log level, valid values are CRIT, ERROR, WARN, INFO, DEBUG, TRACE")
	f.String("log-type", DefaultCelestiaDAServerConfig.LogType, "log type (plaintext or json)")

	das.CelestiaDAConfigAddOptions("celestia", f)

	k, err := confighelpers.BeginCommonParse(f, args)
	if err != nil {
		return nil, err
	}

	var serverConfig CelestiaDAServerConfig
	if err := confighelpers.EndCommonParse(k, &serverConfig); err != nil {
		return nil, err
	}

	return &serverConfig, nil
}

type L1ReaderCloser struct {
	l1Reader *headerreader.HeaderReader
}

func (c *L1ReaderCloser) Close(_ context.Context) error {
	c.l1Reader.StopOnly()
	return nil
}

func (c *L1ReaderCloser) String() string {
	return "l1 reader closer"
}

// Checks metrics and PProf flag, runs them if enabled.
// Note: they are separate so one can enable/disable them as they wish, the only
// requirement is that they can't run on the same address and port.
func startMetrics(cfg *CelestiaDAServerConfig) error {
	mAddr := fmt.Sprintf("%v:%v", cfg.MetricsServer.Addr, cfg.MetricsServer.Port)
	pAddr := fmt.Sprintf("%v:%v", cfg.PprofCfg.Addr, cfg.PprofCfg.Port)
	if cfg.Metrics && cfg.PProf && mAddr == pAddr {
		return fmt.Errorf("metrics must be enabled via command line by adding --metrics, json config has no effect")
	}
	if cfg.Metrics && cfg.PProf && mAddr == pAddr {
		return fmt.Errorf("metrics and pprof cannot be enabled on the same address:port: %s", mAddr)
	}
	if cfg.Metrics {
		go metrics.CollectProcessMetrics(cfg.MetricsServer.UpdateInterval)
		exp.Setup(fmt.Sprintf("%v:%v", cfg.MetricsServer.Addr, cfg.MetricsServer.Port))
	}
	if cfg.PProf {
		genericconf.StartPprof(pAddr)
	}
	return nil
}

func startup() error {

	serverConfig, err := parseDAServer(os.Args[1:])
	if err != nil {
		fmt.Println("Server config: ", serverConfig)
		confighelpers.PrintErrorAndExit(err, printSampleUsage)
	}
	if !(serverConfig.EnableRPC) {
		confighelpers.PrintErrorAndExit(errors.New("please specify --enable-rpc"), printSampleUsage)
	}

	logLevel, err := genericconf.ToSlogLevel(serverConfig.LogLevel)
	if err != nil {
		confighelpers.PrintErrorAndExit(err, printSampleUsage)
	}

	handler, err := genericconf.HandlerFromLogType(serverConfig.LogType, io.Writer(os.Stderr))
	if err != nil {
		flag.Usage()
		return fmt.Errorf("error parsing log type when creating handler: %w", err)
	}
	glogger := gethlog.NewGlogHandler(handler)
	glogger.Verbosity(logLevel)
	gethlog.SetDefault(gethlog.NewLogger(glogger))

	if err := startMetrics(serverConfig); err != nil {
		return err
	}

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	celestiaDA, err := das.NewCelestiaDA(&serverConfig.CelestiaDa)
	var celestiaReader types.CelestiaReader
	var celestiaWriter types.CelestiaWriter
	var rpcServer *http.Server
	if serverConfig.EnableRPC {
		if err != nil {
			return err
		}
		celestiaReader = celestiaDA
		celestiaWriter = celestiaDA

		rpcServer, err = das.StartDASRPCServer(ctx, serverConfig.RPCAddr, serverConfig.RPCPort, serverConfig.RPCServerTimeouts, serverConfig.RPCServerBodyLimit, celestiaReader, celestiaWriter)
		if err != nil {
			return err
		}

	}

	<-sigint
	celestiaDA.Stop()

	if rpcServer != nil {
		err = rpcServer.Shutdown(ctx)
	}

	return err
}
