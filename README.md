# Arbitrum Nitro Data Availability Server for Celestia DA

*NOTE:* Currently for use against [celestia-node](https://github.com/celestiaorg/celestia-node) version 0.15.0

## Build locally

`cd cmd && go build -o celestia-server`

## Docker

`FROM ghcr.io/celestiaorg/nitro-das-celestia:v0.2.0`


## Example usage

```
./celestia-server --enable-rpc --rpc-addr $RPC_ADDR \
      --rpc-port $RPC_PORT --celestia.auth-token $AUTH_TOKEN \
      --celestia.gas-price $GAS_PRICE \
      --celestia.gas-multiplier $GAS_MULTIPLIER \
      --celestia.namespace-id $NAMESPACEID \
      --celestia.rpc $CELESTIA_NODE_ENDPOINT \
      --celestia.keyring-keyname $KEYNAME
```

## Flags

```
./celestiadaserver --help
Usage of daserver:
      --celestia.auth-token string                         Auth token for Celestia Node
      --celestia.dangerous-reorg-on-read-failure           DANGEROUS: reorg if any error during reads from celestia node
      --celestia.enable                                    Enable Celestia DA
      --celestia.gas-multiplier float                      Gas multiplier for Celestia transactions (default 1.01)
      --celestia.gas-price float                           Gas for retrying Celestia transactions (default 0.01)
      --celestia.keyring-keyname string                    Celestia DA node keyring keyname for blobs submissions
      --celestia.namespace-id string                       Celestia Namespace to post data to
      --celestia.noop-writer                               Noop writer (disable posting to celestia)
      --celestia.read-auth-token string                    Auth token for Celestia Node
      --celestia.read-rpc string                           separate celestia RPC endpoint for reads
      --celestia.rpc string                                Rpc endpoint for celestia-node
      --celestia.validator-config.blobstream string        Blobstream address, only used for validation
      --celestia.validator-config.eth-rpc string           L1 Websocket connection, only used for validation
      --celestia.validator-config.tendermint-rpc string    Tendermint RPC endpoint, only used for validation
      --enable-rpc                                         enable the HTTP-RPC server listening on rpc-addr and rpc-port
      --log-level string                                   log level, valid values are CRIT, ERROR, WARN, INFO, DEBUG, TRACE (default "INFO")
      --log-type string                                    log type (plaintext or json) (default "plaintext")
      --metrics                                            enable metrics
      --metrics-server.addr string                         metrics server address (default "127.0.0.1")
      --metrics-server.port int                            metrics server port (default 6070)
      --metrics-server.update-interval duration            metrics server update interval (default 3s)
      --pprof                                              enable pprof
      --pprof-cfg.addr string                              pprof server address (default "127.0.0.1")
      --pprof-cfg.port int                                 pprof server port (default 6071)
      --rpc-addr string                                    HTTP-RPC server listening interface (default "localhost")
      --rpc-port uint                                      HTTP-RPC server listening port (default 9876)
      --rpc-server-body-limit int                          HTTP-RPC server maximum request body size in bytes; the default (0) uses geth's 5MB limit
      --rpc-server-timeouts.idle-timeout duration          the maximum amount of time to wait for the next request when keep-alives are enabled (http.Server.IdleTimeout) (default 2m0s)
      --rpc-server-timeouts.read-header-timeout duration   the amount of time allowed to read the request headers (http.Server.ReadHeaderTimeout) (default 30s)
      --rpc-server-timeouts.read-timeout duration          the maximum duration for reading the entire request (http.Server.ReadTimeout) (default 30s)
      --rpc-server-timeouts.write-timeout duration         the maximum duration before timing out writes of the response (http.Server.WriteTimeout) (default 30s)
```
