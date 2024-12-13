# Arbitrum Nitro Data Availability Server for Celestia DA

A data availability server for the Arbitrum Nitro stack, leveraging Celestia DA ✨

## Build locally

`cd cmd && go build -o celestia-server`

## Docker

`FROM ghcr.io/celestiaorg/nitro-das-celestia:v0.3.1`


## Example usage

```
./celestia-server --enable-rpc --rpc-addr $RPC_ADDR \
      --rpc-port $RPC_PORT --celestia.auth-token $AUTH_TOKEN \
      --celestia.gas-price $GAS_PRICE \
      --celestia.gas-multiplier $GAS_MULTIPLIER \
      --celestia.namespace-id $NAMESPACEID \
      --celestia.rpc $CELESTIA_NODE_ENDPOINT \
      --celestia.keyname $KEYNAME
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
      --celestia.keyname string                            Celestia DA node keyring keyname for blobs submissions
      --celestia.namespace-id string                       Celestia Namespace to post data to
      --celestia.noop-writer                               Noop writer (disable posting to celestia)
      --celestia.read-auth-token string                    Auth token for Celestia Node
      --celestia.read-rpc string                           separate celestia RPC endpoint for reads
      --celestia.rpc string                                Rpc endpoint for celestia-node
      --celestia.validator-config.blobstream string        Blobstream address, only used for validation
      --celestia.validator-config.eth-rpc string           Parent chain connection, only used for validation
      --celestia.cache-time                                how often to clean the in memory cache
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

## Running a Validator
>[!CAUTION]
> The celestia server binary won't throw an error if you forget to set the validator config, if you are running validators for your chain, please read carefully

In order to ensure the validator for an Orbit chain is capable of fulffiling its role in case of a challenge, its important that the celestia-server command is given the following flags:
- `--celestia.validator-config.blobstream string        Blobstream address, only used for validation`
- `--celestia.validator-config.eth-rpc string           Parent chain connection, only used for validation`

For the `blobstream` flag, you want to pass an address for the blobstream instance in the parent chain (i.e if you are running a validator for an Ethereum L2, the parent chain is Ethereum Mainnet), addresses for currently deployed instances of [SP1 Blobstream](https://docs.celestia.org/how-to-guides/blobstream#what-is-sp1-blobstream) can be found [here](https://docs.celestia.org/how-to-guides/blobstream#deployed-contracts). If you are deploying on a parent chain that is not in this list, please follow [this guide ](https://docs.celestia.org/how-to-guides/sp1-blobstream-deploy) to get a new deployment running and contact, and reach out to the [Succinct Team](https://linktr.ee/succinctlabs) for more information.

For the `eth-rpc` flag, you just need to provide an rpc for the parent chain, and since you are running a node you likely already have an endpoint available in your nitro node config that can be re-used here. (NOTE: connection type is http)

