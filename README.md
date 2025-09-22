# Arbitrum Nitro Data Availability Server for Celestia DA

A data availability server for the Arbitrum Nitro stack, leveraging Celestia DA ✨

## Build locally

`cd cmd && go build -o celestia-server`

## Docker

`FROM ghcr.io/celestiaorg/nitro-das-celestia:v0.5.4`


## Example usage

```
./celestia-server --enable-rpc --rpc-addr $RPC_ADDR \
      --rpc-port $RPC_PORT \
      --celestia.auth-token $AUTH_TOKEN \
      --celestia.gas-price $GAS_PRICE \
      --celestia.gas-multiplier $GAS_MULTIPLIER \
      --celestia.namespace-id $NAMESPACEID \
      --celestia.rpc $CELESTIA_NODE_ENDPOINT 
```

## Running Docker Image

```
docker run --name celestia-server \
      -p 26657:26657 \
      -e AUTH_TOKEN=your_token  \
      -e NAMESPACEID=your_namespace  \
      -e CELESTIA_NODE_ENDPOINT=your_node_endpoint \
      ghcr.io/celestiaorg/nitro-das-celestia:v0.4.3
```

## Example Docker Compose

For an example on how to use the images in conjunction with other containers, check the [docker-compose.yaml](https://github.com/celestiaorg/nitro-das-celestia/blob/main/docker-compose.yaml) in this repository for an example

## Fallback setup

If the orbit chain uses celestia da, but has fallbacks enabled using an anytrust setup, a `daprovider` connection is needed. The `daprovider` binary can be ran as a wrapper around an existing rest aggregator endpoint, for example:

```
daprovider:
    image: ghcr.io/celestiaorg/nitro:v3.6.8
    entrypoint: /usr/local/bin/daprovider
    ports:
      - "127.0.0.1:9880:9880"
    command:
      - --das-server.addr=0.0.0.0
      - --das-server.port=9880
      - --das-server.data-availability.enable=true
      - --das-server.data-availability.rest-aggregator.enable=true
      - --das-server.data-availability.rest-aggregator.urls=<rest_aggregator_url>
      - --das-server.data-availability.parent-chain-node-url=<ethereum_rpc>
      - --das-server.data-availability.sequencer-inbox-address=<squencer_inbox_address>
```

This then can be used in your celestia server as:
```
celestia-server:
    image: ghcr.io/celestiaorg/nitro-das-celestia:v0.5.4
    container_name: celestia-server
    entrypoint:
      - /bin/celestia-server
      - --das.enable
      - --fallback-enabled
      - --celestia.namespace-id
      - $NAMESPACE
      - --rpc-addr
      - "0.0.0.0"
      - --rpc-port
      - "26657"
      - --das.rpc.url
      - $DAPROVIDER_URL
      - --celestia.rpc
      - $CELESTIA_RPC_ENDPOINT
      - --log-level
      - "DEBUG"
    ports:
      - "1317:1317"
      - "9090:9090"
      - "26657:26657" # Celestia RPC Port
      - "1095:1095"
      - "8080:8080"
```

## Flags

```
./celestia-server --help
Usage of daserver:
      --celestia.auth-token string                         Auth token for Celestia Node
      --celestia.cache-time duration                       how often to clean the in memory cache (default 30m0s)
      --celestia.dangerous-reorg-on-read-failure           DANGEROUS: reorg if any error during reads from celestia node
      --celestia.enable                                    Enable Celestia DA
      --celestia.gas-multiplier float                      Gas multiplier for Celestia transactions (default 1.01)
      --celestia.gas-price float                           Gas for retrying Celestia transactions (default 0.01)
      --celestia.namespace-id string                       Celestia Namespace to post data to
      --celestia.noop-writer                               Noop writer (disable posting to celestia)
      --celestia.read-auth-token string                    Auth token for Celestia Node
      --celestia.read-rpc string                           separate celestia RPC endpoint for reads
      --celestia.rpc string                                Rpc endpoint for celestia-node
      --celestia.validator-config.blobstream string        Blobstream address, only used for validation
      --celestia.validator-config.eth-rpc string           Parent chain connection, only used for validation
      --celestia.validator-config.sleep-time int           How many seconds to wait before initiating another filtering loop for Blobstream events (default 3600)
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

## Running a da server for an Orbit x Celestia chain

Before proceeding, it is highly encouraged to familiarize yourself with [Celestia](https://docs.celestia.org/) and more specifically with [DA Nodes](https://docs.celestia.org/how-to-guides/light-node) (light, full, bridge)

## Running a Batch Poster

If you are running a celestia-sever for a batch poster node, you need to take the following into account:

- if you don't provide a `gas-price` and a `gas-multipler`, you will be automatically opting for gas estimation from your celestia-node
- you should run this on the same machine as your nitro batch poster node
- you WILL NOT be able to use a hosted provider for your celestia-node endpoint. You will have to run your own celestia-node in order to post data to Celestia
- you can get the `auth token` for your node like [this](https://docs.celestia.org/how-to-guides/quick-start#get-your-auth-token)
- you will need to pick a [namespace](https://docs.celestia.org/tutorials/node-tutorial#namespaces) were to write data to and make sure to use this in other nodes and share with node runners.

## Running a Full Node

If you are running a celestia-server as part of a full node setup for an orbit x celestia da chain, note the folloing:

- you don't need to provide a `gas-price` or a `gas-multiplier`, since the node won't be submitting data to celestia
- you should run this on the same machine as your nitro full node or block the `store` endpoint if you are not running a batch poster
- you only need a namespace to use when fetching data from Celestia (the rollup should make this clear and accesible to you), and a celestia-node endpoint (core / consensus endpoints won't work!). If you do not wish to run your own celestia light node, or da bridge node, you can get a hosted endpoint from providers like:
  - [Quicknode](https://www.quicknode.com/docs/celestia)



## Running a Validator
>[!CAUTION]
> The celestia server binary won't throw an error if you forget to set the validator config, if you are running validators for your chain, please read carefully

In order to ensure the validator for an Orbit chain is capable of fulffiling its role in case of a challenge, its important that the celestia-server command is given the following flags / configurations:
- `--celestia.validator-config.blobstream string        Blobstream address, only used for validation`
- `--celestia.validator-config.eth-rpc string           Parent chain connection, only used for validation`

Additionally the `--celestia.validator-config.sleep-time` lets you configure how many seconds you want the `GetProof` method to wait before trying to fetch for an onchain event for a Blobstream proof (default is `3600` or 1 hour). Note that all the validator config values can be hot reloaded.

For the `blobstream` flag, you want to pass an address for the blobstream instance in the parent chain (i.e if you are running a validator for an Ethereum L2, the parent chain is Ethereum Mainnet), addresses for currently deployed instances of [SP1 Blobstream](https://docs.celestia.org/how-to-guides/blobstream#what-is-sp1-blobstream) can be found [here](https://docs.celestia.org/how-to-guides/blobstream#deployed-contracts). If you are deploying on a parent chain that is not in this list, please follow [this guide ](https://docs.celestia.org/how-to-guides/sp1-blobstream-deploy) to get a new deployment running and contact, and reach out to the [Succinct Team](https://linktr.ee/succinctlabs) for more information.

For the `eth-rpc` flag, you just need to provide an rpc for the parent chain, and since you are running a node you likely already have an endpoint available in your nitro node config that can be re-used here. (NOTE: connection type is http)

## Testing GetProof

While e2e tests excist, users might want to test and verify that the da server's `GetProof` method functions as expected, the [`blobstream_test.go`](https://github.com/celestiaorg/nitro-das-celestia/blob/main/das/blobstream_test.go) provides a way to do this.

There's an example `.env` file you can switch the values for, which are preconfigured to run against a Nitro x Celestia deployment on Arbitrum One (Mainnet).

The easiest way to run the test is to:

- run a celestia light node against celestia mainnet
- put an RPC endpoint for Arbitrum one in your `.env` file
- run `go test -v -timeout 30s -run ^TestGetProofVerification$/^Get_Proof_e2e$`

For those interested in doing their own testing, you can switch the values in the `.env` accordingly (make sure you are using the correct blobstream address for the network given in the ETH_RPC variable. All other values can be found through the celestia node cli or through the use of an explorer such as [Celenium](https://celenium.io/). If you are going to perform the test against a network other than Arbitrum One, you will need to deploy the wrapper contract around the blobstream verification library, the necessary contracts and deployment scripts can be found in the [`test`](https://github.com/celestiaorg/nitro-das-celestia/tree/main/test) folder

