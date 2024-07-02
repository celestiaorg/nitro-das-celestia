# Arbitrum Nitro Data Availability Server for Celestia DA

## Build

`cd cmd && go build -o celestia-server

## Use

```
./celestia-server --enable-rpc --rpc-addr $RPC_ADDR --rpc-port $RPC_PORT --celestia.auth-token $AUTH_TOKEN --celestia.gas-price $GAS_PRICE --celestia.gas-multiplier $GAS_MULTIPLIER --celestia.namespace-id $NAMESPACEID --celestia.rpc $CELESTIA_NODE_ENDPOINT
```
