## Contracts

This directory contains the Solidity side of the upgraded DA API integration:

- `src/CelestiaDAProofValidator.sol` implements Nitro's custom DA proof validator interface for Celestia certificates.
- `test/CelestiaDAProofValidator.t.sol` covers certificate-validity and read-preimage proof verification without a live Blobstream deployment.
- `test/mocks/MockBlobstream.sol` provides the minimal attestation oracle used by the unit tests.

## Tooling

The contracts use Foundry with Soldeer-managed dependencies.

```sh
cd contracts
forge soldeer install
forge build
forge test -vvv
```

## Dependencies

Introduced dependencies are intentionally kept scoped to the contracts work:

- `@nitro-contracts` for `ICustomDAProofValidator`
- `forge-std` for Foundry test helpers
- `@openzeppelin-contracts` for contract utilities pulled by Nitro contracts
