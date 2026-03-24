# AGENTS.md

This repository implements a Celestia DA provider and proof validator integration for Nitro.

The most important rule for any AI working in this repo:

- Do not "align" tests to current behavior if that behavior violates the Arbitrum DA integration contract.
- Prefer preserving or adding tests that encode the spec, even if they currently fail.
- Treat failing spec tests as implementation gaps to fix, not as reasons to weaken the test suite.

## Critical DA Semantics

For invalid certificates:

- The system must not return infrastructure-style errors.
- The validator path must return a successful response with `claimedValid=0`.
- The onchain `validateCertificate` flow must return `false`, not revert.
- `validateCertificate`-style helper logic should return `false, nil` for invalid certs.

Examples of invalid-certificate conditions in this repo:

- malformed certificate bytes
- unattested height / no Blobstream event
- uncommitted height
- bad attestation / invalid proof of validity
- non-attestable certificate fields such as zero shares length or zero data root

For infrastructure or transient failures:

- Return errors.
- Do not silently translate them into "invalid certificate".

Examples of infrastructure failures:

- L1 / RPC unreachable
- RPC timeout
- proof backend unavailable
- database / storage outage

## Reader Rules

Reader APIs:

- `RecoverPayload`
- `CollectPreimages`
- `RecoverPayloadAndPreimages`

Expected behavior:

- Invalid certificate => `daprovider.CertificateValidationError`
- Infrastructure failure => ordinary error
- Empty batch => success, not error

Important:

- Preserve exact error classification. Do not collapse validation failures into generic errors.

## Validator Rules

Validator APIs:

- `GenerateCertificateValidityProof`
- `GenerateReadPreimageProof`

Expected behavior:

- Invalid certificate => no error, proof claims invalid
- Infrastructure failure => error

Important:

- Missing Blobstream event and uncommitted height are currently covered by tests as invalid-certificate cases.
- Do not change those tests to expect timeouts or generic failures just to make the suite green.

## Onchain Rules

The Solidity validator should:

- return `false` for invalid proofs / invalid certificates
- not revert for invalid certificate cases

There is already useful coverage in:

- `contracts/test/CelestiaDAProofValidator.t.sol`

Before adding more Solidity tests, check whether the behavior is already covered there.

## Testing Guidance

High-value spec tests already added or emphasized in this repo include:

- invalid-vs-infra classification for reader methods
- invalid certificate behavior for validator methods
- empty-batch success behavior for reader methods
- no-event / uncommitted-height invalidity behavior
- read-preimage layout and boundary coverage
- `MaxMessageSize` fallback on invalid onchain return values

If tests fail, first decide whether:

1. the test is expressing the intended spec
2. the implementation is non-compliant
3. the test is actually wrong

Bias toward fixing code, not lowering the test bar.

## Files To Check First

- `daserver/celestia.go`
- `daserver/blobstream_test.go`
- `daserver/types/reader.go`
- `daserver/types/reader_test.go`
- `daserver/max_message_size_test.go`
- `contracts/src/CelestiaDAProofValidator.sol`
- `contracts/test/CelestiaDAProofValidator.t.sol`

## Known Current Gaps

As of the latest test work in this repo, the main spec gaps are:

- end-to-end Nitro BOLD/custom-DA challenge coverage against the real provider is still pending

Do not remove or soften tests that cover these areas unless the spec itself changes.
