# Migration Guide: nitro-das-celestia -> Nitro v3.10 Custom DA API

This guide upgrades `nitro-das-celestia` to the Nitro v3.10 Custom DA API. It is tailored to:

- Devnet usage today (with mainnet configs later)
- On-chain proof verification using Blobstream
- Proof-only certificates (no signature bytes)
- Fallback to AnyTrust/DAS only on store failure

The goal is to reuse existing Celestia logic wherever possible, while adopting the new v3.10 Custom DA provider API.

---

## 0) What changes vs legacy DAS/AnyTrust

Legacy:
- DAS/AnyTrust message header bytes
- DAS RPC methods and keyset logic
- `das-server` config flags

v3.10 Custom DA:
- `daprovider_*` RPC methods only
- CustomDA certificate format posted to SequencerInbox
- Rollup uses a custom DA validator contract

ReferenceDA (Nitro v3.10) is the minimal example. We will keep the same provider API but create a Celestia-specific certificate and validator.

---

## 1) Target architecture

**We keep**
- Celestia write/read logic
- Proof generation logic (Blobstream)
- Existing configs for Celestia nodes, auth tokens, namespaces

**We replace/add**
- CustomDA certificate format
- Custom DA validator contract
- `daprovider` RPC entrypoint

**Fallback path**
- Keep DAS/AnyTrust fallback, but only use it when Celestia store fails.

---

## 2) Certificate format (proof-only, no signature)

### Proposed certificate (v1)

```
CelestiaDACertV1 {
  uint8  header = 0x01                 // CustomDA flag
  uint8  providerType = 0x0C           // Celestia provider type
  uint16 version = 1
  bytes32 dataRoot                     // Celestia data root
  bytes32 namespace                    // Namespace ID
  uint64 height                        // Celestia block height
  uint32 shareStart                    // Share range start
  uint32 shareLen                      // Share range length
  bytes32 txCommitment                 // Celestia blob commitment
  bytes   blobstreamProof              // proof blobstream verifies
}
```

Notes:
- Proof-only: no signature field.
- `txCommitment` (Celestia blob commitment) ensures the DA data matches the sequencer payload.
- `blobstreamProof` is validated on-chain.

---

## 3) On-chain validator (Blobstream)

Create a new contract `CelestiaDAProofValidator` that:

- Parses `CelestiaDACertV1`.
- Verifies the Blobstream proof on L1.
- Validates `txCommitment` against data root (or proof output).

**Devnet**
- Deploy a Blobstream contract on the L1 devnet.
- Configure its address in `CelestiaDAProofValidator`.

**Mainnet**
- Point to the canonical Blobstream deployment for mainnet (configurable).

---

## 4) Custom DA provider API implementation

### 4.1 Writer

Implement `daprovider.Writer`:

- Store payload in Celestia
- Build and serialize `CelestiaDACertV1`
- Return the cert bytes as `SerializedDACert`
- If Celestia store fails, fallback to DAS store

### 4.2 Reader

Implement `daprovider.Reader`:

- Parse certificate
- Fetch payload from Celestia
- Verify payload integrity via `txCommitment`
- Return payload

### 4.3 Validator

Implement `daprovider.Validator`:

- Use on-chain Blobstream proof validation
- No signature validation
- Return validity proof data if needed

---

## 5) Fallback policy (store failure only)

If Celestia store fails, fallback to AnyTrust/DAS:

- Keep `daclient` for AnyTrust aggregator
- Do NOT fallback on read failures unless explicitly enabled

Pseudo logic:

```
try celestia.Store(payload)
  -> return CelestiaDACertV1
catch
  -> return anytrust.Store(payload)
```

---

## 6) Config and flags

### Provider server flags (new)

```
--mode celestia
--provider-server.addr 0.0.0.0
--provider-server.port 9880
--provider-server.enable-da-writer

--celestia.* (existing flags reused)
--celestia.validator-config.blobstream <L1 address>
--celestia.validator-config.eth-rpc <L1 RPC>

--fallback-enabled true
--das.rpc.url <AnyTrust RPC>
```

### Nitro node config

```
node.da.external-provider.enable = true
node.da.external-provider.with-writer = true
node.da.external-provider.rpc.url = http://<celestia-provider>:9880

node.da.anytrust.enable = true
node.da.anytrust.rpc-aggregator.backends = [...]
```

---

## 7) Repo changes (file-level plan)

### New files
- `daserver/cert/celestia_cert.go`
  - Serialize/deserialize `CelestiaDACertV1` and constants (header/providerType)
- `daserver/validator/celestia_validator.go`
  - Blobstream proof verification helpers (on-chain)
- `daserver/daprovider_server.go`
  - Implements `daprovider_*` RPC methods using new certs

### Updated files
- `daserver/rpc_server.go`
  - Register new `daprovider_*` handlers, keep `celestia_*` namespace
- `daserver/celestia.go`
  - Add certificate creation from Celestia write output
  - Expose proof construction input for validator
- `daserver/types/reader.go`
- Replace `CelestiaMessageHeaderFlag` parsing with CustomDA header (0x01) + Celestia provider type (0x0C)
- Recover payload using `txCommitment` integrity
- `cmd/celestiadaserver.go`
  - Add `--mode celestia` and CustomDA options
  - Keep DAS fallback flags

### Reuse
- `daserver/types/*` (BlobPointer, Celestia proofs)
- Celestia read/write code
- Existing configuration logic (auth token, namespace, validator-config)

---

## 8) Devnet rollout plan

1) Deploy Blobstream contract on devnet L1
2) Deploy `CelestiaDAProofValidator`
3) Redeploy rollup with `customOsp` pointing to validator
4) Run updated Celestia provider (`daprovider` API)
5) Run Nitro node with `node.da.external-provider`
6) Validate:
   - Batch posts include CustomDA cert
   - `daprovider_recoverPayload` works
   - Blobstream proof passes on-chain

---

## 9) Mainnet rollout plan

1) Configure mainnet Blobstream address
2) Deploy `CelestiaDAProofValidator` with that address
3) Redeploy rollup or upgrade if supported
4) Switch batch poster to CustomDA provider

---

## 10) Open decisions

- Exact Blobstream proof format to embed in cert
- Cert size constraints (may require compression)
- Whether to include `payloadSha256` if Blobstream proof already binds it

---

## 11) Quick checklist

- [ ] New CustomDA certificate type defined
- [ ] Celestia write -> cert builder
- [ ] Celestia read -> payload verify
- [ ] Blobstream on-chain verifier
- [ ] `daprovider_*` endpoints exposed
- [ ] Fallback on store failure only
- [ ] Rollup redeployed with custom validator
