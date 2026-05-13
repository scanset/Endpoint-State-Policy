# ESP v1.2.0 — Canonical Execution Schema

**Version:** 1.2.0
**Status:** Normative (v1.2 line only — SUPERSEDED by v2.0.0 for new envelopes)
**Last Updated:** 2026-03-01

---

> **This document describes the v1.2.0 envelope.** New envelopes emitted
> by the agent are v2.0.0 and follow the schema in
> `docs/09_ESP_Canonical_Schema_v2_1_1.md`. This document remains
> normative for archived v1.x envelopes and for consumers that must
> continue reading them; it is NOT updated further.
>
> Key v1.2 → v2.0.0 differences:
>
> - `HostInfo` is polymorphic — `host_type` is a dotted `<provider>.<kind>`
>   string, not implicitly `linux.vm`.
> - A top-level `observations[]` array replaces inline
>   `PolicyResult.evidence`. Policies cite evidence by uuid via
>   `observation_refs[]`.
> - Replay hash invariants are explicit: host block, `observations[]`,
>   and timestamps are excluded.
>
> No migration tool is provided: v1.x envelopes are archived as-is; new
> scans emit v2.0.0.

---

## 1. Overview

This document specifies the canonical schema for ESP scan results. The schema defines the structure produced by the ESP agent for compliance scan output, supporting multiple output formats for different use cases.

---

## 2. Architecture

### 2.1 Data Flow

```
ESP Policy File(s)
    ↓ (compiler)
AST
    ↓ (resolution)
ExecutionContext
    ↓ (execution_engine)
ScanResult (per policy)
    ↓ (ResultBuilder)
    ├── Summary (minimal, CI/CD)
    ├── Attestation (CUI-free, network-safe)
    ├── Full Results (with Evidence)
    └── Assessor Package (with reproducibility) [DEFAULT]
```

### 2.2 Design Principles

| Principle | Description |
|-----------|-------------|
| **Single Envelope** | All policies in one result, regardless of input count |
| **Complete** | Contains all execution data needed for each output mode |
| **Verifiable** | Replay hash enables attestation/full result correlation |
| **Stable** | Same compliance posture produces same hash across runs |
| **Serializable** | JSON format for interoperability |
| **Signable** | Cryptographic signatures bind results to agent identity |
| **Transparent** | Certificate issuance logged to append-only transparency log |

### 2.3 Output Format Selection

| Output Format | Evidence Data | Findings | Collection Methods | Commands/Inputs | Reproducibility | Signature |
|---------------|---------------|----------|-------------------|-----------------|-----------------|-----------|
| `summary` | No | No | No | No | No | No |
| `attestation` | Hash only | No | Type only | No | No | Yes |
| `full` | Full | Yes | Full | No | No | Yes |
| `assessor` | Full | Yes | Full | Yes | Yes | Yes |

**Note:** `assessor` is the default output format as of v1.1.0.

### 2.4 Replay Hash Architecture (v1.2.0)

The `replay_hash` replaces the previous `content_hash` + `evidence_hash` dual-hash system. It is computed from a three-layer `ReplayManifest` that captures intent, contract, and outcome per criterion, rolled up through the CRI tree using a Merkle-style structure.

```
ReplayManifest
├── policy_id, platform, criticality
├── CriterionReplay[] (one per CTN)
│   ├── Intent:   what was checked (fields, operations, expected values)
│   ├── Contract: how it was executed (collector, mode, mappings)
│   └── Outcome:  what passed/failed (per-field pass/fail, NO actual values)
└── ReplayTreeNode (CRI tree rollup)
    ├── Leaf { ctn_node_id } → criterion hash
    └── Block { AND/OR, negate, children } → combined hash
```

**Properties:**
- **Deterministic:** BTreeMap for sorted keys, canonical JSON serialization
- **Stable:** Same policy + same compliance posture = same hash, regardless of actual collected values
- **Tree-aware:** AND vs OR with same children produces different hashes; negation changes hash
- **Privacy-preserving:** Proves verification was performed correctly without revealing evidence data

---

## 3. Result Envelope Schema

### 3.1 Top-Level Structure

All output formats share a common envelope structure:

```json
{
  "envelope": {
    "result_id": "string",
    "schema_version": "string",
    "agent": {},
    "host": {},
    "started_at": "string",
    "completed_at": "string",
    "replay_hash": "string",
    "signature": {},
    "identity_status": {}
  },
  "summary": {},
  "policies": []
}
```

### 3.2 Envelope Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `result_id` | string | Yes | Unique identifier for this result (format: `esp-result-{hex}`) |
| `schema_version` | string | Yes | Result schema version (SemVer) |
| `agent` | object | Yes | Agent information |
| `host` | object | Yes | Host information |
| `started_at` | string | Yes | ISO 8601 timestamp when scan started |
| `completed_at` | string | Yes | ISO 8601 timestamp when scan completed |
| `replay_hash` | string | Yes | SHA-256 replay hash (intent + contract + outcome, see Section 2.4) |
| `signature` | object | No | Cryptographic signature (see Section 3.5) |
| `identity_status` | object | Yes | Identity bootstrap status (see Section 3.6) |

### 3.3 Agent Information

```json
{
  "id": "esp-agent",
  "name": "esp-agent",
  "version": "1.2.0",
  "agent_type": "cli"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Agent identifier |
| `name` | string | Yes | Agent name |
| `version` | string | Yes | Agent version (SemVer) |
| `agent_type` | string | Yes | Agent type: `cli`, `daemon`, `controller` |

### 3.4 Host Information

```json
{
  "id": "host-ad1bfa7a1863edb2",
  "hostname": "server01",
  "os": "linux",
  "arch": "x86_64"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Host identifier (format: `host-{hex}`) |
| `hostname` | string | Yes | Hostname |
| `os` | string | Yes | Operating system: `linux`, `windows`, `macos` |
| `arch` | string | Yes | Architecture: `x86_64`, `aarch64`, etc. |

### 3.5 Signature Block

The signature block provides cryptographic proof of result integrity and agent identity. When present, it contains a digital signature over the envelope's `replay_hash` field, along with the certificate chain and transparency proof for PKI verification.

#### 3.5.1 Structure

```json
{
  "signer_id": "scanset://prod/aws/account/123456789012/workload/esp-agent",
  "signer_type": "agent",
  "algorithm": "ecdsa-p256",
  "public_key": "BASE64_ENCODED_PUBLIC_KEY",
  "signature": "BASE64_ENCODED_SIGNATURE",
  "payload": "BASE64_ENCODED_PAYLOAD",
  "key_id": "pki:cert:1234567890abcdef",
  "signed_at": "2026-01-10T15:30:00Z",
  "covers": ["replay_hash"],
  "certificate_chain": [
    "-----BEGIN CERTIFICATE-----\n<workload-cert>\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n<workload-ca>\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n<ia-cert>\n-----END CERTIFICATE-----"
  ],
  "transparency": {
    "log_index": 47,
    "inclusion_proof": {
      "tree_size": 100,
      "root_hash": "abc123def456789...",
      "hashes": ["hash1...", "hash2...", "hash3..."]
    }
  }
}
```

#### 3.5.2 Signature Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signer_id` | string | Yes | Unique identifier for the signer (see 3.5.3) |
| `signer_type` | string | Yes | Type of signer (currently always `"agent"`) |
| `algorithm` | string | Yes | Signing algorithm identifier (see 3.5.4) |
| `public_key` | string | Yes | Base64-encoded public key for verification |
| `signature` | string | Yes | Base64-encoded signature value |
| `payload` | string | Yes* | Base64-encoded signed payload (see 3.5.6) |
| `key_id` | string | Yes | Key identifier for external lookup (see 3.5.5) |
| `signed_at` | string | Yes | ISO 8601 timestamp when signature was created |
| `covers` | array | Yes | Fields covered by signature |
| `certificate_chain` | array | Yes* | X.509 certificate chain for PKI verification (see 3.5.8) |
| `transparency` | object | Yes* | Transparency log proof (see 3.5.9) |

*Required when PKI identity is available. May be `null` in legacy or degraded modes.

#### 3.5.3 Signer Identification

The `signer_id` format depends on the identity source:

| Identity Source | Format | Example |
|-----------------|--------|---------|
| PKI (Workload Certificate) | SAN URI from certificate | `scanset://prod/aws/account/123456789012/workload/esp-agent` |
| TPM (Legacy) | `tpm:sha256:<fingerprint>` | `tpm:sha256:a1b2c3d4e5f6...` |
| Software (Legacy) | `software:sha256:<fingerprint>` | `software:sha256:d4e5f6a7b8c9...` |

**PKI Signer ID Format:**

When using PKI identity, the `signer_id` is extracted from the workload certificate's Subject Alternative Name (SAN) URI extension. The format is:

```
scanset://{environment}/{provider}/account/{account_id}/workload/{workload_id}
```

| Component | Description | Example |
|-----------|-------------|---------|
| `environment` | Deployment environment | `prod`, `staging`, `dev` |
| `provider` | Cloud provider | `aws`, `gcp`, `azure` |
| `account_id` | Cloud account identifier | `123456789012` |
| `workload_id` | Workload identifier | `esp-agent` |

#### 3.5.4 Algorithm Values

| Value | Description | Key Type |
|-------|-------------|----------|
| `ecdsa-p256` | ECDSA with NIST P-256 curve | PKI or software |
| `tpm-ecdsa-p256` | TPM-backed ECDSA with NIST P-256 curve | Hardware-protected (legacy) |

**Note:** As of v1.1.0, `ecdsa-p256` with PKI identity is the standard signing method.

#### 3.5.5 Key Identification

The `key_id` format depends on the identity source:

| Identity Source | Format | Example |
|-----------------|--------|---------|
| PKI | `pki:cert:<certificate_serial>` | `pki:cert:1234567890abcdef` |
| TPM (Legacy) | `tpm:ephemeral:<key_name>` | `tpm:ephemeral:ESP_EPHEMERAL_a1b2c3d4-...` |
| Software (Legacy) | `software:ephemeral:<uuid>` | `software:ephemeral:550e8400-e29b-...` |

#### 3.5.6 Signed Data and Payload

The signature covers the `replay_hash`:

```
signed_data = SHA256(replay_hash)
```

For example:

```
replay_hash = "sha256:7a3f1e9b4c2d8056..."
signed_data = SHA256("sha256:7a3f1e9b4c2d8056...")
```

**Payload Field:**

The `payload` field contains the Base64-encoded `signed_data` (the 32-byte SHA-256 hash). This field is included to simplify verification by providing the exact bytes that were signed, eliminating the need for verifiers to reconstruct the payload from the envelope fields.

```
payload = Base64(signed_data)
        = Base64(SHA256(replay_hash))
```

**Important:** The ECDSA signature is computed as `ECDSA_Sign(SHA256(signed_data))` because the OpenSSL signing API hashes the input before signing. This means the actual cryptographic operation is:

```
signature = ECDSA_Sign(SHA256(SHA256(replay_hash)))
```

When verifying:
1. Decode `payload` from Base64 → 32 bytes
2. The verifier's ECDSA implementation will hash these 32 bytes before verification
3. This matches what the agent signed

#### 3.5.7 Verification Levels

The signature system supports multiple verification levels:

| Level | Description | Trust Model |
|-------|-------------|-------------|
| **Level 0** | Self-contained verification | Public key included in signature; verifier trusts delivery channel |
| **Level 1** | PKI verification | Certificate chain validated against trusted Root CA |
| **Level 2** | PKI + Transparency | Certificate chain validated AND transparency proof verified |

**Current Implementation:** Level 2 is the standard for PKI-signed results. The certificate chain allows offline verification against a trusted Root CA, and the transparency proof provides tamper-evident audit trail.

#### 3.5.8 Certificate Chain

When present, `certificate_chain` contains an ordered array of PEM-encoded X.509 certificates:

| Index | Certificate | Description |
|-------|-------------|-------------|
| `[0]` | Workload certificate | Signing certificate issued to the agent |
| `[1]` | Workload CA certificate | Intermediate CA for workload certificates |
| `[2]` | Trust System IA certificate | Intermediate Authority certificate |

The chain allows verification up to a trusted Root CA without requiring network access.

**Verification procedure:**

1. Parse all certificates in the chain
2. Verify each certificate's signature against its issuer
3. Verify the chain terminates at a trusted Root CA
4. Validate the leaf certificate (workload cert):
   - `notBefore` ≤ current time ≤ `notAfter`
   - Key Usage includes `digitalSignature`
   - Basic Constraints: `CA:FALSE`
5. Extract the SAN URI and compare with `signer_id`
6. Extract the public key and compare with `public_key` field

#### 3.5.9 Transparency Proof

The `transparency` field provides cryptographic proof that the signing certificate was logged to the Trust System's append-only transparency log at issuance time.

```json
{
  "log_index": 47,
  "inclusion_proof": {
    "tree_size": 100,
    "root_hash": "abc123def456789...",
    "hashes": ["hash1...", "hash2...", "hash3..."]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `log_index` | integer | Index of the certificate entry in the transparency log |
| `inclusion_proof` | object | Merkle tree inclusion proof |

**Inclusion Proof Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `tree_size` | integer | Size of the Merkle tree when proof was generated |
| `root_hash` | string | Hex-encoded root hash of the Merkle tree |
| `hashes` | array | Hex-encoded sibling hashes for proof verification |

**Verification procedure:**

1. Reconstruct the leaf hash: `leaf_hash = SHA256(0x00 || certificate_pem || signer_id)`
2. Walk the proof path using the sibling hashes:
   - For each hash, combine with current hash using: `SHA256(0x01 || left || right)`
3. Compare the computed root with `inclusion_proof.root_hash`
4. Optionally fetch a signed checkpoint from the transparency log to verify `root_hash` is authentic

**Security properties:**

- **Tamper evidence:** Any modification to the log changes the root hash
- **Non-repudiation:** Certificate issuance is permanently recorded
- **Auditability:** Third parties can verify certificate was logged

#### 3.5.10 Verification Procedure (Complete)

To fully verify a signed result with PKI identity:

```
1. PARSE signature block
   - Decode public_key from Base64
   - Decode signature from Base64
   - Decode payload from Base64
   - Parse certificate_chain PEM certificates

2. VERIFY certificate chain
   - Chain: workload_cert → workload_ca → ia_cert → (trusted Root CA)
   - Validate each signature in chain
   - Check workload_cert validity period
   - Check workload_cert key usage

3. VERIFY signer identity
   - Extract SAN URI from workload_cert
   - Compare with signature.signer_id
   - If mismatch: REJECT

4. VERIFY public key match
   - Extract public key from workload_cert
   - Compare with signature.public_key (DER format)
   - If mismatch: REJECT

5. VERIFY cryptographic signature
   - If payload field present (v1.2.0+):
     - Use decoded payload directly as verification input
   - If payload field absent (v1.1.x fallback):
     - Reconstruct: signed_data = SHA256(envelope.content_hash || envelope.evidence_hash)
   - ECDSA_Verify(payload, signature, public_key)
   - If invalid: REJECT

6. VERIFY transparency proof
   - Compute leaf_hash from certificate + signer_id
   - Walk inclusion_proof to compute root
   - Compare with inclusion_proof.root_hash
   - If mismatch: REJECT

7. OPTIONAL: Verify checkpoint
   - Fetch signed checkpoint from transparency log
   - Verify checkpoint signature against Root CA
   - Verify inclusion_proof.root_hash matches checkpoint
   - This provides freshness guarantee

8. ACCEPT if all checks pass
```

#### 3.5.11 Unsigned Results

Results may be unsigned (`signature: null`) in the following cases:

- Summary format (no envelope with full hashes)
- Identity bootstrap failed (see Section 3.6)
- Agent configured to skip identity (`identity.enabled = false`)

When unsigned, consumers should check `identity_status` for the reason.

### 3.6 Identity Status

The `identity_status` field indicates whether the agent successfully established PKI identity and provides diagnostic information if bootstrap failed.

#### 3.6.1 Structure

```json
{
  "bootstrapped": true,
  "signer_id": "scanset://prod/aws/account/123456789012/workload/esp-agent",
  "error": null,
  "error_code": null
}
```

#### 3.6.2 Identity Status Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bootstrapped` | boolean | Yes | Whether PKI identity was successfully established |
| `signer_id` | string | Yes | Identity string (PKI URI or unsigned placeholder) |
| `error` | string | No | Human-readable error message if bootstrap failed |
| `error_code` | string | No | Machine-readable error code if bootstrap failed |

#### 3.6.3 Signer ID When Unsigned

When bootstrap fails, `signer_id` uses a placeholder format:

```
unsigned:agent:{hostname}-{hex_suffix}
```

Example: `unsigned:agent:server01-a1b2c3d4`

This allows tracking which host produced unsigned results.

#### 3.6.4 Error Codes

| Code | Description |
|------|-------------|
| `BOOTSTRAP_DISABLED` | Identity bootstrap disabled in configuration |
| `BOOTSTRAP_CONNECTION_FAILED` | Could not connect to orchestrator or identity provider |
| `BOOTSTRAP_AUTH_FAILED` | Authentication failed (invalid AWS credentials, JWT rejected) |
| `BOOTSTRAP_CERT_FAILED` | Certificate enrollment rejected by certificate issuer |
| `BOOTSTRAP_TIMEOUT` | Bootstrap operation timed out |
| `BOOTSTRAP_TLS_ERROR` | TLS handshake or certificate verification failed |

#### 3.6.5 Examples

**Successful bootstrap:**

```json
{
  "bootstrapped": true,
  "signer_id": "scanset://prod/aws/account/123456789012/workload/esp-agent",
  "error": null,
  "error_code": null
}
```

**Failed bootstrap (connection error):**

```json
{
  "bootstrapped": false,
  "signer_id": "unsigned:agent:server01-a1b2c3d4",
  "error": "Failed to connect to orchestrator: connection refused",
  "error_code": "BOOTSTRAP_CONNECTION_FAILED"
}
```

**Bootstrap disabled:**

```json
{
  "bootstrapped": false,
  "signer_id": "unsigned:agent:server01-a1b2c3d4",
  "error": "Identity bootstrap disabled in configuration",
  "error_code": "BOOTSTRAP_DISABLED"
}
```

---

## 4. Summary Schema

### 4.1 Structure

```json
{
  "total_policies": 3,
  "passed": 1,
  "failed": 2,
  "errors": 0,
  "by_criticality": {
    "critical": { "total": 0, "passed": 0, "failed": 0 },
    "high": { "total": 1, "passed": 1, "failed": 0 },
    "medium": { "total": 2, "passed": 0, "failed": 2 },
    "low": { "total": 0, "passed": 0, "failed": 0 },
    "info": { "total": 0, "passed": 0, "failed": 0 }
  },
  "total_weight": 1.8,
  "passed_weight": 0.8,
  "posture_score": 0.44444448
}
```

### 4.2 Summary Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `total_policies` | integer | Yes | Total number of policies evaluated |
| `passed` | integer | Yes | Number of policies that passed |
| `failed` | integer | Yes | Number of policies that failed |
| `errors` | integer | Yes | Number of policies with errors |
| `by_criticality` | object | Yes | Breakdown by criticality level |
| `total_weight` | float | Yes | Sum of all policy weights |
| `passed_weight` | float | Yes | Sum of weights for passed policies |
| `posture_score` | float | Yes | Overall posture score (0.0 - 1.0) |

### 4.3 Criticality Breakdown

Each criticality level contains:

| Field | Type | Description |
|-------|------|-------------|
| `total` | integer | Total policies at this criticality |
| `passed` | integer | Passed policies at this criticality |
| `failed` | integer | Failed policies at this criticality |

### 4.4 Posture Score Calculation

```
posture_score = passed_weight / total_weight
```

### 4.5 Invariants

```
total_policies == passed + failed + errors
total_policies == sum(by_criticality[*].total)
```

---

## 5. Policy Identity Schema

### 5.1 Structure

```json
{
  "policy_id": "test-file-metadata-001",
  "platform": "linux",
  "criticality": "high",
  "control_mappings": [
    { "framework": "CIS", "control_id": "6.1.1" },
    { "framework": "NIST-800-53", "control_id": "AC-6" }
  ]
}
```

### 5.2 Identity Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy_id` | string | Yes | Unique policy identifier (from META `esp_id`) |
| `platform` | string | Yes | Target platform |
| `criticality` | string | Yes | Severity level |
| `control_mappings` | array | Yes | Framework control mappings |

### 5.3 Platform Values

| Value | Description |
|-------|-------------|
| `windows` | Microsoft Windows |
| `linux` | Linux distributions |
| `macos` | Apple macOS |
| `kubernetes` | Kubernetes clusters |
| `container` | Container images |

### 5.4 Criticality Values

| Value | Default Weight | Description |
|-------|----------------|-------------|
| `critical` | 1.0 | Highest severity — immediate action required |
| `high` | 0.8 | High severity — prioritize remediation |
| `medium` | 0.5 | Medium severity — address in normal cycle |
| `low` | 0.3 | Low severity — address when convenient |
| `info` | 0.1 | Informational — no action required |

### 5.5 Control Mapping Structure

```json
{
  "framework": "string",
  "control_id": "string"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `framework` | string | Framework identifier (e.g., `CIS`, `NIST-800-53`, `DISA-STIG`) |
| `control_id` | string | Control identifier within framework |

---

## 6. Policy Result Schema

### 6.1 Structure (Full Results)

```json
{
  "identity": {},
  "outcome": "pass",
  "weight": 0.8,
  "findings": [],
  "evidence": {}
}
```

### 6.2 Policy Result Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity` | object | Yes | Policy identity (see Section 5) |
| `outcome` | string | Yes | Result: `pass`, `fail`, or `error` |
| `weight` | float | Yes | Policy weight for posture scoring |
| `findings` | array | Yes | Compliance findings (empty if passed) |
| `evidence` | object | Yes | Collected evidence with metadata |

### 6.3 Outcome Values

| Value | Description |
|-------|-------------|
| `pass` | All criteria satisfied |
| `fail` | One or more criteria not satisfied |
| `error` | Execution error prevented evaluation |

---

## 7. Findings Schema

### 7.1 Structure

```json
{
  "finding_id": "f-e873118b",
  "severity": "high",
  "title": "file_content validation failed",
  "description": "File content validation failed:\n  - Object 'passwd_file': Content check failed",
  "expected": {
    "content": "String(\"^root:.*:/bin/bash$\")"
  },
  "actual": {
    "content": "String(\"root:x:0:0:root:/root:/bin/bash\\n...\")"
  },
  "field_path": "CRI_AND > CTN_file_content"
}
```

### 7.2 Finding Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `finding_id` | string | Yes | Unique finding identifier (format: `f-{hex}`) |
| `severity` | string | Yes | Finding severity level |
| `title` | string | Yes | Human-readable title |
| `description` | string | Yes | Detailed description of the finding |
| `expected` | object | Yes | Expected values |
| `actual` | object | Yes | Actual values found |
| `field_path` | string | No | Path in criteria tree |

### 7.3 Severity Values

| Value | Description |
|-------|-------------|
| `critical` | Requires immediate attention |
| `high` | High priority finding |
| `medium` | Standard priority finding |
| `low` | Low priority finding |
| `info` | Informational only |

---

## 8. Evidence Schema

### 8.1 Structure

```json
{
  "data": {
    "file_metadata_passwd_file": {
      "exists": true,
      "file_group": "0",
      "file_mode": "0644",
      "file_owner": "0",
      "file_size": 839,
      "readable": true
    }
  },
  "collection_metadata": [],
  "collected_at": "2026-01-23T22:11:22Z"
}
```

### 8.2 Evidence Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `data` | object | Yes | Collected data keyed by `{ctn_type}_{object_id}` |
| `collection_metadata` | array | Yes | Collection operation details |
| `collected_at` | string | Yes | ISO 8601 timestamp |

### 8.3 Data Key Format

Evidence data is keyed by `{ctn_type}_{object_id}`:

```
file_metadata_passwd_file
tcp_listener_port_2024
k8s_resource_apiserver_pod
```

### 8.4 Common CTN Types and Fields

#### file_metadata

```json
{
  "exists": true,
  "file_group": "0",
  "file_mode": "0644",
  "file_owner": "0",
  "file_size": 839,
  "readable": true
}
```

#### file_content

```json
{
  "file_content": "root:x:0:0:root:/root:/bin/bash\n..."
}
```

#### tcp_listener

```json
{
  "listening": false
}
```

---

## 9. Collection Metadata Schema

### 9.1 Structure

```json
{
  "object_id": "passwd_file",
  "ctn_type": "file_metadata",
  "collector_id": "filesystem_collector",
  "collection_mode": "default",
  "duration_ms": 0,
  "field_count": 6,
  "has_warnings": false,
  "method": {}
}
```

### 9.2 Collection Metadata Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `object_id` | string | Yes | Object identifier |
| `ctn_type` | string | Yes | CTN type collected |
| `collector_id` | string | Yes | Collector that gathered data |
| `collection_mode` | string | Yes | Mode used: `default`, `query`, `list` |
| `duration_ms` | integer | Yes | Collection duration in milliseconds |
| `field_count` | integer | Yes | Number of fields collected |
| `has_warnings` | boolean | Yes | Whether warnings occurred |
| `method` | object | No | Collection method details |

---

## 10. Collection Method Schema

### 10.1 Structure

```json
{
  "method_type": "file_stat",
  "description": "Query file metadata via stat()",
  "target": "/etc/passwd"
}
```

### 10.2 Fields

| Field | Type | Required | Serialization |
|-------|------|----------|---------------|
| `method_type` | string | Yes | Always |
| `description` | string | Yes | Always |
| `target` | string | Yes | Always |
| `command` | string | No | assessor-evidence only |
| `inputs` | object | No | assessor-evidence only |

### 10.3 method_type Values

| Value | Description | Example Target |
|-------|-------------|----------------|
| `command` | System command execution | `rpm:openssl` |
| `file_read` | File content read | `/etc/passwd` |
| `file_stat` | File metadata via stat() | `/etc/passwd` |
| `socket_inspection` | Socket/port inspection | `tcp:22` |
| `api_call` | REST/gRPC API call | `/v1/pods` |
| `registry` | Windows registry read | `HKLM\SOFTWARE\...` |
| `wmi` | Windows WMI query | `Win32_Service` |
| `computed` | Derived/computed value | `computed:var1` |

### 10.4 Target Format by Collector

| Collector | Target Format | Example |
|-----------|---------------|---------|
| FileSystem | File path | `/etc/passwd` |
| TcpListener | `tcp:{port}` | `tcp:22` |
| K8sResource | `Kind:Namespace:Selector` | `Pod:kube-system:component=apiserver` |
| Command (RPM) | `rpm:{package}` | `rpm:openssl` |
| Command (Systemd) | `systemd:{service}` | `systemd:sshd` |
| Command (Sysctl) | `sysctl:{param}` | `sysctl:net.ipv4.ip_forward` |

### 10.5 Assessor-Evidence Extended Fields

When `assessor-evidence` feature is enabled:

```json
{
  "method_type": "command",
  "description": "Query Kubernetes API for Pod resources",
  "target": "Pod:kube-system:component=kube-apiserver",
  "command": "kubectl get pod -n kube-system -l component=kube-apiserver -o json",
  "inputs": {
    "kind": "Pod",
    "namespace": "kube-system",
    "label_selector": "component=kube-apiserver"
  }
}
```

---

## 11. Assessor Package Schema

### 11.1 Additional Structure

The assessor package extends the full result with reproducibility information:

```json
{
  "envelope": {},
  "summary": {},
  "policies": [
    {
      "identity": {},
      "outcome": "pass",
      "weight": 0.8,
      "findings": [],
      "evidence": {},
      "reproducibility": {}
    }
  ],
  "package_info": {}
}
```

### 11.2 Reproducibility Information

```json
{
  "commands": [
    {
      "object_id": "passwd_file",
      "method_type": "file_read",
      "command": "cat /etc/passwd",
      "target": "/etc/passwd",
      "inputs": { "file": "/etc/passwd" }
    }
  ],
  "requirements": [
    "File system access to target paths"
  ],
  "notes": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `commands` | array | Collection commands that can be re-run |
| `requirements` | array | Environment requirements for reproduction |
| `notes` | string | Optional notes for assessors |

### 11.3 Package Information

```json
{
  "format_version": "1.2.0",
  "generated_at": "2026-03-01T12:00:00Z",
  "purpose": "Compliance assessment verification",
  "contains_cui": true,
  "distribution": "Internal use only - contains CUI",
  "notes": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `format_version` | string | Package format version |
| `generated_at` | string | ISO 8601 timestamp |
| `purpose` | string | Package purpose description |
| `contains_cui` | boolean | Whether package contains CUI |
| `distribution` | string | Distribution restrictions |
| `notes` | string | Optional notes |

---

## 12. Output Format Examples

### 12.1 Summary Format

```json
{
  "agent": {
    "id": "esp-agent",
    "name": "esp-agent",
    "version": "1.2.0"
  },
  "summary": {
    "total_policies": 3,
    "passed": 1,
    "failed": 2
  },
  "policies": [
    {
      "policy_id": "test-file-metadata-001",
      "platform": "linux",
      "passed": true,
      "outcome": "Pass",
      "criticality": "High",
      "criteria_counts": {
        "total": 3,
        "passed": 3,
        "failed": 0,
        "error": 0
      },
      "findings_count": 0
    }
  ]
}
```

### 12.2 Attestation Format

```json
{
  "envelope": {
    "result_id": "esp-result-18892f9d95dcc6b5",
    "schema_version": "1.2.0",
    "agent": {
      "id": "esp-agent",
      "name": "esp-agent",
      "version": "1.2.0",
      "agent_type": "cli"
    },
    "host": {
      "id": "host-ad1bfa7a1863edb2",
      "hostname": "server01",
      "os": "linux",
      "arch": "x86_64"
    },
    "started_at": "2026-03-01T12:00:00Z",
    "completed_at": "2026-03-01T12:00:01Z",
    "replay_hash": "sha256:7a3f1e9b4c2d80563ef1a28b9d4c7e5f1234567890abcdef...",
    "signature": {
      "signer_id": "scanset://prod/aws/account/123456789012/workload/esp-agent",
      "signer_type": "agent",
      "algorithm": "ecdsa-p256",
      "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
      "signature": "MEUCIQC...",
      "payload": "8JoFLGh3x2kQY5n...",
      "key_id": "pki:cert:1234567890abcdef",
      "signed_at": "2026-03-01T12:00:01Z",
      "covers": ["replay_hash"],
      "certificate_chain": [
        "-----BEGIN CERTIFICATE-----\n<workload-cert>\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n<workload-ca>\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n<ia-cert>\n-----END CERTIFICATE-----"
      ],
      "transparency": {
        "log_index": 47,
        "inclusion_proof": {
          "tree_size": 100,
          "root_hash": "f6e5d4c3b2a1...",
          "hashes": ["abc123...", "def456..."]
        }
      }
    },
    "identity_status": {
      "bootstrapped": true,
      "signer_id": "scanset://prod/aws/account/123456789012/workload/esp-agent",
      "error": null,
      "error_code": null
    }
  },
  "summary": {
    "total_policies": 3,
    "passed": 1,
    "failed": 2,
    "errors": 0,
    "by_criticality": {
      "critical": { "total": 0, "passed": 0, "failed": 0 },
      "high": { "total": 1, "passed": 1, "failed": 0 },
      "medium": { "total": 2, "passed": 0, "failed": 2 },
      "low": { "total": 0, "passed": 0, "failed": 0 },
      "info": { "total": 0, "passed": 0, "failed": 0 }
    },
    "total_weight": 1.8,
    "passed_weight": 0.8,
    "posture_score": 0.44444448
  },
  "checks": [
    {
      "identity": {
        "policy_id": "test-file-metadata-001",
        "platform": "linux",
        "criticality": "high",
        "control_mappings": [
          { "framework": "CIS", "control_id": "6.1.1" }
        ]
      },
      "outcome": "pass",
      "weight": 0.8
    }
  ]
}
```

### 12.3 Unsigned Result Example

When identity bootstrap fails, results are produced without a signature:

```json
{
  "envelope": {
    "result_id": "esp-result-18892f9d95dcc6b5",
    "schema_version": "1.2.0",
    "agent": {
      "id": "esp-agent",
      "name": "esp-agent",
      "version": "1.2.0",
      "agent_type": "cli"
    },
    "host": {
      "id": "host-ad1bfa7a1863edb2",
      "hostname": "server01",
      "os": "linux",
      "arch": "x86_64"
    },
    "started_at": "2026-03-01T12:00:00Z",
    "completed_at": "2026-03-01T12:00:01Z",
    "replay_hash": "sha256:7a3f1e9b4c2d80563ef1a28b9d4c7e5f1234567890abcdef...",
    "signature": null,
    "identity_status": {
      "bootstrapped": false,
      "signer_id": "unsigned:agent:server01-a1b2c3d4",
      "error": "Failed to connect to orchestrator: connection refused",
      "error_code": "BOOTSTRAP_CONNECTION_FAILED"
    }
  },
  "summary": { "..." : "..." },
  "policies": [ "..." ]
}
```

---

## 13. Schema Versioning

### 13.1 Version Format

Schema versions follow [SemVer 2.0.0]:

```
MAJOR.MINOR.PATCH
```

### 13.2 Compatibility Rules

| Change Type | Version Bump | Example |
|-------------|--------------|---------|
| Breaking field removal | MAJOR | Remove `envelope` |
| Breaking type change | MAJOR | `policy_id` integer → string |
| New required field | MAJOR | Add required `signature` |
| Field replacement | MINOR | `content_hash` + `evidence_hash` → `replay_hash` |
| New optional field | MINOR | Add optional `transparency` |
| Documentation only | PATCH | Clarify description |

### 13.3 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification |
| 1.0.1 | 2026-01-10 | Added Signature Block schema (Section 3.5) |
| 1.1.0 | 2026-01-24 | Added `transparency` field to SignatureBlock (Section 3.5.9) |
|       |            | Added `identity_status` field to envelope (Section 3.6) |
|       |            | Added PKI signer_id format (Section 3.5.3) |
|       |            | Added `pki:cert:` key_id format (Section 3.5.5) |
|       |            | Updated certificate_chain semantics for PKI (Section 3.5.8) |
|       |            | Changed default output format to `assessor` |
|       |            | Added unsigned result example (Section 12.4) |
|       |            | Deprecated TPM and software-only signing modes |
| 1.1.1 | 2026-01-25 | Added `payload` field to SignatureBlock (Section 3.5.6) |
|       |            | Updated verification procedure to use payload (Section 3.5.10) |
|       |            | Clarified ECDSA double-hashing behavior |
| 1.2.0 | 2026-03-01 | **Current version** |
|       |            | Replaced `content_hash` + `evidence_hash` with single `replay_hash` (Section 3.2) |
|       |            | Added Replay Hash Architecture (Section 2.4) |
|       |            | Signature now covers `replay_hash` only; `covers` field updated (Section 3.5) |
|       |            | Signed data changed to `SHA256(replay_hash)` (Section 3.5.6) |
|       |            | Updated verification procedure for v1.2.0 payload (Section 3.5.10) |
|       |            | Updated all output format examples (Section 12) |
|       |            | Package `format_version` bumped to `1.2.0` (Section 11.3) |

### 13.4 Version Validation

Consumers SHOULD validate `schema_version` before processing:

```rust
let version = &envelope.schema_version;
if !version.starts_with("1.") {
    return Err("Unsupported schema version");
}

let parts: Vec<u32> = version.split('.')
    .filter_map(|s| s.parse().ok())
    .collect();
let minor = parts.get(1).copied().unwrap_or(0);
let patch = parts.get(2).copied().unwrap_or(0);

// v1.2.0+: use replay_hash
if minor >= 2 {
    // envelope.replay_hash is the integrity hash
    // signature.covers = ["replay_hash"]
    // signed_data = SHA256(replay_hash)
}

// v1.1.x: legacy dual-hash
if minor == 1 {
    // envelope.content_hash + envelope.evidence_hash
    // signature.covers = ["content_hash", "evidence_hash"]
    // signed_data = SHA256(content_hash || evidence_hash)
    // payload field available if patch >= 1
}
```

---

## 14. Validation Rules

### 14.1 Required Field Validation

| Field | Validation |
|-------|------------|
| `envelope.schema_version` | Valid SemVer |
| `envelope.result_id` | Non-empty, starts with `esp-result-` |
| `envelope.replay_hash` | Non-empty, starts with `sha256:` (v1.2.0+) |
| `envelope.identity_status` | Required object (v1.1.0+) |
| `identity.policy_id` | Non-empty string |
| `identity.platform` | Known platform value |
| `identity.criticality` | Valid enum value |
| `identity.control_mappings` | At least one mapping |

### 14.2 Consistency Validation

| Rule | Validation |
|------|------------|
| Summary counts | `total_policies == passed + failed + errors` |
| Criticality breakdown | `total_policies == sum(by_criticality[*].total)` |
| Posture score | `posture_score == passed_weight / total_weight` |
| Replay hash | Stable across runs with same compliance posture |
| Identity consistency | `envelope.signature.signer_id == envelope.identity_status.signer_id` (when signed) |

### 14.3 Signature Validation

| Rule | Validation |
|------|------------|
| Covers field | Must contain `["replay_hash"]` (v1.2.0+) |
| Algorithm | Must be known algorithm value |
| Public key | Must be valid Base64, must match certificate |
| Signature | Must be valid Base64 |
| Payload | Must be valid Base64, 32 bytes when decoded |
| Signed data | `SHA256(replay_hash)` must verify against signature |
| Certificate chain | Must form valid chain to trusted Root CA |
| Signer ID match | SAN URI from certificate must match `signer_id` |

### 14.4 Transparency Validation

| Rule | Validation |
|------|------------|
| Log index | Non-negative integer |
| Tree size | Must be > log_index |
| Root hash | Valid hex string, 64 characters (SHA-256) |
| Hashes array | All valid hex strings |
| Proof verification | Computed root must match `root_hash` |

### 14.5 Identity Status Validation

| Rule | Validation |
|------|------------|
| Bootstrapped consistency | If `true`, `error` and `error_code` must be `null` |
| Error consistency | If `false` and not disabled, `error` should be non-null |
| Signer ID format | Must match PKI or unsigned format |

### 14.6 Validation Errors

| Error | Condition |
|-------|-----------|
| `InvalidSchemaVersion` | schema_version not valid SemVer |
| `MissingRequiredField` | Required field not present |
| `InvalidCriticality` | Unknown criticality value |
| `InconsistentCounts` | Summary counts don't add up |
| `InvalidTimestamp` | Timestamp not ISO 8601 |
| `InvalidSignature` | Signature verification failed |
| `UnsupportedAlgorithm` | Unknown signing algorithm |
| `InvalidCertificateChain` | Chain validation failed |
| `CertificateExpired` | Signing certificate not valid |
| `SignerMismatch` | SAN URI doesn't match signer_id |
| `KeyMismatch` | Public key doesn't match certificate |
| `InvalidTransparencyProof` | Merkle proof verification failed |
| `InvalidIdentityStatus` | Identity status fields inconsistent |
| `InvalidPayload` | Payload not valid Base64 or wrong length |
| `InvalidReplayHash` | Replay hash missing or malformed |

---

## 15. OSCAL Mapping Reference

### 15.1 Assessment Results Mapping

| ESP Field | OSCAL AR Field |
|-----------|----------------|
| `identity.policy_id` | `observation.collected[].props.esp-policy-id` |
| `identity.control_mappings` | `finding.target.target-id` |
| `outcome` | `observation.collected[].props.outcome` |
| `identity.criticality` | `finding.target.props.criticality` |
| `findings` | `finding[]` |
| `evidence` | `observation.relevant-evidence[]` |

### 15.2 Collection Method Mapping

| ESP Field | OSCAL Field |
|-----------|-------------|
| `method.method_type` | `relevant-evidence.props.collection-method` |
| `method.description` | `relevant-evidence.description` |
| `method.target` | `relevant-evidence.props.target` |
| `method.command` | `relevant-evidence.props.command` |

---

## Appendix A: Migration Guide (v1.1.x to v1.2.0)

### A.1 Breaking Changes

| Change | v1.1.x | v1.2.0 |
|--------|--------|--------|
| Hash fields | `content_hash` + `evidence_hash` | `replay_hash` |
| Signature covers | `["content_hash", "evidence_hash"]` | `["replay_hash"]` |
| Signed data | `SHA256(content_hash \|\| evidence_hash)` | `SHA256(replay_hash)` |
| Schema version | `1.1.1` | `1.2.0` |
| Package format_version | `1.1.1` | `1.2.0` |

### A.2 Consumer Migration

Consumers MUST check `schema_version` and handle both formats:

```rust
if schema_version >= "1.2.0" {
    // Use envelope.replay_hash
    let hash = &envelope.replay_hash;
    // Signature covers ["replay_hash"]
    // Verify: signed_data = SHA256(replay_hash)
} else {
    // Legacy: use envelope.content_hash + envelope.evidence_hash
    let content = &envelope.content_hash;
    let evidence = &envelope.evidence_hash;
    // Signature covers ["content_hash", "evidence_hash"]
    // Verify: signed_data = SHA256(content_hash || evidence_hash)
}
```

### A.3 Verifier Migration

When verifying signatures across schema versions:

```rust
// Determine signed data based on schema version
let signed_data = if let Some(payload) = &signature.payload {
    // Preferred: use payload directly (v1.1.1+)
    base64_decode(payload)?
} else if schema_version >= "1.2.0" {
    // v1.2.0 without payload (should not occur, but handle defensively)
    sha256(replay_hash)
} else {
    // v1.1.0 fallback
    sha256(format!("{}{}", content_hash, evidence_hash))
};

ecdsa_verify(&signed_data, &signature.signature, &public_key)?;
```

### A.4 Daemon Dedup Migration

The daemon's dedup tracker previously cached `evidence_hash`. As of v1.2.0, it caches `replay_hash` instead. The `replay_hash` is stable across runs when compliance posture is unchanged, which was the original design intent that `evidence_hash` failed to achieve due to volatile collection metadata.

### A.5 Database Migration

If storing scan results in a database:

```sql
-- Add new column
ALTER TABLE scan_results ADD COLUMN replay_hash TEXT;

-- For new v1.2.0 results, replay_hash is populated
-- For legacy results, content_hash + evidence_hash remain

-- Optional: drop old columns after migration period
-- ALTER TABLE scan_results DROP COLUMN content_hash;
-- ALTER TABLE scan_results DROP COLUMN evidence_hash;
```

---

## Appendix B: Migration Guide (v1.0.x to v1.1.x)

### B.1 Breaking Changes

None. v1.1.x is backward compatible with v1.0.x.

### B.2 New Required Fields

| Field | Location | Default for Migration |
|-------|----------|----------------------|
| `identity_status` | `envelope` | See B.3 |

### B.3 Handling Legacy Results

When processing v1.0.x results that lack `identity_status`:

```json
{
  "bootstrapped": false,
  "signer_id": "legacy:unknown",
  "error": "Pre-v1.1.0 result without identity status",
  "error_code": "LEGACY_RESULT"
}
```

### B.4 New Optional Fields

| Field | Location | When Present |
|-------|----------|--------------|
| `transparency` | `signature` | PKI-signed results |
| `certificate_chain` | `signature` | PKI-signed results (was optional, now expected) |
| `payload` | `signature` | PKI-signed results (v1.1.1+) |

### B.5 Deprecated Features

| Feature | Status | Replacement |
|---------|--------|-------------|
| TPM signing (`tpm-ecdsa-p256`) | Deprecated | PKI signing (`ecdsa-p256` with certificate chain) |
| Software-only signing | Deprecated | PKI signing |
| `tpm:sha256:*` signer_id format | Deprecated | PKI SAN URI format |
| `software:sha256:*` signer_id format | Deprecated | PKI SAN URI format |
| `content_hash` + `evidence_hash` | Deprecated (v1.2.0) | `replay_hash` |

---

## Appendix C: Trust System Integration

### C.1 Architecture Overview

The ESP agent integrates with a Trust System that provides:

| Component | Function |
|-----------|----------|
| Identity Provider | Issues JWTs based on cloud credentials (AWS STS) |
| Certificate Issuer | Issues short-lived workload certificates |
| Transparency Log | Append-only log of certificate issuances |
| Verifier | Validates signed envelopes |

### C.2 Agent Bootstrap Flow

```
1. Load configuration
2. Create AWS STS presigned URL
3. POST /identity/token → JWT
4. Generate ECDSA P-256 keypair
5. POST /identity/enroll with CSR → Certificate + Transparency Proof
6. Store identity in memory (never persisted)
7. Ready to sign scan results
```

### C.3 Signing Flow

```
1. Complete ESP scan → ScanResult with replay_hash
2. Compute signed_data = SHA256(replay_hash)
3. Sign with workload private key: signature = ECDSA_Sign(SHA256(signed_data))
4. Base64-encode signed_data as payload field
5. Attach certificate_chain and transparency proof
6. Output signed result
```

### C.4 Verification Flow

```
1. Parse signature block
2. Verify certificate chain against trusted Root CA
3. Check certificate validity period
4. Verify signer_id matches certificate SAN URI
5. Verify public key matches certificate
6. If payload field present:
   - Use payload directly for ECDSA verification
   Else if schema_version >= 1.2.0:
   - Reconstruct: signed_data = SHA256(replay_hash)
   Else:
   - Reconstruct: signed_data = SHA256(content_hash || evidence_hash)
7. ECDSA_Verify(payload, signature, public_key)
8. Verify transparency inclusion proof
9. Optionally fetch checkpoint to verify proof freshness
```
