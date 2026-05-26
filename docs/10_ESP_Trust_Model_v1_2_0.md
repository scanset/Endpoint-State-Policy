# ESP v1.2.0 — Trust Model

**Version:** 1.2.0
**Status:** Normative
**Last Updated:** 2026-03-27

---

> **v2.x cross-reference.** The core trust principle stated in §1.1
> (ESP does not trust inputs, does not infer truth, does not leak
> evidence) is **unchanged**. The forensic-chain guarantees in §1.2
> (what/how/state as a replay hash) are **unchanged** for the default
> v1 hash scheme — algorithm, canonicalization rules, and signing
> boundary are the same.
>
> v2.0.0 refinements:
>
> 1. **Host binding is now transport-attested.** The `ResultEnvelope.host`
>    field is populated by `Channel::identify_host()` — the transport
>    that actually reached the target — rather than by
>    `HostInfo::from_system()` on the scanner box. An Azure Bastion scan
>    emits `host_type: "azure.vm"` with `subscription_id` /
>    `resource_group` / `target_resource_id` in `attrs`; an SSH scan
>    emits `host_id: "ssh://<user>@<host>:<port>"`. The envelope attests
>    about the **target**, not the scanner.
>
> 2. **Replay-hash invariants are explicit.** §3.2 of
>    `docs/09_ESP_Canonical_Schema_v2_1_1.md` enumerates what is
>    excluded from the replay hash (host block, observations[],
>    timestamps) so the hash remains stable across scans of the same
>    posture regardless of when or from where the scan ran. The
>    forensic chain threads through observation `content_hash` values,
>    not inline evidence blobs.
>
> 3. **Output formats collapsed.** v2.0.0 removed the `attestation` /
>    `full-results` / `assessor-evidence` Cargo feature matrix described
>    in §7 of this document. `AssessorPackage` is the sole output
>    envelope. Sensitivity tiers are achieved by post-processing the
>    assessor JSON (drop `observations[]` for attestation-equivalent
>    output; drop `observations[].body` + `findings` for
>    summary-equivalent output).
>
> v2.1.0 refinement:
>
> 4. **Wire schema bumped to `2.1.0`** with an additive
>    `replay_hash_version: u8` field on `ResultEnvelope`. Defaults to
>    `1` (the v2.0.0 hash scheme) via `#[serde(default)]`. v2.0.0
>    envelopes deserialize cleanly into v2.1.0 readers and vice versa.
>
> v2.2.0 refinement:
>
> 5. **v2 per-OBJECT replay hash scheme (opt-in).** A second hash scheme
>    is selectable via `ReplayManifest::with_replay_hash_version(2)` and
>    `compute_replay_hash_v2()`. The v1 scheme hashes one combined
>    `(intent, contract, outcome)` per criterion; v2 hashes
>    `(intent, contract, outcome)` per **(criterion, OBJECT)** pair.
>    OBJECTs sharing a template across many hosts (e.g. an RPM check on
>    RHEL9) collapse to one hash; OBJECTs carrying distinct per-asset
>    fields (a distinct cloud resource per OBJECT) get one hash per
>    asset. This enables per-asset drift detection and remediation
>    verification
>    without losing dedup. Cross-version hash comparison (v1 vs v2) is
>    not meaningful — consumers MUST record `replay_hash_version`
>    alongside the hash. The v1 scheme remains the default; existing
>    envelopes and callers are unaffected.
>
> **Body of this document still describes the v1.2 trust model.** §7
> (Result Trust Boundaries) in particular references the v1.x three-
> format output matrix and `schema v1.2.0`. Treat §7 as historical;
> §0 of the canonical-schema doc is the current normative text for the
> result envelope shape and replay-hash canonicalization.

---

## 1. Overview

This document specifies the trust model for ESP v1.2.0, defining trust boundaries, validation requirements, and security guarantees at every stage of policy processing. The trust model is the normative reference for how ESP establishes, maintains, and demonstrates security state.

### 1.1 Core Principle

> ESP does not trust inputs, does not infer truth, and does not leak evidence.
> Trust is established through validation, constrained execution, and controlled disclosure.
> Compliance decisions are deterministic, explicit, and cryptographically provable.

### 1.2 Design Intent

ESP is designed to produce a forensic chain of evidence for security state. Each policy execution establishes an unbroken, independently verifiable record that proves:

- **What** security intent was specified — the policy, compiled to a validated AST
- **How** that intent was executed — the contract binding CTN type to collector and executor
- **What** the system state was at execution time — the outcome, without volatile collected values

These three layers are cryptographically combined into a single replay hash that is stable across runs when compliance posture is unchanged, and changes detectably when posture changes. This hash is the foundation of ESP's tamper-evident evidence chain.

The chain closes from security intent through execution to signed result — without requiring a verifier to trust any intermediate party. An assessor can independently reproduce the collection, verify the outcome matches the signed attestation, and confirm the policy that was checked is exactly what was specified.

### 1.3 Trust Boundary Summary

| Boundary | Threat Mitigated | Mechanism |
|----------|------------------|-----------|
| Policy Input | Malformed or malicious policies | Multi-pass compiler validation |
| Compiler Gate | Unsafe policies reaching execution | Fail-fast with compile-time limits |
| Execution | Uncontrolled system access | Contract-bound, registered strategies |
| Capabilities | Privilege escalation | Explicit whitelists, auditable contracts |
| Configuration | Runtime security bypass | Compile-time constants |
| Results | Information leakage | Output format separation |
| Replay Hash | Evidence tampering, posture misrepresentation | Three-layer SHA-256 tree rollup |
| Signatures | Result tampering | SignatureBlock in ResultEnvelope |
| Logging | Unattributable actions | Mandatory audit events |
| Determinism | Unreproducible results | Explicit evaluation, no inference |

---

## 2. Policy Input Trust Boundary (N-17)

### 2.1 Untrusted Input

ESP policy files (`.esp`) are **untrusted input**. Every policy MUST pass through the compiler pipeline before execution.

The policy format is a purpose-built DSL — not XML, not code — that separates security intent from execution. Policies declare what to check and what state is expected. Execution is handled entirely by registered contracts. This separation is what makes the replay hash meaningful: the intent layer of the hash comes from the compiled AST, not from the raw policy file, and not from the executor.

### 2.2 Compile-Time Resource Limits

The compiler enforces hard boundaries on resource consumption:

| Resource | Limit | Purpose |
|----------|-------|---------|
| File size | Configurable per profile | Prevent resource exhaustion |
| Token count | Max 1M (production) | Bound lexical complexity |
| Parse depth | Max 100 levels | Prevent stack exhaustion |
| Symbol count | Max 50K global | Bound symbol table size |
| Reference depth | Max 50 levels | Prevent infinite resolution |
| Cycle length | Max 100 nodes | Detect circular dependencies |

### 2.3 Security Guarantee

No policy can cause:
- Uncontrolled resource consumption
- Infinite resolution loops
- Unexpected execution behavior

Trust is not granted to policy authors — it is earned through successful compilation.

---

## 3. Compiler as Trust Gate (N-18)

### 3.1 Validation Pipeline

```
Untrusted Input (.esp)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                     COMPILER                            │
│                                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
│  │ Lexical │─▶│ Syntax  │─▶│ Symbols │─▶│  Refs   │   │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │
│                                              │          │
│  ┌─────────┐  ┌─────────┐                   │          │
│  │Semantic │◀─│Structural│◀──────────────────┘          │
│  └─────────┘  └─────────┘                              │
│        │                                                │
│        ▼                                                │
│   VALIDATION PASSED ──────────────────────▶ Trusted AST │
│        │                                                │
│   VALIDATION FAILED ──────────────────────▶ Halt        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Validation Stages

| Stage | Validation | Failure Mode |
|-------|------------|--------------|
| Lexical | Token validity | Reject invalid characters |
| Syntax | Grammar conformance | Reject malformed structures |
| Symbol Discovery | Symbol uniqueness | Reject duplicate definitions |
| Reference Resolution | Reference validity | Reject undefined references |
| Semantic Analysis | Type compatibility | Reject type mismatches |
| Structural Validation | Structural requirements | Reject incomplete definitions |

### 3.3 Security Guarantee

Only policies that conform to explicit, auditable constraints can reach the execution engine. Compilation failures halt the system before execution begins. The compiled AST — not the raw policy file — is what execution operates on, and it is the AST that feeds the intent layer of the replay hash.

---

## 4. Constrained Execution (N-19)

### 4.1 Execution Constraints

The execution engine does NOT execute arbitrary logic:

| Constraint | Enforcement |
|------------|-------------|
| Deterministic evaluation | Fixed traversal order, no randomness |
| Contract-bound execution | Only registered CTN types execute |
| AST-driven logic | Execution follows validated AST nodes |
| No runtime code generation | All behavior defined at compile time |

### 4.2 Execution Architecture

```
Validated AST
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│                   EXECUTION ENGINE                      │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐                   │
│  │   Registry   │───▶│   Contract   │                   │
│  │ (CTN types)  │    │ (allowed ops)│                   │
│  └──────────────┘    └──────────────┘                   │
│         │                   │                           │
│         ▼                   ▼                           │
│  ┌──────────────┐    ┌──────────────┐                   │
│  │  Collector   │───▶│   Executor   │                   │
│  │ (gather data)│    │  (validate)  │                   │
│  └──────────────┘    └──────────────┘                   │
│                             │                           │
│                             ▼                           │
│                        ScanResult                       │
└─────────────────────────────────────────────────────────┘
```

### 4.3 Collector and Executor Requirements

Collectors and executors:
- MUST be explicitly registered in a `CtnStrategyRegistry`
- MUST be bound to specific CTN types via contracts
- MUST operate only on declared objects and states
- MUST NOT introduce new execution paths at runtime

### 4.4 Security Guarantee

Execution cannot exceed the capabilities explicitly exposed by the platform.

---

## 5. CTN Contracts and Capabilities (N-20)

### 5.1 Contract Structure

CTN contracts define what is allowed, not what is convenient:

```rust
pub struct CtnContract {
    pub ctn_type: String,
    pub object_requirements: ObjectRequirements,
    pub state_requirements: StateRequirements,
    pub field_mappings: CtnFieldMappings,
    pub supported_behaviors: Vec<SupportedBehavior>,
}
```

The `field_mappings.validation_mappings.state_to_data` map is a normative part of the trust model: it records exactly how state field names map to collected data field names, and this mapping is captured in the contract layer of the replay hash. This is what makes the hash a proof of execution provenance, not just a proof of outcome.

### 5.2 Capability Principles

| Principle | Enforcement |
|-----------|-------------|
| Explicit capabilities | Contracts enumerate allowed operations |
| No privilege escalation | Collectors cannot exceed declared scope |
| Auditable surface | Contracts are inspectable data |
| Platform isolation | Each platform defines its own contracts |

### 5.3 Command Whitelisting

Platform-specific capabilities (e.g., command execution) MUST be:

| Requirement | Description |
|-------------|-------------|
| **Whitelisted** | Only approved commands can execute |
| **Registered** | Explicitly added to the registry |
| **Reviewed** | Part of platform trust decisions |

**Example: RHEL 9 Command Whitelist**
```rust
executor.allow_commands(&[
    "rpm",        // Package queries only
    "systemctl",  // Service status only
    "sysctl",     // Kernel params read only
    "getenforce", // SELinux status only
]);
```

### 5.4 Security Guarantee

Capabilities are explicit, enumerable, and auditable.

---

## 6. Configuration Trust Boundaries (N-21)

### 6.1 Two-Layer Configuration

ESP configuration is split into two layers with different trust levels:

```
┌─────────────────────────────────────────────────────────┐
│              COMPILE-TIME CONSTANTS                     │
│                                                         │
│  • Security-critical limits                             │
│  • Baked into binary at build time                      │
│  • Cannot be changed at runtime                         │
│  • Defined in config/production.toml                    │
│                                                         │
│  Examples: max_file_size, max_token_count,              │
│            max_processing_time, security_min_log_level  │
└─────────────────────────────────────────────────────────┘
                         │
                         │ Enforces upper bounds
                         ▼
┌─────────────────────────────────────────────────────────┐
│              RUNTIME CONFIGURATION                      │
│                                                         │
│  • Operational tuning (within compile-time bounds)      │
│  • Can be adjusted without rebuild                      │
│  • Cannot exceed compile-time limits                    │
│                                                         │
│  Examples: log_level (≥ min), timeout (≤ max),          │
│            output_format, target_profiles               │
└─────────────────────────────────────────────────────────┘
```

### 6.2 Security Guarantee

Security boundaries cannot be relaxed at runtime.

---

## 7. Result Trust Boundaries (N-22)

> **v2.x note.** This section was rewritten for v2.0.0+. The v1.x
> three-format output matrix (`attestation` / `full-results` /
> `assessor-evidence` behind Cargo features) is gone. The agent emits
> exactly one envelope shape — `AssessorPackage` — and sensitivity
> filtering moved to the consumer pipeline.

### 7.1 Output Architecture

The agent emits a single signed envelope, `AssessorPackage`, carrying
the full result of a scan: policy outcomes, observations, findings,
reproducibility info, the replay hash, and (optionally) the signature
block and identity status.

```
Scan execution
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                   RESULT BUILDER                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              AssessorPackage                     │   │
│  │  envelope: ResultEnvelope                        │   │
│  │    ├ result_id, schema_version, agent, host      │   │
│  │    ├ started_at, completed_at                    │   │
│  │    ├ replay_hash + replay_hash_version           │   │
│  │    ├ identity_status                             │   │
│  │    ├ signature (optional)                        │   │
│  │    └ observations[]   ◄── top-level evidence     │   │
│  │  policies[]: PolicyResult                        │   │
│  │    ├ policy identity, outcome, counts            │   │
│  │    ├ control_mappings                            │   │
│  │    ├ observation_refs[] (cite into envelope)     │   │
│  │    └ findings[] (validation failures)            │   │
│  │  reproducibility: ReproducibilityInfo            │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 7.2 Envelope Contents

| Section | Contents |
|---|---|
| `envelope` (ResultEnvelope) | Scan-level identity, timing, replay hash, signature, identity status, observation array |
| `policies[]` | Per-policy outcome, criteria counts, control mappings, observation references, findings |
| `reproducibility` | Collection commands and inputs enabling an assessor to independently re-run the scan |

### 7.3 Sensitivity Tiers via Consumer Filtering

The envelope shape is fixed, but consumers can derive narrower views by
dropping fields before transmission. Two well-known filter recipes:

| Recipe | Drop from envelope | Resulting view |
|---|---|---|
| **Attestation-equivalent** | `observations[]`, `policies[].findings`, `policies[].observation_refs`, `reproducibility` | Identity, outcome, control mappings, replay hash, signature only |
| **Summary-equivalent** | `observations[].body`, `policies[].findings` | Identity, outcome, observation metadata + content hashes, replay hash, signature |

The replay hash is computed over `(intent, contract, outcome)` only,
so it is **stable under both filters**: an attestation-equivalent
extract carries the same `replay_hash` as the full envelope. A
verifier holding only the attestation-equivalent extract can still
confirm correspondence to a full envelope by hash equality.

### 7.4 Pre-filter vs Post-filter Signing

The signature in the `envelope.signature` block covers the
unfiltered envelope. A consumer that applies a filter and re-signs the
result is producing a *different* attestation that no longer chains
through the agent's signature. Two patterns are supported:

- **Forward the original signature.** Transmit the filter extract
  alongside the original `signature` block. Downstream verifiers
  rehydrate the unfiltered envelope from a local archive (or refuse
  to verify without it) and confirm signature over the full shape.
- **Counter-sign the filter extract.** The consumer's pipeline signs
  the filtered extract with its own key. The chain becomes
  `agent_signature(full) → consumer_signature(extract)`; downstream
  verifiers trust the consumer's key, not the agent's.

The trust model takes no position on which pattern is correct — that
depends on the consumer's PKI and retention policy. It does require
that the choice be explicit. A pipeline that strips fields from a
signed envelope and forwards the original signature *without
preserving the unfiltered envelope somewhere verifiable* breaks the
forensic chain.

### 7.5 Security Guarantee

The guarantee provided by the agent is:

1. The envelope as emitted is signed; tampering with any covered
   field breaks the signature.
2. The replay hash is invariant under the documented filter recipes;
   filtered extracts remain verifiably linked to their unfiltered
   originals via hash equality.
3. The reproducibility block enables an assessor to independently
   re-run the collection and confirm that the outcome they observe
   matches the outcome signed by the agent.

The guarantee the agent does **not** provide:

- That sensitive fields are absent from network traffic. The agent
  emits an envelope that contains them; the consumer pipeline is
  responsible for filtering before transmission. This is a deliberate
  trade-off relative to v1.x, where the format split was binary-level
  containment. v2.x consolidates surface area at the cost of moving
  the leakage boundary to the consumer's pipeline.

---

## 8. Replay Hash Architecture

### 8.1 Purpose and Design Intent

The replay hash is the cryptographic foundation of ESP's forensic evidence chain. It replaces the previous `content_hash` + `evidence_hash` design with a single, stable, three-layer structure that captures the complete verification lifecycle.

The replay hash answers: can you prove, in a deterministic and independently verifiable way, that this specific security intent was executed using this specific contract, and that the outcome was as recorded? This is the same forensic requirement applied to digital evidence management: proving chain of custody without requiring the verifier to trust the collector.

A critical design constraint is that actual collected values — file contents, API responses, command output — are intentionally excluded from the hash. These are volatile: timestamps, counters, and response metadata change between runs without reflecting any change in compliance posture. Including them would destabilize the hash and make drift detection meaningless. The outcome layer captures only pass/fail per field, with the expected value from the policy and the operation applied — not the raw collected data.

### 8.2 Three-Layer Structure

Each criterion (CTN) contributes a hash computed from three layers:

**Layer 1 — Intent** (from the resolved AST)

What the policy author specified: CTN type, STATE fields with expected values and operations, TEST specification (existence check, item check, state operator), and OBJECT identifiers with their declared fields. This layer proves exactly what was being checked.

**Layer 2 — Contract** (from the CtnContract)

How the system executed it: CTN type, collector ID, collection mode, and the validation field mappings (state_field → data_field). This layer proves how the system interpreted and executed the policy intent.

**Layer 3 — Outcome** (from execution results)

What happened: overall status (Pass/Fail/Error), per-object pass/fail, per-field pass/fail with the operation applied and the expected value. This layer does NOT include actual collected values — those are volatile and would destabilize the hash.

### 8.3 Tree Rollup

Criterion hashes are rolled up through the CRI tree structure, preserving the logical shape of the policy:

```
CRI AND
├── CTN sysctl_parameter (node 3) → criterion_hash_3
├── CTN file_content (node 1)     → criterion_hash_1
└── CRI OR (negated: false)
    ├── CTN tcp_listener (node 4) → criterion_hash_4
    └── CTN tcp_listener (node 5) → criterion_hash_5
    → or_block_hash = hash(OR | false | [hash_4, hash_5])
→ tree_hash = hash(AND | false | [hash_1, hash_3, or_block_hash])
```

Block hashes are computed over the logical operator, the negation flag, and the sorted child hashes. Sorting ensures that AND/OR commutativity does not produce different hashes for logically equivalent trees. The final replay hash combines the tree hash with policy identity (policy_id, platform, criticality, control_mappings).

### 8.4 Stability Guarantee

Same policy + same compliance posture = same `replay_hash`, always.

The hash changes when and only when:
- The policy intent changes (STATE fields, expected values, operations, TEST specification)
- The contract changes (collector, field mappings, collection mode)
- The compliance outcome changes (any field passes that previously failed, or vice versa)

Volatile data — timestamps, counters, raw file contents that did not affect the compliance outcome — never enters the hash.

### 8.5 Hash Computation

```rust
// Step 1: Compute per-criterion hashes (intent + contract + outcome)
let criterion_hashes: BTreeMap<String, String> = manifest
    .criteria
    .iter()
    .map(|(id, replay)| (id.clone(), replay.compute_hash()))
    .collect();

// Step 2: Roll up through CRI tree structure
let tree_hash = manifest.tree_structure.compute_hash(&criterion_hashes);

// Step 3: Combine with policy identity
let final_input = FinalHashInput {
    schema_version, policy_id, platform,
    criticality, control_mappings, tree_hash,
};

let replay_hash = sha256(canonical_json(final_input));
// Format: "sha256:<64-char hex digest>"
```

All hash computation uses FIPS 140-3 compliant SHA-256 over canonical JSON (sorted keys via BTreeMap serialization). The hash is computed exactly once during execution and carried through to all output formats unchanged.

### 8.6 Verification Flow

The replay hash present in an attestation can be matched against the replay hash in the locally-held full results to confirm they correspond:

```
┌─────────────────────┐     ┌─────────────────────┐
│  AttestationResult  │     │     FullResult       │
├─────────────────────┤     ├─────────────────────┤
│ envelope:           │     │ envelope:            │
│   replay_hash: X    │ === │   replay_hash: X     │
│                     │     │                      │
│ checks: [...]       │     │ policies: [...]      │
│ (no evidence)       │     │ (with evidence)      │
└─────────────────────┘     └─────────────────────┘

If replay_hash matches:
  ✓ Attestation corresponds to this full result
  ✓ Intent, contract, and outcome have not been tampered with
  ✓ Assessor package retrieval is valid
```

### 8.7 Security Guarantee

The replay hash is a tamper-evident cryptographic commitment to the complete verification lifecycle. Any modification to the policy intent, execution contract, or compliance outcome produces a different hash, making tampering detectable without requiring access to the raw evidence.

---

## 9. Signature Block

### 9.1 Purpose

The `SignatureBlock` in `ResultEnvelope` enables result authentication and tamper detection. As of schema v1.2.0, the signature is computed over the `replay_hash` field only, replacing the previous approach of signing multiple envelope fields separately.

### 9.2 Structure

```rust
pub struct SignatureBlock {
    pub signer_id: String,           // Unique identifier for the signer
    pub signer_type: String,         // Currently always "agent"
    pub algorithm: String,           // e.g., "ecdsa-p256", "tpm-ecdsa-p256"
    pub public_key: String,          // Base64-encoded public key (DER)
    pub signature: String,           // Base64-encoded signature value (DER)
    pub payload: Option<String>,     // Base64-encoded SHA256(replay_hash)
    pub key_id: String,              // Key identifier for external lookup
    pub signed_at: String,           // ISO 8601 timestamp (not part of signed data)
    pub covers: Vec<String>,         // Always ["replay_hash"]
    pub certificate_chain: Option<Vec<String>>,  // PEM, leaf first
    pub transparency: Option<TransparencyProof>, // Certificate transparency proof
}
```

### 9.3 Signing Scope

The signature covers `SHA256(replay_hash)`. The `covers` field is always `["replay_hash"]`. Including the `payload` field (the base64-encoded SHA256 of the replay hash) allows verifiers to directly verify the signature without reconstructing the payload from envelope fields.

| What is signed | Purpose |
|----------------|---------|
| `SHA256(replay_hash)` | Commits to the complete verification lifecycle |

### 9.4 Verification Levels

| Level | Description | Requirements |
|-------|-------------|--------------|
| **Level 0** (Self-contained) | Public key included in block; verifier trusts delivery channel | `public_key` present |
| **Level 1** (PKI) | Certificate chain validated against trusted Root CA | `certificate_chain` present |
| **Level 2** (PKI + Transparency) | Chain validated AND transparency proof verified | `certificate_chain` + `transparency` present |

### 9.5 Supported Algorithms

| Algorithm | Use Case |
|-----------|----------|
| `ecdsa-p256` | General purpose (standard) |
| `tpm-ecdsa-p256` | Hardware-backed (legacy) |

### 9.6 Signer ID Format

The `signer_id` format depends on the identity source:

| Source | Format |
|--------|--------|
| PKI | SAN URI (e.g., `scanset://prod/aws/account/123/workload/agent`) |
| Legacy TPM | `tpm:sha256:<fingerprint>` |
| Legacy Software | `software:sha256:<fingerprint>` |

### 9.7 Key ID Format

| Source | Format |
|--------|--------|
| PKI | `pki:cert:<certificate_serial>` |
| Legacy TPM | `tpm:ephemeral:<key_name>` |
| Legacy Software | `software:ephemeral:<uuid>` |

### 9.8 Security Guarantee

Signed results cannot be modified without detection. The signature commits to the replay hash, which in turn commits to the complete intent + contract + outcome chain. A valid signature over a valid replay hash is proof that the result was produced by the identified signer and has not been tampered with.

---

## 10. Logging and Auditability (N-23)

### 10.1 Logging Requirements

| Requirement | Implementation |
|-------------|----------------|
| Typed error codes | Every error has code, severity, category |
| Mandatory audit events | Security events cannot be disabled |
| File-scoped context | Errors attributed to source files |
| Structured format | Machine-parseable for SIEM integration |

### 10.2 Minimum Log Levels

```toml
# Security-minimum log level enforced at compile time
security_min_log_level = 1  # Warning level minimum

# Audit buffer cannot be reduced below threshold
audit_log_retention_buffer = 50000  # Events retained
```

### 10.3 Audit Events

| Event | Always Logged |
|-------|---------------|
| Policy compilation | ✓ |
| Execution start/end | ✓ |
| Evidence collection | ✓ |
| Result generation | ✓ |
| Signature operations | ✓ |
| Audit suppression attempt | ✓ |

### 10.4 Security Guarantee

Security-relevant behavior is always observable and attributable.

---

## 11. Determinism and Repeatability (N-24)

### 11.1 Determinism Requirements

ESP does NOT guess, infer, or approximate:

| Principle | Implementation |
|-----------|----------------|
| Deterministic execution | Same policy + same state = same result |
| Explicit evaluation | All logic defined in policy, not inferred |
| No heuristics | Pass/fail is binary, never probabilistic |
| Repeatable evidence | Results can be reproduced and verified |

### 11.2 Compliance Decision Basis

**Decisions ARE based on:**
- Explicit policy definitions
- Actual collected system state
- Defined comparison operations
- Documented logical operators

**Decisions are NEVER based on:**
- Statistical inference
- Machine learning predictions
- Heuristic analysis
- Probabilistic reasoning

This is a deliberate design constraint. When a compliance result is used as legal or audit evidence, the decision must be explainable in terms of what was checked, how, and what the system state was — not in terms of what a model predicted. AI may be appropriate for generating narrative around evidence; it has no place in determining pass/fail.

### 11.3 Reproducibility Support

The assessor package format includes reproducibility information sufficient to re-run the exact collection:

```json
{
  "reproducibility": {
    "commands": [
      {
        "object_id": "passwd_file",
        "method_type": "file_stat",
        "command": "stat /etc/passwd",
        "target": "/etc/passwd"
      }
    ],
    "requirements": [
      "File system access to target paths"
    ]
  }
}
```

### 11.4 Security Guarantee

Compliance results are explainable, reproducible, and defensible.

---

## 12. Trust Model Architecture

### 12.1 Complete Trust Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│                         ESP TRUST MODEL                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  UNTRUSTED INPUT          TRUST GATE              TRUSTED OUTPUT     │
│                                                                      │
│  ┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐    │
│  │ .esp files  │────▶│    Compiler     │────▶│  Validated AST  │    │
│  │ (untrusted) │     │ (7-pass check)  │     │   (trusted)     │    │
│  └─────────────┘     └─────────────────┘     └────────┬────────┘    │
│                                                        │             │
│                      ┌─────────────────────────────────┘             │
│                      ▼                                               │
│  ┌──────────────────────────────────────┐                            │
│  │         Constrained Execution         │                            │
│  │  • Contract-bound collectors          │                            │
│  │  • Whitelisted commands               │                            │
│  │  • Deterministic evaluation           │                            │
│  └─────────────────────┬────────────────┘                            │
│                        │                                             │
│                        ▼                                             │
│  ┌──────────────────────────────────────┐                            │
│  │           Replay Manifest             │                            │
│  │  Layer 1: Intent (from AST)           │                            │
│  │  Layer 2: Contract (from CtnContract) │                            │
│  │  Layer 3: Outcome (pass/fail only)    │                            │
│  │  → replay_hash (computed once)        │                            │
│  └─────────────────────┬────────────────┘                            │
│                        │                                             │
│                        ▼                                             │
│  ┌──────────────────────────────────────┐                            │
│  │           Result Builder              │                            │
│  │  • ResultEnvelope with replay_hash    │                            │
│  │  • identity_status                    │                            │
│  │  • Signature block (optional)         │                            │
│  └─────────────────────┬────────────────┘                            │
│                        │                                             │
│                        ▼                                             │
│  ┌──────────────────────────────────────┐                            │
│  │         Controlled Disclosure         │                            │
│  │  • Signed AssessorPackage envelope    │                            │
│  │  • Observations cited by uuid         │                            │
│  │  • Audit logging (mandatory)          │                            │
│  └──────────────────────────────────────┘                            │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 12.2 Forensic Evidence Chain

The trust model produces an end-to-end forensic chain where each link is independently verifiable:

```
Policy (.esp)
    │
    │ Compiler validates and compiles
    ▼
Validated AST ──────────────────────────────────────────┐
    │                                                    │
    │ Execution engine reads AST                         │
    ▼                                                    │
Contract (CtnContract) ─────────────────────────────────┤
    │                                                    │
    │ Collector gathers evidence                         │
    ▼                                                    │
Outcome (pass/fail per field) ──────────────────────────┤
    │                                                    │
    └─────────────────────────────────────────────────▶  │
                                                         ▼
                                               replay_hash = SHA256(
                                                   intent   (from AST)
                                                 + contract (from CtnContract)
                                                 + outcome  (pass/fail only)
                                                 + tree structure
                                                 + policy identity
                                               )
                                                         │
                                               Signature = ECDSA(SHA256(replay_hash))
                                                         │
                                                         ▼
                                               ResultEnvelope
                                               (present in all output formats)
```

A verifier — whether an automated system or a human assessor — can traverse this chain in reverse: verify the signature, confirm the replay hash matches between attestation and full results, use the assessor package to reproduce the collection, and confirm the outcome matches. No link in the chain requires trusting the collector.

### 12.3 Trust Boundary Matrix

| Boundary | Input | Gate | Output |
|----------|-------|------|--------|
| Policy | Untrusted `.esp` | Compiler validation | Trusted AST |
| Execution | Trusted AST | Contract registry | ScanResult |
| Replay Hash | ScanResult + AST + Contract | ReplayManifest builder | `replay_hash` |
| Results | ScanResult + `replay_hash` | ResultBuilder | Typed results |
| Disclosure | Result formats | Feature selection | Controlled output |
| Verification | Results | Signature / hash check | Verified results |
| Audit | All operations | Minimum log level | Audit log |

---

## 13. SSDF Alignment

### 13.1 NIST SSDF Practices

ESP's trust model aligns with NIST Secure Software Development Framework:

| SSDF Practice | ESP Implementation |
|---------------|-------------------|
| **PW.7.1** (Input Validation) | Compile-time limits, type checking, reference validation |
| **PW.8.1** (DoS Protection) | Resource boundaries, timeout enforcement, bounded complexity |
| **PW.3.1** (Audit Logging) | Mandatory security logging, audit retention buffers |
| **RV.1** (Monitoring) | Memory thresholds, processing limits, security events |

---

## 14. User Implications

### 14.1 Policy Authors

| Guarantee | Implication |
|-----------|-------------|
| Compilation gate | Policies that don't compile don't execute |
| Source attribution | Errors include source locations |
| Resource bounds | Complexity limits prevent exhaustion |
| Type safety | Type checking catches errors early |

### 14.2 Scanner Implementers

| Guarantee | Implication |
|-----------|-------------|
| Explicit registration | Collectors must be registered |
| Contract binding | Contracts constrain capabilities |
| Command whitelisting | Commands require explicit approval |
| No escalation | Cannot exceed declared scope |

### 14.3 SaaS Operators

| Guarantee | Implication |
|-----------|-------------|
| Documented filter recipe | Consumer pipeline can derive attestation-equivalent extracts |
| Replay hash binding | Filtered extracts verifiably link to unfiltered envelope |
| Signature verification | Result authenticity confirmation |
| Identity status | PKI bootstrap state observable in envelope |

### 14.4 Security Teams

| Guarantee | Implication |
|-----------|-------------|
| SIEM/SOAR signals | Filtered extracts provide alerting data |
| Posture scores | Weight-based compliance metrics |
| Observation array | Evidence available without per-policy duplication |
| Mandatory audit | Security events always captured |
| Reproducibility | Results are deterministic |

### 14.5 Auditors

| Guarantee | Implication |
|-----------|-------------|
| Reproducibility info | Can re-run collection operations independently |
| Replay hash | Verify extract / envelope correspondence |
| Signature chain | Independently verify result authenticity |
| Observation content hash | Tamper-evidence on individual evidence items |

---

## 15. Validation Rules

### 15.1 Trust Boundary Validation

| Boundary | Validation |
|----------|------------|
| Policy input | Passes all compiler stages |
| Execution | Uses registered contracts only |
| Results | ResultEnvelope properly formed |
| Replay hash | SHA-256 of canonical JSON, computed once |
| Signature | Valid algorithm and key_id; covers `["replay_hash"]` |
| Audit | Minimum log level enforced |

### 15.2 Violation Handling

| Violation | Response |
|-----------|----------|
| Compile failure | Halt, no execution |
| Unregistered CTN | Execution error |
| Capability exceeded | Collection error |
| Invalid signature | Verification failure |
| Hash mismatch | Integrity failure |
| Audit suppression | Denied at compile time |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.2.0 | 2026-03-27 | Replaced `content_hash` + `evidence_hash` with `replay_hash` |
| | | Added three-layer replay hash architecture (intent + contract + outcome) |
| | | Added CRI tree rollup to hash computation |
| | | Updated `SignatureBlock` — covers `["replay_hash"]` only |
| | | Added signature verification levels (Level 0, 1, 2) |
| | | Added `identity_status` to `ResultEnvelope` |
| | | Removed Summary output format |
| | | Updated schema version references to v1.2.0 |
| | | Added forensic evidence chain framing (Section 12.2) |
| | | Added determinism rationale for AI exclusion (Section 11.2) |
| 1.0.0 | 2026-01-09 | Added Summary and Assessor Package formats |
| | | Updated output architecture diagram |
| | | Added reproducibility section |
| | | Added auditor implications |
| 0.9.0 | 2026-01-08 | Initial v1.0.0 specification |
