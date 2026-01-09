# ESP v1.0.0 — Trust Model

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-23

---

## 1. Overview

This document specifies the trust model for ESP v1.0.0, defining trust boundaries, validation requirements, and security guarantees at every stage of policy processing.

### 1.1 Core Principle

> ESP does not trust inputs, does not infer truth, and does not leak evidence.
> Trust is established through validation, constrained execution, and controlled disclosure.

### 1.2 Trust Boundary Summary

| Boundary | Threat Mitigated | Mechanism |
|----------|------------------|-----------|
| Policy Input | Malformed/malicious policies | Multi-pass compiler validation |
| Compiler Gate | Unsafe policies reaching execution | Fail-fast with compile-time limits |
| Execution | Uncontrolled system access | Contract-bound, registered strategies |
| Capabilities | Privilege escalation | Explicit whitelists, auditable contracts |
| Configuration | Runtime security bypass | Compile-time constants |
| Results | Information leakage | Output format separation |
| Evidence Hash | Attestation/evidence mismatch | Cryptographic binding |
| Signatures | Result tampering | SignatureBlock in ResultEnvelope |
| Logging | Unattributable actions | Mandatory audit events |
| Determinism | Unreproducible results | Explicit evaluation, no inference |

---

## 2. Policy Input Trust Boundary (N-17)

### 2.1 Untrusted Input

ESP policy files (`.esp`) are **untrusted input**. Every policy MUST pass through the compiler pipeline before execution.

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
│                                              │         │
│  ┌─────────┐  ┌─────────┐                    │         │
│  │Semantic │◀─│Structural│◀───────────────────┘         │
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

Only policies that conform to explicit, auditable constraints can reach the execution engine. Compilation failures halt the system before execution begins.

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
│  ┌──────────────┐    ┌──────────────┐                  │
│  │   Registry   │───▶│   Contract   │                  │
│  │ (CTN types)  │    │ (allowed ops)│                  │
│  └──────────────┘    └──────────────┘                  │
│         │                   │                           │
│         ▼                   ▼                           │
│  ┌──────────────┐    ┌──────────────┐                  │
│  │  Collector   │───▶│   Executor   │                  │
│  │ (gather data)│    │  (validate)  │                  │
│  └──────────────┘    └──────────────┘                  │
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

### 7.1 Output Architecture

```
ScanResult (per policy)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                   RESULT BUILDER                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              ResultEnvelope (shared)             │   │
│  │  • result_id, schema_version                     │   │
│  │  • agent, host                                   │   │
│  │  • started_at, completed_at                      │   │
│  │  • content_hash, evidence_hash ◄─────────────┐  │   │
│  │  • signature (optional) ◄─── Implementations │  │   │
│  └─────────────────────────────────────────────────┘   │
│                          │                              │
│      ┌───────────────────┼───────────────────┐          │
│      ▼                   ▼                   ▼          │
│  ┌────────┐      ┌─────────────┐      ┌───────────┐    │
│  │Summary │      │ Attestation │      │FullResult │    │
│  │(counts)│      │  (CUI-free) │      │ (w/ CUI)  │    │
│  └────────┘      └─────────────┘      └───────────┘    │
│                                              │          │
│                                              ▼          │
│                                       ┌───────────┐    │
│                                       │ Assessor  │    │
│                                       │ Package   │    │
│                                       │(w/ repro) │    │
│                                       └───────────┘    │
└─────────────────────────────────────────────────────────┘
```

### 7.2 Output Format Classification

| Format | CUI | Network Safe | Use Case |
|--------|-----|--------------|----------|
| Summary | No | Yes | CI/CD pipelines, quick status |
| Attestation | No | Yes | SaaS dashboards, SIEM/SOAR |
| Full Results | Yes | No | Local remediation, incident response |
| Assessor Package | Yes | No | Auditor verification, evidence reproduction |

### 7.3 Content Classification

| Data Type | Classification | Summary | Attestation | Full | Assessor |
|-----------|----------------|---------|-------------|------|----------|
| Policy ID | Metadata | ✓ | ✓ | ✓ | ✓ |
| Outcome | Metadata | ✓ | ✓ | ✓ | ✓ |
| Criticality | Metadata | ✓ | ✓ | ✓ | ✓ |
| Control mappings | Metadata | ✗ | ✓ | ✓ | ✓ |
| Weight | Metadata | ✗ | ✓ | ✓ | ✓ |
| Evidence hash | Metadata | ✗ | ✓ | ✓ | ✓ |
| Host ID | Metadata | ✗ | ✓ | ✓ | ✓ |
| Findings | CUI | ✗ | ✗ | ✓ | ✓ |
| Expected values | CUI | ✗ | ✗ | ✓ | ✓ |
| Actual values | CUI | ✗ | ✗ | ✓ | ✓ |
| Evidence data | CUI | ✗ | ✗ | ✓ | ✓ |
| Collection target | CUI | ✗ | ✗ | ✓ | ✓ |
| Collection command | CUI | ✗ | ✗ | ✗ | ✓ |
| Collection inputs | CUI | ✗ | ✗ | ✗ | ✓ |
| Reproducibility info | CUI | ✗ | ✗ | ✗ | ✓ |

### 7.4 Summary Format (CI/CD-Safe)

Summary output is minimal and contains no sensitive data:

| Included | Purpose |
|----------|---------|
| Agent info | Which scanner ran |
| Policy counts | Pass/fail/error totals |
| Per-policy outcome | Individual policy status |
| Criteria counts | Detailed pass rates |

| Excluded | Rationale |
|----------|-----------|
| Everything else | Minimal footprint for automation |

### 7.5 Attestation Format (SaaS-Safe)

Attestations are safe for network transport and SaaS processing:

| Included | Purpose |
|----------|---------|
| Policy identity | Which policy was checked |
| Outcome (pass/fail) | Security signal for SIEM/SOAR |
| Criticality | Prioritization |
| Weight | Posture score calculation |
| Control mappings | Framework compliance mapping |
| Evidence hash | Verifiable link to full results |
| Signature block | Authenticity verification |

| Excluded | Rationale |
|----------|-----------|
| Findings | Contains expected/actual (CUI) |
| Evidence data | Raw system configuration |
| Collection targets | Reveals system paths |

**SaaS Liability Protection:**

Attestations are designed so that SaaS platforms:
- Can compute compliance posture scores
- Can trigger SIEM/SOAR alerts
- Can correlate with other security signals
- **Cannot** access or be liable for CUI

### 7.6 Full Results (Local-Only)

Full results contain CUI and are for local storage only:

| Included | Purpose |
|----------|---------|
| Everything in attestation | — |
| Findings | Remediation details |
| Evidence data | Collected system values |
| Collection method | How data was gathered |
| Collection target | What was inspected |

| Security Requirement | Enforcement |
|---------------------|-------------|
| Storage | Local filesystem only |
| Transport | NOT transmitted over network by default |
| Access | Controlled by customer |
| Retention | Customer-defined policies |

### 7.7 Assessor Package (Auditor Access)

Assessor packages add collection traceability and reproducibility:

| Included | Purpose |
|----------|---------|
| Everything in full results | — |
| Collection command | Exact command executed |
| Collection inputs | Input parameters used |
| Reproducibility info | How to re-run collection |
| Package metadata | Distribution restrictions |

**Use Cases:**
- External auditor verification
- Evidence reproduction
- Incident investigation

**Package Metadata:**
```json
{
  "format_version": "1.0.0",
  "contains_cui": true,
  "distribution": "Internal use only - contains CUI"
}
```

### 7.8 Security Guarantee

Sensitive system information is never transmitted by default. CUI remains under customer control.

---

## 8. Evidence Hash Verification

### 8.1 Purpose

The `evidence_hash` in `ResultEnvelope` provides cryptographic binding between attestation and full results.

### 8.2 Hash Computation

```rust
// Evidence hash computed from all policy evidence
let mut combined_evidence = Evidence::new();
for policy in &policies {
    combined_evidence.merge(policy.evidence.clone());
}
let evidence_hash = combined_evidence.compute_hash()?; // SHA-256
```

### 8.3 Verification Properties

| Property | Guarantee |
|----------|-----------|
| **Binding** | Attestation is bound to specific evidence |
| **Integrity** | Any evidence modification is detectable |
| **Non-repudiation** | Cannot claim attestation matches different evidence |
| **Retrievability** | Can locate full results matching attestation |

### 8.4 Verification Flow

```
┌─────────────────────┐     ┌─────────────────────┐
│  AttestationResult  │     │     FullResult      │
├─────────────────────┤     ├─────────────────────┤
│ envelope:           │     │ envelope:           │
│   evidence_hash: X  │ === │   evidence_hash: X  │
│                     │     │                     │
│ checks: [...]       │     │ policies: [...]     │
│ (no evidence)       │     │ (with evidence)     │
└─────────────────────┘     └─────────────────────┘

If evidence_hash matches:
  ✓ Attestation corresponds to this full result
  ✓ Evidence has not been tampered with
  ✓ Break-glass retrieval is valid
```

### 8.5 Break-Glass Access

The evidence hash enables secure break-glass workflows:

```
Customer Premises                              SaaS Platform
─────────────────                              ─────────────

FullResult ──────┬── evidence_hash ──────────► AttestationResult
                 │                                   │
                 │                                   ▼
                 │                             SIEM Alert:
                 │                             "High severity
                 │                              policy failed"
                 │                                   │
                 ▼                                   │
Local Storage ◄──────────── Break-glass ────────────┘
                            Request:
                            "evidence_hash: X"
                            "duration: 1 hour"
```

### 8.6 Security Guarantee

Attestations are cryptographically bound to their evidence. Evidence retrieval is auditable and time-limited.

---

## 9. Signature Block

### 9.1 Purpose

The `SignatureBlock` in `ResultEnvelope` enables result authentication and tamper detection.

### 9.2 Structure

```rust
pub struct SignatureBlock {
    pub algorithm: String,           // e.g., "ecdsa-p256"
    pub key_id: String,              // Key identifier
    pub value: String,               // Base64-encoded signature
    pub signed_at: String,           // ISO 8601 timestamp
    pub certificate_chain: Option<Vec<String>>,
}
```

### 9.3 Signing Scope

| What is signed | Purpose |
|----------------|---------|
| `content_hash` | Result integrity |
| `evidence_hash` | Evidence integrity |
| `result_id` | Result identity |
| `completed_at` | Temporal binding |

### 9.4 Supported Algorithms

| Algorithm | Use Case |
|-----------|----------|
| `ecdsa-p256` | General purpose |
| `ecdsa-p384` | Higher security |
| `ed25519` | Performance |
| `rsa-pss-sha256` | Legacy compatibility |
| `tpm-ecdsa-p256` | Hardware-backed |

### 9.5 Security Guarantee

Signed results cannot be modified without detection. Signature verification confirms result authenticity.

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
| Break-glass requests | ✓ |

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

### 11.3 Reproducibility Support

The assessor package format includes reproducibility information:

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
┌─────────────────────────────────────────────────────────────────────┐
│                         ESP TRUST MODEL                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  UNTRUSTED INPUT          TRUST GATE              TRUSTED OUTPUT    │
│                                                                     │
│  ┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐   │
│  │ .esp files  │────▶│    Compiler     │────▶│  Validated AST  │   │
│  │ (untrusted) │     │ (7-pass check)  │     │   (trusted)     │   │
│  └─────────────┘     └─────────────────┘     └────────┬────────┘   │
│                                                       │             │
│                      ┌────────────────────────────────┘             │
│                      ▼                                              │
│  ┌─────────────────────────────────────┐                           │
│  │         Constrained Execution        │                           │
│  │  • Contract-bound collectors         │                           │
│  │  • Whitelisted commands              │                           │
│  │  • Deterministic evaluation          │                           │
│  └──────────────────┬──────────────────┘                           │
│                     │                                               │
│                     ▼                                               │
│  ┌─────────────────────────────────────┐                           │
│  │           Result Builder             │                           │
│  │  • ResultEnvelope with hashes        │                           │
│  │  • Evidence hash binding             │                           │
│  │  • Signature block (optional)        │                           │
│  └──────────────────┬──────────────────┘                           │
│                     │                                               │
│                     ▼                                               │
│  ┌─────────────────────────────────────┐                           │
│  │         Controlled Disclosure        │                           │
│  │  • Summary (CI/CD pipelines)         │                           │
│  │  • Attestation (SaaS-safe)           │                           │
│  │  • Full Results (local-only)         │                           │
│  │  • Assessor Package (auditor access) │                           │
│  │  • Audit logging (mandatory)         │                           │
│  └─────────────────────────────────────┘                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 12.2 Trust Boundary Matrix

| Boundary | Input | Gate | Output |
|----------|-------|------|--------|
| Policy | Untrusted `.esp` | Compiler validation | Trusted AST |
| Execution | Trusted AST | Contract registry | ScanResult |
| Results | ScanResult | ResultBuilder | Typed results |
| Disclosure | Result formats | Feature selection | Controlled output |
| Verification | Results | Signature/hash check | Verified results |
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
| CUI-free attestations | No liability for sensitive data |
| Evidence hash binding | Verifiable link to full results |
| Break-glass support | Time-limited access when needed |
| Signature verification | Result authenticity confirmation |

### 14.4 Security Teams

| Guarantee | Implication |
|-----------|-------------|
| SIEM/SOAR signals | Attestations provide alerting data |
| Posture scores | Weight-based compliance metrics |
| Evidence retrieval | Full results available locally |
| Mandatory audit | Security events always captured |
| Reproducibility | Results are deterministic |

### 14.5 Auditors

| Guarantee | Implication |
|-----------|-------------|
| Assessor packages | Full evidence with collection commands |
| Reproducibility info | Can re-run collection operations |
| Package metadata | Clear CUI handling requirements |
| Evidence hash | Verify attestation/evidence correspondence |

---

## 15. Validation Rules

### 15.1 Trust Boundary Validation

| Boundary | Validation |
|----------|------------|
| Policy input | Passes all compiler stages |
| Execution | Uses registered contracts only |
| Results | ResultEnvelope properly formed |
| Evidence hash | SHA-256 of canonical JSON |
| Signature | Valid algorithm and key_id |
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
| 1.0.0 | 2026-01-23 | Added Summary and Assessor Package formats |
|       |            | Updated output architecture diagram |
|       |            | Added reproducibility section |
|       |            | Added auditor implications |
| 1.0.0 | 2026-01-09 | Updated for results module architecture |
| 0.9.0 | 2026-01-08 | Initial v1.0.0 specification |
