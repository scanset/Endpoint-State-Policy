# ESP v1.0.0 — Overview

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-09

---

> **v2.0.0 cross-reference.** The DSL surface described in this document
> (grammar, types, evaluation) is **unchanged** in v2.0.0. What changes in
> v2.0.0 is the **output envelope**:
>
> - Hosts are polymorphic (`host_type` is a dotted `<provider>.<kind>` —
>   `linux.vm`, `azure.vm`, `aws.account`, `m365.tenant`, ...). The
>   single-Linux-VM assumption in this document's result-format sections
>   is superseded.
> - Evidence is lifted out of `PolicyResult.evidence` into a top-level
>   `observations[]` array; policies cite it by uuid via
>   `PolicyResult.observation_refs[]`.
>
> The full v2.0.0 envelope specification is in
> `docs/09_ESP_Canonical_Schema_v2_1_1.md`. Sections 4–7 of that document
> supersede the result-format tables here for v2.0.0 output.
>
> **v2.1.0** extends the DSL grammar: `SET_REF` is now a first-class
> CTN content operand, letting a policy reference its bound-asset list
> as a single SET block (see EBNF §7 and Symbol Resolution). The wire
> schema additively bumps to `2.1.0` with a new `replay_hash_version`
> field on `ResultEnvelope` (back-compat).
>
> **v2.2.0** adds an opt-in per-OBJECT replay hash scheme
> (`replay_hash_version = 2`). v1 hash semantics are unchanged and
> remain the default.
>
> **v2.2.1** is a hotfix for the agentless CTN-collection timeout —
> see `ESP_CTN_TIMEOUT_SECS` in the Configuration document.

---

## 1. Purpose

This specification defines the Endpoint State Policy (ESP) Domain-Specific Language version 1.0.0. ESP enables declarative definition of compliance checks for endpoint systems.

ESP v1.0.0 establishes:

- **Deterministic parsing** — Unambiguous tokenization and grammar
- **Deterministic semantics** — Fixed evaluation rules
- **Deterministic identity** — Explicit policy identification
- **Deterministic output** — Consistent result formats

---

## 2. Scope

### 2.1 In Scope

| Area | Description |
|------|-------------|
| DSL Grammar | EBNF specification for parsing ESP files |
| Lexical Rules | Tokenization, keywords, operators, literals |
| Type System | Data types and operation compatibility |
| Symbol Resolution | Namespaces, scoping, reference resolution |
| Evaluation Semantics | TEST, CRI, STATE evaluation rules |
| Metadata Requirements | Required and optional META fields |
| Error Model | Error classification and handling |
| Canonical Schema | Result schemas and output formats |
| Trust Model | Security boundaries and guarantees |

### 2.2 Out of Scope

| Area | Rationale |
|------|-----------|
| CTN Type Enumeration | CTN types are extensible via contracts |
| Export Format Specifications | OSCAL/CKLB are separate specifications |
| Runtime Implementation | Implementation-specific |
| Signature Implementation | Implementation-specific (schema provided) |

---

## 3. Terminology

### 3.1 Normative Keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are interpreted as described in BCP 14 [RFC 2119] [RFC 8174].

### 3.2 Definitions

| Term | Definition |
|------|------------|
| **Policy** | An ESP file containing a complete compliance check definition |
| **Compiler** | Software that parses ESP files and produces validated AST |
| **AST** | Abstract Syntax Tree produced by the compiler |
| **ScanResult** | Result of executing a single policy |
| **CTN** | Criterion Type Node — a single compliance check unit |
| **Pass** | Compliance check succeeded |
| **Fail** | Compliance check found non-compliance |
| **Error** | Compliance check could not complete |
| **AssessorPackage** | The sole output envelope; carries policy outcomes, observations, findings, reproducibility info, and the signed `ResultEnvelope` |
| **ResultEnvelope** | Inner envelope: identity, timing, replay hash, signature, observation array |
| **Observation** | One act of data collection against a host, addressable by uuid and content hash |
| **Replay Hash** | Deterministic hash of `(intent, contract, outcome)` per policy, stable across runs of identical posture |

---

## 4. Conformance

### 4.1 Conformance Targets

| Target | Description |
|--------|-------------|
| **ESP Policy v1.0.0** | A policy document written in ESP DSL |
| **ESP Compiler v1.0.0** | Parser, validator, and AST builder |
| **ESP Engine v1.0.0** | Execution engine producing ScanResult |
| **ESP Agent v1.0.0** | CLI that orchestrates scanning and output |

### 4.2 Conformance Statement

An implementation conforms to this specification if it satisfies all MUST and MUST NOT requirements applicable to its conformance target.

---

## 5. Normative References

| Reference | Title |
|-----------|-------|
| [RFC 2119] | Key words for use in RFCs to Indicate Requirement Levels |
| [RFC 8174] | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words |
| [RFC 8259] | The JavaScript Object Notation (JSON) Data Interchange Format |
| [RFC 8785] | JSON Canonicalization Scheme (JCS) |
| [ISO/IEC 14977] | Extended BNF |
| [JSON Schema 2020-12] | JSON Schema: A Media Type for Describing JSON Documents |
| [SemVer 2.0.0] | Semantic Versioning 2.0.0 |
| [FIPS 180-4] | Secure Hash Standard (SHA-256) |

---

## 6. Design Principles

1. **Policy as Data** — Policies describe *what* should be true, not *how* to check it
2. **Fail-Fast Validation** — Errors caught at compile time, not runtime
3. **Contract-Driven Extensibility** — CTN types defined by contracts
4. **Deterministic Evaluation** — Same policy + same state = same result
5. **Compliance-Ready Output** — Results mappable to standard formats
6. **Trust Boundaries** — Inputs untrusted, outputs controlled
7. **Verifiable Results** — Replay hash binds outcome to compiled intent + collected evidence
8. **Single Envelope** — One `AssessorPackage` carries every policy in a scan; sensitivity tiers are derived by consumer-side filtering, not by separate output formats

---

## 7. Document Structure

| Document | Description |
|----------|-------------|
| 01-overview.md | This document |
| 02-lexical-rules.md | Encoding, tokenization, keywords |
| 03-grammar.ebnf | EBNF grammar specification |
| 04-type-system.md | Data types and operations |
| 05-symbol-resolution.md | Namespaces and scoping |
| 06-evaluation-semantics.md | TEST, CRI, STATE evaluation rules |
| 07-meta-requirements.md | META field requirements |
| 08-error-model.md | Error classification and handling |
| 09-canonical-schema.md | Result schemas and output formats |
| 10-trust-model.md | Security boundaries and guarantees |

---

## 8. Architecture Overview

### 8.1 Processing Pipeline

```
ESP Policy File(s) (.esp)
         │
         ▼
┌─────────────────────┐
│      Compiler       │  Lexical → Syntax → Semantic → Structural
│   (Untrusted → AST) │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Execution Engine   │  Resolution → Collection → Validation
│  (AST → ScanResult) │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Result Builder    │  ScanResults → AssessorPackage
└──────────┬──────────┘
           │
           ▼
   AssessorPackage (single signed envelope)
```

### 8.2 Data Flow

| Stage | Input | Output | Trust Level |
|-------|-------|--------|-------------|
| Compilation | `.esp` file | Validated AST | Untrusted → Trusted |
| Resolution | AST | ExecutionContext | Trusted |
| Execution | ExecutionContext | ScanResult | Trusted |
| Result Building | ScanResult[] | AssessorPackage | Controlled Disclosure |

### 8.3 Result Architecture

The agent emits a single signed `AssessorPackage` envelope per scan.
The envelope shape is fixed; consumers derive narrower views by
post-emission filtering (see §10).

```
┌─────────────────────────────────────────────────────────────┐
│                     AssessorPackage                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ envelope: ResultEnvelope                             │   │
│  │   ├ result_id, schema_version                        │   │
│  │   ├ agent: { id, name, version, agent_type }         │   │
│  │   ├ host: { host_type, host_id, attrs, … }           │   │
│  │   ├ started_at, completed_at                         │   │
│  │   ├ replay_hash + replay_hash_version                │   │
│  │   ├ identity_status                                  │   │
│  │   ├ signature: { algorithm, key_id, value, … }       │   │
│  │   └ observations[]   (top-level evidence array)      │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ policies[]: PolicyResult                             │   │
│  │   ├ policy_id, outcome, criticality                  │   │
│  │   ├ counts, control_mappings                         │   │
│  │   ├ observation_refs[] (cite into envelope)          │   │
│  │   └ findings[] (validation failures)                 │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ reproducibility: ReproducibilityInfo                 │   │
│  │   collection commands and inputs                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. Schema Deliverables

| Schema | Purpose |
|--------|---------|
| meta-block.schema.json | META block validation |
| policy-identity.schema.json | Policy identity fields |
| ctn-contract.schema.json | CTN contract definitions |
| result-envelope.schema.json | Inner `ResultEnvelope` shape |
| assessor-package.schema.json | The sole output envelope |
| observation.schema.json | Top-level `observations[]` items |
| collection-method.schema.json | Collection method traceability |
| compliance-finding.schema.json | Finding details |

All schemas conform to JSON Schema Draft 2020-12.

---

## 10. Output

### 10.1 Single Envelope

Since v2.0.0 the agent emits exactly one shape: `AssessorPackage`.
There is no `--format` flag; output is always the full assessor
envelope. The unfiltered envelope is what the agent signs.

### 10.2 Sensitivity Tiers via Consumer Filtering

Consumers derive narrower views by dropping fields before
transmission. The replay hash is computed over
`(intent, contract, outcome)` only, so it is **stable under every
documented filter** — a filtered extract carries the same
`replay_hash` as the unfiltered envelope.

| Filter recipe | Drop from envelope | Resulting view |
|---|---|---|
| Attestation-equivalent | `observations[]`, `policies[].findings`, `policies[].observation_refs`, `reproducibility` | Identity, outcome, control mappings, replay hash, signature |
| Summary-equivalent | `observations[].body`, `policies[].findings` | Identity, outcome, observation metadata + content hashes, replay hash, signature |
| Full | (nothing) | The envelope as emitted |

### 10.3 Use Cases

| Filter recipe | Primary Use Case | Consumer |
|---|---|---|
| Attestation-equivalent | Compliance posture dashboards | SaaS platform |
| Attestation-equivalent | SIEM/SOAR alerting | Security tools |
| Attestation-equivalent | Audit proof | Compliance teams |
| Summary-equivalent | CI/CD pass/fail signals | Build systems |
| Full | Remediation workflows | Operations teams |
| Full | Incident investigation | Security teams |
| Full | Audit verification | External auditors |
| Full | Evidence reproduction | Assessment teams |

### 10.4 Signing After Filtering

The `envelope.signature` block covers the unfiltered envelope.
Consumers that strip fields before transmission have two options:

1. **Forward the original signature** alongside the filtered extract;
   downstream verifiers rehydrate from a local archive (or refuse to
   verify without it) and confirm signature over the full shape.
2. **Counter-sign the filtered extract** with the consumer's own
   key; the chain becomes `agent_signature(full) →
   consumer_signature(extract)` and downstream verifiers trust the
   consumer's key, not the agent's.

The trust model takes no position on which is correct — see
[ESP Trust Model §7.4](10_ESP_Trust_Model_v1_2_0.md) for the full
discussion.

---

## 11. Evidence Hash Verification

The `evidence_hash` field enables verification that an attestation corresponds to specific full results.

### 11.1 Verification Flow

```
Customer Premises                              SaaS Platform
─────────────────                              ─────────────

FullResult ──────┬── evidence_hash ──────────► AttestationResult
                 │                                   │
                 │                                   ▼
                 │                             "87% posture"
                 │                             "evidence_hash: X"
                 │                                   │
                 ▼                                   │
Local Storage ◄──────────── Break-glass ────────────┘
                            "Fetch results
                             matching hash X"
```

### 11.2 Guarantees

1. **Attestation → Full Results**: Given an attestation, retrieve matching full results
2. **Integrity**: Detect tampering of evidence data
3. **Audit Trail**: Prove attestation corresponds to stored evidence

---

## 12. Single Envelope Design

### 12.1 Principle

All output formats produce a **single envelope** containing all scanned policies, regardless of how many ESP files were scanned:

```bash
# Single file → single envelope with 1 policy
esp_agent policy.esp

# Directory with 10 files → single envelope with 10 policies
esp_agent /path/to/policies/
```

### 12.2 Benefits

| Benefit | Description |
|---------|-------------|
| Atomic results | One result ID for entire scan |
| Unified hash | Single evidence hash covers all evidence |
| Simplified processing | Consumers handle one result object |
| Consistent structure | Same format for single or batch scans |

### 12.3 Structure

```json
{
  "envelope": {
    "result_id": "esp-result-...",
    "evidence_hash": "combined-hash-of-all-evidence"
  },
  "summary": {
    "total_policies": 10,
    "passed": 8,
    "failed": 2
  },
  "policies": [
    { "identity": {...}, "outcome": "pass", ... },
    { "identity": {...}, "outcome": "fail", ... },
    ...
  ]
}
```

---

## Revision History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2026-01-09 | Added Summary and Assessor Package formats |
|       |            | Added single envelope design section |
|       |            | Updated architecture diagrams |
|       |            | Added format selection table |
| 1.0.0 | 2026-01-09 | Updated for results module architecture |
| 0.9.0 | 2026-01-08 | Initial release |
