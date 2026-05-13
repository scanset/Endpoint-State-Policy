# ESP v2.1.1 - Canonical Execution Schema

**Version:** 2.1.1
**Status:** Normative (supersedes v1.2.0 / `09_ESP_Canonical_Schema_v1_1_0.md`)
**Last Updated:** 2026-05-13

---

## 0. What's New

### v2.1.1 (over v2.1.0)

- **`PackageInfo` shrinks.** The `contains_cui` and `distribution`
  fields are removed from `PackageInfo`. The envelope no longer makes
  a data-classification claim; classification belongs to the
  consumer pipeline's own framework. The §6 sensitivity-tiers table
  is rewritten as consumer-applied filter recipes rather than
  format-encoded shapes.

### v2.1.0 (additive over v2.0.0)

- **`replay_hash_version: u8` field on `ResultEnvelope`.** Marks which
  replay-hash scheme produced this envelope's `replay_hash`. Defaults to
  `1` (the v2.0.0 hash scheme) via `#[serde(default)]`, so v2.0.0
  envelopes deserialize cleanly into v2.1.0 readers, and v2.1.0
  envelopes produced with the default scheme remain readable by v2.0.0
  consumers. An opt-in `2` value selects the per-OBJECT hash scheme; see
  `execution_engine::types::canonical_manifest` for the leaf-hash
  primitive.

### v2.0.0

v2.0.0 was a breaking schema revision. Two structural changes and one clarification:

1. **Polymorphic `host`.** The `host` object is no longer a Linux/Windows-shaped record. It carries a free-string `host_type` discriminator (dotted `<provider>.<kind>`, e.g. `azure.vm`, `aws.account`, `m365.tenant`, `entra.tenant`, `linux.vm`) and a host-type-specific `attrs` map. Fields that made sense only for VMs (`hostname`, `os`, `arch`) are now optional and live alongside `attrs`.
2. **Evidence as a first-class entity.** Evidence is lifted out of per-policy result objects into a top-level `observations[]` array. Each observation has a stable `uuid`, a `host_ref`, and a `content_hash` over its body bytes. Per-policy results reference observations by uuid via `observation_refs[]`. A single filesystem read or API call can now be cited by many policies without duplication.
3. **Replay hash invariance (clarified, unchanged).** The replay hash continues to cover only `(intent, contract, outcome)`. Host identity, observation uuids, and timestamps remain outside the hash. This is the property that makes cross-host evidence dedup safe: adding or reshaping host/observation metadata never invalidates an attestation.

v1.x envelopes are **not** mechanically upgraded. Old archives remain verifiable by old engines at their original schema version. Agents on v2.0.0 emit v2.0.0 envelopes going forward.

---

## 1. Overview

This document specifies the canonical schema for ESP scan results at DSL schema version 2.0.0. Sections that are unchanged from v1.2.0 are summarized here and reference the v1.1.0 document for the full normative text; sections that change are reproduced in full.

---

## 2. Architecture

Unchanged from v1.2.0 Section 2 except:

- **2.3 Output Format Selection:** `evidence_data` column semantics change - evidence is no longer per-policy, it is referenced by uuid. `attestation` mode now emits `observation_refs[]` with `content_hash` only (no bodies). `full` and `assessor` emit full `observations[]` at the envelope level.
- **2.4 Replay Hash Architecture:** unchanged in computation. Promoted here as a v2.0.0 invariant: **the replay hash MUST NOT incorporate host fields, observation uuids, observation bodies, observation content hashes, or any timestamp.** An implementation that hashes those inputs is non-conformant.

---

## 3. Result Envelope Schema

### 3.1 Top-Level Structure

```json
{
  "envelope": {
    "result_id": "string",
    "schema_version": "2.1.0",
    "agent": {},
    "host": {},
    "started_at": "string",
    "completed_at": "string",
    "replay_hash": "string",
    "replay_hash_version": 1,
    "signature": {},
    "identity_status": {}
  },
  "summary": {},
  "observations": [],
  "policies": []
}
```

**Changes from v1.2.0:**
- New top-level `observations[]` array (see Section 4).
- `host` shape changed (see Section 3.4).
- `policies[].evidence` removed; replaced by `policies[].observation_refs[]` (see Section 4.4).

### 3.2 Envelope Fields

Unchanged except `schema_version` MUST be `"2.1.0"` for v2.1.0 producers
(`"2.0.0"` for v2.0.0 producers; both remain interoperable on the wire).
`replay_hash_version` MUST be present in v2.1.0 envelopes (defaults to `1`
via `#[serde(default)]` when missing; v2.0.0 producers omit it).

### 3.3 Agent Information

Unchanged from v1.2.0 Section 3.3.

### 3.4 Host Information (REWRITTEN)

The `host` object describes **what was scanned**. It is deliberately polymorphic: a VM, a cloud account, an identity tenant, and a SaaS workload configuration are all "hosts" under this model. Each is its own entity and may be scanned independently, even when they are topologically related (e.g. an Azure subscription host and a VM host that lives inside it).

#### 3.4.1 Structure

```json
{
  "host_type": "azure.vm",
  "host_id": "vm-prooflayer-demo",
  "hostname": "vm-prooflayer-demo",
  "os": "linux",
  "arch": "x86_64",
  "attrs": {
    "subscription_id": "2f3a8603-9425-446b-8fa4-09bb61becdcc",
    "resource_group": "rg-prooflayer-demo-eastus",
    "location": "eastus"
  }
}
```

#### 3.4.2 Host Fields

| Field       | Type                | Required | Description |
|-------------|---------------------|----------|-------------|
| `host_type` | string              | Yes      | Dotted `<provider>.<kind>` discriminator (see 3.4.3). Free-form string; registry values in 3.4.4 are recommended, not enforced. |
| `host_id`   | string              | Yes      | Stable identifier within `host_type`. Uniqueness scope is the `host_type`. |
| `hostname`  | string              | No       | DNS or administrative name. Present when meaningful (VMs); omitted for abstract hosts (accounts, tenants). |
| `os`        | string              | No       | Operating system family: `linux`, `windows`, `macos`. VM-like host types only. |
| `arch`      | string              | No       | CPU architecture: `x86_64`, `aarch64`, etc. VM-like host types only. |
| `attrs`     | map<string, Value>  | No       | Host-type-specific structured attributes. `Value` is arbitrary JSON (string, number, bool, object, array, null). |

A conformant envelope MUST have `host_type` and `host_id`. All other fields are optional at the schema level; individual `host_type` profiles (3.4.4) describe which attrs are conventionally expected.

#### 3.4.3 `host_type` Convention

Format: `<provider>.<kind>`, lowercase, dot-separated, ASCII only.

- `<provider>` is the namespace owner: `azure`, `aws`, `gcp`, `m365`, `entra`, `linux`, `windows`, `k8s`, `oci`, etc.
- `<kind>` is the resource shape within that provider: `vm`, `account`, `subscription`, `tenant`, `cluster`, etc.

The field is a free string. Producers MAY emit `host_type` values not listed in the registry below; consumers MUST NOT reject envelopes on the basis of an unrecognized `host_type`.

#### 3.4.4 Recommended `host_type` Registry (Non-Normative)

| `host_type`       | Scope                                      | Typical `attrs` keys |
|-------------------|--------------------------------------------|----------------------|
| `linux.vm`        | On-prem / bare-metal / legacy VM           | `machine_id`, `kernel`, `distro` |
| `windows.vm`      | Windows server/workstation                 | `machine_sid`, `edition`, `build` |
| `azure.vm`        | Azure IaaS VM                              | `subscription_id`, `resource_group`, `location`, `vm_size` |
| `azure.subscription` | Azure subscription-level posture        | `subscription_id`, `tenant_id` |
| `aws.ec2`         | AWS EC2 instance                           | `account_id`, `region`, `instance_id`, `vpc_id` |
| `aws.account`     | AWS account-level posture                  | `account_id`, `org_id`, `partition` |
| `gcp.vm`          | GCP Compute Engine instance                | `project_id`, `zone`, `instance_id` |
| `gcp.project`     | GCP project-level posture                  | `project_id`, `org_id` |
| `m365.tenant`     | Microsoft 365 tenant configuration         | `tenant_id`, `domain` |
| `entra.tenant`    | Entra ID (Azure AD) tenant                 | `tenant_id`, `domain` |
| `k8s.cluster`     | Kubernetes cluster-level posture           | `cluster_name`, `api_server`, `version` |

The registry is advisory. New `host_type` values are added by convention, not by schema revision.

#### 3.4.5 Host Identity Guidance

- `host_id` SHOULD be chosen so that the same host, scanned at different times, produces the same `(host_type, host_id)` pair. For VMs use machine-id / SMBIOS UUID / cloud instance id; for accounts use the immutable account number; for tenants use the tenant GUID.
- `host_id` is NOT required to be globally unique across `host_type` values. `(host_type, host_id)` together form the uniqueness key.
- `host_id` MUST NOT be derived from scan-time state (hostname, IP, etc.) when a stable identifier is available.

### 3.5 Signature Block

Unchanged from v1.2.0 Section 3.5.

### 3.6 Identity Status

Unchanged from v1.2.0 Section 3.6. `identity_status` remains the SIGNER's identity bootstrap state, not the subject's.

---

## 4. Observations (NEW)

Observations are the first-class evidence entities of v2.0.0. An observation is one act of data collection against a host - one file read, one command run, one API call. It has a stable uuid and a content hash, independent of which policies happen to consume it.

### 4.1 Placement

`observations[]` is a top-level envelope field. It is peer to `policies[]`, not nested inside it.

```json
{
  "envelope": { ... },
  "summary": { ... },
  "observations": [
    { "uuid": "...", "host_ref": { ... }, "collected_at": "...", "method": { ... }, "content_hash": "...", "body": { ... } }
  ],
  "policies": [
    { "policy_id": "...", "observation_refs": ["..."], "findings": [...] }
  ]
}
```

### 4.2 Observation Structure

```json
{
  "uuid": "0b2e5c0a-7d1e-4b2f-9c4e-8f1a2d3b4c5e",
  "host_ref": {
    "host_type": "azure.vm",
    "host_id": "vm-prooflayer-demo"
  },
  "collected_at": "2026-04-20T11:30:14.217Z",
  "method": {
    "kind": "file_read",
    "params": { "path": "/etc/os-release" }
  },
  "content_hash": "sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
  "body": {
    "bytes_base64": "...",
    "encoding": "utf-8"
  }
}
```

### 4.3 Observation Fields

| Field          | Type   | Required | Description |
|----------------|--------|----------|-------------|
| `uuid`         | string | Yes      | RFC 4122 v4 UUID. Stable for the lifetime of this envelope; NOT stable across scans. |
| `host_ref`     | object | Yes      | `{ host_type, host_id }` pointing at the envelope's `host` or a logically separate host when a scan covers multiple. v2.0.0 envelopes carry a single top-level `host`; multi-host scans are deferred to a future revision. |
| `collected_at` | string | Yes      | ISO 8601 timestamp. NOT in replay hash. |
| `method`       | object | Yes      | How this observation was collected (see 4.5). |
| `content_hash` | string | Yes      | SHA-256 of the canonical byte representation of `body` (see 4.6). Prefix `sha256:`. |
| `body`         | Value  | No       | The observation payload. Arbitrary JSON. Omitted in `attestation` format (only `content_hash` is kept). |

### 4.4 Policy -> Observation References

Per-policy results reference observations by uuid:

```json
{
  "policy_id": "ksi-cmt-rmv-r9-os-release-001",
  "observation_refs": [
    "0b2e5c0a-7d1e-4b2f-9c4e-8f1a2d3b4c5e"
  ],
  "findings": [ ... ]
}
```

The v1.x `policies[].evidence` field is removed. Producers MUST NOT emit it in v2.0.0 envelopes. Consumers MAY ignore it if present (forward-compat from a buggy producer).

### 4.5 Collection Method

```json
{
  "kind": "file_read" | "exec" | "http" | "sdk_call" | "query" | "...",
  "params": { ... }
}
```

`kind` is a free string; recommended values mirror the existing `collection_method` enum from v1.2.0. `params` is method-specific (path, argv, URL, SDK operation name, etc.) and is what the assessor reproducibility block in Section 10 cites for traceability.

### 4.6 Content Hash Canonicalization

`content_hash` is computed over a canonical byte representation of `body`:

- If `body` is absent, `content_hash` is computed over the raw bytes the collector observed and `body` is suppressed for privacy / size.
- If `body` is present and `body.bytes_base64` is set, the hash is over the decoded bytes.
- Otherwise the hash is over the RFC 8785 JCS-canonicalized JSON encoding of `body`.

The canonicalization choice MUST be recoverable from the observation itself; a `body.encoding` field signals raw-bytes mode.

### 4.7 Cross-Policy Dedup

Two policies that consume the same `/etc/os-release` read MUST reference the same observation uuid. Agents SHOULD coalesce identical `(host_ref, method, params)` collections within a single scan; they MAY also coalesce by `content_hash` post-hoc for identical bodies.

### 4.8 Observation and Replay Hash

Observations do not feed the replay hash. Adding observations, reordering them, or changing their uuids MUST NOT change the envelope's `replay_hash`. The hash is a function of intent + contract + outcome only.

---

## 5. Policy Results

Unchanged from v1.2.0 Section 5 **except**:

- `evidence` field removed.
- `observation_refs: []string` added (uuids pointing into top-level `observations[]`).
- All other fields (findings, criteria_tree, pass/fail, etc.) unchanged.

---

## 6. Sensitivity Tiers (Consumer Filtering)

The agent emits one signed envelope shape. Narrower views are derived
by post-emission filtering. The replay hash is invariant under every
recipe, so filtered extracts remain verifiably linked to the
unfiltered envelope by hash equality.

| Filter recipe | `host`  | `observations[]` bodies | `observation_refs` | `content_hash` | Signature |
|---------------|---------|-------------------------|--------------------|----------------|-----------|
| Summary-equivalent     | full    | absent                  | absent             | present (refs) | Yes       |
| Attestation-equivalent | full    | absent                  | present            | present        | Yes       |
| Full (as emitted)      | full    | present + reproducibility | present          | present        | Yes       |

Under the attestation-equivalent recipe, observations carry only
`uuid + host_ref + collected_at + method + content_hash`. Bodies and
findings drop. The unfiltered envelope is what the agent's signature
covers; consumers re-signing a filtered extract are producing a
distinct attestation (see Trust Model §7.4).

---

## 7. Replay Hash (Invariants)

Unchanged computation; invariants restated as normative for v2.0.0:

1. Inputs: `(intent, contract, outcome)` per criterion, rolled up through the CRI tree.
2. Excluded: `host`, `observations[]` (including uuids, bodies, and content hashes), `started_at`, `completed_at`, `signature`, `identity_status`, `result_id`.
3. Same compliance posture on two different hosts MUST produce the same `replay_hash`.
4. Same policy run twice on the same host at different times MUST produce the same `replay_hash`.
5. Re-serializing the envelope (map key reorder, whitespace, JSON encoding choice) MUST NOT change `replay_hash`.

---

## 8. Migration from v1.2.0

No mechanical upgrade path is specified. Behavior:

- **Old envelopes stay valid at their original schema version.** A v1.2.0 archive is verifiable by a v1.2.0 engine; v2.0.0 engines MAY also verify v1.2.0 envelopes in read-only mode but are not required to.
- **New envelopes are emitted in v2.0.0 natively.** Producers on v2.0.0 MUST emit `schema_version: "2.0.0"` and MUST NOT emit the v1.x `policies[].evidence` field.
- **Replay hashes remain comparable across versions.** Because the hash excludes host and evidence, a policy evaluated the same way on v1.2.0 and v2.0.0 will produce the same `replay_hash`. This is the attestation continuity guarantee across the schema break.

Producers wishing to serve mixed-version consumers SHOULD generate both shapes at emission time rather than converting after the fact.

---

## 9. OSCAL Mapping

The v2.0.0 observation model maps 1:1 onto OSCAL Assessment Results (AR) `observation` objects.

| ESP v2.0.0                         | OSCAL AR                                        |
|------------------------------------|-------------------------------------------------|
| `observations[i].uuid`             | `observation.uuid`                              |
| `observations[i].host_ref`         | `observation.subjects[]` (subject-reference)    |
| `observations[i].collected_at`     | `observation.collected`                         |
| `observations[i].method.kind`      | `observation.methods[]` (string)                |
| `observations[i].method.params`    | `observation.props[]` (ns=esp, name=method-params) |
| `observations[i].content_hash`     | `observation.props[]` (ns=esp, name=content-hash) |
| `host` (as pointed at by host_ref) | OSCAL SSP `system-component` or `inventory-item` depending on `host_type` (VMs -> inventory-item; accounts/tenants -> system-component) |
| `policies[j].findings[k]`          | `finding` with `related-observations[]` back to observation uuids |

Host-type -> OSCAL subject-type mapping is defined by the emitter (`common/src/oscal/`), not the schema, so new `host_type` values can be onboarded without a schema revision.

---

## 10. Assessor Reproducibility Block

Unchanged semantics from v1.2.0; rewired to the new model.

Each observation with `method.kind in {"exec", "file_read", "http", ...}` contributes a row to the assessor `commands[]` block:

```json
{
  "observation_uuid": "0b2e5c0a-...",
  "command": "cat /etc/os-release",
  "cwd": "/",
  "exit_code": 0,
  "stdout_sha256": "sha256:3a7bd3e...",
  "policies_citing": ["ksi-cmt-rmv-r9-os-release-001", "..."]
}
```

A single command appears once in `commands[]` and lists every policy that cited it - the manual-reproduction story for assessors is now a join across `observations` and `policies[].observation_refs`, not a walk of per-policy evidence.

---

## 11. Conformance

A v2.0.0 producer MUST:
- Emit `schema_version: "2.0.0"`.
- Emit a `host` object with at minimum `host_type` and `host_id`.
- Place evidence in top-level `observations[]` with stable uuids for the envelope lifetime.
- Reference observations from policies by uuid, not inline.
- Compute `replay_hash` per Section 7, excluding host and observation values.

A v2.0.0 consumer MUST:
- Accept any ASCII `host_type` string; MUST NOT reject on unknown values.
- Resolve `observation_refs[]` against top-level `observations[]` by uuid.
- Treat absence of `body` in `attestation` format as expected, not as an error.
- Verify `replay_hash` without incorporating host or observation fields.

---

## 12. Open Items (Tracked for v2.1)

- Multi-host scans in a single envelope (observations ref multiple hosts).
- Typed observation bodies per `method.kind`.
- Canonical `host_type` registry promoted from non-normative to registry-controlled.
