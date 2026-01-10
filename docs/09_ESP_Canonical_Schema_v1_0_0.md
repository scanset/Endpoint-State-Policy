# ESP v1.0.0 — Canonical Execution Schema

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-09

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
    └── Assessor Package (with reproducibility)
```

### 2.2 Design Principles

| Principle | Description |
|-----------|-------------|
| **Single Envelope** | All policies in one result, regardless of input count |
| **Complete** | Contains all execution data needed for each output mode |
| **Verifiable** | Evidence hash enables attestation/full result correlation |
| **Serializable** | JSON format for interoperability |

### 2.3 Output Format Selection

| Output Format | Evidence Data | Findings | Collection Methods | Commands/Inputs | Reproducibility |
|---------------|---------------|----------|-------------------|-----------------|-----------------|
| `summary` | No | No | No | No | No |
| `attestation` | Hash only | No | Type only | No | No |
| `full` | Full | Yes | Full | No | No |
| `assessor` | Full | Yes | Full | Yes | Yes |

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
    "content_hash": "string",
    "evidence_hash": "string"
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
| `content_hash` | string | Yes | SHA-256 hash of result content |
| `evidence_hash` | string | Yes | SHA-256 hash of all collected evidence |

### 3.3 Agent Information

```json
{
  "id": "esp-agent",
  "name": "esp-agent",
  "version": "1.0.0",
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
  "format_version": "1.0.0",
  "generated_at": "2026-01-23T22:15:06Z",
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
    "version": "1.0.0"
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
    "result_id": "esp-result-...",
    "evidence_hash": "9fbea98350c00a9642fe91431619dd3a..."
  },
  "summary": {},
  "checks": [
    {
      "identity": {
        "policy_id": "test-file-metadata-001",
        "platform": "linux",
        "criticality": "high",
        "control_mappings": [...]
      },
      "outcome": "pass",
      "weight": 0.8
    }
  ]
}
```

### 12.3 Full Result Format

See Section 3-10 for complete structure. Full example:

```json
{
  "envelope": {
    "result_id": "esp-result-18892f9d95dcc6b5",
    "schema_version": "1.0.0",
    "agent": {
      "id": "esp-agent",
      "name": "esp-agent",
      "version": "1.0.0",
      "agent_type": "cli"
    },
    "host": {
      "id": "host-ad1bfa7a1863edb2",
      "hostname": "server01",
      "os": "linux",
      "arch": "x86_64"
    },
    "started_at": "2026-01-23T22:11:22Z",
    "completed_at": "2026-01-23T22:11:22Z",
    "content_hash": "8726504ca47412e0d8c0be36a1286a79...",
    "evidence_hash": "9fbea98350c00a9642fe91431619dd3a..."
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
  "policies": [
    {
      "identity": {
        "policy_id": "test-file-metadata-001",
        "platform": "linux",
        "criticality": "high",
        "control_mappings": [
          { "framework": "CIS", "control_id": "6.1.1" },
          { "framework": "CIS", "control_id": "6.1.2" },
          { "framework": "NIST-800-53", "control_id": "AC-6" }
        ]
      },
      "outcome": "pass",
      "weight": 0.8,
      "findings": [],
      "evidence": {
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
        "collection_metadata": [
          {
            "object_id": "passwd_file",
            "ctn_type": "file_metadata",
            "collector_id": "filesystem_collector",
            "collection_mode": "default",
            "duration_ms": 0,
            "field_count": 6,
            "has_warnings": false,
            "method": {
              "method_type": "file_stat",
              "description": "Query file metadata via stat()",
              "target": "/etc/passwd"
            }
          }
        ],
        "collected_at": "2026-01-23T22:11:22Z"
      }
    }
  ]
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
| New optional field | MINOR | Add optional `tags` |
| Documentation only | PATCH | Clarify description |

### 13.3 Version Validation

Consumers SHOULD validate `schema_version` before processing:

```rust
if !schema_version.starts_with("1.") {
    return Err("Unsupported schema version");
}
```

---

## 14. Validation Rules

### 14.1 Required Field Validation

| Field | Validation |
|-------|------------|
| `envelope.schema_version` | Valid SemVer |
| `envelope.result_id` | Non-empty, starts with `esp-result-` |
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
| Evidence hash | Matches hash of all evidence data |

### 14.3 Validation Errors

| Error | Condition |
|-------|-----------|
| `InvalidSchemaVersion` | schema_version not valid SemVer |
| `MissingRequiredField` | Required field not present |
| `InvalidCriticality` | Unknown criticality value |
| `InconsistentCounts` | Summary counts don't add up |
| `InvalidTimestamp` | Timestamp not ISO 8601 |

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

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification |
|       |              Updated to match actual implementation output |
|       |            | Added single envelope design (all policies in one result) |
|       |            | Updated field names (`control_id` vs `control`) |
|       |            | Added assessor package schema (Section 11) |
|       |            | Added output format examples (Section 12) |
|       |            | Removed ExecutionManifest (internal IR, not output) |
