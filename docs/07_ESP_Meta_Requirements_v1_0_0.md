# ESP v1.0.0 — META Requirements

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-08

---

## 1. Overview

This document specifies the META block requirements for ESP v1.0.0 policies, including required fields, recommended fields, field formats, and validation rules.

---

## 2. META Block Structure

### 2.1 Syntax

```ebnf
metadata_block ::= "META" statement_end
                   metadata_field+
                   "META_END" statement_end

metadata_field ::= metadata_key space string_value statement_end

metadata_key   ::= identifier
```

### 2.2 Position

The META block MUST appear before the DEF block if present:

```esp
META
    ...
META_END

DEF
    ...
DEF_END
```

### 2.3 Field Format

All META fields use string values in backtick notation:

```esp
META
    field_name `field_value`
META_END
```

---

## 3. Required Fields (N-16)

For v1.0.0 compliance, the following fields MUST be present:

| Field | Description | Example |
|-------|-------------|---------|
| `esp_id` | Unique policy identifier | `stig-sv253284-sehop-enabled` |
| `version` | Policy revision (content version) | `1.0.0` |
| `dsl_schema_version` | ESP language version | `1.0.0` |
| `platform` | Target platform | `windows` |
| `criticality` | Severity level | `high` |
| `control_mapping` | Framework:Control mapping | `DISA-STIG:SV-253284` |
| `title` | Human-readable title | `SEHOP must be enabled` |

### 3.1 esp_id

**Purpose:** Unique identifier for the policy across all deployments.

**Format:** String, typically lowercase with hyphens.

**Constraints:**
- MUST be unique within a policy corpus
- SHOULD use consistent naming convention
- RECOMMENDED format: `{source}-{control-id}-{description}`

**Examples:**
```esp
esp_id `stig-sv253284-sehop-enabled`
esp_id `cis-5.1.1-cron-daemon-enabled`
esp_id `custom-app-config-validation`
```

### 3.2 version

**Purpose:** Policy revision number (content version, not DSL version).

**Format:** String, RECOMMENDED to follow [SemVer 2.0.0].

**Usage:**
- Increment when policy content changes
- Allows tracking policy updates over time
- Distinct from `dsl_schema_version`

**Examples:**
```esp
version `1.0.0`
version `1.0.1`      # Bug fix
version `2.0.0`      # Breaking change
```

### 3.3 dsl_schema_version

**Purpose:** ESP language version this policy conforms to.

**Format:** SemVer 2.0.0 — `MAJOR.MINOR.PATCH[-prerelease][+build]`

**Validation:**
- MUST be valid SemVer format
- Compiler validates compatibility with supported versions

**Examples:**
```esp
dsl_schema_version `1.0.0`
dsl_schema_version `1.1.0`
dsl_schema_version `2.0.0-beta.1`
```

### 3.4 platform

**Purpose:** Target platform for policy evaluation.

**Format:** String, lowercase.

**Common values:**
- `windows`
- `linux`
- `macos`
- `kubernetes`
- `container`

**Examples:**
```esp
platform `windows`
platform `linux`
platform `kubernetes`
```

### 3.5 criticality

**Purpose:** Severity level of the compliance check.

**Format:** Enumerated string (case-insensitive).

**Valid values:**

| Value | Description |
|-------|-------------|
| `critical` | Highest severity — immediate action required |
| `high` | High severity — prioritize remediation |
| `medium` | Medium severity — address in normal cycle |
| `low` | Low severity — address when convenient |
| `info` | Informational — no action required |

**Examples:**
```esp
criticality `critical`
criticality `high`
criticality `medium`
criticality `low`
criticality `info`
```

### 3.6 control_mapping

**Purpose:** Maps policy to compliance framework controls.

**Format:** `FRAMEWORK:CONTROL_ID` with comma separation for multiple mappings.

**Grammar:**
```ebnf
control_mapping ::= mapping ("," mapping)*
mapping         ::= framework ":" control_id
framework       ::= identifier
control_id      ::= identifier ("-" identifier)*
```

**Validation:**
- MUST contain at least one colon-separated pair
- Framework and control_id MUST NOT be empty

**Examples:**
```esp
# Single mapping
control_mapping `DISA-STIG:SV-253284`

# Multiple mappings
control_mapping `NIST-800-53:AC-6,CIS:5.1.1,DISA-STIG:V-242382`
```

**Parsed structure (informative):**
```json
[
  { "framework": "NIST-800-53", "control": "AC-6" },
  { "framework": "CIS", "control": "5.1.1" },
  { "framework": "DISA-STIG", "control": "V-242382" }
]
```

### 3.7 title

**Purpose:** Human-readable policy title.

**Format:** String, concise description.

**Guidelines:**
- SHOULD be descriptive but brief
- SHOULD indicate what is being checked
- Used in reports and findings

**Examples:**
```esp
title `SEHOP must be enabled`
title `SSH root login must be disabled`
title `Kubernetes RBAC must be enabled`
```

---

## 4. Recommended Fields

The following fields are RECOMMENDED for comprehensive policies:

| Field | Description | Example |
|-------|-------------|---------|
| `description` | Detailed description | (long text) |
| `author` | Policy author | `security-team` |
| `agent_type` | Execution context | `endpoint` |
| `tags` | Comma-separated tags | `stig,windows,security` |
| `control_framework` | Primary framework | `DISA-STIG` |
| `control` | Primary control ID | `SV-253284` |

### 4.1 description

**Purpose:** Detailed explanation of what the policy checks.

**Format:** String, may be multi-line using multiline string syntax.

**Example:**
```esp
description `Validates that Structured Exception Handling Overwrite Protection (SEHOP) is enabled in Windows to prevent exploitation of SEH overwrites.`
```

### 4.2 author

**Purpose:** Identifies policy author or team.

**Format:** String.

**Examples:**
```esp
author `security-team`
author `compliance-automation`
author `john.doe@example.com`
```

### 4.3 agent_type

**Purpose:** Specifies execution context for the policy.

**Format:** String.

**Common values:**
- `endpoint` — Runs on endpoint agent
- `controller` — Runs on central controller
- `scanner` — Runs as standalone scan

**Examples:**
```esp
agent_type `endpoint`
agent_type `controller`
```

### 4.4 tags

**Purpose:** Categorization tags for filtering and grouping.

**Format:** Comma-separated string.

**Examples:**
```esp
tags `stig,windows11,sehop,security`
tags `cis,linux,ssh,authentication`
tags `kubernetes,rbac,access-control`
```

### 4.5 control_framework / control

**Purpose:** Primary framework and control (convenience fields).

**Note:** These are redundant with `control_mapping` but provide quick access to the primary control.

**Examples:**
```esp
control_framework `DISA-STIG`
control `SV-253284`
```

---

## 5. Policy Identity (N-13)

### 5.1 Identity Tuple

Every policy has a canonical identity tuple:

```
(esp_id, version, dsl_schema_version)
```

This tuple uniquely identifies a specific policy revision at a specific DSL version.

### 5.2 Components

| Component | Source Field | Purpose |
|-----------|--------------|---------|
| `policy_id` | `esp_id` | Identifies the policy |
| `policy_revision` | `version` | Identifies content version |
| `dsl_schema_version` | `dsl_schema_version` | Identifies language version |

### 5.3 Canonical String

The identity tuple MAY be serialized as:

```
{esp_id}:{version}:{dsl_schema_version}
```

**Example:**
```
stig-sv253284-sehop-enabled:1.0.0:1.0.0
```

### 5.4 Usage

The policy identity is used for:
- Caching compiled policies
- Tracking policy versions
- Correlating results across scans
- Export to compliance frameworks

---

## 6. Validation Rules

### 6.1 Required Field Validation

Missing required fields MUST produce a validation error:

```
ValidationError: Missing required META field 'dsl_schema_version'
```

### 6.2 Format Validation

| Field | Validation |
|-------|------------|
| `dsl_schema_version` | Valid SemVer format |
| `criticality` | One of: critical, high, medium, low, info |
| `control_mapping` | Contains at least one FRAMEWORK:CONTROL pair |

### 6.3 Validation Errors

| Error | Condition |
|-------|-----------|
| `MissingRequiredField` | Required field not present |
| `InvalidCriticality` | Criticality not in allowed enum |
| `InvalidDslVersion` | dsl_schema_version not valid SemVer |
| `InvalidControlMapping` | control_mapping format invalid |

---

## 7. Complete Example

```esp
META
    esp_id `stig-sv253284-sehop-enabled`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    title `SEHOP must be enabled`
    description `Validates Structured Exception Handling Overwrite Protection is enabled`
    platform `windows`
    criticality `high`
    control_framework `DISA-STIG`
    control `SV-253284`
    control_mapping `DISA-STIG:SV-253284`
    agent_type `endpoint`
    author `security-team`
    tags `stig,windows11,sehop,security`
META_END

DEF
    ...
DEF_END
```

---

## 8. Migration Notes

### 8.1 Pre-v1.0.0 Policies

Policies written before v1.0.0 may be missing:
- `version` field
- `dsl_schema_version` field
- `title` field

### 8.2 Migration Checklist

- [ ] Add `version` field (start at `1.0.0`)
- [ ] Add `dsl_schema_version `1.0.0``
- [ ] Add `title` field
- [ ] Verify `control_mapping` format is `FRAMEWORK:CONTROL`
- [ ] Verify `criticality` is valid enum value

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification |
