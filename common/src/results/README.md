# Results Module

Structured types for ESP compliance scan results with feature-gated output modes.

This module provides two output formats: **attestations** for secure network transport, and **full results** for local storage with complete evidence. Choose the appropriate mode based on your security and data requirements.

## Security Model

ESP scan results can contain sensitive information about system configurations, architecture internals, and security posture. This module separates results into two categories:

### Attestations (default)

Network-safe output containing only pass/fail metadata:

- Policy identifiers and outcomes
- Criticality levels and compliance framework mappings
- Aggregate statistics (criteria counts, pass rates)
- Content hashing for integrity verification

**Does not include**: Actual system values, expected configurations, file contents, command outputs, or any data that could expose system internals.

### Full Results

Complete results with evidence for local storage:

- Everything in attestations, plus:
- Expected values (what the policy requires)
- Actual values (what was found on the system)
- Raw collected data and findings

**Warning**: Full results contain sensitive system configuration data. Store locally only—do not transmit over untrusted networks.

## Cryptographic Hashing

The `crypto` module provides **FIPS 140-3 compliant** hashing using platform-native cryptography:

| Platform | Backend | Certification |
|----------|---------|---------------|
| **Windows** | Windows CNG (BCrypt) | FIPS 140-3 certified (built into Windows 10/11/Server 2016+) |
| **Linux/Unix** | OpenSSL FIPS provider | FIPS 140-3 certified |

### Usage

```rust
use common::results::crypto::{hash_content, sha256_hash, verify_hash};

// Hash serializable content (canonical JSON + SHA-256)
let hash = hash_content(&my_struct)?;

// Hash raw bytes
let digest = sha256_hash(b"hello world")?;

// Verify content against hash
let valid = verify_hash(&my_struct, &expected_hash)?;
```

### Cross-Platform Builds

The crypto module automatically selects the appropriate backend at compile time:

- **Windows target**: Uses `windows` crate with BCrypt APIs (no external dependencies)
- **Non-Windows target**: Uses `openssl` crate

This enables cross-compilation without bundling OpenSSL for Windows builds.

## Feature Flags

Enable the output mode you need in your `Cargo.toml`:

```toml
# Attestations only (default)
common = { path = "../common" }

# Full results only
common = { path = "../common", default-features = false, features = ["full-results"] }

# Both modes
common = { path = "../common", features = ["full-results"] }
```

Note: The `crypto` module is always available regardless of feature flags.

## Common Types

These types are always available regardless of feature flags:

| Type | Description |
|------|-------------|
| `Outcome` | Evaluation result: `Pass`, `Fail`, `Error`, `Unknown` |
| `Criticality` | Severity level: `Critical`, `High`, `Medium`, `Low`, `Info` |
| `Weight` | Posture scoring weight (0.0 - 1.0), derived from criticality or explicit |
| `CriteriaCounts` | Pass/fail/error statistics for criteria within a policy |
| `ControlMapping` | Compliance framework reference (e.g., `NIST-800-53:AC-6`) |
| `PolicyOutcome` | Core policy evaluation data shared between both output modes |

### Criticality Weights

Default weights used for posture score calculations:

| Criticality | Default Weight |
|-------------|----------------|
| Critical | 1.0 |
| High | 0.8 |
| Medium | 0.5 |
| Low | 0.2 |
| Info | 0.1 |

## Usage: Attestations

### Required META Fields

The attestation builder requires these fields in the policy's META block:

| Field | Description | Example |
|-------|-------------|---------|
| `esp_scan_id` | Unique policy identifier | `tcp-dangerous-ports-closed` |
| `platform` | Target platform | `linux`, `Kubernetes` |
| `criticality` | Severity level | `critical`, `high`, `medium`, `low`, `info` |
| `control_mapping` | Framework:ControlID pairs | `CIS:2.1,NIST-800-53:CM-7` |

Optional fields:
- `esp_version` - Policy version
- `weight` - Explicit weight override (0.0 - 1.0)

### Building Attestations

```rust
use common::results::{AttestationBuilder, Outcome, CriteriaCounts};
use common::metadata::MetaDataBlock;

// After executing policies, build the attestation
let mut builder = AttestationBuilder::new("agent-001", "controller");

for (metadata, outcome, counts) in policy_results {
    builder.add_check(&metadata, outcome, counts)?;
}

let attestation = builder.build()?;

// Serialize for transport
let json = attestation.to_json()?;
```

### Example Output

```json
{
  "envelope": {
    "attestation_id": "att-1a2b3c4d",
    "timestamp": "2024-01-15T10:30:00Z",
    "agent_id": "agent-001",
    "agent_type": "controller",
    "content_hash": "a1b2c3d4e5f6..."
  },
  "summary": {
    "total_checks": 1,
    "passed": 1,
    "failed": 0,
    "error": 0,
    "total_weight": 0.8,
    "passed_weight": 0.8
  },
  "checks": [
    {
      "policy_id": "tcp-dangerous-ports-closed",
      "platform": "linux",
      "outcome": "pass",
      "criticality": "high",
      "weight": 0.8,
      "control_mappings": [
        { "framework": "CIS", "control_id": "2.1" }
      ],
      "criteria_counts": {
        "total": 3,
        "passed": 3,
        "failed": 0,
        "error": 0
      }
    }
  ]
}
```

### Verifying Attestations

```rust
use common::results::{hash_content, verify_hash};

// Verify content integrity
let is_valid = verify_hash(&attestation_content, &envelope.content_hash)?;
```

## Usage: Full Results

Use full results when you need complete evidence for local audit trails, debugging, or incident response.

```rust
use common::results::full::{FullResultBuilder, HostContext, UserContext};
use common::results::{Outcome, CriteriaCounts};

let host = HostContext::from_system();
let user = UserContext::from_environment();

let mut builder = FullResultBuilder::new("scan-001", host, user);

for (metadata, outcome, counts, findings, evidence) in policy_results {
    builder.add_policy(&metadata, outcome, counts, findings, evidence)?;
}

let result = builder.build();

// Store locally only
std::fs::write("scan_result.json", result.to_json()?)?;
```

Full results include `ComplianceFinding` entries with expected vs. actual values and optional `Evidence` containing raw collected data.

## Control Mapping Format

Control mappings link ESP policies to compliance framework controls. The META field format is:

```
FRAMEWORK:CONTROL_ID,FRAMEWORK:CONTROL_ID,...
```

### Examples

```
# Single mapping
control_mapping `CIS:5.1.1`

# Multiple mappings
control_mapping `NIST-800-53:AC-6,CIS:5.1.1,STIG:V-242382`
```

### Supported Frameworks

Any framework identifier works. Common examples:

| Framework | Example Control IDs |
|-----------|---------------------|
| `NIST-800-53` | `AC-6`, `CM-7`, `SI-2` |
| `CIS` | `1.1.1`, `5.2.3` |
| `STIG` | `V-242382` |
| `CMMC` | `AC.1.001` |
| `PCI-DSS` | `2.2.1` |

### Parsing Control Mappings

```rust
use common::results::ControlMapping;

let mappings = ControlMapping::parse_from_meta("NIST-800-53:AC-6,CIS:5.1.1")?;

for mapping in &mappings {
    println!("{}: {}", mapping.framework, mapping.control_id);
}

// Convert back to META format
let meta_string = ControlMapping::to_meta_format(&mappings);
```

## Module Structure

```
results/
├── mod.rs              # Feature-gated re-exports
├── error.rs            # ResultError type
├── crypto/             # FIPS 140-3 compliant hashing (always available)
│   ├── mod.rs          # Platform-agnostic interface
│   ├── canonical.rs    # Canonical JSON serialization
│   ├── openssl.rs      # Linux/Unix backend (OpenSSL)
│   └── windows.rs      # Windows backend (CNG/BCrypt)
├── common/             # Always available
│   ├── outcome.rs      # Outcome enum
│   ├── criticality.rs  # Criticality + Weight
│   ├── counts.rs       # CriteriaCounts, ResultCounts
│   ├── control.rs      # ControlMapping
│   └── policy_outcome.rs
├── attestation/        # feature = "attestation"
│   ├── types.rs        # ScanAttestation, CheckAttestation
│   ├── builder.rs      # AttestationBuilder
│   ├── hashing.rs      # Re-exports from crypto
│   └── mod.rs
└── full/               # feature = "full-results"
    ├── types.rs        # ScanResult, PolicyResult, Evidence
    ├── builder.rs      # FullResultBuilder
    └── mod.rs
```
