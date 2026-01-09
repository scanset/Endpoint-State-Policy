# ESP Compliance Agent

Reference CLI application for ESP (Endpoint State Policy) compliance scanning.

## Overview

The Agent (`esp_agent`) is a working example of how to build a scanner using `contract_kit` and `execution_engine`. It demonstrates:

- Building a `CtnStrategyRegistry` with collectors and executors
- Using `execution_api` to scan ESP files
- Handling single file and batch directory scanning
- Producing results in multiple output formats (summary, full, attestation, assessor)
- Modular architecture for maintainability

Use this crate as a template when building your own scanner.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         agent                               │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐  │
│  │ main.rs  │  │  cli.rs  │  │ config.rs │  │ scanner.rs│  │
│  │ (entry)  │  │ (args)   │  │ (types)   │  │ (core)    │  │
│  └────┬─────┘  └──────────┘  └───────────┘  └─────┬─────┘  │
│       │                                           │        │
│       │        ┌──────────┐  ┌───────────┐        │        │
│       │        │discovery │  │ registry  │        │        │
│       │        │  .rs     │  │   .rs     │────────┤        │
│       │        └──────────┘  └───────────┘        │        │
│       │                                           │        │
│       │              ┌────────────┐               │        │
│       └──────────────│  output/   │◀──────────────┘        │
│                      │  mod.rs    │                        │
│                      │  full.rs   │                        │
│                      │  attest.rs │                        │
│                      │  summary.rs│                        │
│                      │  assessor.rs                        │
│                      └────────────┘                        │
└────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     contract_kit                            │
│  • collectors, executors, contracts                         │
│  • execution_api (scan_file, scan_ast)                     │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    execution_engine                         │
│  • Resolution, Execution, Strategy framework                │
└─────────────────────────────────────────────────────────────┘
```

## Module Structure

```
agent/src/
├── main.rs           Entry point and orchestration
├── cli.rs            Command-line argument parsing
├── config.rs         Configuration types (OutputFormat, ScanConfig)
├── scanner.rs        Core scanning logic
├── discovery.rs      ESP file discovery utilities
├── registry.rs       Strategy registry setup
└── output/
    ├── mod.rs        Output module coordinator
    ├── full.rs       Full results with evidence
    ├── attestation.rs CUI-free attestation format
    ├── summary.rs    Minimal summary format
    └── assessor.rs   Assessor package with reproducibility
```

## Usage

### Command Line

```bash
# Scan single file
esp_agent policy.esp

# Scan directory
esp_agent /etc/esp/policies/

# Specify output file
esp_agent --output results.json policy.esp

# Choose output format
esp_agent --format attestation -o attestation.json policy.esp

# Quiet mode (suppress progress output)
esp_agent --quiet /path/to/policies/

# Help
esp_agent --help
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--help` | `-h` | Show help message |
| `--quiet` | `-q` | Suppress progress output |
| `--output <file>` | `-o` | Write results to specified file |
| `--format <format>` | `-f` | Output format: `full`, `summary`, `attestation`, `assessor` |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All policies passed |
| 1 | One or more policies failed |
| 2 | Execution error |

## Output Formats

All formats produce a **single envelope** containing all scanned policies, whether scanning a single file or an entire directory.

### Summary (`--format summary`)

Minimal JSON output with pass/fail counts. Useful for CI/CD pipelines.

```json
{
  "agent": { "id": "esp-agent", "version": "1.0.0" },
  "summary": { "total_policies": 3, "passed": 2, "failed": 1 },
  "policies": [
    { "policy_id": "...", "passed": true, "findings_count": 0 }
  ]
}
```

### Full (`--format full`) — Default

Complete results with findings and evidence. For local storage and analysis.

```json
{
  "envelope": {
    "result_id": "esp-result-...",
    "evidence_hash": "sha256:...",
    "agent": { ... },
    "host": { ... }
  },
  "summary": { "total_policies": 3, "passed": 2, "failed": 1 },
  "policies": [
    {
      "identity": { "policy_id": "...", "control_mappings": [...] },
      "outcome": "pass",
      "findings": [],
      "evidence": {
        "data": { ... },
        "collection_metadata": [
          { "method": { "method_type": "file_stat", "target": "/etc/passwd" } }
        ]
      }
    }
  ]
}
```

### Attestation (`--format attestation`)

CUI-free format safe for network transport. Contains evidence hash but no actual evidence data.

```json
{
  "envelope": { "evidence_hash": "sha256:..." },
  "summary": { ... },
  "checks": [
    { "identity": { ... }, "outcome": "pass", "weight": 0.8 }
  ]
}
```

### Assessor (`--format assessor`)

Complete package with reproducibility information for compliance assessors.

```json
{
  "envelope": { ... },
  "summary": { ... },
  "policies": [
    {
      "identity": { ... },
      "outcome": "pass",
      "evidence": { ... },
      "reproducibility": {
        "commands": [
          {
            "object_id": "passwd_file",
            "method_type": "file_read",
            "command": "cat /etc/passwd",
            "target": "/etc/passwd"
          }
        ],
        "requirements": ["File system access to target paths"]
      }
    }
  ],
  "package_info": {
    "format_version": "1.0.0",
    "contains_cui": true,
    "distribution": "Internal use only - contains CUI"
  }
}
```

### Format Comparison

| Content | Summary | Full | Attestation | Assessor |
|---------|---------|------|-------------|----------|
| Policy outcomes | ✓ | ✓ | ✓ | ✓ |
| Control mappings | ✗ | ✓ | ✓ | ✓ |
| Findings | ✗ | ✓ | ✗ | ✓ |
| Evidence data | ✗ | ✓ | ✗ | ✓ |
| Evidence hash | ✗ | ✓ | ✓ | ✓ |
| Collection methods | ✗ | ✓ | ✗ | ✓ |
| Commands/inputs | ✗ | ✗ | ✗ | ✓ |
| Reproducibility info | ✗ | ✗ | ✗ | ✓ |
| Safe for network | ✓ | ✗ | ✓ | ✗ |

## Console Output

**Single file scan:**
```
Scanning 1 ESP file(s)...

[1/1] /path/to/policy.esp
  ✓ PASSED (3/3 criteria)

═══════════════════════════════════════
Scan Summary
═══════════════════════════════════════
  Total:     1
  Passed:    1
  Failed:    0
  Errors:    0
  Duration:  0.02s
  Format:    full
═══════════════════════════════════════

[OK] Results saved to: results.json
```

**Directory scan:**
```
Scanning 5 ESP file(s)...

[1/5] /path/to/file_permissions.esp
  ✓ PASSED (3/3 criteria)

[2/5] /path/to/service_checks.esp
  ✓ PASSED (2/2 criteria)

[3/5] /path/to/kernel_params.esp
  ✗ FAILED (1 findings)
    - f-abc123: sysctl_parameter validation failed

═══════════════════════════════════════
Scan Summary
═══════════════════════════════════════
  Total:     5
  Passed:    4
  Failed:    1
  Errors:    0
  Duration:  0.15s
  Format:    full
═══════════════════════════════════════

[OK] Results saved to: results.json
```

## Building Your Own Agent

### 1. Registry Setup (`registry.rs`)

The registry maps CTN types to collector/executor pairs:

```rust
use contract_kit::execution_api::strategies::{CtnStrategyRegistry, StrategyError};
use contract_kit::{collectors, contracts, executors, commands};

pub fn create_scanner_registry() -> Result<CtnStrategyRegistry, StrategyError> {
    let mut registry = CtnStrategyRegistry::new();

    // File-based strategies
    let metadata_contract = contracts::create_file_metadata_contract();
    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::FileMetadataExecutor::new(metadata_contract)),
    )?;

    // Command-based strategies (with platform whitelist)
    let command_executor = commands::create_rhel9_command_executor();
    let command_collector = collectors::CommandCollector::new(
        "my-command-collector",
        command_executor
    );

    let rpm_contract = contracts::create_rpm_package_contract();
    registry.register_ctn_strategy(
        Box::new(command_collector.clone()),
        Box::new(executors::RpmPackageExecutor::new(rpm_contract)),
    )?;

    Ok(registry)
}
```

### 2. Scanning (`scanner.rs`)

Use `execution_api` to execute scans:

```rust
use contract_kit::execution_api::{
    scan_file_with_logging,
    logging,
    ScanResult,
};
use std::sync::Arc;

fn scan(registry: Arc<CtnStrategyRegistry>, path: &Path) -> Result<ScanResult, Error> {
    logging::set_file_context(path.to_path_buf(), 1);
    let result = scan_file_with_logging(path, registry)?;
    logging::clear_file_context();
    Ok(result)
}
```

### 3. Output Generation (`output/`)

Build results using the unified builder:

```rust
use common::results::{ResultBuilder, PolicyInput, Evidence};

let builder = ResultBuilder::from_system("my-agent");
let policies: Vec<PolicyInput> = scan_results.iter().map(|sr| {
    PolicyInput::new(...)
        .with_findings(sr.findings.clone())
        .with_evidence(sr.evidence.clone())
}).collect();

let full_result = builder.build_full_result(policies)?;
```

### 4. Dependencies (`Cargo.toml`)

```toml
[package]
name = "my_agent"
version = "0.1.0"
edition = "2021"

[dependencies]
contract_kit = { path = "../contract_kit" }
common = { path = "../common", features = ["full-results", "attestation", "assessor-evidence"] }
serde_json = "1.0"

[[bin]]
name = "my_scanner"
path = "src/main.rs"
```

## Included CTN Types

This reference agent includes strategies for:

| CTN Type | Collector | Purpose |
|----------|-----------|---------|
| `file_metadata` | FileSystemCollector | File permissions, owner, size |
| `file_content` | FileSystemCollector | File content string operations |
| `json_record` | FileSystemCollector | Structured JSON validation |
| `computed_values` | ComputedValuesCollector | RUN operation results |
| `tcp_listener` | TcpListenerCollector | Port listening state |
| `k8s_resource` | K8sResourceCollector | Kubernetes API objects |

See `registry.rs` for the complete setup.

## Related Documentation

- [contract_kit](../contract_kit/README.md) - Collectors, executors, contracts
- [execution_engine](../execution_engine/README.md) - Core execution framework
- [common](../common/README.md) - Shared types and results module
- [Scanner Development Guide](../docs/guides/Contract_Development_Guide.md) - Adding CTN types

## License

See repository root for license information.
