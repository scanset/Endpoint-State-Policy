# Agent

Reference CLI application for ESP (Endpoint State Policy) compliance scanning.

## Overview

The Agent (`agent`) is a working example of how to build a scanner using `contract_kit` and `agent_core`. It demonstrates:

- Building a `CtnStrategyRegistry` with collectors and executors
- Using `agent_core_api` to scan ESP files
- Handling single file and batch directory scanning
- Producing JSON results

Use this crate as a template when building your own scanner.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         agent                               │
│  ┌─────────────┐    ┌─────────────┐                        │
│  │   main.rs   │───▶│ registry.rs │                        │
│  │   (CLI)     │    │ (setup)     │                        │
│  └─────────────┘    └──────┬──────┘                        │
└────────────────────────────┼────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     contract_kit                            │
│  • collectors, executors, contracts                         │
│  • agent_core_api (scan_file, scan_ast)                     │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      agent_core                             │
│  • Resolution, Execution, Strategy framework                │
└─────────────────────────────────────────────────────────────┘
```

## Usage

### Command Line

```bash
# Scan single file
esp_agent policy.esp

# Scan directory
esp_agent /etc/esp/policies/

# Help
esp_agent --help
```

### Output

**Single file scan:**
```
ESP Scanner starting
Phase 1: Compiling ESP file
Phase 2: Converting AST
Phase 3: Resolving references
Phase 4: Executing compliance scan

=== Scan Results ===
Status: COMPLIANT
Total Criteria: 3
Passed: 3
Failed: 0
Pass Rate: 100.0%
Findings: 0
Duration: 0.02s

[OK] Results saved to: scan_result.json
```

**Directory scan:**
```
Scanning 5 ESP files...

[1/5] Scanning: file_permissions.esp
  ✓ COMPLIANT (3 criteria)

[2/5] Scanning: service_checks.esp
  ✓ COMPLIANT (2 criteria)

[3/5] Scanning: kernel_params.esp
  ✗ NON-COMPLIANT (1 findings)

=== Batch Scan Summary ===
Files Scanned: 5
Successful: 5
Compliant: 4
Non-Compliant: 1
Duration: 0.15s

[OK] Results saved to: batch_results.json
```

## Building Your Own Agent

The key components are:

### 1. Registry Setup (`registry.rs`)

The registry maps CTN types to collector/executor pairs:

```rust
use contract_kit::agent_core_api::strategies::{CtnStrategyRegistry, StrategyError};
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

    // Add more strategies as needed...

    Ok(registry)
}
```

### 2. Scanning (`main.rs`)

Use `agent_core_api` to execute scans:

```rust
use contract_kit::agent_core_api::{
    scan_file_with_logging,
    format_report,
    logging,
    ScanResult,
};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    logging::init_global_logging()?;

    // Create registry
    let registry = Arc::new(create_scanner_registry()?);

    // Scan file
    let result = scan_file_with_logging("policy.esp", registry)?;

    // Report results
    println!("{}", format_report(&result));

    // Save JSON
    let json = serde_json::to_string_pretty(&result)?;
    std::fs::write("scan_result.json", &json)?;

    // Exit code based on compliance
    if !result.tree_passed {
        std::process::exit(1);
    }

    Ok(())
}
```

### 3. Dependencies (`Cargo.toml`)

```toml
[package]
name = "my_agent"
version = "0.1.0"
edition = "2021"

[dependencies]
contract_kit = { path = "../contract_kit" }
common = { path = "../common" }
serde_json = "1.0"

[[bin]]
name = "my_scanner"
path = "src/main.rs"
```

## Key APIs

### Registry Creation

```rust
use contract_kit::agent_core_api::strategies::CtnStrategyRegistry;

let mut registry = CtnStrategyRegistry::new();

// Register: collector + executor for each CTN type
registry.register_ctn_strategy(
    Box::new(collector),
    Box::new(executor),
)?;

// Check registry health
let stats = registry.get_statistics();
println!("CTN types: {}", stats.total_ctn_types);
```

### Scanning

```rust
use contract_kit::agent_core_api::{
    scan_file,              // Basic scan
    scan_file_with_logging, // With progress logging
    scan_ast,               // Pre-compiled AST
};

// Simple scan
let result = scan_file("policy.esp", registry.clone())?;

// With logging (requires logging::init_global_logging())
let result = scan_file_with_logging("policy.esp", registry.clone())?;

// Pre-compiled AST (for orchestrator scenarios)
let ast = compile_file("policy.esp")?;
let result = scan_ast(&ast, registry.clone())?;
```

### Result Handling

```rust
use contract_kit::agent_core_api::{
    is_compliant,
    pass_rate,
    format_summary,
    format_report,
};

// Check compliance
if result.tree_passed {
    println!("COMPLIANT");
}

// Get pass rate
let rate = pass_rate(&result); // 0.0 - 100.0

// Format output
println!("{}", format_summary(&result)); // One line
println!("{}", format_report(&result));  // Full report

// Access details
println!("Total: {}", result.criteria_counts.total);
println!("Passed: {}", result.criteria_counts.passed);
println!("Findings: {}", result.findings.len());
```

### File Context (for batch processing)

```rust
use contract_kit::agent_core_api::logging;

// Set context for error reporting
logging::set_file_context(file_path.to_path_buf(), file_id);

// Scan...
let result = scan_file_with_logging(&file_path, registry.clone())?;

// Clear context
logging::clear_file_context();

// Print cargo-style summary at end
logging::print_cargo_style_summary();
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
| `rpm_package` | CommandCollector | RPM package checks |
| `systemd_service` | CommandCollector | Service status |
| `sysctl_parameter` | CommandCollector | Kernel parameters |
| `selinux_status` | CommandCollector | SELinux enforcement |

See `registry.rs` for the complete setup.

## Related Documentation

- [contract_kit](../contract_kit/README.md) - Collectors, executors, contracts
- [agent_core](../agent_core/README.md) - Core execution framework
- [common](../common/README.md) - Shared types and logging
- [Scanner Development Guide](../contract_kit/Scanner_Development_Guide.md) - Adding CTN types

## License

See repository root for license information.
