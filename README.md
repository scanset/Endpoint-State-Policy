
# Endpoint State Policy (ESP)

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![GitHub release](https://img.shields.io/github/v/release/CurtisSlone/Endpoint-State-Policy)](https://github.com/CurtisSlone/Endpoint-State-Policy/releases)

**Policy as Data: A declarative language for endpoint compliance validation**

---

## Overview

Endpoint State Policy (ESP) is a platform-agnostic policy language that separates **security intent** from **execution logic**. Policies are written as structured data, not imperative scripts, making them inspectable, testable, and portable across different scanner implementations.

```
┌─────────────────────────────────────────────────────────────┐
│                    ESP Policy Files                         │
│              (Security Intent as Data)                      │
└────────────────────────────┬────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
┌──────────────────────┐      ┌──────────────────────┐
│      Compiler        │      │     agent_core       │
│                      │      │                      │
│ • Syntax validation  │      │ • Resolution engine  │
│ • Type checking      │      │ • Execution engine   │
│ • Reference resolution│     │ • Strategy framework │
│ • Fail-fast design   │      │ • Evidence generation│
└──────────────────────┘      └──────────────────────┘
              │                              │
              └──────────────┬───────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                   Compliance Results                        │
│              (Repeatable, Auditable Evidence)               │
└─────────────────────────────────────────────────────────────┘
```

### Core Philosophy

**Policy as Data, Not Code**

ESP policies describe *what* should be true, not *how* to check it. This separation enables:
- Policy authors to focus on security intent
- Scanner implementers to optimize execution
- Auditors to inspect policies without reading code
- Organizations to share policies across different platforms

**Fail-Fast Compiler**

The compiler enforces strict validation at compile time:
- Syntax and grammar validation
- Type compatibility checking
- Reference resolution and cycle detection
- Security limits baked into the binary (SSDF compliant)

Errors are caught before execution, not during a scan.

**Constrained Execution**

The runtime engine operates within strict boundaries:
- Whitelisted command execution only
- Deterministic evaluation order
- Repeatable evidence generation
- No code injection from policy files

### Trust Model

ESP enforces trust boundaries at every stage:

```
┌─────────────────────────────────────────────────────────────────────┐
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
│  │         Controlled Disclosure        │                           │
│  │  • Attestations (network-safe)       │                           │
│  │  • Full results (local-only)         │                           │
│  │  • Audit logging (mandatory)         │                           │
│  └─────────────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────────────┘
```

| Boundary | Threat Mitigated |
|----------|------------------|
| Policy Input | Malformed/malicious policies |
| Compiler Gate | Unsafe policies reaching execution |
| Execution | Uncontrolled system access |
| Capabilities | Privilege escalation |
| Results | Information leakage |

See [ESP Trust Model](docs/Trust_Model.md) for complete details.

---

## What Problem ESP Solves

Traditional compliance automation (SCAP/XCCDF) suffers from:
- Verbose, fragile XML
- Tight coupling between policy and execution
- Poor extensibility
- High authoring and maintenance cost

ESP addresses this by:
- Separating policy definition from scanner implementation
- Using a typed, validated DSL
- Enforcing contracts between collectors and executors
- Making policies readable by humans and machines

ESP focuses on **technical controls** — controls validated by inspecting endpoint state.

---

## Example Policy

```esp
# MITRE ATT&CK T1133 - External Remote Services
# Ensure SSH is configured securely

META
    esp_scan_id `mitre-t1133-ssh-hardening`
    control_framework `MITRE-ATTACK`
    control `T1133`
    control_mapping `MITRE-ATTACK:T1133`
    title `External Remote Services - SSH Hardening`
    platform `linux`
    criticality `high`
META_END

DEF
    OBJECT sshd_config_file
        path `/etc/ssh/sshd_config`
    OBJECT_END

    STATE no_root_login
        content string contains `PermitRootLogin no`
    STATE_END

    STATE no_password_auth
        content string contains `PasswordAuthentication no`
    STATE_END

    STATE no_empty_passwords
        content string contains `PermitEmptyPasswords no`
    STATE_END

    CRI AND
        CTN file_content
            TEST all all AND
            STATE_REF no_root_login
            STATE_REF no_password_auth
            STATE_REF no_empty_passwords
            OBJECT_REF sshd_config_file
        CTN_END
    CRI_END
DEF_END
```

This policy:
- Defines what file to examine (`OBJECT`)
- Specifies expected content (`STATE`)
- Combines checks with AND logic (`CRI`)
- Maps to MITRE ATT&CK T1133 (`META`)

The scanner handles collection and validation. The policy expresses intent.

---

## Architecture

### Workspace Structure

```
Endpoint-State-Policy/
├── common/                 # Shared types and utilities
│   ├── ast/                # AST node definitions
│   ├── config/             # Runtime configuration
│   ├── logging/            # Structured logging system
│   ├── results/            # Attestation and result types
│   └── utils/              # Span tracking, source maps
│
├── compiler/               # ESP language compiler
│   ├── file_processor/     # File I/O and validation
│   ├── lexical/            # Tokenization
│   ├── syntax/             # AST construction
│   ├── symbols/            # Symbol discovery
│   ├── reference_resolution/
│   ├── semantic_analysis/
│   └── validation/         # Structural validation
│
├── agent_core/             # Execution framework
│   ├── conversion/         # AST → execution types
│   ├── resolution/         # Variable/SET resolution
│   ├── execution/          # Validation engine
│   ├── strategies/         # CTN contracts and traits
│   └── types/              # Runtime type system
│
├── contract_kit/           # Reference implementations
│   ├── collectors/         # Data collection
│   ├── executors/          # Validation logic
│   ├── contracts/          # CTN specifications
│   └── agent_core_api/     # High-level scan API
│
├── agent/                  # Reference CLI scanner
│
├── config/                 # Build profiles (TOML)
│   ├── development.toml
│   ├── testing.toml
│   └── production.toml
│
└── docs/                   # Documentation
    ├── EBNF.md             # Language grammar
    ├── ESP_Language_Guide.pdf
    ├── ESP_Trust_Model.md  # Security trust boundaries
    └── Scanner_Development_Guide.md
```

### Component Responsibilities

| Component | Purpose |
|-----------|---------|
| **common** | Shared types: AST, logging, config, results |
| **compiler** | Parse and validate ESP files (7-pass pipeline) |
| **agent_core** | Resolution and execution framework |
| **contract_kit** | Reference collectors, executors, contracts |
| **agent** | Reference CLI application |

### Data Flow

```
policy.esp
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                        Compiler                             │
│  File → Tokens → AST → Symbols → References → Semantics    │
└────────────────────────────┬────────────────────────────────┘
                             │ Validated AST
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      agent_core                             │
│  Conversion → Resolution → Execution → Results              │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
                      ScanResult (JSON)
```

---

## Control Framework Coverage

ESP can express technical controls from any framework with observable requirements:

- **NIST SP 800-53** / **800-171**
- **MITRE ATT&CK** (detection-oriented)
- **DISA STIGs**
- **CIS Benchmarks**
- **Custom organizational baselines**

ESP answers: *"Is this endpoint in the required technical state?"*

---

## Quick Start

### Prerequisites

- **Rust 1.70+** ([rustup.rs](https://rustup.rs/))

### Build

```bash
git clone https://github.com/CurtisSlone/Endpoint-State-Policy.git
cd Endpoint-State-Policy

# Build all crates
cargo build --workspace --release
```

### Run a Scan

```bash
# Using the reference agent
cargo run -p agent -- policy.esp

# Or after installing
./target/release/esp_agent policy.esp
```

### Run Tests

```bash
cargo test --workspace
```

---

### Makefile Commands

The project includes a Makefile for common development tasks:

| Command | Description |
|---------|-------------|
| `make build` | Build all crates |
| `make dev` | Build in development mode |
| `make release` | Build optimized release |
| `make test` | Run all tests |
| `make test-unit` | Run unit tests only |
| `make lint` | Run strict clippy checks |
| `make format` | Format code with rustfmt |
| `make pre-commit` | Run pre-commit checks (format, lint, test) |
| `make ci` | Run all CI checks |
| `make clean` | Clean build artifacts |
| `make docs` | Generate and open documentation |

**Pre-commit hook setup:**
```bash
echo '#!/bin/sh
make pre-commit' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

## Usage Paths

### 1. Use the Reference Scanner

The `agent` crate provides a working CLI scanner:

```bash
esp_agent policy.esp              # Single file
esp_agent /path/to/policies/      # Directory batch
```

### 2. Build Your Own Scanner

Use `contract_kit` to create a custom scanner:

```rust
use contract_kit::agent_core_api::{scan_file, CtnStrategyRegistry};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build registry with your strategies
    let registry = Arc::new(create_my_registry()?);

    // Scan
    let result = scan_file("policy.esp", registry)?;

    if result.tree_passed {
        println!("Compliant");
    }

    Ok(())
}
```

See [contract_kit](contract_kit/README.md) and [Scanner Development Guide](docs/Scanner_Development_Guide.md).

### 3. Embed the Engine

Use `compiler` and `agent_core` directly for full control:

```rust
use compiler::pipeline;
use agent_core::conversion::convert_ast_to_scanner_types;
use agent_core::resolution::ResolutionEngine;
use agent_core::execution::ExecutionEngine;

// Compile
let ast = pipeline::process_file("policy.esp")?.ast;

// Convert and resolve
let types = convert_ast_to_scanner_types(&ast)?;
let context = resolve(types)?;

// Execute
let result = ExecutionEngine::new(context, registry).execute()?;
```

---

## Documentation

| Document | Audience | Description |
|----------|----------|-------------|
| [ESP Language Guide](docs/ESP_Language_Guide.md) | Policy Authors | Complete language reference |
| [ESP Trust Model](docs/Trust_Model.md) | Security Teams | Trust boundaries and guarantees |
| [EBNF Grammar](docs/EBNF.md) | Language Implementers | Formal grammar specification |
| [Scanner Development Guide](docs/Scanner_Development_Guide.md) | Scanner Developers | Building custom CTN types |
| [common README](common/README.md) | Developers | Shared types and utilities |
| [compiler README](compiler/README.md) | Developers | Compiler architecture |
| [agent_core README](agent_core/README.md) | Developers | Execution framework |
| [contract_kit README](contract_kit/README.md) | Developers | Reference implementations |
| [agent README](agent/README.md) | Developers | CLI reference |

---

## Key Concepts

### Policy Elements

| Element | Purpose | Example |
|---------|---------|---------|
| `META` | Policy metadata (ID, framework, criticality) | `esp_scan_id`, `control_mapping` |
| `VAR` | Reusable values | `VAR config_path string \`/etc/app.conf\`` |
| `OBJECT` | What to collect | File paths, package names, service names |
| `STATE` | What to validate | Expected permissions, content, status |
| `CRI` | Logical grouping | `CRI AND` / `CRI OR` |
| `CTN` | Individual check | Combines OBJECT + STATE with TEST spec |
| `SET` | Object collections | Union, intersection, complement |
| `RUN` | Computations | String ops, arithmetic |

### TEST Specification

```esp
TEST <existence_check> <item_check> [<state_operator>]
```

- **Existence**: `all`, `any`, `none`, `at_least_one`, `only_one`
- **Item**: `all`, `any`, `none`, `at_least_one`, `only_one`
- **State Operator**: `AND`, `OR`, `ONE`

### CTN Types (Reference Implementations)

| Type | Collector | Purpose |
|------|-----------|---------|
| `file_metadata` | FileSystem | Permissions, owner, size |
| `file_content` | FileSystem | Content validation |
| `json_record` | FileSystem | Structured JSON |
| `rpm_package` | Command | Package checks |
| `systemd_service` | Command | Service status |
| `sysctl_parameter` | Command | Kernel params |
| `selinux_status` | Command | SELinux mode |

---

## Security

ESP is designed with security as a core principle:

- **No code execution** - Policies are data, not scripts
- **Whitelisted commands** - Only approved commands can execute
- **Type-safe compilation** - Errors caught at compile time
- **Compile-time limits** - Resource boundaries baked into binary
- **Constrained execution** - Deterministic, repeatable behavior

### Reporting Security Issues

For security vulnerabilities, contact **curtis@scanset.io** directly rather than opening a public issue.

---

## Roadmap

### Current (v0.1)
- ✅ Core ESP language and compiler
- ✅ Execution engine with full feature support
- ✅ Reference scanner implementations
- ✅ SET, FILTER, RUN operations
- ✅ Pattern matching and behaviors

### Planned
- [ ] Additional platform collectors
- [ ] Enhanced error messages
- [ ] Policy composition and inheritance
- [ ] Remote endpoint scanning

---

## Resources

- **Repository**: https://github.com/CurtisSlone/Endpoint-State-Policy
- **Issues**: https://github.com/CurtisSlone/Endpoint-State-Policy/issues
- **Contact**: curtis@scanset.io

---

**ESP — Making endpoint compliance declarative, testable, and auditable.**
