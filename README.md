# Endpoint State Policy (ESP)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![GitHub tag](https://img.shields.io/github/v/tag/CurtisSlone/Endpoint-State-Policy?sort=semver)](https://github.com/CurtisSlone/Endpoint-State-Policy/tags)

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
│      Compiler        │      │   execution_engine   │
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

See [Trust Model](docs/Trust_Model.md) for complete details.

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

## Quick Start

### Prerequisites

- **Rust 1.85+** ([rustup.rs](https://rustup.rs/))
- **Linux/macOS**: OpenSSL development libraries (`libssl-dev` on Ubuntu, `openssl` on macOS)
- **Windows**: No additional dependencies (uses native CNG)

### Dev Container (Recommended)

This repository includes a **VS Code Dev Container** for fast setup:

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop) and [VS Code](https://code.visualstudio.com/)
2. Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
3. Clone and open in VS Code:
   ```bash
   git clone https://github.com/CurtisSlone/Endpoint-State-Policy.git
   code Endpoint-State-Policy
   ```
4. Click "Reopen in Container" when prompted

### Build and Run

```bash
# Build
cargo build --workspace

# Run scans on example policies
make run ESP=esp/
```

### Example Policies

See the [`esp/`](esp/) directory for example policies demonstrating:
- File metadata validation (`test_file_metadata.esp`)
- File content validation (`test_file_content.esp`)
- TCP listener validation (`test_tcp_listener.esp`)

---

## Architecture

### Component Responsibilities

| Component | Purpose |
|-----------|---------|
| **common** | Shared types: AST, logging, config, results, crypto |
| **compiler** | Parse and validate ESP files (7-pass pipeline) |
| **execution_engine** | Resolution and execution framework |
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
│                    execution_engine                         │
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

## CTN Types

| Type | Platform | Purpose |
|------|----------|---------|
| `file_metadata` | Linux/Windows | Permissions, owner, size, existence |
| `file_content` | Linux/Windows | Content validation (contains, pattern_match) |
| `json_record` | Linux/Windows | Structured JSON field validation |
| `tcp_listener` | Linux | TCP port listening state |
| `k8s_resource` | Kubernetes | Kubernetes API resource validation |

See [contract_kit/docs/](contract_kit/docs/) for complete CTN type reference.

---

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make build` | Build the agent |
| `make run ESP=<path>` | Run agent on file or directory |
| `make run-compiler ESP=<path>` | Run compiler only |
| `make test` | Run all tests |
| `make lint` | Run strict clippy checks |

---

## Documentation

| Document | Description |
|----------|-------------|
| [ESP Language Guide](docs/ESP_Language_Guide.md) | Complete language reference |
| [EBNF Grammar](docs/EBNF.md) | Formal grammar specification |
| [Trust Model](docs/Trust_Model.md) | Security boundaries and guarantees |
| [Scanner Development Guide](docs/Scanner_Development_Guide.md) | Building custom CTN types |
| [CTN Type Reference](contract_kit/docs/) | Collector/executor documentation |

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full | Primary development platform |
| macOS | ✅ Full | Requires OpenSSL via Homebrew |
| Windows | ✅ Full | Uses native CNG APIs |

---

## Security

- **No code execution** — Policies are data, not scripts
- **Whitelisted commands** — Only approved commands can execute
- **FIPS 140-3 cryptography** — Platform-native certified implementations

For security vulnerabilities, contact **curtis@scanset.io**.

---

## License

Apache 2.0

---

**ESP — Making endpoint compliance declarative, testable, and auditable.**
