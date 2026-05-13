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
│      Compiler        │      │   Execution Engine   │
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

---

## Why ESP?

Traditional compliance automation (SCAP/XCCDF) suffers from:

- **Verbose, fragile XML** — Policies are difficult to read, write, and maintain
- **Tight coupling** — Policy definition is intertwined with scanner implementation
- **Poor extensibility** — Adding new check types requires modifying the standard
- **High cost** — Authoring and maintaining policies requires specialized expertise

ESP addresses these problems by:

- **Separating policy from execution** — Policies describe *what* should be true, scanners decide *how* to check it
- **Using a typed, validated DSL** — Catch errors at compile time, not during scans
- **Enforcing contracts** — CTN types define clear interfaces between policies and implementations
- **Human and machine readable** — Policies are inspectable by auditors and parseable by tools

ESP focuses on **technical controls** — controls validated by inspecting endpoint state.

---

## Policy Categories

ESP policies fall into one of two categories based on what an OBJECT
represents:

| Category | What the OBJECT is | Example |
|---|---|---|
| **asset-internal** | An item being scanned **on** a resource. The policy runs against the resource itself. | RHEL9 host checking an installed RPM package; a Windows server inspecting a registry key |
| **asset-list** | A cloud resource that is itself the thing being scanned. The bound-asset list is supplied as OBJECTs to the policy. | Azure subscription enumerating VMs; AWS account listing S3 buckets |

The replay-hash scheme, dedup semantics, and host-binding rules all
depend on this categorization:

- **asset-internal** OBJECTs share a template across many hosts and
  dedup naturally — identical intent + outcome produces one hash.
- **asset-list** OBJECTs carry asset-specific fields
  (e.g. `resource_id`) and produce distinct hashes per asset.

See the `replay_hash_version = 2` scheme in
[docs/10_ESP_Trust_Model_v1_2_0.md](docs/10_ESP_Trust_Model_v1_2_0.md)
for how per-(criterion, OBJECT) hashing exploits this distinction.

---

## Core Philosophy

### Policy as Data, Not Code

ESP policies describe *what* should be true, not *how* to check it. This separation enables:

- **Policy authors** to focus on security intent without implementation details
- **Scanner implementers** to optimize execution for their platform
- **Auditors** to inspect policies without reading code
- **Organizations** to share policies across different scanner implementations

### Fail-Fast Compiler

The compiler enforces strict validation at compile time through a 7-pass pipeline:

1. File processing with UTF-8 and size validation
2. Lexical analysis with token limits
3. Syntax validation and AST construction
4. Symbol discovery and table building
5. Reference resolution and cycle detection
6. Semantic analysis and type checking
7. Structural validation and limit enforcement

Errors are caught before execution, not during a scan. Security limits are baked into the binary at compile time (SSDF compliant).

### Constrained Execution

The runtime engine operates within strict boundaries:

- **Whitelisted command execution** — Only approved commands can run
- **Deterministic evaluation order** — Same policy produces same results
- **Repeatable evidence generation** — Collection methods are documented
- **No code injection** — Policies cannot execute arbitrary code

---

## Trust Model

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
│  │  • Signed AssessorPackage envelope   │                           │
│  │  • Observations cited by uuid        │                           │
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

📄 See [ESP Trust Model](docs/10_ESP_Trust_Model_v1_2_0.md) for complete details.

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

### Build

```bash
# Build all crates
cargo build --workspace

# Run tests
make test

# Run linting
make lint
```

### Validate ESP Files (Compiler Only)

```bash
# Compile a single file
cargo run -p compiler -- policy.esp

# Compile a directory
cargo run -p compiler -- policies/
```

---

## Architecture

### Crate Overview

| Crate | Purpose |
|-------|---------|
| **common** | Shared types: AST, logging, configuration, results, FIPS 140-3 cryptography |
| **compiler** | Parse and validate ESP files through 7-pass pipeline |
| **execution_engine** | Resolution engine, execution framework, strategy system |

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
│                    Execution Engine                         │
│  Conversion → Resolution → Execution → Results              │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
                    Compliance Results
```

### Compiler Pipeline

The compiler transforms ESP source through seven distinct passes:

| Pass | Module | Purpose |
|------|--------|---------|
| 1 | `file_processor` | UTF-8 validation, size limits, encoding |
| 2 | `lexical` | Token stream generation |
| 3 | `syntax` | Grammar validation, AST construction |
| 4 | `symbols` | Symbol table building |
| 5 | `reference_resolution` | Cross-reference validation, cycle detection |
| 6 | `semantic_analysis` | Type checking, runtime operation validation |
| 7 | `validation` | Structural requirements, implementation limits |

### Execution Engine

The execution engine consumes validated AST and produces compliance results:

| Phase | Purpose |
|-------|---------|
| Conversion | Transform AST to execution types |
| Resolution | Variable substitution, SET expansion, dependency ordering |
| Execution | Data collection, state validation, evidence generation |

---

## Control Framework Coverage

ESP can express technical controls from any framework with observable requirements:

| Framework | Example Use |
|-----------|-------------|
| **NIST SP 800-53 / 800-171** | Configuration management controls |
| **MITRE ATT&CK** | Detection-oriented validation |
| **DISA STIGs** | Security configuration baselines |
| **CIS Benchmarks** | Hardening verification |
| **Custom baselines** | Organization-specific requirements |

ESP answers: *"Is this endpoint in the required technical state?"*

---

## ESP Agent SDK

For building scanners that execute ESP policies, see the **ESP Agent SDK**:

🔗 **[github.com/scanset/ESP-Agent-SDK](https://github.com/scanset/ESP-Agent-SDK)**

The SDK provides:
- Reference CTN type implementations (file_metadata, file_content, tcp_listener, etc.)
- Collector and executor patterns
- Example agent application
- Contract development guide

---

## Design Partners Wanted

**ScanSet** is building the Compliance Evidence Layer — infrastructure that produces cryptographically verifiable proof of compliance, continuously. We're seeking **design partners** to shape the orchestration and integration layers.

### What We're Building

ESP is the policy engine. ScanSet is the infrastructure that operationalizes it:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ScanSet Evidence Layer                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐   │
│  │   Policy    │     │  Orchestration  │     │     Trust       │   │
│  │  (ESP Core) │────▶│     Layer       │────▶│ Infrastructure  │   │
│  │             │     │                 │     │                 │   │
│  │ • Compiler  │     │ • Agent mgmt    │     │ • Signing       │   │
│  │ • Engine    │     │ • Policy routing│     │ • Attestations  │   │
│  │ • Contracts │     │ • Evidence flow │     │ • Verification  │   │
│  └─────────────┘     └─────────────────┘     └─────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│                    ┌─────────────────┐                             │
│                    │   Connectors    │                             │
│                    │                 │                             │
│                    │ • SIEM / SOAR   │                             │
│                    │ • GRC Platforms │                             │
│                    │ • Threat Models │                             │
│                    │ • AI Agents     │                             │
│                    └─────────────────┘                             │
└─────────────────────────────────────────────────────────────────────┘
```

### What Design Partners Get

- **Early access** to orchestration and trust infrastructure
- **Custom connector development** for your SIEM/SOAR (Splunk, Sentinel, ServiceNow, etc.)
- **Direct input** on API design and integration patterns
- **Priority support** during implementation

### What We're Looking For

| Profile | Why You'd Be a Great Fit |
|---------|--------------------------|
| **Federal Contractors** | FedRAMP/FISMA continuous monitoring, 3PAO evidence packages |
| **Regulated SaaS** | SOC 2 evidence automation, customer audit responses |
| **Cloud-Native Teams** | GitOps integration, CI/CD compliance gates |
| **MSPs / MSSPs** | Multi-tenant evidence collection, client reporting |

### The Vision

Compliance outcomes should be **provable, not explained**:

- **Attestations flow to your SIEM** — failed controls become security events
- **SOAR playbooks trigger automatically** — remediation closes the loop with signed proof
- **Threat models update in real-time** — attack paths light up when controls fail
- **3PAO audits become queries** — not quarterly fire drills

### Get Involved

📧 **Contact**: curtis@scanset.io

🌐 **Learn more**: [scanset.io](https://scanset.io)

We're not looking for customers yet — we're looking for partners who want to shape how compliance evidence infrastructure gets built.

---

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make build` | Build all crates |
| `make test` | Run all tests |
| `make test-unit` | Run unit tests only |
| `make lint` | Run strict clippy checks |
| `make format` | Format code |
| `make docs` | Generate documentation |
| `make pre-commit` | Run all checks before commit |

---

## Documentation

### ESP Language Specification

| Document | Description |
|----------|-------------|
| [ESP Overview](docs/01_ESP_Overview_v1_0_0.md) | Language introduction and concepts |
| [Lexical Rules](docs/02_ESP_Lexical_Rules_v1_0_0.md) | Token definitions and lexical structure |
| [Grammar EBNF](docs/03_ESP_Grammar_EBNF_v2_1_0.md) | Formal grammar specification |
| [Type System](docs/04_ESP_Type_System_v1_0_0.md) | Data types and type compatibility |
| [Symbol Resolution](docs/05_ESP_Symbol_Resolution_v1_0_0.md) | Symbol tables and reference resolution |
| [Evaluation Semantics](docs/06_ESP_Evaluation_Semantics_v1_0_0.md) | Runtime evaluation rules |
| [Meta Requirements](docs/07_ESP_Meta_Requirements_v1_0_0.md) | Structural requirements |
| [Error Model](docs/08_ESP_Error_Model_v1_0_0.md) | Error codes and handling |
| [Canonical Schema](docs/09_ESP_Canonical_Schema_v1_0_0.md) | Output format specification |
| [Trust Model](docs/10_ESP_Trust_Model_v1_2_0.md) | Security boundaries and trust |
| [Configuration](docs/11_ESP_Configuration_v1_0_0.md) | Build and runtime configuration |
| [Logging](docs/12_ESP_Logging_v1_0_0.md) | Logging system specification |

### Crate Documentation

| Crate | README |
|-------|--------|
| common | [common/README.md](common/README.md) |
| compiler | [compiler/README.md](compiler/README.md) |
| execution_engine | [execution_engine/README.md](execution_engine/README.md) |

---

## Platform Support

| Platform | Cryptography | Status |
|----------|--------------|--------|
| Linux | OpenSSL FIPS | ✅ Full support |
| macOS | OpenSSL | ✅ Full support (requires Homebrew OpenSSL) |
| Windows | CNG (BCrypt) | ✅ Full support (native, no dependencies) |

Cross-compilation from Linux to Windows is supported without bundling OpenSSL.

---

## Security

### Design Principles

- **No code execution** — Policies are data, not scripts
- **Whitelisted commands** — Only approved commands can execute
- **FIPS 140-3 cryptography** — Platform-native certified implementations
- **Compile-time limits** — Security boundaries baked into binary
- **Mandatory audit logging** — Security events always logged

### Reporting Vulnerabilities

For security vulnerabilities, contact **curtis@scanset.io**.

---

## License

Apache 2.0 — See [LICENSE](LICENSE) for details.

---

**ESP — Making endpoint compliance declarative, testable, and auditable.**
