# ESP Trust Model

ESP is designed around the principle that **inputs are untrusted**, **execution must be constrained**, and **outputs must be deliberately disclosed**.

This document describes the trust boundaries enforced at every stage of policy processing.

---

## Core Principle

> ESP does not trust inputs, does not infer truth, and does not leak evidence.
> Trust is established through validation, constrained execution, and controlled disclosure.

---

## Trust Boundaries

### 1. Policy Input

**ESP policy files are untrusted input.**

Every `.esp` file must pass through a multi-stage compiler pipeline before any execution occurs. The compiler validates:

- Syntax and grammar
- Semantic correctness
- Reference integrity
- Structural constraints
- Complexity bounds

Compile-time limits enforce hard boundaries on:

| Resource | Limit | Purpose |
|----------|-------|---------|
| File size | Configurable per profile | Prevent resource exhaustion |
| Token count | Max 1M (production) | Bound lexical complexity |
| Parse depth | Max 100 levels | Prevent stack exhaustion |
| Symbol count | Max 50K global | Bound symbol table size |
| Reference depth | Max 50 levels | Prevent infinite resolution |
| Cycle length | Max 100 nodes | Detect circular dependencies |

**Security Guarantee:**
No policy can cause uncontrolled resource consumption, infinite resolution, or unexpected execution behavior.

Trust is not granted to policy authors — it is earned through successful compilation.

---

### 2. Compiler as Gatekeeper

**The compiler is the primary trust gate.**

```
Untrusted Input (.esp)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                     COMPILER                            │
│                                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
│  │ Lexical │─▶│ Syntax  │─▶│ Symbols │─▶│  Refs   │   │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │
│                                              │         │
│  ┌─────────┐  ┌─────────┐                    │         │
│  │Semantic │◀─│Structural│◀───────────────────┘         │
│  └─────────┘  └─────────┘                              │
│        │                                                │
│        ▼                                                │
│   VALIDATION PASSED ────────────────────────────────────┼──▶ Trusted AST
│        │                                                │
│   VALIDATION FAILED ────────────────────────────────────┼──▶ Halt (no execution)
│                                                         │
└─────────────────────────────────────────────────────────┘
```

The compiler enforces:

| Validation | Stage | Failure Mode |
|------------|-------|--------------|
| Token validity | Lexical | Reject invalid characters |
| Grammar conformance | Syntax | Reject malformed structures |
| Symbol uniqueness | Symbol Discovery | Reject duplicate definitions |
| Reference validity | Reference Resolution | Reject undefined references |
| Type compatibility | Semantic Analysis | Reject type mismatches |
| Structural requirements | Structural Validation | Reject incomplete definitions |

**Security Guarantee:**
Only policies that conform to explicit, auditable constraints can reach the execution engine.

Compilation failures halt the system before execution begins.

---

### 3. Constrained Execution

**The execution engine does not execute arbitrary logic.**

`agent_core` operates under strict constraints:

| Constraint | Enforcement |
|------------|-------------|
| Deterministic evaluation | Fixed traversal order, no randomness |
| Contract-bound execution | Only registered CTN types execute |
| AST-driven logic | Execution follows validated AST nodes |
| No runtime code generation | All behavior defined at compile time |

Collectors and executors:

- Must be explicitly registered in a `CtnStrategyRegistry`
- Are bound to specific CTN types via contracts
- Operate only on declared objects and states
- Cannot introduce new execution paths at runtime

```
Validated AST
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│                   EXECUTION ENGINE                      │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐                  │
│  │   Registry   │───▶│   Contract   │                  │
│  │ (CTN types)  │    │ (allowed ops)│                  │
│  └──────────────┘    └──────────────┘                  │
│         │                   │                           │
│         ▼                   ▼                           │
│  ┌──────────────┐    ┌──────────────┐                  │
│  │  Collector   │───▶│   Executor   │                  │
│  │ (gather data)│    │  (validate)  │                  │
│  └──────────────┘    └──────────────┘                  │
│                             │                           │
│                             ▼                           │
│                      CtnResult                          │
└─────────────────────────────────────────────────────────┘
```

**Security Guarantee:**
Execution cannot exceed the capabilities explicitly exposed by the platform.

---

### 4. Contracts and Capabilities

**CTN contracts define what is allowed, not what is convenient.**

Each CTN type maps to a specific collector + executor pair with explicit capabilities:

```rust
pub struct CtnContract {
    pub ctn_type: String,
    pub object_requirements: ObjectRequirements,   // What objects must provide
    pub state_requirements: StateRequirements,     // What validations are allowed
    pub field_mappings: CtnFieldMappings,          // How fields map
    pub supported_behaviors: Vec<SupportedBehavior>, // Optional features
}
```

| Principle | Enforcement |
|-----------|-------------|
| Explicit capabilities | Contracts enumerate allowed operations |
| No privilege escalation | Collectors cannot exceed declared scope |
| Auditable surface | Contracts are inspectable data |
| Platform isolation | Each platform defines its own contracts |

Platform-specific capabilities (e.g., command execution) must be:

- **Whitelisted** - Only approved commands can execute
- **Registered** - Explicitly added to the registry
- **Reviewed** - Part of platform trust decisions

```rust
// Example: RHEL 9 command whitelist
executor.allow_commands(&[
    "rpm",        // Package queries only
    "systemctl",  // Service status only
    "sysctl",     // Kernel params read only
    "getenforce", // SELinux status only
]);
```

**Security Guarantee:**
Capabilities are explicit, enumerable, and auditable.

---

### 5. Configuration Boundaries

**ESP configuration is split into two layers with different trust levels.**

```
┌─────────────────────────────────────────────────────────┐
│              COMPILE-TIME CONSTANTS                     │
│                                                         │
│  • Security-critical limits                             │
│  • Baked into binary at build time                      │
│  • Cannot be changed at runtime                         │
│  • Defined in config/production.toml                    │
│                                                         │
│  Examples: max_file_size, max_token_count,              │
│            max_processing_time, security_min_log_level  │
└─────────────────────────────────────────────────────────┘
                         │
                         │ Enforces upper bounds
                         ▼
┌─────────────────────────────────────────────────────────┐
│              RUNTIME PREFERENCES                        │
│                                                         │
│  • User experience options                              │
│  • Configurable via environment variables               │
│  • Bounded by compile-time constraints                  │
│                                                         │
│  Examples: logging verbosity, output format,            │
│            performance metrics, analysis depth          │
└─────────────────────────────────────────────────────────┘
```

| Layer | Trust Level | Modifiable At |
|-------|-------------|---------------|
| Compile-time constants | High (security-critical) | Build time only |
| Runtime preferences | Lower (UX-focused) | Runtime, within bounds |

**Security Guarantee:**
Operational flexibility cannot bypass security boundaries.

---

### 6. Results and Disclosure

**ESP distinguishes between truth determination and information disclosure.**

Compliance results are separated into two categories with different trust implications:

```
┌─────────────────────────────────────────────────────────┐
│                    ATTESTATIONS                         │
│                   (Network-Safe)                        │
│                                                         │
│  ✓ Pass/fail outcomes                                   │
│  ✓ Aggregate statistics                                 │
│  ✓ Policy metadata                                      │
│  ✓ Content hashing for integrity                        │
│                                                         │
│  ✗ No actual system values                              │
│  ✗ No expected configurations                           │
│  ✗ No file contents                                     │
│  ✗ No command outputs                                   │
└─────────────────────────────────────────────────────────┘
         │
         │  Default output
         ▼
    Network Transport (Safe)

┌─────────────────────────────────────────────────────────┐
│                   FULL RESULTS                          │
│                   (Local Only)                          │
│                                                         │
│  ✓ Everything in attestations                           │
│  ✓ Complete collected evidence                          │
│  ✓ Actual vs expected values                            │
│  ✓ Raw system data                                      │
│                                                         │
│  ⚠ Contains sensitive information                       │
│  ⚠ Local storage only                                   │
│  ⚠ Requires explicit opt-in                             │
└─────────────────────────────────────────────────────────┘
         │
         │  Opt-in only
         ▼
    Local Storage (Protected)
```

| Result Type | Default | Contains Sensitive Data | Transport |
|-------------|---------|------------------------|-----------|
| Attestation | ✓ Yes | No | Network-safe |
| Full Results | ✗ No | Yes | Local only |

**Security Guarantee:**
Sensitive system information is never transmitted by default.

---

### 7. Logging and Auditability

**Logging is part of the security boundary, not a convenience feature.**

| Requirement | Implementation |
|-------------|----------------|
| Typed error codes | Every error has a code, severity, and category |
| Mandatory audit events | Security-relevant events cannot be disabled |
| File-scoped context | Errors are attributed to source files |
| Structured format | Machine-parseable for SIEM integration |

```rust
// Security-minimum log level enforced at compile time
security_min_log_level = 1  // Warning level minimum

// Audit buffer cannot be reduced below threshold
audit_log_retention_buffer = 50000  // Events retained
```

The logging system guarantees:

- All compilation failures are logged with source location
- All execution errors are logged with context
- Security events (resource limits, validation failures) are always captured
- Log levels below the security minimum cannot suppress audit events

**Security Guarantee:**
Security-relevant behavior is always observable and attributable.

---

### 8. Determinism and Repeatability

**ESP does not guess, infer, or approximate.**

| Principle | Implementation |
|-----------|----------------|
| Deterministic execution | Same policy + same state = same result |
| Explicit evaluation | All logic defined in policy, not inferred |
| No heuristics | Pass/fail is binary, never probabilistic |
| Repeatable evidence | Results can be reproduced and verified |

Compliance decisions are based on:

- Explicit policy definitions
- Actual collected system state
- Defined comparison operations
- Documented logical operators

Compliance decisions are never based on:

- Statistical inference
- Machine learning predictions
- Heuristic analysis
- Probabilistic reasoning

**Security Guarantee:**
Compliance results are explainable, reproducible, and defensible.

---

## Trust Model Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ESP TRUST MODEL                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
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
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

| Boundary | Threat Mitigated | Mechanism |
|----------|------------------|-----------|
| Policy Input | Malformed/malicious policies | Multi-pass compiler validation |
| Compiler Gate | Unsafe policies reaching execution | Fail-fast with compile-time limits |
| Execution | Uncontrolled system access | Contract-bound, registered strategies |
| Capabilities | Privilege escalation | Explicit whitelists, auditable contracts |
| Configuration | Runtime security bypass | Compile-time constants |
| Results | Information leakage | Attestation/full-result separation |
| Logging | Unattributable actions | Mandatory audit events |
| Determinism | Unreproducible results | Explicit evaluation, no inference |

---

## SSDF Alignment

ESP's trust model aligns with NIST Secure Software Development Framework practices:

| SSDF Practice | ESP Implementation |
|---------------|-------------------|
| **PW.7.1** (Input Validation) | Compile-time limits, type checking, reference validation |
| **PW.8.1** (DoS Protection) | Resource boundaries, timeout enforcement, bounded complexity |
| **PW.3.1** (Audit Logging) | Mandatory security logging, audit retention buffers |
| **RV.1** (Monitoring) | Memory thresholds, processing limits, security events |

---

## Implications for Users

### Policy Authors

- Policies that don't compile don't execute
- Compilation errors include source locations
- Complexity limits prevent accidental resource exhaustion
- Type checking catches errors before deployment

### Scanner Implementers

- Collectors and executors must be explicitly registered
- Contracts define and constrain capabilities
- Command execution requires whitelisting
- No implicit privilege escalation

### Security Teams

- Attestations are safe for network transport
- Full evidence requires explicit opt-in
- Audit logs capture all security-relevant events
- Compliance results are deterministic and reproducible

---

## Related Documentation

- [Compiler README](compiler/README.md) - Validation pipeline details
- [agent_core README](agent_core/README.md) - Execution constraints
- [Config README](config/README.md) - Build profile security limits
- [Results README](common/results/README.md) - Attestation vs full results
