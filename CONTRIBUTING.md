# Contributing to Endpoint State Policy (ESP)

Thank you for your interest in contributing to **Endpoint State Policy (ESP)**.

ESP is an open, extensible framework for defining and executing endpoint compliance policies using a declarative language. Contributions are welcome from engineers who want to improve the language, execution engine, scanners, documentation, or overall developer experience.

This document outlines **how to contribute effectively** and what to expect.

---

## Project Philosophy

Before contributing, it helps to understand the guiding principles of ESP:

- **Declarative over imperative** – policies describe *what should be true*, not *how to check it*
- **Separation of concerns** – compiler, execution engine, and scanners are intentionally decoupled
- **Explicit contracts** – behavior is defined through contracts, not implicit assumptions
- **Security-first** – policies are data, not executable code
- **Extensibility over completeness** – ESP is designed to grow through new scanners and capabilities

If your contribution aligns with these principles, it likely fits well.

---

## Ways to Contribute

### 1. Bug Reports

If you find a bug:

- Open a GitHub Issue
- Include:
  - ESP version / commit
  - What you expected to happen
  - What actually happened
  - Minimal reproduction steps (policy + command if possible)

Clear, reproducible bug reports are highly valued.

---

### 2. Documentation Improvements

Documentation contributions are always welcome:

- Clarifying existing docs
- Fixing inaccuracies
- Adding examples
- Improving onboarding or "how it works" explanations

If something confused you, it will confuse others.

---

### 3. ESP Language Enhancements

Examples:

- New operators
- Improved error messages
- Validation improvements
- Grammar refinements

**Important:**  
Language changes should preserve determinism, safety, and clarity.  
Avoid features that introduce hidden execution or side effects.

---

### 4. Scanner / CTN Implementations

You can add new technical capabilities by implementing:

- A **CTN contract**
- A **collector**
- An **executor**

Examples:

- New OS features
- New configuration formats
- Cloud or platform-specific checks
- Database or API validation

See: `docs/Scanner_Development_Guide.md`

---

### 5. Performance and Architecture Improvements

Thoughtful refactors are welcome, especially:

- Execution engine performance
- Memory usage
- Batch collection improvements
- Cleaner trait boundaries

Large architectural changes should start as an issue or discussion first.

---

## Repository Structure (Quick Reference)

```
esp_compiler/       # ESP language compiler
esp_scanner_base/   # Execution engine and core framework
esp_scanner_sdk/    # Reference scanners and CLI
docs/               # Specifications and guides
```

Try to keep changes scoped to the appropriate crate.

---

## Development Setup

### Prerequisites

- Rust **1.70+**
- Cargo
- Git

### Build

```bash
cargo build --workspace
```

### Run Tests

```bash
cargo test --workspace
```

### Formatting & Linting

```bash
cargo fmt
cargo clippy --workspace --all-targets
```

Please run these before submitting a pull request.

---

## Pull Request Guidelines

When opening a PR:

- **Describe the problem** – What does this PR fix or improve?
- **Explain the approach** – Why this solution?
- **Keep changes focused** – One feature or fix per PR when possible
- **Add tests when applicable**
- **Update documentation if behavior changes**

Small, well-scoped PRs are easier to review and merge.

---

## Coding Guidelines

- Prefer explicitness over cleverness
- Avoid hidden behavior
- Favor readability over micro-optimizations
- Use existing patterns in the codebase
- Keep error messages actionable and descriptive

If you're unsure, consistency with existing code is usually the right choice.

---

## Security Considerations

ESP intentionally avoids:

- Arbitrary code execution
- Unrestricted shell access
- Runtime policy mutation

If you believe a change could impact security:

- Call it out explicitly in the PR
- Explain the threat model
- Explain why the change is safe

Security issues should not be reported via public issues.  
Please email: **curtis@scanset.io**

---

## Community & Conduct

ESP follows a simple rule:

> Be professional, constructive, and respectful.

Strong technical opinions are welcome. Personal attacks are not.
