# Software Bill of Materials (SBOM)

This directory contains the **CycloneDX SBOM** for the ESP workspace —
the authoritative provenance record of every direct and transitive
crate the workspace depends on.

## NIST SP 800-218 SSDF mapping

These artifacts implement the following Secure Software Development
Framework tasks:

| SSDF Task | Implementation |
|---|---|
| **PS.3.2** — Collect, safeguard, maintain, and share provenance data for software components | The CycloneDX SBOM enumerates every component with name, version, license, and source URL |
| **PW.4.1** — Acquire and maintain well-secured software components | License + source allow-list enforced by [`deny.toml`](../../deny.toml) at build time; SBOM records what was acquired |
| **PW.4.4** — Verify that components comply with security requirements | RustSec advisory denial enforced by [`make audit`](../../Makefile); CycloneDX entries cross-reference advisory IDs when present |
| **PS.2** — Software release integrity | Each release SHOULD ship its SBOM alongside the signed envelope schema; the SBOM is regenerated as part of `make security` and refreshed at every release |

## Artifacts

| File | Format | Purpose |
|---|---|---|
| `*.cdx.json` | CycloneDX 1.5 JSON | Per-crate SBOMs for each workspace member; consumed by SBOM scanners (Dependency-Track, Grype, etc.) and federal compliance auditors |

`cargo cyclonedx` produces one SBOM per workspace member; for ESP that's
typically:
- `common.cdx.json`
- `compiler.cdx.json`
- `execution_engine.cdx.json`

## Regenerating

```bash
# Generate fresh SBOMs (writes to this directory)
make sbom
```

The SBOM **must** be regenerated when:
- Any dependency is added, removed, or version-bumped (i.e., when
  `Cargo.lock` changes)
- Before tagging a release
- After running `cargo update`

`make security` (the full security gate) regenerates the SBOM as part
of its run, so CI on every PR will catch drift automatically.

## Binary-embedded SBOM (cargo-auditable)

Release binaries built with `make build-auditable` carry their full
dependency tree embedded as compressed JSON. Operators can audit a
deployed binary post-distribution:

```bash
# Inspect the dep tree embedded in the binary
cargo auditable inspect path/to/binary

# Run vulnerability scan against the embedded data
cargo audit bin path/to/binary
```

This supports SSDF **RV.1.1** (ongoing vulnerability monitoring of
deployed software) and **PW.4.4** (verification of components after
distribution).

## Format notes

ESP standardizes on **CycloneDX** (not SPDX) because:

- CycloneDX is the primary SBOM format used in vulnerability
  management workflows (NVD CVE cross-referencing, Dependency-Track,
  OWASP).
- CycloneDX 1.5 covers all NTIA minimum SBOM elements required by EO
  14028.
- A single format reduces SBOM divergence between artifacts.

If a downstream consumer requires SPDX, convert with a standard tool
such as `cyclonedx convert` or `bomctl convert` rather than maintaining
parallel artifacts in this directory.
