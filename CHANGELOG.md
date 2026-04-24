# Changelog with Security Notes

## [2.0.0] — 2026-04-20

**Schema v2.0.0 — Polymorphic hosts, first-class observations, transport-attested identity.**

This is a major release. The ESP DSL (grammar, types, evaluation) is unchanged; the break is confined to the **output envelope** (`common::results`) and the **channel trait** (`execution_engine::strategies::channel`). v1.x envelopes remain readable by their original consumers — no migration tool is provided; archived v1.x envelopes stay as-is, new scans emit v2.0.0.

### Added

- **Canonical schema spec `docs/09_ESP_Canonical_Schema_v2_0_0.md`** — 12 sections defining the polymorphic host model, `observations[]` array, replay-hash invariants, non-normative `host_type` registry (`linux.vm`, `azure.vm`, `aws.account`, `m365.tenant`, ...), OSCAL mapping table, and conformance rules. The v1.2 canonical schema (`09_ESP_Canonical_Schema_v1_1_0.md`) is marked SUPERSEDED for new envelopes but kept normative for archived ones.
- **`common::results::observation`** — new module with `Observation`, `HostRef`, `ObservationRef`, `ObservationMethod`. Self-contained RFC 4122 v4 uuid generator (time+counter, no external crate). `ObservationRef` uses `#[serde(transparent)]` so references serialize as bare strings, not `{uuid: "..."}` objects.
- **`ResultEnvelope.observations: Vec<Observation>`** — top-level evidence array. `PolicyResult.observation_refs: Vec<ObservationRef>` cites observations by uuid. A single file read cited by ten policies now appears once in `observations[]`, ten times in `observation_refs[]`.
- **`Channel::identify_host() -> Result<HostInfo, ChannelError>`** — new trait method with a default impl (`<os_family>.vm` + `<kind>-unknown` host_id). `LocalChannel` overrides it to read `/etc/machine-id` with a djb2-hostname fallback. Public helper `os_family_label(OsFamily) -> &'static str`.
- **`pub use common::results::{HostInfo, HostRef}`** in `execution_engine::strategies::channel` — out-of-tree channel crates (channels/, future aws-ssm, winrm) no longer need a direct `common` dependency.
- **Wire-shape test vectors** — `common/tests/vectors_v2/` contains 7 hand-written golden JSON files (`host_azure_vm.json`, `host_linux_vm.json`, `host_ssh_remote.json`, `host_aws_account.json`, `observation_file_read.json`, `observation_exec.json`, `observation_ref.json`) plus a README. Integration test `common/tests/vectors_v2.rs` (11 tests) round-trips each through its typed struct and asserts `serde_json::Value` equality, pinning: polymorphic `host_type` + full `attrs`, non-VM shape field omission (not `null`), `ObservationRef` bare-string serialization, embedded `HostRef` two-field invariant, `Observation.body` elision in attestation shape.
- **v2.0.0 cross-reference banners** inserted in docs 01_Overview, 04_Type_System, 06_Evaluation_Semantics, 10_Trust_Model, 12_Logging, and 09_Canonical_Schema_v1_1_0. Each banner is scoped to what in that document does or does not change under v2.0.0; the v1.x normative body is preserved intact.

### Changed

- **`HostInfo` is polymorphic.** Replaced the v1.x fixed shape (`id`, `hostname`, `os`, `arch`) with `host_type: String` (dotted `<provider>.<kind>`), `host_id: String`, optional `hostname` / `os` / `arch` / `fqdn` (omitted — not `null` — for non-VM hosts), and `attrs: BTreeMap<String, serde_json::Value>` for host-type-specific structured attributes.
- **Legacy `HostInfo::new(id, hostname, os, arch)` preserved** — it now infers `host_type` from `os` (`linux` → `linux.vm`, etc.), keeping ~20 existing callsites source-compatible. New canonical constructor is `HostInfo::for_host_type(host_type, host_id)` with builder-style `.with_hostname()` / `.with_os()` / `.with_arch()` / `.with_attr()` / `.with_fqdn()`. `HostInfo::id()` back-compat accessor returns `&host_id` for call-sites reading the old field name.
- **`SCHEMA_VERSION` bumped** `"1.2.0"` → `"2.0.0"` in `common::results::envelope`. Serialized envelopes now carry `"schema_version": "2.0.0"` on the wire.
- **`PolicyResult.evidence` retained with `#[serde(default, skip_serializing_if)]`** during the transition window. `observation_refs` is the v2.0.0 canonical path; `evidence` stays readable for v1.x consumers that haven't migrated.

### Removed

v2.0.0 collapses the old three-format output matrix to a single shape. The assessor envelope was already a superset of attestation + full-results; maintaining three parallel formats behind Cargo features cost more than it delivered. The `AssessorPackage` is now the **only** output type and is always compiled in.

- **`AttestationResult`, `CheckAttestation`, `AttestationBuilder`, `CheckInput`** — removed from `common::results`. Use `AssessorPackage` + `AssessorInput`; the attestation shape is a subset (drop `findings` / `observations[]` on the consumer side if CUI-free transport is required).
- **`FullResult`, `FullResultBuilder`, `PolicyInput`** — removed. `PolicyResult` is retained and is the per-policy entry inside `AssessorPackage`.
- **`ResultBuilder::build_attestation`, `build_full_result`, `build_both`, `build_all`** — removed. Only `ResultBuilder::build_assessor_package(policies, replay_hash, identity_status)` remains.
- **Cargo features `attestation`, `full-results`, `assessor-evidence`** — removed from `common/Cargo.toml`. The feature set is now `default = []`.
- **Agent output modules `agent/src/output/attestation.rs`, `full.rs`, `summary.rs`** — deleted. `output/assessor.rs` and `output/console.rs` remain.
- **`OutputFormat` enum** (`agent/src/config.rs`) and the **`output_format` field on `ScanConfig`** — removed.
- **CLI `--format` / `-f` flag** — removed from `agent/src/cli.rs` and its help text. There is nothing to select; the agent always emits an `AssessorPackage`.

### Behavior Change

- **Replay-hash invariants are now explicit.** The hash excludes the `host` block, `observations[]`, and all timestamps — so it remains stable across scans of the same posture regardless of scan time, scanner identity, or which channel collected evidence. Schema §6 defines the canonicalization in full.
- **Agent emits only `AssessorPackage`.** A scan invoked with no flags produces the same envelope shape as one previously invoked with `--format assessor`. Scripts that relied on `--format attestation` or `--format full` to strip fields should instead post-process the assessor JSON (drop `observations[]` for attestation-equivalent output; drop `observations[].body` + `findings` for summary-equivalent output).

### Files Modified

| File | Crate | Changes |
|------|-------|---------|
| `common/src/results/observation.rs` | common | New file. `Observation`, `HostRef`, `ObservationRef` (`#[serde(transparent)]`), `ObservationMethod` with `file_read` / `exec` / `http` / `sdk_call` convenience constructors. Self-contained uuid v4 generator. 10 unit tests. |
| `common/src/results/envelope.rs` | common | `SCHEMA_VERSION` → `"2.0.0"`. `HostInfo` rewritten polymorphic. Legacy `HostInfo::new` preserved with `host_type` inferred from `os`. New `::for_host_type()` canonical v2 constructor. `HostInfo::id()` back-compat accessor. `ResultEnvelope.observations: Vec<Observation>` added with `#[serde(default, skip_serializing_if)]`. Helpers `record_observation()` / `with_observations()`. |
| `common/src/results/full.rs` | common | **Deleted** (v2.0.0 assessor-only refactor). `PolicyResult` itself lives in `assessor.rs` and is the per-policy entry in `AssessorPackage`. |
| `common/src/results/attestation.rs` | common | **Deleted** (v2.0.0 assessor-only refactor). |
| `common/src/results/builder.rs` | common | Stripped to `PolicyMetadata` + `AssessorInput` + `ResultBuilder::build_assessor_package`. `CheckInput`, `PolicyInput`, and the `build_attestation` / `build_full_result` / `build_both` / `build_all` methods removed. |
| `common/src/results/mod.rs` | common | `pub mod observation;` declaration. Unconditional re-exports (no more `#[cfg(feature = ...)]`). `attestation` / `full` module declarations removed. `pub type AssessorResult = AssessorPackage` alias added. |
| `common/Cargo.toml` | common | Removed `attestation`, `full-results`, `assessor-evidence` features. `[features]` is now `default = []`. |
| `agent/src/output/mod.rs` | agent | `build_output` simplified — no `OutputFormat` match, always produces assessor JSON. `attestation` / `full` / `summary` module declarations removed. |
| `agent/src/output/attestation.rs`, `full.rs`, `summary.rs` | agent | **Deleted.** |
| `agent/src/config.rs` | agent | `OutputFormat` enum and `ScanConfig.output_format` field removed. |
| `agent/src/cli.rs` | agent | `--format` / `-f` parsing removed. Help text updated — no OUTPUT FORMATS section. |
| `agent/src/scanner.rs` | agent | `output::build_output(scan_results, host, config.output_format)` simplified to `output::build_output(scan_results, host)`. Output summary line shows literal `(assessor)`. |
| `common/tests/vectors_v2/*.json` | common | New. 7 hand-written golden JSON files pinning the v2.0.0 wire shape. |
| `common/tests/vectors_v2/README.md` | common | New. Invariants pinned + editing rules (no regeneration from live scans; attrs keys stay alphabetized). |
| `common/tests/vectors_v2.rs` | common | New integration test. 11 tests: 6 round-trips + 5 shape invariants. |
| `execution_engine/src/strategies/channel.rs` | execution_engine | `pub use common::results::{HostInfo, HostRef}` re-export. `Channel::identify_host()` trait method with default impl. `LocalChannel::identify_host` reads `/etc/machine-id` (or `/var/lib/dbus/machine-id`) with djb2-hostname fallback; populates hostname / os / arch / kernel in attrs. `os_family_label()` made `pub`. New tests `local_channel_identify_host_produces_vm_shape`, `local_channel_host_id_stable_across_calls`. |
| `docs/09_ESP_Canonical_Schema_v2_0_0.md` | docs | New. 12-section normative spec for v2.0.0 envelopes. |
| `docs/09_ESP_Canonical_Schema_v1_1_0.md` | docs | Status annotation: SUPERSEDED for new envelopes; enumerates v1.2 → v2.0.0 differences. v1.x body preserved intact. |
| `docs/01_ESP_Overview_v1_0_0.md` | docs | v2.0.0 cross-reference banner after frontmatter. |
| `docs/04_ESP_Type_System_v1_0_0.md` | docs | v2.0.0 cross-reference banner — clarifies `Value` is envelope-layer only, DSL types unchanged. |
| `docs/06_ESP_Evaluation_Semantics_v1_0_0.md` | docs | v2.0.0 cross-reference banner — outcome semantics unchanged; evidence wire shape moves to `observations[]` + `observation_refs[]`. |
| `docs/10_ESP_Trust_Model_v1_0_0.md` | docs | v2.0.0 cross-reference banner — two refinements: transport-attested host binding and explicit replay-hash invariants. |
| `docs/12_ESP_Logging_v1_0_0.md` | docs | v2.0.0 cross-reference banner — additive `observation_uuid` field; channel-level events SHOULD include `channel_kind` / `target_resource_id`. |

### Backward Compatibility

- **Source-level:** existing callers of `HostInfo::new(id, hostname, os, arch)` continue to compile and produce semantically equivalent envelopes — `host_type` is inferred from `os`. The `.id()` method preserves read access to the renamed `host_id` field. `PolicyResult.evidence` is still writable for the transition window.
- **Wire-level:** v1.x envelopes emitted by prior releases remain valid v1.x envelopes and are read by v1.x consumers unchanged. v2.0.0 envelopes are NOT backward-compatible: the new `host_type` discriminator and `observations[]` array are required fields. v1.x consumers reading v2.0.0 output will reject on the schema-version check.
- **No migration tool is provided.** Archived v1.x envelopes are kept as-is; new scans emit v2.0.0. This is a deliberate design decision — migrating historical data would require synthesizing `host_type` / `host_id` for envelopes whose source transport is no longer available.

### Security Notes

- **Host binding is now attested by the transport that actually reached the target**, not by `HostInfo::from_system()` on the scanner box. An Azure Bastion scan emits `host_type: "azure.vm"` with `subscription_id` / `resource_group` / `target_resource_id` in `attrs`; an SSH scan emits `host_id: "ssh://<user>@<host>:<port>"`. An envelope now cryptographically binds the compliance outcome to the **target** identity, not the scanner identity.
- **Replay-hash canonicalization is explicit and version-locked.** Schema §6 enumerates the excluded fields (host, observations, timestamps) and the canonical byte representation. Implementations that diverge from §6 produce invalid hashes — the test-vector round-trips (common/tests/vectors_v2.rs) catch silent serialization drift.
- **`ObservationRef` bare-string serialization is pinned by vector test.** Removing `#[serde(transparent)]` would silently change `"uuid-abc"` to `{"uuid":"uuid-abc"}` on the wire and break every downstream consumer (SIEM ingester, OSCAL emitter, replay validator) without a Rust compile error. The `observation_ref_is_bare_string` test prevents this.

### Migration Checklist (for downstream code)

| Step | Action |
|------|--------|
| 1 | Update `common` dep to `2.0.0`. |
| 2 | Replace `HostInfo::from_system()` call sites with `channel.identify_host()?` — the transport knows more about the target than the scanner's local environment does. |
| 3 | When constructing `HostInfo` directly, prefer `HostInfo::for_host_type("linux.vm", host_id).with_hostname(...)` over the legacy 4-arg `::new()`. |
| 4 | Stop reading `PolicyResult.evidence` in new code; switch to resolving `PolicyResult.observation_refs` against `ResultEnvelope.observations`. |
| 5 | Assert `schema_version == "2.0.0"` explicitly at consumer entry points. v1.x envelopes should route to a legacy reader, not the v2 path. |
| 6 | Remove any enablement of the old Cargo features (`attestation`, `full-results`, `assessor-evidence`) — `common` rejects them at build time. |
| 7 | If you called `ResultBuilder::build_attestation` / `build_full_result` / `build_both` / `build_all`, switch to `build_assessor_package(policies, replay_hash, identity_status)`. Replace `CheckInput` / `PolicyInput` constructions with `AssessorInput`. |
| 8 | If you shelled out to the agent with `--format <...>`, drop the flag — the agent now always emits `AssessorPackage`. Post-process the JSON if you need a narrower shape. |

---

## [1.2.3] — 2026-04-10

### Fixed

- **PATH merging in SystemCommandExecutor** (execution_engine): The base restricted `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`) was previously applied via `.env("PATH", ...)` followed by `.envs(&self.static_env)`. While `std::process::Command` does allow later `.env()` calls to override earlier ones, the single-call base path meant any `set_env("PATH", "/usr/pgsql-16/bin:/usr/pgsql-15/bin:...")` replaced the base entirely instead of extending it. Vendor-specific binary locations that should have been additive ended up displacing standard system paths (or vice versa depending on HashMap ordering), producing `ProgramNotFound` errors for tools like `psql` that are installed under `/usr/pgsql-16/bin`.

### Behavior Change

`execute()` now **merges** the PATH instead of overriding it:

1. Start with the base restricted PATH: `/usr/bin:/bin:/usr/sbin:/sbin`
2. If `set_env("PATH", ...)` was called, prepend its value to the base
3. If `set_env_from("PATH", "SOME_VAR")` resolves, prepend its value to the result
4. Apply the merged PATH as a single `.env("PATH", final_path)` call
5. Iterate all other static and dynamic env vars separately, skipping the `PATH` key

Resolution order for the spawned process is now:

```
env_clear()
  -> PATH = [dynamic PATH prepend] + [static PATH prepend] + [restricted base]
  -> all other static env vars
  -> all other dynamic env vars (resolved at call time)
```

### Use Cases Unlocked

- **PostgreSQL on RHEL**: `psql` at `/usr/pgsql-16/bin/psql` is now reachable when the command factory calls `set_env("PATH", "/usr/pgsql-16/bin:/usr/pgsql-15/bin:/usr/pgsql-14/bin:...")`. The extended PATH is merged with the base, so both vendor tools and system utilities remain on the search path.
- **Any vendor-installed tool** that lives outside `/usr/bin`, `/bin`, `/usr/sbin`, or `/sbin` can now be reached by extending PATH rather than overriding it.

### Files Modified

| File | Crate | Changes |
|------|-------|---------|
| `command_executor.rs` | execution_engine | `execute()` — replaced single `.env("PATH", ...)` + `.envs(&static_env)` + `.envs(&dynamic_resolved)` with explicit PATH merging (prepend static, then prepend dynamic, then apply once) followed by per-key iteration that skips the PATH key. Behavior for non-PATH env vars is unchanged. |

### Backward Compatibility

Fully backward compatible. Executors that do not call `set_env("PATH", ...)` or `set_env_from("PATH", ...)` behave identically to v1.2.2 — they receive the same restricted base PATH.

Executors that previously called `set_env("PATH", ...)` expecting their value to replace the base will now see the base **appended** to their value. If a caller actually needs to fully replace the base PATH, that is a new API request (not covered by this release).

---

## [1.2.2] — 2026-04-09

### Added

- **Dynamic environment variable injection** (execution_engine): `SystemCommandExecutor` now supports injecting environment variables into spawned processes after `env_clear()`. Two modes:
  - `set_env(key, value)` — static injection, value fixed at configuration time.
  - `set_env_from(child_var, source_var)` — dynamic injection, reads `source_var` from the agent's environment on every `execute()` call. Supports credential rotation without agent restart.
- Resolution order in spawned process: `env_clear()` → `PATH` (restricted) → static env → dynamic env (resolved at call time).
- New tests: `test_set_env_from_resolves_at_execute_time`, `test_set_env_from_skips_missing_var`.

### Use Cases

- PostgreSQL: `set_env_from("PGPASSWORD", "ESP_PG_PASS")` — psql reads password from agent env on each scan.
- AWS CLI: `set_env_from("HOME", "ESP_HOME")` — explicit home dir for credential file discovery.
- Kubernetes: `set_env_from("KUBECONFIG", "ESP_KUBECONFIG")` — kubectl config path injection.
- Any tool that reads credentials or config from environment variables.

### Security Notes

- `env_clear()` behavior is unchanged — all inherited vars are still wiped.
- Only explicitly configured vars (via `set_env` or `set_env_from`) reach the child process.
- Dynamic vars that are not set in the agent's environment are silently skipped (no error, no default).
- Credential values from `set_env_from` are never logged in evidence or command strings.

### Files Modified

| File | Crate | Changes |
|------|-------|---------|
| `command_executor.rs` | execution_engine | Added `static_env` and `dynamic_env` fields, `set_env()`, `set_envs()`, `set_env_from()`, `resolve_dynamic_env()` methods. Updated `execute()` to inject both static and dynamic env vars after `env_clear()`. Added 2 new tests. |

### Backward Compatibility

Fully backward compatible. Existing API (`new()`, `with_timeout()`, `allow_command()`, `allow_commands()`, `is_allowed()`, `execute()`) is unchanged. Executors with no env configuration behave identically to v1.2.1.

---

## [1.2.1] — 2026-04-08

### Fixed

- **Criterion execution error reporting** (execution_engine): Errors returned by `execute_single_criterion()` are now caught and recorded as `Outcome::Fail` on the affected criterion rather than propagating as a hard `Err` that aborted the entire policy execution. Previously, any execution error (missing contract, collector, executor, timeout, etc.) caused `execute()` to return `Err(ExecutionError)` with no policy result. The criterion is now marked failed with the error message, execution continues through the remaining tree, and the policy outcome reflects the failure correctly.

### Files Modified

| File | Crate | Changes |
|------|-------|---------|
| `engine.rs` | execution_engine | `execute_tree()` — replaced `?` propagation on `execute_single_criterion()` with a `match` that converts `Err` to `CtnExecutionResult::fail()` |

---

## [1.2.0] — 2026-03-01

### Summary

Replaces the dual-hash system (`content_hash` + `evidence_hash`) with a single **`replay_hash`** computed from a three-layer `ReplayManifest`. This eliminates hash instability caused by volatile evidence fields (timestamps, collection counters, metadata) while providing a stronger integrity guarantee that captures *what was checked*, *how it was executed*, and *what passed or failed* — without including actual collected values.

### Breaking Changes

- **Envelope schema**: `content_hash` and `evidence_hash` fields removed from `ResultEnvelope`. Replaced by single `replay_hash` field.
- **Signature covers**: `covers` field changes from `["content_hash", "evidence_hash"]` to `["replay_hash"]`.
- **Signed data**: Signature payload changes from `SHA256(content_hash || evidence_hash)` to `SHA256(replay_hash)`.
- **Schema version**: Bumped from `1.1.1` to `1.2.0`.
- Consumers parsing the envelope must handle the new field name. See Migration Guide (Appendix A of schema doc).

### Added

- **`ReplayManifest`** — New canonical manifest type in `canonical_manifest.rs` with three-layer structure per criterion:
  - **Intent layer**: What was checked (STATE fields, operations, expected values, TEST spec, OBJECT identifiers, record checks).
  - **Contract layer**: How it was executed (CTN type, collector ID, collection mode, field mappings).
  - **Outcome layer**: What passed/failed per field (operation, expected value, pass/fail boolean — NO actual collected values).
- **`ReplayTreeNode`** — Merkle-style CRI tree rollup enum (`Leaf` / `Block`) that mirrors the AND/OR/NOT logical structure, ensuring tree topology affects the hash.
- **`CriterionReplay`** — Per-criterion replay struct combining intent + contract + outcome with deterministic hash computation.
- **`replay_hash` field** on `ResultEnvelope`, `ExecutionManifest`, and `PolicyExecutionResult`.
- **`has_valid_hash()`** method replacing `has_valid_hashes()` on `ExecutionManifest`.
- **`finalize_hash()`** method replacing `finalize_hashes()` on `ExecutionManifest`.
- **`set_replay_manifest()`** method replacing `set_content_manifest()` / `set_evidence_manifest()`.
- **`with_replay_hash()`** builder method on `ResultEnvelope`, `AttestationBuilder`, `FullResultBuilder`, `AssessorPackageBuilder`, and `ResultBuilder`.
- **`replay_hash_matches()`** method on `ResultEnvelope` replacing `evidence_matches()`.
- **`build_replay_manifest()`** in execution engine, orchestrating per-criterion replay extraction from the CRI tree result.

### Removed

- **`ContentManifest`** — Previously captured policy identity + criteria structure.
- **`EvidenceManifest`** — Previously captured collected evidence (source of hash instability).
- **`CriterionEvidence`** / **`ObjectEvidence`** — Evidence manifest sub-types.
- **`content_hash`** and **`evidence_hash`** fields from `ResultEnvelope`, `ExecutionManifest`, and `PolicyExecutionResult`.
- **`has_valid_hashes()`**, **`finalize_hashes()`**, **`set_content_manifest()`**, **`set_evidence_manifest()`** from `ExecutionManifest`.
- **`with_content_hash()`** and **`with_evidence_hash()`** from all builders.
- **`evidence_matches()`** from `ResultEnvelope`.
- **`build_content_manifest()`**, **`build_evidence_manifest()`**, **`compute_criteria_structure_hash()`**, **`tree_to_structure_string()`** from execution engine.

### Changed

- **Execution engine `execute()`**: Now calls `build_replay_manifest()` and computes a single `replay_hash` instead of building two separate manifests.
- **All output builders** (`AttestationBuilder`, `FullResultBuilder`, `AssessorPackageBuilder`, `ResultBuilder`): Accept single `replay_hash` parameter instead of `content_hash` + `evidence_hash`.
- **`SignatureBlock::standard_covers()`**: Returns `["replay_hash"]` instead of `["content_hash", "evidence_hash"]`.
- **`PackageInfo.format_version`**: Bumped to `"1.2.0"`.
- **`SCHEMA_VERSION` constant**: Changed from `"1.1.0"` to `"1.2.0"`.
- **Scanner `types/mod.rs`**: Re-exports updated from `ContentManifest`/`EvidenceManifest` to `ReplayManifest`/`CriterionReplay`/`ReplayTreeNode`.

### Design Rationale

The previous dual-hash system was unstable because `EvidenceManifest` included volatile fields — collection timestamps, field counts, duration measurements, and HashMap-ordered data — that changed between runs even when compliance posture was identical. This caused the daemon's dedup tracker to submit full results on every scan cycle, defeating change detection entirely.

The replay hash solves this by hashing only deterministic, compliance-relevant data:

| Layer | Captures | Excludes |
|-------|----------|----------|
| Intent | STATE fields, operations, expected values, TEST spec | Runtime resolution metadata |
| Contract | CTN type, collector, collection mode, field mappings | Timing, ordering |
| Outcome | Pass/fail per field with operation + expected | **Actual collected values** |

Excluding actual values is critical: a sysctl parameter reading `1` today and `1` tomorrow should produce the same hash if both pass the `equals "1"` check. The replay hash proves the verification was performed correctly and produced the same result, without revealing or depending on the evidence data.

The Merkle-style tree rollup ensures that logical structure matters: `AND(A, B)` produces a different hash than `OR(A, B)` even with identical child criteria, and negation (`NOT`) is included in the hash input.

### Files Modified

| File | Crate | Changes |
|------|-------|---------|
| `canonical_manifest.rs` | scanner | Complete rewrite — `ReplayManifest` replaces `ContentManifest` + `EvidenceManifest` |
| `engine.rs` | scanner | `build_replay_manifest()` replaces `build_content_manifest()` + `build_evidence_manifest()` |
| `manifest.rs` | scanner | `ExecutionManifest` uses `replay_manifest` + `replay_hash` |
| `types/mod.rs` | scanner | Updated re-exports |
| `envelope.rs` | common | `replay_hash` replaces `content_hash` + `evidence_hash`; schema version `1.2.0` |
| `builder.rs` | common | All `build_*()` methods take single `replay_hash` |
| `attestation.rs` | common | `AttestationBuilder` uses `with_replay_hash()` |
| `full.rs` | common | `FullResultBuilder` uses `with_replay_hash()` |
| `assessor.rs` | common | `AssessorPackageBuilder` uses `with_replay_hash()` |

### Pending (Daemon Layer)

| File | Changes Needed |
|------|----------------|
| `dedup.rs` | Doc comments + tracing labels (`evidence_hash` → `replay_hash`) |
| `main.rs` | `package.envelope.evidence_hash` → `package.envelope.replay_hash` |
| `output/mod.rs` | `combine_scan_hashes()` → single replay hash |
| `output/signing.rs` | `compute_signed_data()` takes single hash |
| `output/assessor.rs` | Builder call updated for single hash |
| `ScanResult` struct | `content_hash` + `evidence_hash` → `replay_hash` |
| `console.rs` | No changes needed |

## [1.1.0] - 2026-01-24

### Added
- **TransparencyProof Types** (common): New types for certificate transparency log integration:
  - `TransparencyProof` - Container with `log_index` and Merkle inclusion proof
  - `InclusionProof` - Merkle tree proof with `tree_size`, `root_hash`, and sibling `hashes`
  - Supports Level 2 verification (PKI + transparency proof validation)
- **IdentityStatus Type** (common): New type for tracking PKI bootstrap status:
  - `IdentityStatus::success(signer_id)` - Successful PKI identity establishment
  - `IdentityStatus::failed(signer_id, error, error_code)` - Bootstrap failure with diagnostics
  - `IdentityStatus::disabled(signer_id)` - Identity explicitly disabled in configuration
  - Standard error codes: `BOOTSTRAP_DISABLED`, `BOOTSTRAP_CONNECTION_FAILED`, `BOOTSTRAP_AUTH_FAILED`, `BOOTSTRAP_CERT_FAILED`, `BOOTSTRAP_TIMEOUT`, `BOOTSTRAP_TLS_ERROR`
  - Helper function `generate_unsigned_signer_id()` for fallback signer IDs
- **SignatureBlock.transparency** (common): Optional `TransparencyProof` field for certificate transparency integration.
- **SignatureBlock::with_pki()** (common): New constructor for creating signature blocks with full PKI identity (certificate chain + transparency proof).
- **SignatureBlock Helper Methods** (common): `has_pki()`, `has_transparency()`, `has_level2_support()` for verification level detection.
- **ResultEnvelope::with_identity()** (common): New constructor accepting explicit `IdentityStatus`.
- **ResultEnvelope::is_identity_bootstrapped()** (common): Helper method to check PKI status.
- **SCHEMA_VERSION Constant** (common): Exported constant `"1.1.0"` for schema version.

### Changed
- **Schema Version** (common): Updated from `1.0.0` to `1.1.0`.
- **ResultEnvelope** (common): Added required `identity_status: IdentityStatus` field. All result envelopes now track PKI bootstrap status.
- **AttestationBuilder** (common): Now requires `with_identity_status()` before `build()`. Returns error if not provided.
- **FullResultBuilder** (common): Now requires `with_identity_status()` before `build()`. Returns error if not provided.
- **AssessorPackageBuilder** (common): Now requires `with_identity_status()` before `build()`. Returns error if not provided.
- **ResultBuilder Methods** (common): All build methods now require `identity_status` parameter:
  - `build_attestation(checks, content_hash, evidence_hash, identity_status)`
  - `build_full_result(policies, content_hash, evidence_hash, identity_status)`
  - `build_assessor_package(policies, content_hash, evidence_hash, identity_status)`
  - `build_both(policies, content_hash, evidence_hash, identity_status)`
  - `build_all(policies, content_hash, evidence_hash, identity_status)`
- **PackageInfo.format_version** (common): Updated default from `"1.0.0"` to `"1.1.0"`.
- **ESP Canonical Schema Documentation** (docs): Updated `09_ESP_Canonical_Schema_v1_1_0.md` with:
  - Section 3.5.9: Transparency proof specification
  - Section 3.6: Identity status specification
  - Updated SignatureBlock schema with `transparency` field
  - Updated ResultEnvelope schema with `identity_status` field
  - Certificate chain verification procedures
  - Transparency proof verification algorithm

### Migration Guide
- All code that builds results must now provide `IdentityStatus`:
```rust
  // Before (1.0.0)
  let result = builder.build_attestation(checks, content_hash, evidence_hash)?;

  // After (1.1.0)
  let identity_status = IdentityStatus::success("scanset://prod/aws/...");
  // Or for unsigned results:
  let identity_status = IdentityStatus::disabled("unsigned:agent:hostname");

  let result = builder.build_attestation(checks, content_hash, evidence_hash, identity_status)?;
```
- `ResultEnvelope::new()` still works but uses `IdentityStatus::default()`. Prefer `ResultEnvelope::with_identity()` for explicit status.

### Notes
- This release adds support for PKI identity tracking and certificate transparency, preparing for Trust System integration.
- Results without PKI identity remain valid but will have `identity_status.bootstrapped = false`.
- The `signature` field remains optional; unsigned results have `signature: null` with appropriate `identity_status`.

## [1.0.0] - 2026-01-09

### Added
- **ESP Language Specification** (docs): Complete 12-document specification suite:
  - `01_ESP_Overview_v1_0_0.md` - Language introduction and concepts
  - `02_ESP_Lexical_Rules_v1_0_0.md` - Token definitions and lexical structure
  - `03_ESP_Grammar_EBNF_v1_0_0.md` - Formal grammar specification
  - `04_ESP_Type_System_v1_0_0.md` - Data types and type compatibility
  - `05_ESP_Symbol_Resolution_v1_0_0.md` - Symbol tables and reference resolution
  - `06_ESP_Evaluation_Semantics_v1_0_0.md` - Runtime evaluation rules
  - `07_ESP_Meta_Requirements_v1_0_0.md` - Structural requirements
  - `08_ESP_Error_Model_v1_0_0.md` - Error codes and handling
  - `09_ESP_Canonical_Schema_v1_0_0.md` - Output format specification
  - `10_ESP_Trust_Model_v1_0_0.md` - Security boundaries and trust
  - `11_ESP_Configuration_v1_0_0.md` - Build and runtime configuration
  - `12_ESP_Logging_v1_0_0.md` - Logging system specification
- **Assessor Evidence Feature** (common): New `assessor-evidence` feature flag providing `AssessorPackage`, `AssessorPolicyResult`, `CollectionCommand`, and `ReproducibilityInfo` types for assessor-grade evidence packages with collection commands.
- **CollectionMethod Traceability** (common): New `CollectionMethod` type for documenting how evidence was collected:
  - `CollectionMethod::command(cmd, target)` - System command execution
  - `CollectionMethod::api(endpoint, resource)` - REST/gRPC API calls
  - `CollectionMethod::file_read(path)` - Direct file access
  - `CollectionMethod::computed()` - Derived/calculated values
  - Builder pattern with `with_description()` for human-readable context
- **CollectedData.set_method()** (execution_engine): Integration point for documenting collection method in `CollectedData` struct.

### Changed
- **Results Module Restructure** (common): Reorganized results module with clearer feature tiers:
  - Core types always available: `Outcome`, `Criticality`, `Weight`, `CriteriaCounts`, `CollectionMethod`, `Evidence`, `ComplianceFinding`, `ResultBuilder`
  - `attestation` feature (default): Network-safe `AttestationResult`, `CheckAttestation`
  - `full-results` feature: Complete `FullResult`, `PolicyResult` with evidence
  - `assessor-evidence` feature: `AssessorPackage` with collection commands (implies `full-results`)
- **Documentation Updates**: Updated all crate READMEs with links to specification documents and accurate module documentation.

### Removed
- **Agent Crate**: Moved to [ESP Agent SDK](https://github.com/scanset/ESP-Agent-SDK) - Reference scanner implementation with CLI agent.
- **Contract Kit Crate**: Moved to [ESP Agent SDK](https://github.com/scanset/ESP-Agent-SDK) - Reference CTN type implementations (file_metadata, file_content, tcp_listener, k8s_resource, etc.).
- **Makefile Run Targets**: Removed all `run*` targets (`run`, `run-summary`, `run-attestation`, `run-full`, `run-assessor`, `run-batch`, `run-release`, `run-batch-release`, `run-compiler`, `run-compiler-release`) as agent is no longer in this repository.
- **Cross-Compilation Targets**: Removed `build-windows` and `build-linux` targets (agent-specific).
- **Install Target**: Removed `make install` (was for agent binary).
- **Watch Agent Target**: Removed `watch-agent` (agent-specific).

### Notes
- This release focuses the core ESP repository on the language specification, compiler, and execution engine.
- Scanner implementations should use the [ESP Agent SDK](https://github.com/scanset/ESP-Agent-SDK) which provides reference collectors, executors, and an example agent application.
- The core crates (`common`, `compiler`, `execution_engine`) remain fully functional as libraries for building custom scanner implementations.

## [0.2.0] - 2026-01-08

### Added

- **Platform-Specific Cryptography** (common): New `crypto` module providing FIPS 140-3 compliant hashing with platform-native backends:
  - Windows: Windows CNG (BCrypt) - built into Windows 10/11/Server 2016+
  - Linux/Unix: OpenSSL FIPS provider
- **Cross-Compilation Support**: Windows builds no longer require OpenSSL. The `windows` crate provides native CNG bindings that cross-compile cleanly from Linux.
- **Canonical JSON Serialization** (common): New `crypto::canonical` module ensures deterministic JSON output for consistent content hashing regardless of field ordering.
- **Results Module Restructure** (common): New consolidated result types for cleaner API:
  - `ExecutionEnvelope`: Universal wrapper with WHO/WHAT/WHERE/WHEN metadata (agent, host, timestamps, signature)
  - `ExecutionSummary`: Aggregate statistics with posture scoring and criticality breakdown
  - `Evidence`: Raw collected data container with collection metadata
  - `EvidenceSummary`: CUI-free evidence summary for attestations
  - `PolicyIdentity`: Lightweight policy identification for attestations
  - `CollectionRecord`: Metadata about individual collection operations
- **CTN Type Documentation** (contract_kit): Comprehensive reference documentation for all CTN types in `contract_kit/docs/`:
  - `ctn_file_metadata.md`: File permissions, ownership, existence validation
  - `ctn_file_content.md`: File content validation with string operations
  - `ctn_json_record.md`: Structured JSON field validation with record checks
  - `ctn_tcp_listener.md`: TCP port listening state validation
  - `ctn_k8s_resource.md`: Kubernetes API resource validation
  - `ctn_computed_values.md`: RUN operation result validation
- **Test ESP Policies** (esp): Three reference policies demonstrating CTN types:
  - `test_file_metadata.esp`: System file permissions validation (CIS 6.1.1, 6.1.2)
  - `test_file_content.esp`: System account configuration validation (CIS 5.4.1)
  - `test_tcp_listener.esp`: Network port validation (CIS 3.4.1)
- **Agent CLI** (agent): New reference CLI application using `execution_engine` for batch scanning with JSON output

### Changed

- **Crate Rename**: `agent_core` renamed to `execution_engine` to better reflect its purpose as the resolution and execution framework
- **Executor Trait Signature** (execution_engine): `execute_with_contract` now takes owned `HashMap<String, CollectedData>` instead of reference, enabling executors to include collected data in results without cloning
- **CtnExecutionResult** (execution_engine): Now includes `collected_data: HashMap<String, CollectedData>` field and `with_collected_data()` builder method for evidence preservation
- **Attestation Hashing** (common): `attestation::hashing` module now re-exports from `crypto` module for backwards compatibility. Existing code using `hash_content()`, `verify_hash()`, and `sha256_hash()` continues to work unchanged.
- **Dependencies** (common): Crypto dependencies are now platform-conditional:
  - `openssl` only included on non-Windows targets
  - `windows` crate with `Win32_Security_Cryptography` feature only included on Windows targets
- **Clippy Lint Rules**: Enforced stricter linting across all crates:
  - `#![deny(clippy::unwrap_used)]` - Prevents panics from `.unwrap()` in production code
  - `#![deny(clippy::expect_used)]` - Prevents panics from `.expect()` in production code
  - `#![deny(clippy::indexing_slicing)]` - Requires safe `.get()` access instead of direct indexing
  - `#![allow(...)]` attributes added to test modules where these patterns are acceptable
- **Makefile**: Updated for agent-focused workflow:
  - `make build` now builds the agent
  - `make run ESP=<path>` runs agent on file or directory
  - `make run-compiler ESP=<path>` runs compiler only
  - `make lint` runs strict clippy checks
  - Removed cross-compilation targets (simplified for development)
- **README.md**: Streamlined from ~500 to ~150 lines:
  - Removed verbose trust model diagrams (referenced doc instead)
  - Removed embedded code examples (referenced `esp/` directory)
  - Added Dev Container setup instructions
  - Added CTN types table with links to documentation
  - Updated architecture diagram

### Fixed

- **Safe Indexing** (contract_kit): Fixed clippy `indexing_slicing` violations in collectors:
  - `command.rs`: 4 fixes for command output parsing
  - `tcp_listener.rs`: 8 fixes for `/proc/net/tcp` parsing
  - All direct array indexing (`parts[0]`) replaced with safe `.get()` access

### Removed

- **Feature-Gated OpenSSL** (common): The `attestation` feature no longer gates the `openssl` dependency. Cryptography is always available via the platform-appropriate backend.
- **Consolidated CTN Types** (contract_kit): Reduced total number of contracts by consolidating platform-specific implementations:
  - Removed RHEL-specific RPM, systemd, sysctl, SELinux contracts (moved to platform-specific extensions)
  - Core CTN types now focus on cross-platform primitives: `file_metadata`, `file_content`, `json_record`, `tcp_listener`, `k8s_resource`, `computed_values`

### Documentation

- **Scanner Development Guide**: Major update with new sections:
  - Command Execution: Sandbox constraints, environment variable handling, output parsing
  - Understanding Command Output: Detailed examples for `/proc/net/tcp`, `stat`, `kubectl`
  - Type Conversion Rules: Source data to ResolvedValue mapping
  - Safe Output Parsing: Using `.get()` instead of direct indexing
  - Updated best practices and checklists
- **ESP Language Guide**: Updated to reference test policies and CTN documentation:
  - Part 3-5 now use `test_file_metadata.esp`, `test_file_content.esp`, `test_tcp_listener.esp` as examples
  - Added links to `contract_kit/docs/` throughout
  - Updated CTN Type Reference table with documentation links
- **Common Crate README**: Added documentation for new result types:
  - `ExecutionEnvelope`, `ExecutionSummary`, `Evidence`, `PolicyIdentity`
  - Updated module structure to reflect new files
- **Results Module README**: New comprehensive documentation covering:
  - Security model (attestation vs full results)
  - Module structure with new consolidated types
  - Key types reference with usage examples

## [0.1.4] - 2026-01-06

### Added
- **Platform-Specific Cryptography** (common): New `crypto` module providing FIPS 140-3 compliant hashing with platform-native backends:
  - Windows: Windows CNG (BCrypt) - built into Windows 10/11/Server 2016+
  - Linux/Unix: OpenSSL FIPS provider
- **Cross-Compilation Support**: Windows builds no longer require OpenSSL. The `windows` crate provides native CNG bindings that cross-compile cleanly from Linux.
- **Canonical JSON Serialization** (common): New `crypto::canonical` module ensures deterministic JSON output for consistent content hashing regardless of field ordering.

### Changed
- **Attestation Hashing** (common): `attestation::hashing` module now re-exports from `crypto` module for backwards compatibility. Existing code using `hash_content()`, `verify_hash()`, and `sha256_hash()` continues to work unchanged.
- **Dependencies** (common): Crypto dependencies are now platform-conditional:
  - `openssl` only included on non-Windows targets
  - `windows` crate with `Win32_Security_Cryptography` feature only included on Windows targets

### Removed
- **Feature-Gated OpenSSL** (common): The `attestation` feature no longer gates the `openssl` dependency. Cryptography is always available via the platform-appropriate backend.


## [0.1.3] - 2026-01-03

### Changed
- **Evidence Propagation** (agent_core): `ExecutionEngine::build_evidence()` now extracts evidence from `CtnExecutionResult.details` and propagates it to `PolicyExecutionResult.evidence`. Previously, evidence was always `None`.


## [0.1.1] - 2026-01-01

### Fixed
- K8sResourceCollector now correctly uses in-cluster authentication when running inside Kubernetes pods. Previously, kubectl would fail to auto-detect ServiceAccount credentials when `KUBERNETES_SERVICE_HOST` was set.

# 31 DEC 2025 - v.0.1 release
