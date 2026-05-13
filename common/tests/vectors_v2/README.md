# ESP v2.0.0 Canonical Wire-Shape Vectors

These JSON files are the authoritative examples of the v2.0.0 wire shape
for the entities defined in
`docs/09_ESP_Canonical_Schema_v2_1_1.md` (which the v2.1.0 schema bump
additively extends — see that document's §0). v2.0.0 envelopes
deserialize cleanly under v2.1.0 readers because the new
`replay_hash_version` field carries a `#[serde(default = 1)]`, so these
vectors continue to validate without modification:

| File                          | Pins                                                               |
|-------------------------------|--------------------------------------------------------------------|
| `host_azure_vm.json`          | `azure.vm` `HostInfo` with full Azure Bastion provider context     |
| `host_linux_vm.json`          | `linux.vm` `HostInfo` as produced by `LocalChannel::identify_host` |
| `host_ssh_remote.json`        | SSH-transport `HostInfo` (no hostname, `ssh://` host_id)           |
| `host_aws_account.json`       | `aws.account` — non-VM shape, no hostname/os/arch                  |
| `observation_file_read.json`  | `Observation` + `file_read` method + populated `body`              |
| `observation_exec.json`       | `Observation` + `exec` method + omitted `body` (attestation form)  |
| `observation_ref.json`        | `ObservationRef` — bare-string serialization (NOT `{uuid: ...}`)   |

## How they're used

`common/tests/vectors_v2.rs` loads each file, deserializes into the typed
Rust struct, re-serializes, and asserts `serde_json::Value` round-trip
equality. This locks down two invariants at the type-surface:

1. **Parse invariant** — the type can accept its own canonical form.
2. **Emit invariant** — the type, once parsed, serializes back to
   semantically identical JSON (no field loss, no extra fields, no
   shape drift).

Any schema change that breaks these vectors must be accompanied by a
deliberate update to the file AND a version bump in
`common::results::SCHEMA_VERSION`.

## Editing guidance

- Hand-written with fixed values. Do NOT regenerate from live scans:
  timestamps and uuids would drift and the vectors would stop being
  golden.
- Keys inside `attrs` / `params` must stay alphabetized (BTreeMap emits
  sorted). If you add a key, insert it in alphabetical position.
- Never add placeholder comments (`// TODO`, `"_comment"` keys, etc) —
  the parser rejects non-schema fields in strict mode.
