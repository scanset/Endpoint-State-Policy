//! Observation types for ESP scan results (schema v2.0.0)
//!
//! An **observation** is one act of data collection against a host -
//! a file read, a command run, an API call, an SDK query. It is the
//! first-class evidence entity in v2.0.0: independently identifiable
//! by uuid, independently addressable by content hash, and referenced
//! from any number of policies that happen to consume it.
//!
//! ## Relation to v1.x `Evidence`
//!
//! v1.x embedded collected data inside each `PolicyResult.evidence`.
//! That duplicated work across policies - two policies that both
//! inspect `/etc/os-release` produced two copies of the same bytes.
//!
//! v2.0.0 lifts evidence out of policies entirely. Collected data lives
//! in `ResultEnvelope.observations[]` and policies cite observations
//! by uuid via `PolicyResult.observation_refs[]`. A single read is cited
//! once and referenced many times.
//!
//! ## Schema Reference
//!
//! Implements Section 4 of ESP v2.0.0 Canonical Execution Schema
//! (`docs/09_ESP_Canonical_Schema_v2_0_0.md`).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Observation
// ============================================================================

/// One act of evidence collection against a host.
///
/// Fields:
/// - `uuid` - RFC 4122 v4, stable for the lifetime of this envelope
///   (NOT stable across scans).
/// - `host_ref` - which host this observation was collected from.
/// - `collected_at` - ISO 8601 timestamp. NOT in the replay hash.
/// - `method` - how the observation was produced (file_read, exec, ...).
/// - `content_hash` - `sha256:<hex>` over the canonical byte representation
///   of `body` (see §4.6 of the schema). Present even when `body` is
///   suppressed (attestation format).
/// - `body` - the observation payload. Arbitrary JSON. Omitted in
///   attestation format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub uuid: String,
    pub host_ref: HostRef,
    pub collected_at: String,
    pub method: ObservationMethod,
    pub content_hash: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

impl Observation {
    /// Construct a new observation with a freshly generated uuid.
    pub fn new(
        host_ref: HostRef,
        method: ObservationMethod,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            uuid: generate_uuid_v4(),
            host_ref,
            collected_at: current_timestamp(),
            method,
            content_hash: content_hash.into(),
            body: None,
        }
    }

    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = uuid.into();
        self
    }

    pub fn with_collected_at(mut self, ts: impl Into<String>) -> Self {
        self.collected_at = ts.into();
        self
    }

    pub fn with_body(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }

    /// Produce a reference token pointing at this observation.
    pub fn as_ref(&self) -> ObservationRef {
        ObservationRef {
            uuid: self.uuid.clone(),
        }
    }

    /// Strip `body` for attestation emission. `content_hash` is preserved.
    pub fn without_body(mut self) -> Self {
        self.body = None;
        self
    }
}

// ============================================================================
// HostRef
// ============================================================================

/// Reference to a host from an observation.
///
/// In v2.0.0 a single envelope carries one top-level `host`, so `host_ref`
/// values within an envelope all match that host. The pair shape is
/// preserved so multi-host envelopes can be introduced in a later
/// schema revision without breaking consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRef {
    pub host_type: String,
    pub host_id: String,
}

impl HostRef {
    pub fn new(host_type: impl Into<String>, host_id: impl Into<String>) -> Self {
        Self {
            host_type: host_type.into(),
            host_id: host_id.into(),
        }
    }
}

// ============================================================================
// ObservationRef
// ============================================================================

/// Reference from a policy result to an observation by uuid.
///
/// Serializes as a bare string for compactness (`"uuid-..."`), not a
/// `{ "uuid": "..." }` object. Policies carry `Vec<ObservationRef>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObservationRef {
    pub uuid: String,
}

impl ObservationRef {
    pub fn new(uuid: impl Into<String>) -> Self {
        Self {
            uuid: uuid.into(),
        }
    }
}

impl From<String> for ObservationRef {
    fn from(uuid: String) -> Self {
        Self { uuid }
    }
}

impl From<&str> for ObservationRef {
    fn from(uuid: &str) -> Self {
        Self {
            uuid: uuid.to_string(),
        }
    }
}

// ============================================================================
// ObservationMethod
// ============================================================================

/// How an observation was produced.
///
/// `kind` is a free-form string; recommended values mirror the v1.2
/// `CollectionMethodType` enum (`file_read`, `exec`, `http`, `sdk_call`,
/// `query`, `registry_read`, etc.). Free-string so new channels can
/// introduce new methods without a schema revision.
///
/// `params` is method-specific. For `exec` it carries argv; for
/// `file_read` a path; for `http` a URL; for `sdk_call` an operation
/// name and a sanitized parameter map. The assessor reproducibility
/// block (§10) materializes commands from these params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationMethod {
    pub kind: String,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, serde_json::Value>,
}

impl ObservationMethod {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            params: BTreeMap::new(),
        }
    }

    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.params.insert(key.into(), value);
        self
    }

    /// Convenience: file_read observation method.
    pub fn file_read(path: impl Into<String>) -> Self {
        Self::new("file_read").with_param("path", serde_json::Value::String(path.into()))
    }

    /// Convenience: exec observation method.
    pub fn exec(argv: Vec<String>) -> Self {
        Self::new("exec").with_param(
            "argv",
            serde_json::Value::Array(argv.into_iter().map(serde_json::Value::String).collect()),
        )
    }

    /// Convenience: http observation method.
    pub fn http(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self::new("http")
            .with_param("method", serde_json::Value::String(method.into()))
            .with_param("url", serde_json::Value::String(url.into()))
    }

    /// Convenience: sdk_call observation method.
    pub fn sdk_call(operation: impl Into<String>) -> Self {
        Self::new("sdk_call")
            .with_param("operation", serde_json::Value::String(operation.into()))
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn current_timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Generate a UUID v4 string without pulling the `uuid` crate if it isn't
/// already a dependency. Uses a 128-bit value from the system nanosecond
/// clock combined with a process-local counter, then formats per RFC 4122
/// v4 bit layout.
///
/// This is adequate for per-envelope uniqueness (which is the only
/// requirement) but is NOT a cryptographically random UUID. Swap to
/// `uuid::Uuid::new_v4()` if/when the uuid crate lands in Cargo.toml.
fn generate_uuid_v4() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Build 128 bits: [nanos:64 | counter:64]
    let hi = nanos;
    let lo = counter;

    // Apply RFC 4122 v4 bit mask:
    //   time_hi_and_version:  top 4 bits of bytes 6-7 = 0100 (version 4)
    //   clock_seq_hi_and_reserved: top 2 bits of byte 8 = 10 (variant RFC 4122)
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&hi.to_be_bytes());
    bytes[8..16].copy_from_slice(&lo.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant RFC 4122

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ============================================================================
// Tests
// ============================================================================

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ref_round_trip() {
        let r = HostRef::new("azure.vm", "vm-prooflayer-demo");
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"host_type\":\"azure.vm\""));
        assert!(json.contains("\"host_id\":\"vm-prooflayer-demo\""));

        let parsed: HostRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn observation_ref_serializes_as_bare_string() {
        let r = ObservationRef::new("0b2e5c0a-7d1e-4b2f-9c4e-8f1a2d3b4c5e");
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"0b2e5c0a-7d1e-4b2f-9c4e-8f1a2d3b4c5e\"");

        let parsed: ObservationRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.uuid, "0b2e5c0a-7d1e-4b2f-9c4e-8f1a2d3b4c5e");
    }

    #[test]
    fn observation_method_file_read() {
        let m = ObservationMethod::file_read("/etc/os-release");
        assert_eq!(m.kind, "file_read");
        assert_eq!(
            m.params.get("path"),
            Some(&serde_json::Value::String("/etc/os-release".into()))
        );
    }

    #[test]
    fn observation_method_exec() {
        let m = ObservationMethod::exec(vec!["cat".into(), "/etc/os-release".into()]);
        assert_eq!(m.kind, "exec");
        let argv = m.params.get("argv").unwrap().as_array().unwrap();
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[0], serde_json::Value::String("cat".into()));
    }

    #[test]
    fn observation_new_generates_uuid_and_timestamp() {
        let host = HostRef::new("linux.vm", "host-abc");
        let method = ObservationMethod::file_read("/etc/os-release");
        let obs = Observation::new(host.clone(), method, "sha256:deadbeef");

        assert_eq!(obs.uuid.len(), 36); // uuid v4 string
        assert_eq!(obs.uuid.chars().filter(|c| *c == '-').count(), 4);
        assert_eq!(obs.host_ref, host);
        assert_eq!(obs.content_hash, "sha256:deadbeef");
        assert!(obs.body.is_none());
        assert!(!obs.collected_at.is_empty());
    }

    #[test]
    fn observation_uuids_are_unique() {
        let host = HostRef::new("linux.vm", "host-abc");
        let method = ObservationMethod::file_read("/etc/os-release");
        let o1 = Observation::new(host.clone(), method.clone(), "sha256:a");
        let o2 = Observation::new(host, method, "sha256:a");
        assert_ne!(o1.uuid, o2.uuid);
    }

    #[test]
    fn observation_uuid_has_v4_bits() {
        let host = HostRef::new("linux.vm", "host-abc");
        let obs = Observation::new(
            host,
            ObservationMethod::file_read("/x"),
            "sha256:0",
        );
        // version 4 nibble at index 14 (after 3 dashes, 0-indexed char 14)
        let bytes: Vec<char> = obs.uuid.chars().collect();
        assert_eq!(bytes[14], '4', "uuid {} missing v4 nibble", obs.uuid);
        // variant bits: char at index 19 must be one of 8/9/a/b
        assert!(
            matches!(bytes[19], '8' | '9' | 'a' | 'b'),
            "uuid {} missing RFC 4122 variant",
            obs.uuid
        );
    }

    #[test]
    fn observation_as_ref_matches_uuid() {
        let obs = Observation::new(
            HostRef::new("linux.vm", "h"),
            ObservationMethod::file_read("/x"),
            "sha256:0",
        );
        let r = obs.as_ref();
        assert_eq!(r.uuid, obs.uuid);
    }

    #[test]
    fn observation_without_body_keeps_hash() {
        let obs = Observation::new(
            HostRef::new("linux.vm", "h"),
            ObservationMethod::file_read("/x"),
            "sha256:deadbeef",
        )
        .with_body(serde_json::json!({"k": "v"}));
        assert!(obs.body.is_some());

        let stripped = obs.without_body();
        assert!(stripped.body.is_none());
        assert_eq!(stripped.content_hash, "sha256:deadbeef");
    }

    #[test]
    fn observation_full_round_trip_json() {
        let obs = Observation::new(
            HostRef::new("azure.vm", "vm-x"),
            ObservationMethod::exec(vec!["cat".into(), "/etc/os-release".into()]),
            "sha256:3a7bd3e2",
        )
        .with_body(serde_json::json!({
            "bytes_base64": "TkFNRT0iUm9ja3kgTGludXgi",
            "encoding": "utf-8"
        }));

        let json = serde_json::to_string(&obs).unwrap();
        let parsed: Observation = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.uuid, obs.uuid);
        assert_eq!(parsed.host_ref, obs.host_ref);
        assert_eq!(parsed.content_hash, obs.content_hash);
        assert_eq!(parsed.method.kind, "exec");
        assert!(parsed.body.is_some());
    }
}
