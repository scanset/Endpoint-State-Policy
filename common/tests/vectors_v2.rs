//! ESP v2.0.0 canonical wire-shape vectors.
//!
//! Loads the hand-written golden JSON files in `tests/vectors_v2/`,
//! deserializes them into the typed structs exposed by
//! `common::results`, re-serializes, and asserts that the resulting
//! `serde_json::Value` is equal to the original. This catches silent
//! schema drift: adding a field without updating the vector (or vice
//! versa) fails this test.
//!
//! See `tests/vectors_v2/README.md` for the invariants these vectors
//! pin and the rules for editing them.

use std::path::PathBuf;

use common::results::{HostInfo, HostRef, Observation, ObservationRef};

fn vector_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("vectors_v2");
    p.push(name);
    p
}

fn load_vector(name: &str) -> serde_json::Value {
    let path = vector_path(name);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read vector {}: {}", path.display(), e));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse vector {}: {}", path.display(), e))
}

/// Round-trip a vector through type `T` and assert the re-emitted JSON
/// matches the original (by `Value` equality, so whitespace and key
/// order are not material).
fn assert_roundtrip<T>(name: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let original = load_vector(name);

    let typed: T = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("deserialize {} as {}: {}", name, std::any::type_name::<T>(), e));

    let reemitted = serde_json::to_value(&typed)
        .unwrap_or_else(|e| panic!("reserialize {}: {}", name, e));

    assert_eq!(
        original,
        reemitted,
        "\nschema drift detected in vector `{}`\n--- expected (vector file) ---\n{}\n--- got (round-tripped) ---\n{}\n",
        name,
        serde_json::to_string_pretty(&original).unwrap_or_default(),
        serde_json::to_string_pretty(&reemitted).unwrap_or_default(),
    );
}

// ---------------------------------------------------------------------------
// HostInfo vectors
// ---------------------------------------------------------------------------

#[test]
fn host_azure_vm_round_trips() {
    assert_roundtrip::<HostInfo>("host_azure_vm.json");
}

#[test]
fn host_linux_vm_round_trips() {
    assert_roundtrip::<HostInfo>("host_linux_vm.json");
}

#[test]
fn host_ssh_remote_round_trips() {
    assert_roundtrip::<HostInfo>("host_ssh_remote.json");
}

#[test]
fn host_aws_account_round_trips() {
    assert_roundtrip::<HostInfo>("host_aws_account.json");
}

// ---------------------------------------------------------------------------
// Shape-level spot checks — catch field renames that a dumb round-trip
// might miss (e.g. if someone renamed `host_type` -> `kind` in both the
// struct and the vector at once, round-trip would still pass but the
// wire shape would have silently changed).
// ---------------------------------------------------------------------------

#[test]
fn azure_vm_has_all_expected_attrs() {
    let v = load_vector("host_azure_vm.json");
    assert_eq!(v["host_type"], "azure.vm");
    let attrs = v["attrs"]
        .as_object()
        .expect("azure.vm attrs must be an object");
    for key in [
        "bastion_name",
        "local_port",
        "remote_port",
        "resource_group",
        "ssh_user",
        "subscription_id",
        "target_resource_id",
        "transport",
    ] {
        assert!(
            attrs.contains_key(key),
            "azure.vm vector missing attrs.{}",
            key
        );
    }
    assert_eq!(attrs["transport"], "az_bastion_tunnel");
}

#[test]
fn aws_account_has_no_vm_fields() {
    let v = load_vector("host_aws_account.json");
    assert_eq!(v["host_type"], "aws.account");
    // Non-VM shape: hostname/os/arch/fqdn must be absent, not null.
    for f in ["hostname", "os", "arch", "fqdn"] {
        assert!(
            v.get(f).is_none(),
            "aws.account vector must omit `{}` entirely (got {:?})",
            f,
            v.get(f)
        );
    }
}

// ---------------------------------------------------------------------------
// Observation vectors
// ---------------------------------------------------------------------------

#[test]
fn observation_file_read_round_trips() {
    assert_roundtrip::<Observation>("observation_file_read.json");
}

#[test]
fn observation_exec_round_trips() {
    assert_roundtrip::<Observation>("observation_exec.json");
}

#[test]
fn observation_exec_omits_body() {
    // The attestation shape drops `body` but keeps `content_hash`.
    // A `null` body would be wrong — it must be absent.
    let v = load_vector("observation_exec.json");
    assert!(
        v.get("body").is_none(),
        "observation_exec vector must omit `body` entirely (got {:?})",
        v.get("body")
    );
    assert!(v["content_hash"].as_str().unwrap_or("").starts_with("sha256:"));
}

// ---------------------------------------------------------------------------
// ObservationRef — the wire shape here is a BARE STRING, not an object.
// This is easy to break by accident (removing `#[serde(transparent)]`),
// so pin it hard.
// ---------------------------------------------------------------------------

#[test]
fn observation_ref_is_bare_string() {
    let v = load_vector("observation_ref.json");
    assert!(
        v.is_string(),
        "observation_ref vector must serialize as a bare JSON string, got: {:?}",
        v
    );

    let typed: ObservationRef = serde_json::from_value(v.clone()).expect("parse ObservationRef");
    assert_eq!(typed.uuid, "0b2e5c0a-7d1e-4b2f-9c4e-8f1a2d3b4c5e");

    let reemitted = serde_json::to_value(&typed).expect("reserialize");
    assert_eq!(v, reemitted);
}

// ---------------------------------------------------------------------------
// HostRef embedded inside Observation must match the standalone shape.
// ---------------------------------------------------------------------------

#[test]
fn observation_host_ref_shape_matches_standalone() {
    let obs = load_vector("observation_file_read.json");
    let host_ref = &obs["host_ref"];

    // Typed parse: catches field renames.
    let parsed: HostRef =
        serde_json::from_value(host_ref.clone()).expect("parse embedded host_ref");
    assert_eq!(parsed.host_type, "azure.vm");
    assert_eq!(parsed.host_id, "vm-prooflayer-demo");

    // And only these two fields — no drift.
    let keys: Vec<&String> = host_ref
        .as_object()
        .expect("host_ref must be an object")
        .keys()
        .collect();
    assert_eq!(
        keys.len(),
        2,
        "HostRef must have exactly host_type + host_id, got {:?}",
        keys
    );
}
