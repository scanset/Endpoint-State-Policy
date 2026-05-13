#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Drift-coupling test: `SCHEMA_VERSION` constant ↔ canonical-schema doc title.
//!
//! Catches the class of drift where one is bumped without the other.
//! Hit historically: SCHEMA_VERSION was bumped to 2.1.0 in code while
//! the doc title still said 2.0.0, and again to 2.1.1 in code while
//! the test asserted 2.1.0. This test fires before either reaches main.

use std::path::PathBuf;

use common::results::SCHEMA_VERSION;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("common crate has a workspace parent")
        .to_path_buf()
}

#[test]
fn schema_version_matches_canonical_schema_doc_title() {
    // Find the highest-numbered v2.x.x schema doc.
    let docs_dir = workspace_root().join("docs");
    let mut matches: Vec<PathBuf> = std::fs::read_dir(&docs_dir)
        .expect("read docs/ directory")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("09_ESP_Canonical_Schema_v2_") && n.ends_with(".md"))
                .unwrap_or(false)
        })
        .collect();
    matches.sort();
    let current = matches
        .last()
        .expect("at least one v2.x canonical-schema doc must exist under docs/");

    let contents = std::fs::read_to_string(current).expect("read schema doc");
    let title = contents
        .lines()
        .next()
        .expect("schema doc must have a non-empty first line");

    // Title format: "# ESP v2.1.1 - Canonical Execution Schema"
    let title_version = title
        .split_whitespace()
        .find_map(|w| w.strip_prefix('v'))
        .expect("title must contain 'vX.Y.Z'");

    assert_eq!(
        SCHEMA_VERSION,
        title_version,
        "\nSCHEMA_VERSION drift detected:\n\
         \n  common::results::SCHEMA_VERSION = {:?}\n\
         \n  {} title  = {:?}\n\
         \nIf you bumped one, bump the other:\n\
         \n  1. common/src/results/envelope.rs::SCHEMA_VERSION\n\
         \n  2. {} (title + `**Version:**` field)\n\
         \nAlso rename the doc filename to match if the version changed (e.g.,\n\
         09_ESP_Canonical_Schema_v2_1_0.md -> 09_ESP_Canonical_Schema_v2_1_1.md).",
        SCHEMA_VERSION,
        current
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("(unknown)"),
        title_version,
        current.display(),
    );
}
