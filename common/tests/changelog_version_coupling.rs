#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Drift-coupling test: top CHANGELOG entry version ↔ `workspace.package.version`.
//!
//! Catches the class of drift where the workspace version is bumped
//! without a corresponding CHANGELOG entry (or vice versa).

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("common crate has a workspace parent")
        .to_path_buf()
}

/// Parse the `version = "X.Y.Z"` line from the top-level `Cargo.toml`'s
/// `[workspace.package]` section.
fn workspace_version() -> String {
    let cargo_toml = workspace_root().join("Cargo.toml");
    let contents = std::fs::read_to_string(&cargo_toml).expect("read workspace Cargo.toml");

    let mut in_workspace_package = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace_package = trimmed == "[workspace.package]";
            continue;
        }
        if in_workspace_package {
            if let Some(rest) = trimmed.strip_prefix("version") {
                // version = "X.Y.Z"
                let value = rest
                    .trim_start_matches([' ', '=', '"'])
                    .trim_end_matches('"');
                return value.to_string();
            }
        }
    }
    panic!("Could not find [workspace.package] version in {:?}", cargo_toml);
}

/// Parse the top-most `## [X.Y.Z]` heading from `CHANGELOG.md`.
fn changelog_top_version() -> String {
    let changelog = workspace_root().join("CHANGELOG.md");
    let contents = std::fs::read_to_string(&changelog).expect("read CHANGELOG.md");

    for line in contents.lines() {
        let trimmed = line.trim();
        // Match: `## [X.Y.Z] — date` or `## [X.Y.Z] - date`
        if let Some(rest) = trimmed.strip_prefix("## [") {
            if let Some(end) = rest.find(']') {
                return rest[..end].to_string();
            }
        }
    }
    panic!("Could not find a `## [X.Y.Z]` heading in CHANGELOG.md");
}

#[test]
fn changelog_top_entry_matches_workspace_version() {
    let ws = workspace_version();
    let cl = changelog_top_version();

    assert_eq!(
        ws,
        cl,
        "\nCHANGELOG / Cargo.toml version drift detected:\n\
         \n  Cargo.toml [workspace.package].version = {:?}\n\
         \n  CHANGELOG.md top entry                  = {:?}\n\
         \nIf you bumped the workspace version, add a matching CHANGELOG entry.\n\
         If you added a CHANGELOG entry, bump the workspace version to match.",
        ws,
        cl,
    );
}
