#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Drift-coupling tests for the workspace version:
//!
//! 1. Top CHANGELOG entry version ↔ `workspace.package.version`.
//!    Catches workspace bumps without a matching CHANGELOG entry, and
//!    vice versa.
//!
//! 2. Every path-versioned `workspace.dependencies` entry ↔
//!    `workspace.package.version`. Cargo-deny requires path deps for
//!    publishable crates to carry an explicit version; this asserts
//!    those versions stay in sync with the workspace version so a
//!    crate bump can't silently leave the internal deps behind.

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
    panic!(
        "Could not find [workspace.package] version in {:?}",
        cargo_toml
    );
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

/// Parse all path-versioned entries from the `[workspace.dependencies]`
/// section of the top-level Cargo.toml. Returns `(crate_name, version)`
/// pairs for every entry that has both `path = "..."` and `version = "..."`.
fn workspace_path_dependencies() -> Vec<(String, String)> {
    let cargo_toml = workspace_root().join("Cargo.toml");
    let contents = std::fs::read_to_string(&cargo_toml).expect("read workspace Cargo.toml");

    let mut out = Vec::new();
    let mut in_workspace_dependencies = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace_dependencies = trimmed == "[workspace.dependencies]";
            continue;
        }
        if !in_workspace_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // crate_name = { path = "...", version = "X.Y.Z", ... }
        let Some((name, rest)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        // Only path-style deps with an explicit version.
        if !rest.contains("path") || !rest.contains("version") {
            continue;
        }
        if let Some(v_start) = rest.find("version") {
            let after = &rest[v_start..];
            if let Some(open) = after.find('"') {
                let after_quote = &after[open + 1..];
                if let Some(close) = after_quote.find('"') {
                    out.push((name.to_string(), after_quote[..close].to_string()));
                }
            }
        }
    }
    out
}

#[test]
fn changelog_top_entry_matches_workspace_version() {
    let ws = workspace_version();
    let cl = changelog_top_version();

    assert_eq!(
        ws, cl,
        "\nCHANGELOG / Cargo.toml version drift detected:\n\
         \n  Cargo.toml [workspace.package].version = {:?}\n\
         \n  CHANGELOG.md top entry                  = {:?}\n\
         \nIf you bumped the workspace version, add a matching CHANGELOG entry.\n\
         If you added a CHANGELOG entry, bump the workspace version to match.",
        ws, cl,
    );
}

#[test]
fn workspace_path_dep_versions_match_workspace_version() {
    let ws = workspace_version();
    let path_deps = workspace_path_dependencies();

    assert!(
        !path_deps.is_empty(),
        "Expected to find at least one path-versioned entry in \
         [workspace.dependencies] (e.g., `common = {{ path = \"common\", \
         version = \"X.Y.Z\" }}`). cargo-deny requires path deps on \
         publishable crates to carry an explicit version; if none are \
         present, the build will likely fail in CI."
    );

    let drift: Vec<&(String, String)> = path_deps.iter().filter(|(_, v)| v != &ws).collect();

    assert!(
        drift.is_empty(),
        "\nworkspace.dependencies / workspace.package version drift detected:\n\
         \n  Cargo.toml [workspace.package].version = {:?}\n\
         \n  [workspace.dependencies] entries with drifted versions:\n\
         {}\n\
         \nWhen bumping `workspace.package.version`, also bump the\n\
         `version = \"...\"` field on every internal path dep in\n\
         `[workspace.dependencies]`.",
        ws,
        drift
            .iter()
            .map(|(name, version)| format!("    {name} = {{ ..., version = \"{version}\" }}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
