#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Drift-coupling test: EBNF terminal keywords ↔ parser `Keyword` enum.
//!
//! Catches the class of drift where one is extended without the other.
//! Hit historically: SET_REF as a CTN content operand was added to the
//! parser in v2.1.0 but never appeared in the EBNF's `ctn_content` rule,
//! and the CHANGELOG narrative falsely claimed "the EBNF already listed
//! it." This test surfaces that kind of asymmetry before merge.

use std::collections::BTreeSet;
use std::path::PathBuf;

use compiler::grammar::keywords::reserved_keywords;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("compiler crate has a workspace parent")
        .to_path_buf()
}

/// Extract every double-quoted UPPERCASE_IDENT or lowercase_keyword string
/// from the EBNF doc. EBNF rules quote literal keywords, so any token that
/// the grammar treats as a reserved word should appear quoted somewhere.
fn ebnf_quoted_terminals(ebnf: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in ebnf.lines() {
        let mut buf = String::new();
        let mut in_quote = false;
        for c in line.chars() {
            if c == '"' {
                if in_quote {
                    // Closing quote — accept the buffer if it looks like a keyword
                    if is_keyword_shape(&buf) {
                        out.insert(buf.clone());
                    }
                    buf.clear();
                    in_quote = false;
                } else {
                    in_quote = true;
                }
            } else if in_quote {
                buf.push(c);
            }
        }
    }
    out
}

/// A "keyword shape" is either:
/// - All uppercase + underscore (CTN, SET_REF, REGEX_CAPTURE, ...)
/// - All lowercase + underscore (parameters, parameters_end, select, ...)
///
/// Excludes single characters, mixed-case strings, and anything with
/// non-identifier characters — those are punctuation, identifiers, or
/// formatted strings that aren't keywords.
fn is_keyword_shape(s: &str) -> bool {
    if s.len() < 2 {
        return false;
    }
    let all_upper = s
        .chars()
        .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit());
    let all_lower = s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit());
    let starts_alpha = s.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
    (all_upper || all_lower) && starts_alpha
}

fn ebnf_path() -> PathBuf {
    let docs = workspace_root().join("docs");
    std::fs::read_dir(&docs)
        .expect("read docs/ directory")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("03_ESP_Grammar_EBNF") && n.ends_with(".md"))
                .unwrap_or(false)
        })
        .expect("EBNF grammar doc must exist under docs/")
}

#[test]
fn every_parser_keyword_appears_in_ebnf() {
    let ebnf_file = ebnf_path();
    let ebnf = std::fs::read_to_string(&ebnf_file).expect("read EBNF doc");
    let ebnf_keywords = ebnf_quoted_terminals(&ebnf);
    let parser_keywords: BTreeSet<String> = reserved_keywords()
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let missing_from_ebnf: Vec<&String> = parser_keywords.difference(&ebnf_keywords).collect();

    assert!(
        missing_from_ebnf.is_empty(),
        "\nEBNF / parser drift: keywords accepted by the parser but missing from the EBNF.\n\
         \nMissing terminals: {:?}\n\
         \nFile: {}\n\
         \nEither the EBNF needs to be updated to document the keyword, or the\n\
         parser shouldn't be accepting it. The class-of-bug this test catches\n\
         is v2.1.0's SET_REF-as-CTN-operand: parser was extended, EBNF wasn't.",
        missing_from_ebnf,
        ebnf_file.display(),
    );
}

#[test]
fn ebnf_doesnt_document_keywords_the_parser_rejects() {
    let ebnf_file = ebnf_path();
    let ebnf = std::fs::read_to_string(&ebnf_file).expect("read EBNF doc");
    let ebnf_keywords = ebnf_quoted_terminals(&ebnf);
    let parser_keywords: BTreeSet<String> = reserved_keywords()
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // Allow-list: EBNF terminals that aren't in `reserved_keywords()` because
    // they're handled by lookup paths other than the Keyword enum (operators,
    // META field validators, RUN parameter parsers, enum-value matchers).
    // Adding a new terminal here should be a deliberate code-review decision:
    // the test fires whenever new EBNF terminals don't have a parser-side
    // home, which is exactly the drift signal we want.
    let allowlist: BTreeSet<String> = [
        // Data type identifiers (handled by data-type lookup, not Keyword)
        "string",
        "int",
        "float",
        "boolean",
        "binary",
        "record_data",
        "version",
        "evr_string",
        // OBJECT element keywords (parsed by object-element dispatcher)
        "field",
        "module_name",
        "verb",
        "noun",
        "module_id",
        "module_version",
        // Boolean literals (lexed as Token::Boolean, not Keyword)
        "true",
        "false",
        // TEST existence / item-check enum values
        "all",
        "any",
        "none",
        "at_least_one",
        "only_one",
        "none_satisfy",
        // SET operation names (lexed contextually inside SET blocks)
        "intersection",
        "union",
        "complement",
        // Comparison / string / set operators (Token::Operator variants)
        "contains",
        "starts",
        "ends",
        "not_contains",
        "not_starts",
        "not_ends",
        "ieq",
        "ine",
        "matches",
        "pattern_match",
        "subset_of",
        "superset_of",
        // META field identifiers (validated by META schema, not parsed as keywords)
        "esp_id",
        "platform",
        "criticality",
        "title",
        "description",
        "author",
        "dsl_schema_version",
        "control_mapping",
        "agent_type",
        // Criticality / severity enum values
        "low",
        "medium",
        "high",
        "critical",
        "info",
        // RUN block parameter identifiers
        "delimiter",
        "character",
        "pattern",
        "length",
        "start",
        "literal",
        "text",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();

    let missing_from_parser: Vec<&String> = ebnf_keywords
        .difference(&parser_keywords)
        .filter(|kw| !allowlist.contains(*kw))
        .collect();

    assert!(
        missing_from_parser.is_empty(),
        "\nEBNF / parser drift: EBNF quotes terminals the parser doesn't recognize as keywords.\n\
         \nUnrecognized terminals: {:?}\n\
         \nFile: {}\n\
         \nEither add the keyword to `reserved_keywords()` (and the Keyword enum)\n\
         in compiler/src/grammar/keywords.rs, or add it to the allow-list in this\n\
         test if it's intentionally an identifier rather than a reserved word.",
        missing_from_parser,
        ebnf_file.display(),
    );
}
