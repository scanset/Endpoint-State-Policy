//! Hashing utilities for attestation content
//!
//! Re-exports from the `crypto` module for backwards compatibility.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use common::results::attestation::hashing;
//!
//! let content = MyContent { ... };
//! let hash = hashing::hash_content(&content)?;
//! ```

// Re-export everything from crypto module
pub use super::super::crypto::{
    hash_content, hex_decode, hex_encode, sha256_hash, to_canonical_json, verify_hash, HashingError,
};

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestContent {
        zebra: String,
        apple: String,
        number: i32,
    }

    #[test]
    fn test_hash_content_via_reexport() {
        let content = TestContent {
            zebra: "z".to_string(),
            apple: "a".to_string(),
            number: 1,
        };

        let hash1 = hash_content(&content).unwrap();
        let hash2 = hash_content(&content).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verify_hash_via_reexport() {
        let content = TestContent {
            zebra: "z".to_string(),
            apple: "a".to_string(),
            number: 1,
        };

        let hash = hash_content(&content).unwrap();
        assert!(verify_hash(&content, &hash).unwrap());
    }
}
