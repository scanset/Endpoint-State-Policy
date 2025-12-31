//! Hashing utilities for attestation content
//!
//! Provides FIPS 140 compliant hashing using OpenSSL and canonical JSON
//! serialization for deterministic content hashing.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use common::results::attestation::hashing;
//!
//! let content = MyContent { ... };
//! let hash = hashing::hash_content(&content)?;
//! ```

use openssl::hash::{hash, MessageDigest};
use serde::Serialize;

/// Hash content using SHA-256 (FIPS 140 compliant via OpenSSL)
///
/// Serializes the content to canonical JSON before hashing.
pub fn hash_content<T: Serialize>(content: &T) -> Result<String, HashingError> {
    let canonical = to_canonical_json(content)?;
    let digest = sha256_hash(canonical.as_bytes())?;
    Ok(hex_encode(&digest))
}

/// Hash raw bytes using SHA-256
pub fn sha256_hash(data: &[u8]) -> Result<Vec<u8>, HashingError> {
    hash(MessageDigest::sha256(), data)
        .map(|d| d.to_vec())
        .map_err(|e| HashingError::OpenSslError(e.to_string()))
}

/// Serialize to canonical JSON (sorted keys, no extra whitespace)
///
/// This ensures deterministic serialization for consistent hashing.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, HashingError> {
    // serde_json already produces deterministic output for the same input
    // For true canonical JSON (sorted keys), we need to go through Value
    let json_value =
        serde_json::to_value(value).map_err(|e| HashingError::SerializationError(e.to_string()))?;

    let canonical = canonicalize_value(&json_value);

    serde_json::to_string(&canonical).map_err(|e| HashingError::SerializationError(e.to_string()))
}

/// Recursively sort object keys for canonical representation
fn canonicalize_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // Sort keys and recursively canonicalize values
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));

            let canonical_map: serde_json::Map<String, serde_json::Value> = sorted
                .into_iter()
                .map(|(k, v)| (k.clone(), canonicalize_value(v)))
                .collect();

            serde_json::Value::Object(canonical_map)
        }
        serde_json::Value::Array(arr) => {
            // Recursively canonicalize array elements (order preserved)
            serde_json::Value::Array(arr.iter().map(canonicalize_value).collect())
        }
        // Primitive values pass through unchanged
        other => other.clone(),
    }
}

/// Encode bytes as lowercase hex string
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, HashingError> {
    if hex.len() % 2 != 0 {
        return Err(HashingError::InvalidHex(
            "Odd length hex string".to_string(),
        ));
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| HashingError::InvalidHex(e.to_string()))
        })
        .collect()
}

/// Verify that content matches a given hash
pub fn verify_hash<T: Serialize>(content: &T, expected_hash: &str) -> Result<bool, HashingError> {
    let actual_hash = hash_content(content)?;
    Ok(actual_hash == expected_hash)
}

/// Errors that can occur during hashing
#[derive(Debug, Clone)]
pub enum HashingError {
    /// OpenSSL operation failed
    OpenSslError(String),
    /// JSON serialization failed
    SerializationError(String),
    /// Invalid hex string
    InvalidHex(String),
}

impl std::fmt::Display for HashingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashingError::OpenSslError(e) => write!(f, "OpenSSL error: {}", e),
            HashingError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            HashingError::InvalidHex(e) => write!(f, "Invalid hex: {}", e),
        }
    }
}

impl std::error::Error for HashingError {}

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
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = sha256_hash(data).unwrap();

        // Known SHA-256 hash of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(hex_encode(&hash), expected);
    }

    #[test]
    fn test_canonical_json_sorted_keys() {
        let content = TestContent {
            zebra: "last".to_string(),
            apple: "first".to_string(),
            number: 42,
        };

        let canonical = to_canonical_json(&content).unwrap();

        // Keys should be sorted alphabetically
        assert!(canonical.find("apple").unwrap() < canonical.find("number").unwrap());
        assert!(canonical.find("number").unwrap() < canonical.find("zebra").unwrap());
    }

    #[test]
    fn test_hash_content_deterministic() {
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
    fn test_hex_encode_decode_roundtrip() {
        let original = vec![0x00, 0xff, 0x42, 0xab];
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("0").is_err()); // Odd length
        assert!(hex_decode("gg").is_err()); // Invalid chars
    }

    #[test]
    fn test_verify_hash() {
        let content = TestContent {
            zebra: "z".to_string(),
            apple: "a".to_string(),
            number: 1,
        };

        let hash = hash_content(&content).unwrap();

        assert!(verify_hash(&content, &hash).unwrap());
        assert!(!verify_hash(&content, "wrong_hash").unwrap());
    }

    #[test]
    fn test_nested_object_canonicalization() {
        #[derive(Serialize)]
        struct Outer {
            z_field: Inner,
            a_field: Inner,
        }

        #[derive(Serialize)]
        struct Inner {
            beta: i32,
            alpha: i32,
        }

        let content = Outer {
            z_field: Inner { beta: 2, alpha: 1 },
            a_field: Inner { beta: 4, alpha: 3 },
        };

        let canonical = to_canonical_json(&content).unwrap();

        // Outer keys sorted
        assert!(canonical.find("a_field").unwrap() < canonical.find("z_field").unwrap());

        // Inner keys sorted (alpha before beta)
        let first_alpha = canonical.find("alpha").unwrap();
        let first_beta = canonical.find("beta").unwrap();
        assert!(first_alpha < first_beta);
    }
}
