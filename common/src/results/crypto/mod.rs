//! Cryptographic utilities for ESP results
//!
//! Provides FIPS 140-3 compliant hashing using platform-native cryptography:
//! - **Windows**: Windows CNG (BCrypt) - built into all modern Windows versions
//! - **Linux/Unix**: OpenSSL FIPS provider
//!
//! ## Usage
//!
//! ```rust,ignore
//! use common::results::crypto::{hash_content, sha256_hash, verify_hash};
//!
//! // Hash serializable content
//! let hash = hash_content(&my_struct)?;
//!
//! // Hash raw bytes
//! let digest = sha256_hash(b"hello world")?;
//!
//! // Verify content against hash
//! let valid = verify_hash(&my_struct, &expected_hash)?;
//! ```

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(not(windows))]
mod openssl;
#[cfg(not(windows))]
use openssl as platform;

mod canonical;

use serde::Serialize;

pub use canonical::to_canonical_json;

/// Hash content using SHA-256 (FIPS 140-3 compliant)
///
/// Serializes the content to canonical JSON before hashing to ensure
/// deterministic results regardless of field ordering.
pub fn hash_content<T: Serialize>(content: &T) -> Result<String, HashingError> {
    let canonical = to_canonical_json(content)?;
    let digest = sha256_hash(canonical.as_bytes())?;
    Ok(hex_encode(&digest))
}

/// Hash raw bytes using SHA-256
///
/// Uses platform-native FIPS 140-3 compliant cryptography:
/// - Windows: BCrypt (CNG)
/// - Linux: OpenSSL
pub fn sha256_hash(data: &[u8]) -> Result<Vec<u8>, HashingError> {
    platform::sha256(data)
}

/// Verify that content matches a given hash
pub fn verify_hash<T: Serialize>(content: &T, expected_hash: &str) -> Result<bool, HashingError> {
    let actual_hash = hash_content(content)?;
    Ok(actual_hash == expected_hash)
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

/// Errors that can occur during hashing operations
#[derive(Debug, Clone)]
pub enum HashingError {
    /// Platform cryptographic operation failed
    CryptoError(String),
    /// JSON serialization failed
    SerializationError(String),
    /// Invalid hex string
    InvalidHex(String),
}

impl std::fmt::Display for HashingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashingError::CryptoError(e) => write!(f, "Cryptographic error: {}", e),
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
}
