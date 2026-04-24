//! OpenSSL backend for FIPS 140-3 compliant hashing
//!
//! Used on Linux and other Unix platforms.

use super::HashingError;
use openssl::hash::{hash, MessageDigest};

/// Compute SHA-256 hash using OpenSSL
pub fn sha256(data: &[u8]) -> Result<Vec<u8>, HashingError> {
    hash(MessageDigest::sha256(), data)
        .map(|d| d.to_vec())
        .map_err(|e| HashingError::CryptoError(format!("OpenSSL error: {}", e)))
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::super::hex_encode;
    use super::*;

    #[test]
    fn test_sha256_known_value() {
        let data = b"hello world";
        let hash = sha256(data).unwrap();

        // Known SHA-256 hash of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(hex_encode(&hash), expected);
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"").unwrap();

        // Known SHA-256 hash of empty string
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex_encode(&hash), expected);
    }
}
