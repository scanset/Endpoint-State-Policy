//! Windows CNG (BCrypt) backend for FIPS 140-3 compliant hashing
//!
//! Uses Windows Cryptography Next Generation API which is:
//! - Built into all modern Windows versions (10, 11, Server 2016+)
//! - FIPS 140-3 certified as part of Windows
//! - No external dependencies required

use super::HashingError;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE,
    BCRYPT_HASH_HANDLE, BCRYPT_HASH_LENGTH, BCRYPT_SHA256_ALGORITHM,
};

/// SHA-256 digest length in bytes
const SHA256_DIGEST_LENGTH: usize = 32;

/// Compute SHA-256 hash using Windows CNG (BCrypt)
pub fn sha256(data: &[u8]) -> Result<Vec<u8>, HashingError> {
    unsafe {
        // Open algorithm provider
        let mut alg_handle = BCRYPT_ALG_HANDLE::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg_handle,
            BCRYPT_SHA256_ALGORITHM,
            PCWSTR::null(),
            0,
        );

        if status.is_err() {
            return Err(HashingError::CryptoError(format!(
                "BCryptOpenAlgorithmProvider failed: {:?}",
                status
            )));
        }

        // Ensure we close the algorithm provider when done
        let _alg_guard = AlgHandleGuard(alg_handle);

        // Get hash length to verify
        let mut hash_length: u32 = 0;
        let mut result_length: u32 = 0;
        let status = BCryptGetProperty(
            alg_handle,
            BCRYPT_HASH_LENGTH,
            Some(&mut hash_length as *mut u32 as *mut u8),
            std::mem::size_of::<u32>() as u32,
            &mut result_length,
            0,
        );

        if status.is_err() {
            return Err(HashingError::CryptoError(format!(
                "BCryptGetProperty failed: {:?}",
                status
            )));
        }

        if hash_length as usize != SHA256_DIGEST_LENGTH {
            return Err(HashingError::CryptoError(format!(
                "Unexpected hash length: {} (expected {})",
                hash_length, SHA256_DIGEST_LENGTH
            )));
        }

        // Create hash object
        let mut hash_handle = BCRYPT_HASH_HANDLE::default();
        let status = BCryptCreateHash(alg_handle, &mut hash_handle, None, None, 0);

        if status.is_err() {
            return Err(HashingError::CryptoError(format!(
                "BCryptCreateHash failed: {:?}",
                status
            )));
        }

        // Ensure we destroy the hash handle when done
        let _hash_guard = HashHandleGuard(hash_handle);

        // Hash the data
        let status = BCryptHashData(hash_handle, data, 0);

        if status.is_err() {
            return Err(HashingError::CryptoError(format!(
                "BCryptHashData failed: {:?}",
                status
            )));
        }

        // Finalize and get the hash
        let mut hash_output = vec![0u8; SHA256_DIGEST_LENGTH];
        let status = BCryptFinishHash(hash_handle, &mut hash_output, 0);

        if status.is_err() {
            return Err(HashingError::CryptoError(format!(
                "BCryptFinishHash failed: {:?}",
                status
            )));
        }

        Ok(hash_output)
    }
}

/// RAII guard for BCrypt algorithm handle
struct AlgHandleGuard(BCRYPT_ALG_HANDLE);

impl Drop for AlgHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}

/// RAII guard for BCrypt hash handle
struct HashHandleGuard(BCRYPT_HASH_HANDLE);

impl Drop for HashHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptDestroyHash(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_value() {
        let data = b"hello world";
        let hash = sha256(data).unwrap();

        // Known SHA-256 hash of "hello world"
        assert_eq!(hash.len(), SHA256_DIGEST_LENGTH);

        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let actual_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        assert_eq!(actual_hex, expected_hex);
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"").unwrap();

        // Known SHA-256 hash of empty string
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let actual_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        assert_eq!(actual_hex, expected_hex);
    }

    #[test]
    fn test_sha256_large_data() {
        // Test with larger data to ensure buffer handling is correct
        let data = vec![0xABu8; 10000];
        let hash = sha256(&data).unwrap();

        assert_eq!(hash.len(), SHA256_DIGEST_LENGTH);
    }
}
