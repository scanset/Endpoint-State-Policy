//! Transparency proof types for certificate transparency log integration
//!
//! These types represent proofs from the Trust System's append-only
//! transparency log, providing cryptographic evidence that a signing
//! certificate was logged at issuance time.
//!
//! ## Schema Reference
//!
//! Implements Section 3.5.9 of ESP v1.1.0 Canonical Execution Schema.
//!
//! ## Security Properties
//!
//! - **Tamper evidence**: Any modification to the log changes the root hash
//! - **Non-repudiation**: Certificate issuance is permanently recorded
//! - **Auditability**: Third parties can verify certificate was logged
//!
//! ## Verification
//!
//! To verify an inclusion proof:
//! 1. Reconstruct the leaf hash: `SHA256(0x00 || certificate_pem || signer_id)`
//! 2. Walk the proof path using sibling hashes
//! 3. Compare computed root with `inclusion_proof.root_hash`
//! 4. Optionally verify against a signed checkpoint from the transparency log

use serde::{Deserialize, Serialize};

// ============================================================================
// TransparencyProof
// ============================================================================

/// Transparency proof from the certificate transparency log
///
/// Provides cryptographic proof that a signing certificate was logged
/// to the Trust System's append-only transparency log at issuance time.
///
/// ## Example
///
/// ```json
/// {
///   "log_index": 47,
///   "inclusion_proof": {
///     "tree_size": 100,
///     "root_hash": "f6e5d4c3b2a1...",
///     "hashes": ["abc123...", "def456..."]
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TransparencyProof {
    /// Index of the certificate entry in the transparency log
    ///
    /// This is a monotonically increasing value assigned when the
    /// certificate was logged. Can be used to fetch the entry directly.
    pub log_index: u64,

    /// Merkle tree inclusion proof
    ///
    /// Contains the sibling hashes needed to recompute the root hash
    /// and verify the certificate exists at the claimed index.
    pub inclusion_proof: InclusionProof,
}

impl TransparencyProof {
    /// Create a new transparency proof
    pub fn new(log_index: u64, inclusion_proof: InclusionProof) -> Self {
        Self {
            log_index,
            inclusion_proof,
        }
    }

    /// Create a transparency proof with individual components
    pub fn from_parts(
        log_index: u64,
        tree_size: u64,
        root_hash: impl Into<String>,
        hashes: Vec<String>,
    ) -> Self {
        Self {
            log_index,
            inclusion_proof: InclusionProof::new(tree_size, root_hash, hashes),
        }
    }

    /// Get the tree size at the time the proof was generated
    pub fn tree_size(&self) -> u64 {
        self.inclusion_proof.tree_size
    }

    /// Get the root hash
    pub fn root_hash(&self) -> &str {
        &self.inclusion_proof.root_hash
    }

    /// Get the number of sibling hashes in the proof
    pub fn proof_length(&self) -> usize {
        self.inclusion_proof.hashes.len()
    }
}

// ============================================================================
// InclusionProof
// ============================================================================

/// Merkle tree inclusion proof
///
/// Contains the sibling hashes needed to verify that an entry exists
/// at a specific index in the Merkle tree. Follows RFC 6962 structure.
///
/// ## Verification Algorithm
///
/// ```text
/// 1. Start with leaf_hash (computed from certificate + signer_id)
/// 2. For each sibling hash in proof path:
///    - If current node is left child:  current = SHA256(0x01 || current || sibling)
///    - If current node is right child: current = SHA256(0x01 || sibling || current)
/// 3. Compare final current with root_hash
/// ```
///
/// ## Example
///
/// ```json
/// {
///   "tree_size": 100,
///   "root_hash": "f6e5d4c3b2a1e5d4c3b2a1f6e5d4c3b2a1e5d4c3b2a1f6e5d4c3b2a1e5d4c3b2",
///   "hashes": ["abc123...", "def456...", "789ghi..."]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProof {
    /// Size of the Merkle tree when the proof was generated
    ///
    /// This must be greater than the log_index of the entry being proved.
    /// A proof is valid for any tree size >= this value (consistency).
    pub tree_size: u64,

    /// Root hash of the Merkle tree (hex-encoded SHA-256)
    ///
    /// This is the hash at the top of the tree that commits to all entries.
    /// Should be verified against a signed checkpoint for full security.
    pub root_hash: String,

    /// Sibling hashes for proof verification (hex-encoded SHA-256)
    ///
    /// Ordered from leaf level to root. The number of hashes depends on
    /// the tree structure and the position of the entry being proved.
    pub hashes: Vec<String>,
}

impl InclusionProof {
    /// Create a new inclusion proof
    pub fn new(tree_size: u64, root_hash: impl Into<String>, hashes: Vec<String>) -> Self {
        Self {
            tree_size,
            root_hash: root_hash.into(),
            hashes,
        }
    }

    /// Create an empty inclusion proof (for cases where proof is not available)
    pub fn empty() -> Self {
        Self {
            tree_size: 0,
            root_hash: String::new(),
            hashes: Vec::new(),
        }
    }

    /// Check if this proof is empty/unset
    pub fn is_empty(&self) -> bool {
        self.tree_size == 0 && self.root_hash.is_empty() && self.hashes.is_empty()
    }

    /// Get the depth of the proof (number of sibling hashes)
    pub fn depth(&self) -> usize {
        self.hashes.len()
    }
}

impl Default for InclusionProof {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inclusion_proof_new() {
        let proof = InclusionProof::new(
            100,
            "f6e5d4c3b2a1e5d4c3b2a1f6e5d4c3b2a1e5d4c3b2a1f6e5d4c3b2a1e5d4c3b2",
            vec!["abc123".to_string(), "def456".to_string()],
        );

        assert_eq!(proof.tree_size, 100);
        assert_eq!(
            proof.root_hash,
            "f6e5d4c3b2a1e5d4c3b2a1f6e5d4c3b2a1e5d4c3b2a1f6e5d4c3b2a1e5d4c3b2"
        );
        assert_eq!(proof.hashes.len(), 2);
        assert_eq!(proof.depth(), 2);
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_inclusion_proof_empty() {
        let proof = InclusionProof::empty();

        assert_eq!(proof.tree_size, 0);
        assert!(proof.root_hash.is_empty());
        assert!(proof.hashes.is_empty());
        assert!(proof.is_empty());
    }

    #[test]
    fn test_inclusion_proof_default() {
        let proof = InclusionProof::default();
        assert!(proof.is_empty());
    }

    #[test]
    fn test_transparency_proof_new() {
        let inclusion = InclusionProof::new(100, "root_hash_here", vec!["hash1".to_string()]);

        let proof = TransparencyProof::new(47, inclusion);

        assert_eq!(proof.log_index, 47);
        assert_eq!(proof.tree_size(), 100);
        assert_eq!(proof.root_hash(), "root_hash_here");
        assert_eq!(proof.proof_length(), 1);
    }

    #[test]
    fn test_transparency_proof_from_parts() {
        let proof = TransparencyProof::from_parts(
            47,
            100,
            "f6e5d4c3b2a1",
            vec!["abc123".to_string(), "def456".to_string()],
        );

        assert_eq!(proof.log_index, 47);
        assert_eq!(proof.inclusion_proof.tree_size, 100);
        assert_eq!(proof.inclusion_proof.root_hash, "f6e5d4c3b2a1");
        assert_eq!(proof.inclusion_proof.hashes.len(), 2);
    }

    #[test]
    fn test_transparency_proof_default() {
        let proof = TransparencyProof::default();

        assert_eq!(proof.log_index, 0);
        assert!(proof.inclusion_proof.is_empty());
    }

    #[test]
    fn test_inclusion_proof_serialization() {
        let proof = InclusionProof::new(
            100,
            "f6e5d4c3b2a1e5d4c3b2a1f6e5d4c3b2a1e5d4c3b2a1f6e5d4c3b2a1e5d4c3b2",
            vec!["abc123".to_string(), "def456".to_string()],
        );

        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"tree_size\":100"));
        assert!(json.contains("\"root_hash\":"));
        assert!(json.contains("\"hashes\":"));

        let parsed: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn test_transparency_proof_serialization() {
        let proof = TransparencyProof::from_parts(
            47,
            100,
            "f6e5d4c3b2a1",
            vec!["abc123".to_string(), "def456".to_string()],
        );

        let json = serde_json::to_string_pretty(&proof).unwrap();
        assert!(json.contains("\"log_index\": 47"));
        assert!(json.contains("\"inclusion_proof\":"));

        let parsed: TransparencyProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn test_transparency_proof_full_example() {
        // Example from the schema document
        let json = r#"{
            "log_index": 47,
            "inclusion_proof": {
                "tree_size": 100,
                "root_hash": "abc123def456789",
                "hashes": ["hash1", "hash2", "hash3"]
            }
        }"#;

        let proof: TransparencyProof = serde_json::from_str(json).unwrap();

        assert_eq!(proof.log_index, 47);
        assert_eq!(proof.inclusion_proof.tree_size, 100);
        assert_eq!(proof.inclusion_proof.root_hash, "abc123def456789");
        assert_eq!(proof.inclusion_proof.hashes.len(), 3);
        assert_eq!(proof.inclusion_proof.hashes[0], "hash1");
        assert_eq!(proof.inclusion_proof.hashes[1], "hash2");
        assert_eq!(proof.inclusion_proof.hashes[2], "hash3");
    }

    #[test]
    fn test_equality() {
        let proof1 = TransparencyProof::from_parts(47, 100, "root", vec!["h1".to_string()]);

        let proof2 = TransparencyProof::from_parts(47, 100, "root", vec!["h1".to_string()]);

        let proof3 = TransparencyProof::from_parts(48, 100, "root", vec!["h1".to_string()]);

        assert_eq!(proof1, proof2);
        assert_ne!(proof1, proof3);
    }
}
