//! Identity status types for PKI bootstrap tracking
//!
//! Tracks whether the agent successfully established PKI identity
//! and provides diagnostic information if bootstrap failed.
//!
//! ## Schema Reference
//!
//! Implements Section 3.6 of ESP v1.1.0 Canonical Execution Schema.
//!
//! ## Usage
//!
//! The `IdentityStatus` is included in every result envelope to indicate
//! whether the result was signed with a PKI identity or is unsigned.
//!
//! ```rust,ignore
//! // Successful bootstrap
//! let status = IdentityStatus::success("scanset://prod/aws/account/123/workload/agent");
//!
//! // Failed bootstrap
//! let status = IdentityStatus::failed(
//!     "unsigned:agent:hostname-abc123",
//!     "Failed to connect to orchestrator",
//!     "BOOTSTRAP_CONNECTION_FAILED",
//! );
//!
//! // Bootstrap disabled
//! let status = IdentityStatus::disabled("unsigned:agent:hostname-abc123");
//! ```

use serde::{Deserialize, Serialize};

// ============================================================================
// IdentityStatus
// ============================================================================

/// Identity bootstrap status
///
/// Indicates whether the agent successfully established PKI identity
/// and provides diagnostic information if bootstrap failed.
///
/// ## Signed Results
///
/// When `bootstrapped` is `true`:
/// - `signer_id` contains the PKI SAN URI from the certificate
/// - `error` and `error_code` are `None`
/// - The envelope's `signature` field will be populated
///
/// ## Unsigned Results
///
/// When `bootstrapped` is `false`:
/// - `signer_id` contains a placeholder: `unsigned:agent:{hostname}-{suffix}`
/// - `error` contains a human-readable error message
/// - `error_code` contains a machine-readable code
/// - The envelope's `signature` field will be `null`
///
/// ## Example (Success)
///
/// ```json
/// {
///   "bootstrapped": true,
///   "signer_id": "scanset://prod/aws/account/123456789012/workload/esp-agent",
///   "error": null,
///   "error_code": null
/// }
/// ```
///
/// ## Example (Failure)
///
/// ```json
/// {
///   "bootstrapped": false,
///   "signer_id": "unsigned:agent:server01-a1b2c3d4",
///   "error": "Failed to connect to orchestrator: connection refused",
///   "error_code": "BOOTSTRAP_CONNECTION_FAILED"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityStatus {
    /// Whether PKI identity was successfully established
    pub bootstrapped: bool,

    /// Identity string
    ///
    /// Format depends on bootstrap status:
    /// - Success: PKI SAN URI (e.g., `scanset://prod/aws/account/123/workload/agent`)
    /// - Failure: Placeholder (e.g., `unsigned:agent:hostname-abc123`)
    pub signer_id: String,

    /// Human-readable error message if bootstrap failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Machine-readable error code if bootstrap failed
    ///
    /// Standard codes:
    /// - `BOOTSTRAP_DISABLED` - Identity bootstrap disabled in configuration
    /// - `BOOTSTRAP_CONNECTION_FAILED` - Could not connect to orchestrator/IdP
    /// - `BOOTSTRAP_AUTH_FAILED` - Authentication failed (invalid credentials)
    /// - `BOOTSTRAP_CERT_FAILED` - Certificate enrollment rejected
    /// - `BOOTSTRAP_TIMEOUT` - Bootstrap operation timed out
    /// - `BOOTSTRAP_TLS_ERROR` - TLS handshake or verification failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl IdentityStatus {
    /// Create status for successful bootstrap
    ///
    /// # Arguments
    ///
    /// * `signer_id` - The PKI SAN URI from the workload certificate
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let status = IdentityStatus::success(
    ///     "scanset://prod/aws/account/123456789012/workload/esp-agent"
    /// );
    /// ```
    pub fn success(signer_id: impl Into<String>) -> Self {
        Self {
            bootstrapped: true,
            signer_id: signer_id.into(),
            error: None,
            error_code: None,
        }
    }

    /// Create status for failed bootstrap
    ///
    /// # Arguments
    ///
    /// * `unsigned_signer_id` - Placeholder signer ID for unsigned results
    /// * `error` - Human-readable error message
    /// * `error_code` - Machine-readable error code
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let status = IdentityStatus::failed(
    ///     "unsigned:agent:server01-a1b2c3d4",
    ///     "Failed to connect to orchestrator: connection refused",
    ///     "BOOTSTRAP_CONNECTION_FAILED",
    /// );
    /// ```
    pub fn failed(
        unsigned_signer_id: impl Into<String>,
        error: impl Into<String>,
        error_code: impl Into<String>,
    ) -> Self {
        Self {
            bootstrapped: false,
            signer_id: unsigned_signer_id.into(),
            error: Some(error.into()),
            error_code: Some(error_code.into()),
        }
    }

    /// Create status for disabled identity bootstrap
    ///
    /// Used when identity bootstrap is disabled in configuration.
    ///
    /// # Arguments
    ///
    /// * `unsigned_signer_id` - Placeholder signer ID for unsigned results
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let status = IdentityStatus::disabled("unsigned:agent:server01-a1b2c3d4");
    /// ```
    pub fn disabled(unsigned_signer_id: impl Into<String>) -> Self {
        Self {
            bootstrapped: false,
            signer_id: unsigned_signer_id.into(),
            error: Some("Identity bootstrap disabled in configuration".to_string()),
            error_code: Some("BOOTSTRAP_DISABLED".to_string()),
        }
    }

    /// Create status indicating identity was not configured
    ///
    /// Used as a fallback when no identity status was explicitly set.
    /// This should generally not appear in production results.
    pub fn not_configured() -> Self {
        Self {
            bootstrapped: false,
            signer_id: "unsigned:agent:unknown".to_string(),
            error: Some("Identity status not configured".to_string()),
            error_code: Some("IDENTITY_NOT_CONFIGURED".to_string()),
        }
    }

    /// Check if identity was successfully bootstrapped
    pub fn is_bootstrapped(&self) -> bool {
        self.bootstrapped
    }

    /// Check if there was an error during bootstrap
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get the error code if present
    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }

    /// Get the error message if present
    pub fn error_message(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Check if bootstrap was disabled (not an error, just not attempted)
    pub fn is_disabled(&self) -> bool {
        self.error_code.as_deref() == Some("BOOTSTRAP_DISABLED")
    }
}

impl Default for IdentityStatus {
    /// Default to not configured state
    ///
    /// This default should be overwritten before the result is finalized.
    /// It exists primarily for builder patterns and test convenience.
    fn default() -> Self {
        Self::not_configured()
    }
}

// ============================================================================
// Error Code Constants
// ============================================================================

/// Standard bootstrap error codes
pub mod error_codes {
    /// Identity bootstrap disabled in configuration
    pub const BOOTSTRAP_DISABLED: &str = "BOOTSTRAP_DISABLED";

    /// Could not connect to orchestrator or identity provider
    pub const BOOTSTRAP_CONNECTION_FAILED: &str = "BOOTSTRAP_CONNECTION_FAILED";

    /// Authentication failed (invalid AWS credentials, JWT rejected)
    pub const BOOTSTRAP_AUTH_FAILED: &str = "BOOTSTRAP_AUTH_FAILED";

    /// Certificate enrollment rejected by certificate issuer
    pub const BOOTSTRAP_CERT_FAILED: &str = "BOOTSTRAP_CERT_FAILED";

    /// Bootstrap operation timed out
    pub const BOOTSTRAP_TIMEOUT: &str = "BOOTSTRAP_TIMEOUT";

    /// TLS handshake or certificate verification failed
    pub const BOOTSTRAP_TLS_ERROR: &str = "BOOTSTRAP_TLS_ERROR";

    /// Key generation failed
    pub const BOOTSTRAP_KEY_ERROR: &str = "BOOTSTRAP_KEY_ERROR";

    /// Identity status not configured (should not appear in production)
    pub const IDENTITY_NOT_CONFIGURED: &str = "IDENTITY_NOT_CONFIGURED";
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate an unsigned signer ID from hostname
///
/// Format: `unsigned:agent:{hostname}-{suffix}`
///
/// The suffix provides uniqueness when the hostname alone is not sufficient.
pub fn generate_unsigned_signer_id(hostname: &str, suffix: &str) -> String {
    format!("unsigned:agent:{}-{}", hostname, suffix)
}

/// Generate an unsigned signer ID with auto-generated suffix
///
/// Uses a hash of the current timestamp for the suffix.
pub fn generate_unsigned_signer_id_auto(hostname: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // Simple hash for suffix
    let suffix = format!("{:08x}", (timestamp & 0xFFFF_FFFF) as u32);

    generate_unsigned_signer_id(hostname, &suffix)
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
    fn test_identity_status_success() {
        let status =
            IdentityStatus::success("scanset://prod/aws/account/123456789012/workload/esp-agent");

        assert!(status.is_bootstrapped());
        assert!(!status.has_error());
        assert!(status.error.is_none());
        assert!(status.error_code.is_none());
        assert_eq!(
            status.signer_id,
            "scanset://prod/aws/account/123456789012/workload/esp-agent"
        );
    }

    #[test]
    fn test_identity_status_failed() {
        let status = IdentityStatus::failed(
            "unsigned:agent:server01-abc123",
            "Failed to connect to orchestrator: connection refused",
            "BOOTSTRAP_CONNECTION_FAILED",
        );

        assert!(!status.is_bootstrapped());
        assert!(status.has_error());
        assert_eq!(status.signer_id, "unsigned:agent:server01-abc123");
        assert_eq!(
            status.error_message(),
            Some("Failed to connect to orchestrator: connection refused")
        );
        assert_eq!(status.error_code(), Some("BOOTSTRAP_CONNECTION_FAILED"));
    }

    #[test]
    fn test_identity_status_disabled() {
        let status = IdentityStatus::disabled("unsigned:agent:server01-abc123");

        assert!(!status.is_bootstrapped());
        assert!(status.has_error());
        assert!(status.is_disabled());
        assert_eq!(
            status.error_message(),
            Some("Identity bootstrap disabled in configuration")
        );
        assert_eq!(status.error_code(), Some("BOOTSTRAP_DISABLED"));
    }

    #[test]
    fn test_identity_status_not_configured() {
        let status = IdentityStatus::not_configured();

        assert!(!status.is_bootstrapped());
        assert!(status.has_error());
        assert_eq!(status.signer_id, "unsigned:agent:unknown");
        assert_eq!(status.error_code(), Some("IDENTITY_NOT_CONFIGURED"));
    }

    #[test]
    fn test_identity_status_default() {
        let status = IdentityStatus::default();

        assert!(!status.is_bootstrapped());
        assert_eq!(status.error_code(), Some("IDENTITY_NOT_CONFIGURED"));
    }

    #[test]
    fn test_serialization_success() {
        let status =
            IdentityStatus::success("scanset://prod/aws/account/123456789012/workload/esp-agent");

        let json = serde_json::to_string(&status).unwrap();

        // error and error_code should be omitted when None
        assert!(!json.contains("\"error\":"));
        assert!(!json.contains("\"error_code\":"));
        assert!(json.contains("\"bootstrapped\":true"));
        assert!(json.contains("\"signer_id\":"));

        let parsed: IdentityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }

    #[test]
    fn test_serialization_failed() {
        let status = IdentityStatus::failed(
            "unsigned:agent:server01-abc123",
            "Connection refused",
            "BOOTSTRAP_CONNECTION_FAILED",
        );

        let json = serde_json::to_string_pretty(&status).unwrap();

        assert!(json.contains("\"bootstrapped\": false"));
        assert!(json.contains("\"error\":"));
        assert!(json.contains("\"error_code\":"));
        assert!(json.contains("BOOTSTRAP_CONNECTION_FAILED"));

        let parsed: IdentityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }

    #[test]
    fn test_serialization_full_example_success() {
        let json = r#"{
            "bootstrapped": true,
            "signer_id": "scanset://prod/aws/account/123456789012/workload/esp-agent"
        }"#;

        let status: IdentityStatus = serde_json::from_str(json).unwrap();

        assert!(status.is_bootstrapped());
        assert!(!status.has_error());
        assert_eq!(
            status.signer_id,
            "scanset://prod/aws/account/123456789012/workload/esp-agent"
        );
    }

    #[test]
    fn test_serialization_full_example_failed() {
        let json = r#"{
            "bootstrapped": false,
            "signer_id": "unsigned:agent:server01-a1b2c3d4",
            "error": "Failed to connect to orchestrator: connection refused",
            "error_code": "BOOTSTRAP_CONNECTION_FAILED"
        }"#;

        let status: IdentityStatus = serde_json::from_str(json).unwrap();

        assert!(!status.is_bootstrapped());
        assert!(status.has_error());
        assert_eq!(status.signer_id, "unsigned:agent:server01-a1b2c3d4");
        assert_eq!(
            status.error_message(),
            Some("Failed to connect to orchestrator: connection refused")
        );
        assert_eq!(status.error_code(), Some("BOOTSTRAP_CONNECTION_FAILED"));
    }

    #[test]
    fn test_equality() {
        let status1 = IdentityStatus::success("signer1");
        let status2 = IdentityStatus::success("signer1");
        let status3 = IdentityStatus::success("signer2");

        assert_eq!(status1, status2);
        assert_ne!(status1, status3);
    }

    #[test]
    fn test_generate_unsigned_signer_id() {
        let signer_id = generate_unsigned_signer_id("myhost", "abc123");
        assert_eq!(signer_id, "unsigned:agent:myhost-abc123");
    }

    #[test]
    fn test_generate_unsigned_signer_id_auto() {
        let signer_id = generate_unsigned_signer_id_auto("myhost");

        assert!(signer_id.starts_with("unsigned:agent:myhost-"));
        // Should have 8 hex chars as suffix
        let suffix = signer_id.strip_prefix("unsigned:agent:myhost-").unwrap();
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_error_codes_constants() {
        assert_eq!(error_codes::BOOTSTRAP_DISABLED, "BOOTSTRAP_DISABLED");
        assert_eq!(
            error_codes::BOOTSTRAP_CONNECTION_FAILED,
            "BOOTSTRAP_CONNECTION_FAILED"
        );
        assert_eq!(error_codes::BOOTSTRAP_AUTH_FAILED, "BOOTSTRAP_AUTH_FAILED");
        assert_eq!(error_codes::BOOTSTRAP_CERT_FAILED, "BOOTSTRAP_CERT_FAILED");
        assert_eq!(error_codes::BOOTSTRAP_TIMEOUT, "BOOTSTRAP_TIMEOUT");
        assert_eq!(error_codes::BOOTSTRAP_TLS_ERROR, "BOOTSTRAP_TLS_ERROR");
    }
}
