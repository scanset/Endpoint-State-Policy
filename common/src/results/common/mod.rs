//! Common types shared between attestation and full-results features
//!
//! These types are used regardless of which feature set is enabled.

pub mod control;
pub mod counts;
pub mod criticality;
pub mod outcome;
pub mod policy_outcome;

// Re-exports for convenience
pub use control::{ControlMapping, ControlMappingError};
pub use counts::{CriteriaCounts, ResultCounts};
pub use criticality::{Criticality, Weight};
pub use outcome::Outcome;
pub use policy_outcome::PolicyOutcome;
