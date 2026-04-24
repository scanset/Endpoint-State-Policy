//! Shared primitive types used throughout the `results` module (outcomes,
//! criticality levels, control mappings, weights, counts). Always compiled.

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
