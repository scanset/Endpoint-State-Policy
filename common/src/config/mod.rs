//! Configuration module for ESP
//!
//! Provides compile-time constants and runtime configuration types.

pub mod constants;
pub mod runtime;

// Re-export compile_time constants at module level
pub use constants::compile_time;
