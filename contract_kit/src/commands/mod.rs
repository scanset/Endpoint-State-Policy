//! Command execution configurations for different platforms
//!
//! Provides whitelisted command executors for secure system scanning.

pub mod k8s;
pub mod rhel9;

pub use k8s::create_k8s_command_executor;
pub use rhel9::create_rhel9_command_executor;
