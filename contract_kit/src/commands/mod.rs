//! Command execution configurations for different platforms
//!
//! Provides whitelisted command executors for secure system scanning.

pub mod k8s;

pub use k8s::create_k8s_command_executor;
