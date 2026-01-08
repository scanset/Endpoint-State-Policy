//! # ESP Contract Kit
//!
//! Extended scanner strategies for ESP compliance validation.
//! Provides collectors, executors, contracts, and a high-level API for executing scans.
//!
//! ## Modules
//!
//! - `collectors` - Data collection from system (files, commands)
//! - `executors` - Validation logic for each CTN type
//! - `contracts` - CTN type definitions and field mappings
//! - `commands` - Platform-specific command whitelists
//! - `execution_api` - High-level scan execution API
//!
//! ## Usage
//!
//! To build a scanner, create a new crate that:
//! 1. Imports collectors/executors from `contract_kit`
//! 2. Creates a `CtnStrategyRegistry` using `execution_api` types
//! 3. Calls `scan_file()` or `scan_ast()`
//!
//! ```rust,ignore
//! use contract_kit::execution_api::{
//!     scan_file, CtnStrategyRegistry, CtnStrategy,
//! };
//! use contract_kit::collectors::FileMetadataCollector;
//! use contract_kit::executors::FilePermissionsExecutor;
//!
//! // Build registry with your strategies
//! let mut registry = CtnStrategyRegistry::new();
//! registry.register(
//!     "unix_file_permissions",
//!     CtnStrategy::new(
//!         Box::new(FileMetadataCollector::new()),
//!         Box::new(FilePermissionsExecutor::new()),
//!     ),
//! )?;
//!
//! // Scan
//! let result = scan_file("policy.esp", Arc::new(registry))?;
//! ```

pub mod collectors;
pub mod commands;
pub mod contracts;
pub mod execution_api;
pub mod executors;
