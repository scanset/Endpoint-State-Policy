//! Conversion module for transforming compiler AST to execution types
//!
//! This module provides utilities to convert the ESP compiler's AST output
//! into the types used by the agent_core execution engine.
//!
//! # Example
//!
//! ```ignore
//! use agent_core::conversion::convert_ast_to_scanner_types;
//!
//! // After compiling an ESP file
//! let ast = compiler::compile_file("policy.esp")?;
//!
//! // Convert to execution types
//! let (variables, states, objects, runtime_ops, sets, criteria, metadata) =
//!     convert_ast_to_scanner_types(&ast)?;
//!
//! // Create execution context and run
//! let context = ExecutionContext::new(variables, states, objects, ...);
//! ```

mod from_ast;

pub use from_ast::{convert_ast_to_scanner_types, ConversionError, ConversionResult};
