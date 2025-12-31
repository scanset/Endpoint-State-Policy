//! ESP Utils - Shared types and utilities for ESP lexer and parser
//!
//! This crate provides dependency-free, shared primitive types, enums, identifiers,
//! and helper utilities used by both the lexer and AST/parser for the ESP language.

pub mod span;

pub use span::{Position, SourceMap, Span, Spanned};
