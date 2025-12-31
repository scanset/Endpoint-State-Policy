//! Token system for ESP lexical analysis
//!
//! This module provides the complete token system for the ESP parser, implementing
//! lexical analysis (tokenization) of ESP source code. It converts raw text into
//! a stream of tokens that can be consumed by the parser.
//!
//! # Overview
//!
//! The tokens module handles the first phase of the ESP multi-pass architecture:
//! converting source text into a structured stream of tokens that represent
//! keywords, identifiers, literals, and operators defined in the ESP grammar.
//!
//! ## Key Components
//!
//! - **[`Token`]** - Complete enumeration of all ESP token types
//! - **[`StringLiteral`]** - Handles ESP string literal variants (backtick, raw, multiline)
//! - **[`TokenStream`]** - Efficient stream management with lookahead and filtering
//! - **[`SpannedToken`]** - Tokens with source location information
//!
//! ## Token Types
//!
//! ### Structural Tokens
//! Block delimiters (`DEF`/`DEF_END`, `STATE`/`STATE_END`, etc.), references
//! (`VAR`, `STATE_REF`, `OBJECT_REF`), and control flow keywords.
//!
//! ### Literal Tokens
//! - **String literals**: All ESP string variants with proper escape handling
//! - **Numeric literals**: 64-bit integers and IEEE 754 double-precision floats
//! - **Boolean literals**: `true` and `false`
//!
//! ### Operation Tokens
//! - **Comparison**: `=`, `!=`, `>`, `<`, `>=`, `<=`
//! - **String operations**: `ieq`, `contains`, `starts`, `ends`, etc.
//! - **Pattern operations**: `pattern_match`, `matches`
//! - **Set operations**: `subset_of`, `superset_of`
//! - **Logical operations**: `AND`, `OR`, `ONE`
//!
//! ### Identifier Tokens
//! Raw identifier text (semantic classification happens in later parser passes).
//!
//! ## String Literal Handling
//!
//! ESP supports multiple string literal formats:
//! - **Backtick strings**: `` `content` `` - standard strings with escape sequences
//! - **Raw strings**: `r`content`` - no escape processing
//! - **Multiline strings**: `` ```content``` `` - spanning multiple lines
//! - **Raw multiline**: `r```content``` `` - multiline without escapes
//! - **Empty strings**: `` `` `` - explicit empty string representation
//!
//! ## Token Stream Management
//!
//! The `TokenStream` provides efficient navigation through tokens with:
//! - **Lookahead**: Peek at upcoming tokens without advancing
//! - **Filtering**: Separate significant tokens from whitespace/comments
//! - **Checkpoints**: Save and restore stream positions for backtracking
//! - **Error recovery**: Skip to synchronization points after parse errors
//!
//! ## Token Classification
//!
//! Tokens are classified into categories for different parsing phases:
//! - `Structural` - Keywords that define program structure
//! - `Operation` - Operators and comparison functions
//! - `Literal` - Constant values (strings, numbers, booleans)
//! - `Identifier` - User-defined names (variables, states, objects)
//! - `Whitespace` - Formatting tokens (spaces, tabs, newlines)
//! - `Special` - Comments and end-of-file markers
//!
//! ## Parser Integration
//!
//! The token system integrates with the multi-pass parser architecture:
//! 1. **Lexical Analysis** (Pass 1) - Convert source text to token stream
//! 2. **Syntax Parsing** (Pass 2) - Use token stream to build AST
//! 3. **Later Passes** - Use token span information for error reporting
//!
//! All tokens include span information for precise error reporting and
//! source location tracking throughout the parsing pipeline.

pub mod token;
pub mod token_stream;

// Re-export key types for convenience
pub use token::{StringLiteral, Token, TokenClass};
pub use token_stream::{
    SpannedToken, SpannedTokenExt, TokenStream, TokenStreamBuilder, TokenStreamError,
};

// ADDED: Re-export classification functions for lexical analyzer
pub use token::{
    classify_operator_symbol, classify_operator_word, classify_word,
    is_context_sensitive_identifier, is_data_type_identifier, is_operator_symbol,
};

// Re-export span types from utils
pub use common::utils::{Position, SourceMap, Span, Spanned};

/// Module version
pub const VERSION: &str = "1.0.0";
