//! Source location tracking for ESP Compiler
//!
//! This module provides types for tracking positions and spans in source text
//! during parsing and validation. Accurate location tracking is essential for
//! providing helpful error messages.
use serde::{Deserialize, Serialize};
use std::fmt;

/// A position in source text with line, column, and byte offset.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
pub struct Position {
    /// Byte offset from start of input (0-based)
    pub offset: usize,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based)
    pub column: u32,
}

impl Position {
    /// Create a new position
    pub fn new(offset: usize, line: u32, column: u32) -> Self {
        Self {
            offset,
            line,
            column,
        }
    }

    /// Create the starting position (offset 0, line 1, column 1)
    pub fn start() -> Self {
        Self {
            offset: 0,
            line: 1,
            column: 1,
        }
    }

    /// Advance position by one character
    pub fn advance(self, ch: char) -> Self {
        match ch {
            '\n' => Self {
                offset: self.offset + 1,
                line: self.line + 1,
                column: 1,
            },
            '\t' => Self {
                offset: self.offset + 1,
                line: self.line,
                column: self.column + 4 - ((self.column - 1) % 4),
            },
            _ => Self {
                offset: self.offset + ch.len_utf8(),
                line: self.line,
                column: self.column + 1,
            },
        }
    }

    /// Advance position by a string
    pub fn advance_str(self, s: &str) -> Self {
        s.chars().fold(self, |pos, ch| pos.advance(ch))
    }

    /// Advance position by n bytes (useful for known ASCII sequences)
    pub fn advance_bytes(self, n: usize) -> Self {
        Self {
            offset: self.offset + n,
            line: self.line,
            column: self.column + n as u32,
        }
    }
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// A span of source text from start to end position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Span {
    /// Start position (inclusive)
    pub start: Position,
    /// End position (exclusive)
    pub end: Position,
}

impl Span {
    /// Create a new span
    pub fn new(start: Position, end: Position) -> Self {
        debug_assert!(
            start.offset <= end.offset,
            "Span start must not be after end"
        );
        Self { start, end }
    }

    /// Get the start position of this span
    pub fn start(&self) -> Position {
        self.start
    }

    /// Get the end position of this span
    pub fn end(&self) -> Position {
        self.end
    }

    /// Create a single-character span
    pub fn single(pos: Position) -> Self {
        let end = Position {
            offset: pos.offset + 1,
            line: pos.line,
            column: pos.column + 1,
        };
        Self { start: pos, end }
    }

    /// Create a span from byte offsets (useful for testing)
    pub fn from_offsets(start: usize, end: usize) -> Self {
        Self {
            start: Position::new(start, 0, 0),
            end: Position::new(end, 0, 0),
        }
    }

    /// Merge two spans into one covering both
    pub fn merge(self, other: Self) -> Self {
        let start = if self.start.offset < other.start.offset {
            self.start
        } else {
            other.start
        };

        let end = if self.end.offset > other.end.offset {
            self.end
        } else {
            other.end
        };

        Self { start, end }
    }

    /// Extend this span to include another span
    pub fn extend(self, other: Self) -> Self {
        self.merge(other)
    }

    /// Combine this span with another to create a span that covers both
    pub fn to(&self, other: Span) -> Span {
        let start = if self.start().offset < other.start().offset {
            self.start()
        } else {
            other.start()
        };
        let end = if self.end().offset > other.end().offset {
            self.end()
        } else {
            other.end()
        };
        Span::new(start, end)
    }

    /// Get the byte length of this span
    pub fn len(&self) -> usize {
        self.end.offset - self.start.offset
    }

    /// Check if this span is empty
    pub fn is_empty(&self) -> bool {
        self.start.offset == self.end.offset
    }

    /// Check if this span contains a position
    pub fn contains(&self, pos: Position) -> bool {
        pos.offset >= self.start.offset && pos.offset < self.end.offset
    }

    /// Check if this span contains another span
    pub fn contains_span(&self, other: &Span) -> bool {
        self.contains(other.start) && other.end.offset <= self.end.offset
    }

    /// Get the source text for this span from the input
    pub fn slice<'a>(&self, input: &'a str) -> &'a str {
        &input[self.start.offset..self.end.offset]
    }

    /// Create an unknown/dummy span (useful for generated nodes)
    pub fn dummy() -> Self {
        Self {
            start: Position::start(),
            end: Position::start(),
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start.line == self.end.line {
            write!(
                f,
                "{}:{}-{}",
                self.start.line, self.start.column, self.end.column
            )
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// A value with its source location
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Spanned<T> {
    /// The value
    pub value: T,
    /// The source span
    pub span: Span,
}

impl<T> Spanned<T> {
    /// Create a new spanned value
    pub fn new(value: T, span: Span) -> Self {
        Self { value, span }
    }

    /// Map the value while preserving the span
    pub fn map<U, F>(self, f: F) -> Spanned<U>
    where
        F: FnOnce(T) -> U,
    {
        Spanned {
            value: f(self.value),
            span: self.span,
        }
    }

    /// Get a reference to the inner value
    pub fn as_ref(&self) -> Spanned<&T> {
        Spanned {
            value: &self.value,
            span: self.span,
        }
    }

    /// Get the inner value
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T: fmt::Display> fmt::Display for Spanned<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// A source map that tracks line starts for efficient position lookup
#[derive(Debug, Clone)]
pub struct SourceMap {
    /// The original source text
    pub source: String,
    /// Byte offsets of line starts
    line_starts: Vec<usize>,
}

impl SourceMap {
    /// Create a new source map from source text
    pub fn new(source: String) -> Self {
        let mut line_starts = vec![0];
        for (offset, ch) in source.char_indices() {
            if ch == '\n' {
                line_starts.push(offset + 1);
            }
        }
        Self {
            source,
            line_starts,
        }
    }

    /// Get the line and column for a byte offset
    pub fn position_at(&self, offset: usize) -> Position {
        let line = self
            .line_starts
            .binary_search(&offset)
            .unwrap_or_else(|i| i - 1);

        let line_start = self.line_starts[line];
        let column = self.source[line_start..offset].chars().count();

        Position::new(offset, (line + 1) as u32, (column + 1) as u32)
    }

    /// Get a line of text by line number (1-based)
    pub fn get_line(&self, line_num: u32) -> Option<&str> {
        if line_num == 0 {
            return None;
        }

        let line_idx = (line_num - 1) as usize;
        if line_idx >= self.line_starts.len() {
            return None;
        }

        let start = self.line_starts[line_idx];
        let end = if line_idx + 1 < self.line_starts.len() {
            self.line_starts[line_idx + 1] - 1
        } else {
            self.source.len()
        };

        Some(self.source[start..end].trim_end_matches('\n'))
    }

    /// Get the text covered by a span
    pub fn span_text(&self, span: &Span) -> &str {
        span.slice(&self.source)
    }

    /// Format an error message with source context
    pub fn format_error(&self, span: &Span, message: &str) -> String {
        let mut result = String::new();

        // Error message
        result.push_str(&format!("Error: {}\n", message));
        result.push_str(&format!(
            "  --> {}:{}\n",
            span.start.line, span.start.column
        ));

        // Show the relevant line(s)
        if let Some(line) = self.get_line(span.start.line) {
            let line_num_str = format!("{}", span.start.line);
            let padding = " ".repeat(line_num_str.len());

            result.push_str(&format!("   {} |\n", padding));
            result.push_str(&format!("{} | {}\n", line_num_str, line));

            // Underline the error span
            let mut underline = String::new();
            underline.push_str(&format!("   {} | ", padding));

            // Add spaces before the error
            for _ in 1..span.start.column {
                underline.push(' ');
            }

            // Add carets under the error
            let span_len = if span.start.line == span.end.line {
                (span.end.column - span.start.column) as usize
            } else {
                line.len() - (span.start.column - 1) as usize
            };

            for _ in 0..span_len.max(1) {
                underline.push('^');
            }

            result.push_str(&underline);
            result.push('\n');
        }

        result
    }
}
