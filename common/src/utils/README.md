# Utils Module

Source location tracking utilities for the ESP compiler.

This module provides dependency-free primitive types for tracking positions and spans in source text during parsing and validation. Accurate location tracking is essential for providing helpful error messages.

## Overview

```
┌─────────────────────────────────────────────────────────┐
│                      SourceMap                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │ "VAR config string `value`\nSTATE check..."     │   │
│  └─────────────────────────────────────────────────┘   │
│       │                                                 │
│       ▼                                                 │
│  line_starts: [0, 28, ...]                             │
└─────────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────┐     ┌──────────────────┐
│     Position     │     │      Span        │
│  offset: 4       │     │  start ──────────┼──► Position
│  line: 1         │     │  end ────────────┼──► Position
│  column: 5       │     └──────────────────┘
└──────────────────┘              │
                                  ▼
                         ┌──────────────────┐
                         │   Spanned<T>     │
                         │  value: T        │
                         │  span: Span      │
                         └──────────────────┘
```

## Types

### Position

A point in source text with line, column, and byte offset:

```rust
use common::utils::Position;

// Create a position
let pos = Position::new(42, 3, 10);  // offset 42, line 3, column 10
println!("{}", pos);  // "3:10"

// Starting position (offset 0, line 1, column 1)
let start = Position::start();

// Advance through text
let pos = Position::start();
let pos = pos.advance('H');      // column 2
let pos = pos.advance('\n');     // line 2, column 1
let pos = pos.advance('\t');     // tab advances to next 4-column boundary

// Advance by string
let pos = Position::start().advance_str("hello\nworld");
assert_eq!(pos.line, 2);
assert_eq!(pos.column, 6);
```

| Field | Type | Description |
|-------|------|-------------|
| `offset` | `usize` | Byte offset from start (0-based) |
| `line` | `u32` | Line number (1-based) |
| `column` | `u32` | Column number (1-based) |

### Span

A range of source text from start to end position:

```rust
use common::utils::{Span, Position};

// Create a span
let start = Position::new(0, 1, 1);
let end = Position::new(5, 1, 6);
let span = Span::new(start, end);

// Single character span
let span = Span::single(Position::start());

// From byte offsets (for testing)
let span = Span::from_offsets(10, 20);

// Merge spans
let span1 = Span::from_offsets(0, 10);
let span2 = Span::from_offsets(15, 25);
let merged = span1.merge(span2);  // covers 0..25

// Check containment
if span.contains(position) {
    // position is within span
}

// Get text from source
let text = span.slice(source_text);

// Display
println!("{}", span);  // "1:1-6" (same line) or "1:1-2:3" (multi-line)
```

| Method | Description |
|--------|-------------|
| `new(start, end)` | Create span from positions |
| `single(pos)` | Single-character span |
| `from_offsets(start, end)` | Create from byte offsets |
| `merge(other)` | Combine two spans |
| `extend(other)` | Alias for merge |
| `to(other)` | Combine spans (alternate API) |
| `len()` | Byte length of span |
| `is_empty()` | Check if zero-length |
| `contains(pos)` | Check if position is in span |
| `contains_span(other)` | Check if span contains another |
| `slice(input)` | Extract text from source |
| `dummy()` | Create placeholder span |

### Spanned\<T\>

A value paired with its source location:

```rust
use common::utils::{Spanned, Span, Position};

// Create a spanned value
let span = Span::new(Position::start(), Position::new(5, 1, 6));
let spanned = Spanned::new("hello", span);

// Access value and span
println!("Value: {}", spanned.value);
println!("At: {}", spanned.span);

// Map the value
let upper: Spanned<String> = spanned.map(|s| s.to_uppercase());

// Get reference
let ref_spanned: Spanned<&&str> = spanned.as_ref();

// Extract value
let value = spanned.into_inner();
```

### SourceMap

Efficient position lookup and error formatting:

```rust
use common::utils::{SourceMap, Span, Position};

// Create from source text
let source = "VAR config string `value`\nSTATE check\n    field int = 42\nSTATE_END";
let map = SourceMap::new(source.to_string());

// Look up position from byte offset
let pos = map.position_at(30);
println!("Line {}, Column {}", pos.line, pos.column);

// Get a specific line (1-based)
if let Some(line) = map.get_line(2) {
    println!("Line 2: {}", line);  // "STATE check"
}

// Get text covered by a span
let span = Span::from_offsets(4, 10);
let text = map.span_text(&span);
```

## Error Formatting

`SourceMap` provides cargo-style error formatting:

```rust
use common::utils::{SourceMap, Span, Position};

let source = "VAR config string `value`\nSTATE check\n    field int = 42\nSTATE_END";
let map = SourceMap::new(source.to_string());

// Create span for "field"
let span = Span::new(
    Position::new(38, 3, 5),
    Position::new(43, 3, 10),
);

let error_msg = map.format_error(&span, "undefined variable 'field'");
println!("{}", error_msg);
```

Output:
```
Error: undefined variable 'field'
  --> 3:5
   |
 3 |     field int = 42
   |     ^^^^^
```

## Usage in AST Nodes

All AST nodes include optional span information:

```rust
use common::ast::StateDefinition;
use common::utils::Span;

let state = StateDefinition {
    id: "my_state".to_string(),
    fields: vec![],
    record_checks: vec![],
    is_global: true,
    span: Some(span),  // Track source location
};

// Use span for error reporting
if let Some(span) = &state.span {
    let error = source_map.format_error(span, "duplicate state identifier");
    eprintln!("{}", error);
}
```

## Usage in Tokens

Lexer tokens track their source location:

```rust
use common::utils::{Span, Position};

struct Token {
    kind: TokenKind,
    lexeme: String,
    span: Span,
}

// Create token with span
let token = Token {
    kind: TokenKind::Identifier,
    lexeme: "config".to_string(),
    span: Span::new(
        Position::new(4, 1, 5),
        Position::new(10, 1, 11),
    ),
};
```

## Tab Handling

Tabs advance to the next 4-column boundary:

```rust
use common::utils::Position;

let pos = Position::new(0, 1, 1);
let pos = pos.advance('\t');  // column 5 (next multiple of 4 + 1)

let pos = Position::new(0, 1, 3);
let pos = pos.advance('\t');  // column 5

let pos = Position::new(0, 1, 5);
let pos = pos.advance('\t');  // column 9
```

## Serde Support

All types implement `Serialize` and `Deserialize`:

```rust
use common::utils::{Position, Span};

let span = Span::new(Position::start(), Position::new(10, 1, 11));
let json = serde_json::to_string(&span)?;
let restored: Span = serde_json::from_str(&json)?;
```

## Module Structure

```
utils/
├── mod.rs    # Re-exports
└── span.rs   # Position, Span, Spanned, SourceMap
```

## Related Modules

- [AST Module](../ast/README.md) - Uses spans for node location tracking
- [Logging Module](../logging/README.md) - Uses spans in error events
