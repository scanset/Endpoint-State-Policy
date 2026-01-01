//! # Binary and EVR String Comparison Operations
//!
//! Implements specialized comparison logic for Binary and EVR (Epoch-Version-Release) data types.

use crate::types::common::{Operation, ResolvedValue};
use std::cmp::Ordering;

/// Error types for comparison operations
#[derive(Debug, thiserror::Error)]
pub enum ComparisonError {
    #[error("Invalid EVR format: {0}")]
    InvalidEvrFormat(String),

    #[error("Invalid binary data: {0}")]
    InvalidBinaryData(String),

    #[error("Invalid pattern '{pattern}': {reason}")]
    InvalidPattern { pattern: String, reason: String },

    #[error("Unsupported operation '{operation:?}' for type {data_type}")]
    UnsupportedOperation {
        operation: Operation,
        data_type: String,
    },

    #[error("Type mismatch in comparison: {message}")]
    TypeMismatch { message: String },
}

/// String comparison operations with full EBNF compliance
pub mod string {
    use super::*;

    /// Compare two string values with the given operation
    pub fn compare(
        actual: &str,
        expected: &str,
        operation: Operation,
    ) -> Result<bool, ComparisonError> {
        match operation {
            // Basic equality
            Operation::Equals => Ok(actual == expected),
            Operation::NotEqual => Ok(actual != expected),

            // Case-insensitive comparisons (NEW)
            Operation::CaseInsensitiveEquals => {
                Ok(actual.to_lowercase() == expected.to_lowercase())
            }
            Operation::CaseInsensitiveNotEqual => {
                Ok(actual.to_lowercase() != expected.to_lowercase())
            }

            // Contains operations
            Operation::Contains => Ok(actual.contains(expected)),
            Operation::NotContains => Ok(!actual.contains(expected)),

            // Prefix operations
            Operation::StartsWith => Ok(actual.starts_with(expected)),
            Operation::NotStartsWith => Ok(!actual.starts_with(expected)), // NEW

            // Suffix operations
            Operation::EndsWith => Ok(actual.ends_with(expected)),
            Operation::NotEndsWith => Ok(!actual.ends_with(expected)), // NEW

            // Pattern matching with regex (IMPROVED)
            Operation::PatternMatch | Operation::Matches => match regex::Regex::new(expected) {
                Ok(re) => Ok(re.is_match(actual)),
                Err(e) => Err(ComparisonError::InvalidPattern {
                    pattern: expected.to_string(),
                    reason: format!("Invalid regex pattern: {}", e),
                }),
            },

            // Ordering operations (for string comparison)
            Operation::GreaterThan => Ok(actual > expected),
            Operation::LessThan => Ok(actual < expected),
            Operation::GreaterThanOrEqual => Ok(actual >= expected),
            Operation::LessThanOrEqual => Ok(actual <= expected),

            // Unsupported operations for strings
            _ => Err(ComparisonError::UnsupportedOperation {
                operation,
                data_type: "string".to_string(),
            }),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_case_insensitive_equals() {
            assert!(compare("Hello", "hello", Operation::CaseInsensitiveEquals).unwrap());
            assert!(compare("WORLD", "world", Operation::CaseInsensitiveEquals).unwrap());
            assert!(!compare("Hello", "Goodbye", Operation::CaseInsensitiveEquals).unwrap());
        }

        #[test]
        fn test_case_insensitive_not_equal() {
            assert!(compare("Hello", "Goodbye", Operation::CaseInsensitiveNotEqual).unwrap());
            assert!(!compare("Hello", "hello", Operation::CaseInsensitiveNotEqual).unwrap());
        }

        #[test]
        fn test_not_starts_with() {
            assert!(compare("Hello World", "Goodbye", Operation::NotStartsWith).unwrap());
            assert!(!compare("Hello World", "Hello", Operation::NotStartsWith).unwrap());
        }

        #[test]
        fn test_not_ends_with() {
            assert!(compare("Hello World", ".txt", Operation::NotEndsWith).unwrap());
            assert!(!compare("Hello World", "World", Operation::NotEndsWith).unwrap());
        }

        #[test]
        fn test_pattern_match() {
            assert!(compare("Hello World", r"^Hello.*World$", Operation::PatternMatch).unwrap());
            assert!(compare("test123", r"\d+", Operation::Matches).unwrap());
            assert!(!compare("Hello", r"^\d+$", Operation::PatternMatch).unwrap());
        }

        #[test]
        fn test_contains() {
            assert!(compare("Hello World", "World", Operation::Contains).unwrap());
            assert!(!compare("Hello World", "Goodbye", Operation::Contains).unwrap());
        }

        #[test]
        fn test_not_contains() {
            assert!(compare("Hello World", "Goodbye", Operation::NotContains).unwrap());
            assert!(!compare("Hello World", "World", Operation::NotContains).unwrap());
        }

        #[test]
        fn test_starts_with() {
            assert!(compare("Hello World", "Hello", Operation::StartsWith).unwrap());
            assert!(!compare("Hello World", "World", Operation::StartsWith).unwrap());
        }

        #[test]
        fn test_ends_with() {
            assert!(compare("Hello World", "World", Operation::EndsWith).unwrap());
            assert!(!compare("Hello World", "Hello", Operation::EndsWith).unwrap());
        }

        #[test]
        fn test_ordering() {
            assert!(compare("beta", "alpha", Operation::GreaterThan).unwrap());
            assert!(compare("alpha", "beta", Operation::LessThan).unwrap());
            assert!(compare("test", "test", Operation::GreaterThanOrEqual).unwrap());
            assert!(compare("test", "test", Operation::LessThanOrEqual).unwrap());
        }
    }
}

/// Binary data comparison
pub mod binary {
    use super::*;

    /// Compare two binary values
    pub fn compare(
        expected: &[u8],
        actual: &[u8],
        operation: Operation,
    ) -> Result<bool, ComparisonError> {
        match operation {
            Operation::Equals => Ok(expected == actual),
            Operation::NotEqual => Ok(expected != actual),
            Operation::Contains => {
                // Byte sequence search
                Ok(contains_bytes(actual, expected))
            }
            _ => Err(ComparisonError::UnsupportedOperation {
                operation,
                data_type: "binary".to_string(),
            }),
        }
    }

    /// Check if haystack contains needle as byte sequence
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if needle.len() > haystack.len() {
            return false;
        }

        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Decode base64 string to binary (simple implementation without external deps)
    /// Note: For production use, consider using the `base64` crate
    pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, ComparisonError> {
        // Simple base64 decode - handles standard base64 alphabet
        const BASE64_CHARS: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut result = Vec::new();
        let bytes = encoded.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'=' {
                break;
            }

            // Collect 4 base64 chars
            let mut group = [0u8; 4];
            let mut group_len = 0;

            for j in 0..4 {
                if i + j >= bytes.len() || bytes[i + j] == b'=' {
                    break;
                }

                let pos = BASE64_CHARS
                    .iter()
                    .position(|&c| c == bytes[i + j])
                    .ok_or_else(|| {
                        ComparisonError::InvalidBinaryData(format!(
                            "Invalid base64 character at position {}",
                            i + j
                        ))
                    })?;

                group[j] = pos as u8;
                group_len += 1;
            }

            // Decode the group
            if group_len >= 2 {
                result.push((group[0] << 2) | (group[1] >> 4));
            }
            if group_len >= 3 {
                result.push((group[1] << 4) | (group[2] >> 2));
            }
            if group_len >= 4 {
                result.push((group[2] << 6) | group[3]);
            }

            i += 4;
        }

        Ok(result)
    }

    /// Encode binary to base64 string (simple implementation)
    pub fn encode_base64(data: &[u8]) -> String {
        const BASE64_CHARS: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut result = String::new();
        let mut i = 0;

        while i < data.len() {
            let b1 = data[i];
            let b2 = if i + 1 < data.len() { data[i + 1] } else { 0 };
            let b3 = if i + 2 < data.len() { data[i + 2] } else { 0 };

            result.push(BASE64_CHARS[(b1 >> 2) as usize] as char);
            result.push(BASE64_CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);

            if i + 1 < data.len() {
                result.push(BASE64_CHARS[(((b2 & 0x0F) << 2) | (b3 >> 6)) as usize] as char);
            } else {
                result.push('=');
            }

            if i + 2 < data.len() {
                result.push(BASE64_CHARS[(b3 & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }

            i += 3;
        }

        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_binary_equals() {
            let data1 = vec![1, 2, 3, 4];
            let data2 = vec![1, 2, 3, 4];
            let data3 = vec![1, 2, 3, 5];

            assert!(compare(&data1, &data2, Operation::Equals).unwrap());
            assert!(!compare(&data1, &data3, Operation::Equals).unwrap());
        }

        #[test]
        fn test_binary_contains() {
            let haystack = vec![1, 2, 3, 4, 5, 6];
            let needle = vec![3, 4, 5];
            let missing = vec![7, 8];

            assert!(compare(&needle, &haystack, Operation::Contains).unwrap());
            assert!(!compare(&missing, &haystack, Operation::Contains).unwrap());
        }

        #[test]
        fn test_base64_decode() {
            let encoded = "SGVsbG8gV29ybGQ="; // "Hello World"
            let decoded = decode_base64(encoded).unwrap();
            assert_eq!(decoded, b"Hello World");
        }

        #[test]
        fn test_base64_roundtrip() {
            let original = b"Hello World";
            let encoded = encode_base64(original);
            let decoded = decode_base64(&encoded).unwrap();
            assert_eq!(decoded, original);
        }
    }
}

/// Collection (set) comparison operations
pub mod collection {
    use super::*;
    use std::collections::HashSet;

    /// Compare two collections using set operations
    pub fn compare(
        actual: &[ResolvedValue],
        expected: &[ResolvedValue],
        operation: Operation,
    ) -> Result<bool, ComparisonError> {
        match operation {
            Operation::SubsetOf => Ok(is_subset(actual, expected)),
            Operation::SupersetOf => Ok(is_superset(actual, expected)),
            Operation::Equals => Ok(are_equal(actual, expected)),
            Operation::NotEqual => Ok(!are_equal(actual, expected)),
            _ => Err(ComparisonError::UnsupportedOperation {
                operation,
                data_type: "collection".to_string(),
            }),
        }
    }

    /// Check if actual is a subset of expected
    /// All elements in actual must be present in expected
    fn is_subset(actual: &[ResolvedValue], expected: &[ResolvedValue]) -> bool {
        let actual_set: HashSet<String> = actual.iter().map(serialize_value).collect();

        let expected_set: HashSet<String> = expected.iter().map(serialize_value).collect();

        actual_set.is_subset(&expected_set)
    }

    /// Check if actual is a superset of expected
    /// All elements in expected must be present in actual
    fn is_superset(actual: &[ResolvedValue], expected: &[ResolvedValue]) -> bool {
        let actual_set: HashSet<String> = actual.iter().map(serialize_value).collect();

        let expected_set: HashSet<String> = expected.iter().map(serialize_value).collect();

        actual_set.is_superset(&expected_set)
    }

    /// Check if two collections are equal (same elements, any order)
    fn are_equal(actual: &[ResolvedValue], expected: &[ResolvedValue]) -> bool {
        if actual.len() != expected.len() {
            return false;
        }

        let actual_set: HashSet<String> = actual.iter().map(serialize_value).collect();

        let expected_set: HashSet<String> = expected.iter().map(serialize_value).collect();

        actual_set == expected_set
    }

    /// Serialize ResolvedValue to string for comparison
    /// This allows comparing different types in collections
    fn serialize_value(value: &ResolvedValue) -> String {
        match value {
            ResolvedValue::String(s) => s.clone(),
            ResolvedValue::Integer(i) => i.to_string(),
            ResolvedValue::Float(f) => f.to_string(),
            ResolvedValue::Boolean(b) => b.to_string(),
            ResolvedValue::Version(v) => v.clone(),
            ResolvedValue::EvrString(e) => e.clone(),
            ResolvedValue::Binary(b) => format!("binary:{}", b.len()),
            ResolvedValue::RecordData(_) => "record".to_string(),
            ResolvedValue::Collection(items) => {
                format!("collection:{}", items.len())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_subset_of() {
            let actual = vec![
                ResolvedValue::String("a".to_string()),
                ResolvedValue::String("b".to_string()),
            ];
            let expected = vec![
                ResolvedValue::String("a".to_string()),
                ResolvedValue::String("b".to_string()),
                ResolvedValue::String("c".to_string()),
            ];

            assert!(compare(&actual, &expected, Operation::SubsetOf).unwrap());
            assert!(!compare(&expected, &actual, Operation::SubsetOf).unwrap());
        }

        #[test]
        fn test_superset_of() {
            let actual = vec![
                ResolvedValue::String("a".to_string()),
                ResolvedValue::String("b".to_string()),
                ResolvedValue::String("c".to_string()),
            ];
            let expected = vec![
                ResolvedValue::String("a".to_string()),
                ResolvedValue::String("b".to_string()),
            ];

            assert!(compare(&actual, &expected, Operation::SupersetOf).unwrap());
            assert!(!compare(&expected, &actual, Operation::SupersetOf).unwrap());
        }

        #[test]
        fn test_collection_equals() {
            let coll1 = vec![
                ResolvedValue::String("a".to_string()),
                ResolvedValue::String("b".to_string()),
            ];
            let coll2 = vec![
                ResolvedValue::String("b".to_string()),
                ResolvedValue::String("a".to_string()),
            ];

            assert!(compare(&coll1, &coll2, Operation::Equals).unwrap());
        }

        #[test]
        fn test_not_equal() {
            let coll1 = vec![
                ResolvedValue::String("a".to_string()),
                ResolvedValue::String("b".to_string()),
            ];
            let coll2 = vec![
                ResolvedValue::String("a".to_string()),
                ResolvedValue::String("c".to_string()),
            ];

            assert!(compare(&coll1, &coll2, Operation::NotEqual).unwrap());
        }

        #[test]
        fn test_mixed_types() {
            let actual = vec![
                ResolvedValue::String("test".to_string()),
                ResolvedValue::Integer(42),
            ];
            let expected = vec![
                ResolvedValue::String("test".to_string()),
                ResolvedValue::Integer(42),
                ResolvedValue::Boolean(true),
            ];

            assert!(compare(&actual, &expected, Operation::SubsetOf).unwrap());
        }

        #[test]
        fn test_empty_collections() {
            let empty: Vec<ResolvedValue> = vec![];
            let non_empty = vec![ResolvedValue::String("a".to_string())];

            // Empty set is subset of any set
            assert!(compare(&empty, &non_empty, Operation::SubsetOf).unwrap());

            // Non-empty set is superset of empty set
            assert!(compare(&non_empty, &empty, Operation::SupersetOf).unwrap());

            // Empty sets are equal
            assert!(compare(&empty, &empty, Operation::Equals).unwrap());
        }
    }
}

/// EVR (Epoch-Version-Release) string comparison
pub mod evr {
    use super::*;

    /// EVR string structure: epoch:version-release[.dist]
    /// Examples: "1:2.3.4-5.el8", "0:1.0-1", "2.0-1"
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EvrString {
        pub epoch: u32,
        pub version: String,
        pub release: String,
    }

    impl EvrString {
        /// Parse EVR string
        /// Format: [epoch:]version[-release[.dist]]
        pub fn parse(evr_str: &str) -> Result<Self, ComparisonError> {
            // Split on colon for epoch
            let (epoch_str, rest) = if let Some(colon_pos) = evr_str.find(':') {
                let (e, r) = evr_str.split_at(colon_pos);
                (e, &r[1..]) // Skip the colon
            } else {
                ("0", evr_str)
            };

            let epoch = epoch_str.parse::<u32>().map_err(|_| {
                ComparisonError::InvalidEvrFormat(format!("Invalid epoch: {}", epoch_str))
            })?;

            // Split on hyphen for version and release
            let (version, release) = if let Some(hyphen_pos) = rest.find('-') {
                let (v, r) = rest.split_at(hyphen_pos);
                (v.to_string(), r[1..].to_string()) // Skip the hyphen
            } else {
                (rest.to_string(), String::new())
            };

            if version.is_empty() {
                return Err(ComparisonError::InvalidEvrFormat(
                    "Version cannot be empty".to_string(),
                ));
            }

            Ok(Self {
                epoch,
                version,
                release,
            })
        }

        /// Compare two EVR strings
        pub fn compare(&self, other: &Self) -> Ordering {
            // First compare epochs
            match self.epoch.cmp(&other.epoch) {
                Ordering::Equal => {}
                other => return other,
            }

            // Then compare versions using RPM-style version comparison
            match compare_version_strings(&self.version, &other.version) {
                Ordering::Equal => {}
                other => return other,
            }

            // Finally compare releases
            compare_version_strings(&self.release, &other.release)
        }
    }

    /// RPM-style version comparison
    /// Compares version strings segment by segment, handling numeric and alphabetic parts
    fn compare_version_strings(a: &str, b: &str) -> Ordering {
        let mut a_segments = VersionSegments::new(a);
        let mut b_segments = VersionSegments::new(b);

        loop {
            match (a_segments.next(), b_segments.next()) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(seg_a), Some(seg_b)) => match compare_segments(&seg_a, &seg_b) {
                    Ordering::Equal => continue,
                    other => return other,
                },
            }
        }
    }

    /// Compare individual version segments
    fn compare_segments(a: &str, b: &str) -> Ordering {
        // Try numeric comparison first
        match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(num_a), Ok(num_b)) => num_a.cmp(&num_b),
            _ => a.cmp(b), // Fallback to string comparison
        }
    }

    /// Iterator over version string segments (split by dots and non-alphanumeric)
    struct VersionSegments<'a> {
        remaining: &'a str,
    }

    impl<'a> VersionSegments<'a> {
        fn new(s: &'a str) -> Self {
            Self { remaining: s }
        }
    }

    impl<'a> Iterator for VersionSegments<'a> {
        type Item = String;

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining.is_empty() {
                return None;
            }

            // Find the next segment boundary (dot or non-alphanumeric)
            let end = self
                .remaining
                .find(|c: char| c == '.' || (!c.is_alphanumeric() && c != '_'))
                .unwrap_or(self.remaining.len());

            if end == 0 {
                // Skip delimiter
                self.remaining = &self.remaining[1..];
                return self.next();
            }

            let segment = self.remaining[..end].to_string();
            self.remaining = &self.remaining[end..];

            Some(segment)
        }
    }

    /// Compare two EVR strings with operation
    pub fn compare(
        expected: &str,
        actual: &str,
        operation: Operation,
    ) -> Result<bool, ComparisonError> {
        let expected_evr = EvrString::parse(expected)?;
        let actual_evr = EvrString::parse(actual)?;

        // Compare actual to expected (actual OP expected)
        let ordering = actual_evr.compare(&expected_evr);

        Ok(match operation {
            Operation::Equals => ordering == Ordering::Equal,
            Operation::NotEqual => ordering != Ordering::Equal,
            Operation::GreaterThan => ordering == Ordering::Greater,
            Operation::LessThan => ordering == Ordering::Less,
            Operation::GreaterThanOrEqual => {
                ordering == Ordering::Greater || ordering == Ordering::Equal
            }
            Operation::LessThanOrEqual => ordering == Ordering::Less || ordering == Ordering::Equal,
            _ => {
                return Err(ComparisonError::UnsupportedOperation {
                    operation,
                    data_type: "evr_string".to_string(),
                })
            }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_evr_parsing() {
            let evr = EvrString::parse("1:2.3.4-5.el8").unwrap();
            assert_eq!(evr.epoch, 1);
            assert_eq!(evr.version, "2.3.4");
            assert_eq!(evr.release, "5.el8");

            let evr = EvrString::parse("2.3.4-5").unwrap();
            assert_eq!(evr.epoch, 0);
            assert_eq!(evr.version, "2.3.4");
            assert_eq!(evr.release, "5");

            let evr = EvrString::parse("1.0").unwrap();
            assert_eq!(evr.epoch, 0);
            assert_eq!(evr.version, "1.0");
            assert_eq!(evr.release, "");
        }

        #[test]
        fn test_evr_comparison() {
            // Test with actual < expected: compare("2.0", "2.1", LessThan) should be true
            // Because actual (2.0) < expected (2.1)
            assert!(compare("1:2.1-1", "1:2.0-1", Operation::LessThan).unwrap());
            assert!(compare("1:2.0-1", "1:2.1-1", Operation::GreaterThan).unwrap());

            // Different epochs
            assert!(compare("2:1.0-1", "1:1.0-1", Operation::LessThan).unwrap());
            assert!(compare("1:1.0-1", "2:1.0-1", Operation::GreaterThan).unwrap());

            // Same version, different releases
            assert!(compare("1.0-2", "1.0-1", Operation::LessThan).unwrap());
            assert!(compare("1.0-1", "1.0-2", Operation::GreaterThan).unwrap());

            // Equality
            assert!(compare("1:2.3.4-5", "1:2.3.4-5", Operation::Equals).unwrap());
        }

        #[test]
        fn test_version_segment_comparison() {
            assert_eq!(compare_segments("1", "2"), Ordering::Less);
            assert_eq!(compare_segments("10", "9"), Ordering::Greater);
            assert_eq!(compare_segments("alpha", "beta"), Ordering::Less);
        }
    }
}

/// Extension methods for ResolvedValue comparison
pub trait ComparisonExt {
    /// Perform comparison operation between two resolved values
    fn compare_with(
        &self,
        other: &ResolvedValue,
        operation: Operation,
    ) -> Result<bool, ComparisonError>;
}

impl ComparisonExt for ResolvedValue {
    fn compare_with(
        &self,
        other: &ResolvedValue,
        operation: Operation,
    ) -> Result<bool, ComparisonError> {
        // FIXED: self is actual (collected data), other is expected (policy value)
        match (self, other) {
            // String comparison
            // self = actual (collected), other = expected (policy)
            (ResolvedValue::String(actual), ResolvedValue::String(expected)) => {
                string::compare(actual, expected, operation)
            }

            // Integer comparison
            // self = actual (collected), other = expected (policy)
            (ResolvedValue::Integer(actual), ResolvedValue::Integer(expected)) => match operation {
                Operation::Equals => Ok(actual == expected),
                Operation::NotEqual => Ok(actual != expected),
                Operation::GreaterThan => Ok(actual > expected),
                Operation::LessThan => Ok(actual < expected),
                Operation::GreaterThanOrEqual => Ok(actual >= expected),
                Operation::LessThanOrEqual => Ok(actual <= expected),
                _ => Err(ComparisonError::UnsupportedOperation {
                    operation,
                    data_type: "integer".to_string(),
                }),
            },

            // Float comparison
            // self = actual (collected), other = expected (policy)
            (ResolvedValue::Float(actual), ResolvedValue::Float(expected)) => match operation {
                Operation::Equals => Ok((actual - expected).abs() < f64::EPSILON),
                Operation::NotEqual => Ok((actual - expected).abs() >= f64::EPSILON),
                Operation::GreaterThan => Ok(actual > expected),
                Operation::LessThan => Ok(actual < expected),
                Operation::GreaterThanOrEqual => Ok(actual >= expected),
                Operation::LessThanOrEqual => Ok(actual <= expected),
                _ => Err(ComparisonError::UnsupportedOperation {
                    operation,
                    data_type: "float".to_string(),
                }),
            },

            // Boolean comparison
            // self = actual (collected), other = expected (policy)
            (ResolvedValue::Boolean(actual), ResolvedValue::Boolean(expected)) => match operation {
                Operation::Equals => Ok(actual == expected),
                Operation::NotEqual => Ok(actual != expected),
                _ => Err(ComparisonError::UnsupportedOperation {
                    operation,
                    data_type: "boolean".to_string(),
                }),
            },

            // Binary comparison
            // self = actual (collected), other = expected (policy)
            (ResolvedValue::Binary(actual), ResolvedValue::Binary(expected)) => {
                binary::compare(actual, expected, operation)
            }

            // EVR string comparison
            // self = actual (collected), other = expected (policy)
            (ResolvedValue::EvrString(actual), ResolvedValue::EvrString(expected)) => {
                evr::compare(actual, expected, operation)
            }

            // Collection comparison
            // self = actual (collected), other = expected (policy)
            (ResolvedValue::Collection(actual), ResolvedValue::Collection(expected)) => {
                collection::compare(actual, expected, operation)
            }

            // Type mismatch
            _ => Err(ComparisonError::TypeMismatch {
                message: format!("Cannot compare {:?} with {:?}", self, other),
            }),
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_resolved_value_binary_comparison() {
        let val1 = ResolvedValue::Binary(vec![1, 2, 3]);
        let val2 = ResolvedValue::Binary(vec![1, 2, 3]);
        let val3 = ResolvedValue::Binary(vec![4, 5, 6]);

        assert!(val1.compare_with(&val2, Operation::Equals).unwrap());
        assert!(val1.compare_with(&val3, Operation::NotEqual).unwrap());
    }
}
