//! Canonical JSON serialization for deterministic hashing
//!
//! Ensures consistent JSON output regardless of HashMap ordering or
//! serialization implementation details.

use super::HashingError;
use serde::Serialize;

/// Serialize to canonical JSON (sorted keys, no extra whitespace)
///
/// This ensures deterministic serialization for consistent hashing.
/// Objects have their keys sorted alphabetically at all nesting levels.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, HashingError> {
    let json_value =
        serde_json::to_value(value).map_err(|e| HashingError::SerializationError(e.to_string()))?;

    let canonical = canonicalize_value(&json_value);

    serde_json::to_string(&canonical).map_err(|e| HashingError::SerializationError(e.to_string()))
}

/// Recursively sort object keys for canonical representation
fn canonicalize_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // Sort keys and recursively canonicalize values
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));

            let canonical_map: serde_json::Map<String, serde_json::Value> = sorted
                .into_iter()
                .map(|(k, v)| (k.clone(), canonicalize_value(v)))
                .collect();

            serde_json::Value::Object(canonical_map)
        }
        serde_json::Value::Array(arr) => {
            // Recursively canonicalize array elements (order preserved)
            serde_json::Value::Array(arr.iter().map(canonicalize_value).collect())
        }
        // Primitive values pass through unchanged
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestContent {
        zebra: String,
        apple: String,
        number: i32,
    }

    #[test]
    fn test_canonical_json_sorted_keys() {
        let content = TestContent {
            zebra: "last".to_string(),
            apple: "first".to_string(),
            number: 42,
        };

        let canonical = to_canonical_json(&content).unwrap();

        // Keys should be sorted alphabetically
        assert!(canonical.find("apple").unwrap() < canonical.find("number").unwrap());
        assert!(canonical.find("number").unwrap() < canonical.find("zebra").unwrap());
    }

    #[test]
    fn test_nested_object_canonicalization() {
        #[derive(Serialize)]
        struct Outer {
            z_field: Inner,
            a_field: Inner,
        }

        #[derive(Serialize)]
        struct Inner {
            beta: i32,
            alpha: i32,
        }

        let content = Outer {
            z_field: Inner { beta: 2, alpha: 1 },
            a_field: Inner { beta: 4, alpha: 3 },
        };

        let canonical = to_canonical_json(&content).unwrap();

        // Outer keys sorted
        assert!(canonical.find("a_field").unwrap() < canonical.find("z_field").unwrap());

        // Inner keys sorted (alpha before beta)
        let first_alpha = canonical.find("alpha").unwrap();
        let first_beta = canonical.find("beta").unwrap();
        assert!(first_alpha < first_beta);
    }

    #[test]
    fn test_array_order_preserved() {
        let arr = vec!["zebra", "apple", "mango"];
        let canonical = to_canonical_json(&arr).unwrap();

        // Array order should be preserved
        assert!(canonical.find("zebra").unwrap() < canonical.find("apple").unwrap());
        assert!(canonical.find("apple").unwrap() < canonical.find("mango").unwrap());
    }
}
