//! Inline CTN execution — direct invocation of a registered CTN strategy
//! without going through the .esp parser, compiler, or policy execution
//! tree.
//!
//! # When to use this
//!
//! Intended for **asset discovery / inventory enumeration**, where:
//! - There is no audit-meaningful policy to attest about. The credential's
//!   grants are the scope; the CTN is just a typed enumeration call.
//! - The caller (typically a server) will wrap the returned `CollectedData`
//!   in its own envelope and sign it as discovery evidence.
//!
//! For **evidence-gathering scans** — policy assertions with
//! pass/fail outcomes, control mappings, criticality, and the rest of the
//! META block's audit context — continue to use the file-based path
//! (`.esp` → lexer → parser → compiler → execute). That path is what
//! produces a complete `AssessorPackage` with `policies[]`, `findings[]`,
//! `outcome`, etc.
//!
//! # What this skips
//!
//! - `.esp` lexing / parsing
//! - META validation (`esp_id`, `version`, `criticality`, `control_mapping`, …)
//! - Policy compilation / criterion evaluation tree
//! - State assertion / findings / outcome calculation
//!
//! It's literally: build an `ExecutableObject` from caller-supplied fields,
//! look up the registered collector, dispatch it, return `CollectedData`.

use std::time::{Duration, Instant};

use crate::execution::behavior::BehaviorHints;
use crate::strategies::{CollectedData, CollectionError, CtnStrategyRegistry};
use crate::types::common::ResolvedValue;
use crate::types::execution_context::{ExecutableObject, ExecutableObjectElement};

#[derive(Debug, thiserror::Error)]
pub enum InlineExecutionError {
    #[error("CTN type '{0}' is not registered")]
    CtnNotRegistered(String),

    #[error("collection failed for '{ctn_type}': {source}")]
    Collection {
        ctn_type: String,
        #[source]
        source: CollectionError,
    },
}

/// One inline CTN dispatch — caller supplies the CTN type, an OBJECT
/// identifier (for tracing in the returned `CollectedData`), the OBJECT's
/// fields as `(name, value)` pairs, and an optional list of BEHAVIOR
/// values that the collector will see as `BehaviorHints`.
#[derive(Debug, Clone)]
pub struct InlineRequest {
    pub ctn_type: String,
    pub object_id: String,
    pub fields: Vec<(String, ResolvedValue)>,
    pub behavior_values: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InlineResult {
    pub ctn_type: String,
    pub object_id: String,
    pub collected_data: CollectedData,
    pub duration: Duration,
}

/// Look up the registered collector for `ctn_type`, build an
/// `ExecutableObject` from the request fields, dispatch the collector,
/// return its `CollectedData`. Skips everything the parser/compiler layer
/// would normally do (see module docs).
pub fn execute_inline(
    registry: &CtnStrategyRegistry,
    request: InlineRequest,
) -> Result<InlineResult, InlineExecutionError> {
    let contract = registry
        .get_ctn_contract(&request.ctn_type)
        .map_err(|_| InlineExecutionError::CtnNotRegistered(request.ctn_type.clone()))?;
    let collector = registry
        .get_collector_for_ctn(&request.ctn_type)
        .map_err(|_| InlineExecutionError::CtnNotRegistered(request.ctn_type.clone()))?;

    let mut elements: Vec<ExecutableObjectElement> = request
        .fields
        .iter()
        .map(|(name, value)| ExecutableObjectElement::Field {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();

    if !request.behavior_values.is_empty() {
        elements.push(ExecutableObjectElement::Behavior {
            values: request.behavior_values.clone(),
        });
    }

    let object = ExecutableObject {
        identifier: request.object_id.clone(),
        elements,
        is_global: false,
    };

    let hints = BehaviorHints::parse(&request.behavior_values);

    let started = Instant::now();
    let collected = collector
        .collect_for_ctn_with_hints(&object, contract.as_ref(), &hints)
        .map_err(|e| InlineExecutionError::Collection {
            ctn_type: request.ctn_type.clone(),
            source: e,
        })?;
    let duration = started.elapsed();

    Ok(InlineResult {
        ctn_type: request.ctn_type,
        object_id: request.object_id,
        collected_data: collected,
        duration,
    })
}

// ----------------------------------------------------------------------
// Builder — ergonomic alternative to constructing `InlineRequest` directly
// ----------------------------------------------------------------------

/// Fluent builder for `InlineRequest` + one-call execution.
///
/// ```ignore
/// use execution_engine::inline::InlineRequestBuilder;
///
/// let result = InlineRequestBuilder::new("az_resource_list")
///     .object_id("subscription_scope")
///     .field_string("scope", "subscription")
///     .execute(&registry)?;
/// ```
pub struct InlineRequestBuilder {
    ctn_type: String,
    object_id: String,
    fields: Vec<(String, ResolvedValue)>,
    behavior_values: Vec<String>,
}

impl InlineRequestBuilder {
    pub fn new(ctn_type: impl Into<String>) -> Self {
        Self {
            ctn_type: ctn_type.into(),
            object_id: String::new(),
            fields: Vec::new(),
            behavior_values: Vec::new(),
        }
    }

    pub fn object_id(mut self, id: impl Into<String>) -> Self {
        self.object_id = id.into();
        self
    }

    pub fn field(mut self, name: impl Into<String>, value: ResolvedValue) -> Self {
        self.fields.push((name.into(), value));
        self
    }

    pub fn field_string(self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.field(name, ResolvedValue::String(value.into()))
    }

    pub fn field_bool(self, name: impl Into<String>, value: bool) -> Self {
        self.field(name, ResolvedValue::Boolean(value))
    }

    pub fn field_int(self, name: impl Into<String>, value: i64) -> Self {
        self.field(name, ResolvedValue::Integer(value))
    }

    pub fn behavior(mut self, value: impl Into<String>) -> Self {
        self.behavior_values.push(value.into());
        self
    }

    pub fn build(self) -> InlineRequest {
        let object_id = if self.object_id.is_empty() {
            format!("{}-inline", self.ctn_type)
        } else {
            self.object_id
        };
        InlineRequest {
            ctn_type: self.ctn_type,
            object_id,
            fields: self.fields,
            behavior_values: self.behavior_values,
        }
    }

    pub fn execute(
        self,
        registry: &CtnStrategyRegistry,
    ) -> Result<InlineResult, InlineExecutionError> {
        execute_inline(registry, self.build())
    }
}
