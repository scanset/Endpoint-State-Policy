//! SSDF-Compliant types for Pass 4: Reference Validation
//!
//! Simplified from over-engineered original with security-aware statistics
//! and compile-time boundary tracking for audit compliance.

use common::config::constants::compile_time::references::*;
use std::collections::HashMap;

/// Validation statistics with security boundary tracking
#[derive(Debug, Clone, Default)]
pub struct ValidationStats {
    /// Total relationships processed from Pass 3
    pub total_relationships: usize,
    /// Successfully validated relationships
    pub validated_count: usize,
    /// Validation errors encountered
    pub error_count: usize,
    /// Simple cycles detected
    pub cycle_count: usize,
    /// Security boundary checks performed
    pub security_checks_performed: usize,
    /// Security violations detected (SSDF: RV.1 Monitoring)
    pub security_violations: usize,
    /// Maximum reference depth encountered
    pub max_reference_depth: usize,
    /// Processing time in milliseconds (for audit logging)
    pub processing_time_ms: u64,
}

impl ValidationStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate validation success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_relationships == 0 {
            1.0
        } else {
            self.validated_count as f64 / self.total_relationships as f64
        }
    }

    /// Check if validation was successful (no errors or security violations)
    pub fn is_successful(&self) -> bool {
        self.error_count == 0
            && self.security_violations == 0
            && self.validated_count == self.total_relationships
    }

    /// Check if any security boundaries were approached (warning threshold)
    pub fn has_security_warnings(&self) -> bool {
        self.max_reference_depth > (MAX_REFERENCE_DEPTH * 3 / 4) // 75% of limit
            || self.total_relationships > (MAX_RELATIONSHIPS_PER_PASS * 3 / 4)
    }

    /// Get security compliance status for audit logging (SSDF: PW.3.1)
    pub fn security_compliance_status(&self) -> &'static str {
        if self.security_violations > 0 {
            "NON_COMPLIANT"
        } else if self.has_security_warnings() {
            "WARNING"
        } else {
            "COMPLIANT"
        }
    }

    /// Create summary string for logging and reporting
    pub fn summary(&self) -> String {
        format!(
            "Validation: {}/{} validated ({:.1}%), {} cycles, {} security checks, compliance: {}",
            self.validated_count,
            self.total_relationships,
            self.success_rate() * 100.0,
            self.cycle_count,
            self.security_checks_performed,
            self.security_compliance_status()
        )
    }

    /// Get performance metrics for monitoring (SSDF: RV.1)
    pub fn performance_metrics(&self) -> HashMap<String, f64> {
        let mut metrics = HashMap::new();

        if self.total_relationships > 0 {
            metrics.insert(
                "validation_rate_per_ms".to_string(),
                self.validated_count as f64 / self.processing_time_ms.max(1) as f64,
            );

            metrics.insert(
                "error_rate".to_string(),
                self.error_count as f64 / self.total_relationships as f64,
            );
        }

        metrics.insert(
            "security_check_efficiency".to_string(),
            if self.security_checks_performed > 0 {
                self.security_violations as f64 / self.security_checks_performed as f64
            } else {
                0.0
            },
        );

        metrics.insert(
            "reference_depth_utilization".to_string(),
            self.max_reference_depth as f64 / MAX_REFERENCE_DEPTH as f64,
        );

        metrics
    }

    /// Record security check performed
    pub fn record_security_check(&mut self) {
        self.security_checks_performed += 1;
    }

    /// Record security violation
    pub fn record_security_violation(&mut self) {
        self.security_violations += 1;
    }

    /// Update maximum reference depth seen
    pub fn update_max_depth(&mut self, depth: usize) {
        self.max_reference_depth = self.max_reference_depth.max(depth);
    }
}

/// Final result from Pass 4 reference validation with security tracking
#[derive(Debug, Clone)]
pub struct ReferenceValidationResult {
    /// Validation statistics with security metrics
    pub stats: ValidationStats,
    /// Simple dependency cycles detected (node sequences)
    pub cycles: Vec<Vec<String>>,
    /// Overall success flag
    pub is_successful: bool,
    /// Security compliance details for audit trail
    pub security_compliance: SecurityComplianceInfo,
}

/// Security compliance information for audit logging (SSDF: PW.3.1)
#[derive(Debug, Clone)]
pub struct SecurityComplianceInfo {
    /// All compile-time limits that were checked
    pub limits_checked: HashMap<String, (usize, usize)>, // (current, limit)
    /// Any warnings about approaching limits
    pub warnings: Vec<String>,
    /// Timestamp of validation for audit trail
    pub validation_timestamp: u64,
    /// Validation performed under which security boundaries
    pub active_boundaries: Vec<String>,
}

impl SecurityComplianceInfo {
    pub fn new() -> Self {
        Self {
            limits_checked: HashMap::new(),
            warnings: Vec::new(),
            validation_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            active_boundaries: vec![
                "MAX_REFERENCE_DEPTH".to_string(),
                "MAX_RELATIONSHIPS_PER_PASS".to_string(),
                "MAX_DEPENDENCY_NODES".to_string(),
                "MAX_CYCLE_LENGTH".to_string(),
            ],
        }
    }

    /// Record a limit check for audit trail
    pub fn record_limit_check(
        &mut self,
        limit_name: &str,
        current_value: usize,
        limit_value: usize,
    ) {
        self.limits_checked
            .insert(limit_name.to_string(), (current_value, limit_value));

        // Add warning if approaching limit (80% threshold)
        if limit_value > 0 && current_value as f64 / limit_value as f64 >= 0.8 {
            self.warnings.push(format!(
                "{}: {} approaching limit of {} ({}%)",
                limit_name,
                current_value,
                limit_value,
                (current_value as f64 / limit_value as f64 * 100.0) as u32
            ));
        }
    }

    /// Check if all security boundaries were respected
    pub fn is_compliant(&self) -> bool {
        self.limits_checked
            .iter()
            .all(|(_, (current, limit))| current <= limit)
    }

    /// Get compliance summary for audit logs
    pub fn compliance_summary(&self) -> String {
        format!(
            "Security compliance: {} limits checked, {} warnings, status: {}",
            self.limits_checked.len(),
            self.warnings.len(),
            if self.is_compliant() { "PASS" } else { "FAIL" }
        )
    }
}

impl Default for SecurityComplianceInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceValidationResult {
    pub fn new() -> Self {
        Self {
            stats: ValidationStats::new(),
            cycles: Vec::new(),
            is_successful: false,
            security_compliance: SecurityComplianceInfo::new(),
        }
    }

    /// Create new result with security compliance tracking
    pub fn new_with_compliance() -> Self {
        let mut result = Self::new();

        // Initialize with current compile-time limits for audit trail
        result.security_compliance.record_limit_check(
            "MAX_REFERENCE_DEPTH",
            0,
            MAX_REFERENCE_DEPTH,
        );
        result.security_compliance.record_limit_check(
            "MAX_RELATIONSHIPS_PER_PASS",
            0,
            MAX_RELATIONSHIPS_PER_PASS,
        );
        result.security_compliance.record_limit_check(
            "MAX_DEPENDENCY_NODES",
            0,
            MAX_DEPENDENCY_NODES,
        );
        result
            .security_compliance
            .record_limit_check("MAX_CYCLE_LENGTH", 0, MAX_CYCLE_LENGTH);

        result
    }

    pub fn success_rate(&self) -> f64 {
        self.stats.success_rate()
    }

    pub fn has_cycles(&self) -> bool {
        !self.cycles.is_empty()
    }

    pub fn error_count(&self) -> usize {
        self.stats.error_count
    }

    pub fn total_relationships(&self) -> usize {
        self.stats.total_relationships
    }

    /// Check if validation meets security compliance requirements
    pub fn is_security_compliant(&self) -> bool {
        self.security_compliance.is_compliant() && self.stats.security_violations == 0
    }

    /// Get comprehensive summary including security status
    pub fn summary(&self) -> String {
        format!(
            "Pass 4 Summary: {} validated, {} cycles, {:.1}% success, security: {}",
            self.stats.validated_count,
            self.cycles.len(),
            self.success_rate() * 100.0,
            self.stats.security_compliance_status()
        )
    }

    /// Get cycle descriptions for logging/reporting
    pub fn cycle_descriptions(&self) -> Vec<String> {
        self.cycles
            .iter()
            .enumerate()
            .map(|(i, cycle)| format!("Cycle {}: {}", i + 1, cycle.join(" -> ")))
            .collect()
    }

    /// Check if result indicates critical issues requiring immediate attention
    pub fn has_critical_issues(&self) -> bool {
        self.stats.error_count > 0 || !self.cycles.is_empty() || self.stats.security_violations > 0
    }

    /// Get breakdown of issues for reporting and audit logging
    pub fn issue_breakdown(&self) -> HashMap<String, usize> {
        let mut breakdown = HashMap::new();

        if self.stats.error_count > 0 {
            breakdown.insert("undefined_references".to_string(), self.stats.error_count);
        }

        if !self.cycles.is_empty() {
            breakdown.insert("dependency_cycles".to_string(), self.cycles.len());
        }

        if self.stats.security_violations > 0 {
            breakdown.insert(
                "security_violations".to_string(),
                self.stats.security_violations,
            );
        }

        if self.is_successful && self.cycles.is_empty() && self.stats.security_violations == 0 {
            breakdown.insert("no_issues".to_string(), 1);
        }

        breakdown
    }

    /// Get security metrics for monitoring and audit compliance (SSDF: RV.1)
    pub fn security_metrics(&self) -> HashMap<String, String> {
        let mut metrics = HashMap::new();

        metrics.insert(
            "compliance_status".to_string(),
            self.stats.security_compliance_status().to_string(),
        );

        metrics.insert(
            "security_violations".to_string(),
            self.stats.security_violations.to_string(),
        );

        metrics.insert(
            "max_reference_depth".to_string(),
            format!("{}/{}", self.stats.max_reference_depth, MAX_REFERENCE_DEPTH),
        );

        metrics.insert(
            "relationship_utilization".to_string(),
            format!(
                "{}/{}",
                self.stats.total_relationships, MAX_RELATIONSHIPS_PER_PASS
            ),
        );

        metrics.insert(
            "security_checks_performed".to_string(),
            self.stats.security_checks_performed.to_string(),
        );

        metrics.insert(
            "validation_timestamp".to_string(),
            self.security_compliance.validation_timestamp.to_string(),
        );

        metrics
    }

    /// Generate audit log entry for SSDF compliance (PW.3.1)
    pub fn audit_log_entry(&self) -> String {
        format!(
            "REFERENCE_VALIDATION_AUDIT: timestamp={}, relationships={}, validated={}, errors={}, cycles={}, security_violations={}, compliance={}, max_depth={}/{}, processing_time={}ms",
            self.security_compliance.validation_timestamp,
            self.stats.total_relationships,
            self.stats.validated_count,
            self.stats.error_count,
            self.cycles.len(),
            self.stats.security_violations,
            self.stats.security_compliance_status(),
            self.stats.max_reference_depth,
            MAX_REFERENCE_DEPTH,
            self.stats.processing_time_ms
        )
    }

    /// Update security compliance with actual usage values
    pub fn update_security_compliance(
        &mut self,
        relationships_processed: usize,
        max_depth_seen: usize,
    ) {
        self.security_compliance.record_limit_check(
            "MAX_RELATIONSHIPS_PER_PASS",
            relationships_processed,
            MAX_RELATIONSHIPS_PER_PASS,
        );

        self.security_compliance.record_limit_check(
            "MAX_REFERENCE_DEPTH",
            max_depth_seen,
            MAX_REFERENCE_DEPTH,
        );

        self.stats.update_max_depth(max_depth_seen);
    }

    /// Get warnings about approaching security limits
    pub fn security_warnings(&self) -> &[String] {
        &self.security_compliance.warnings
    }

    /// Check if validation should be considered successful for production use
    pub fn is_production_ready(&self) -> bool {
        self.is_successful
            && self.is_security_compliant()
            && !self.has_critical_issues()
            && self.stats.security_violations == 0
    }
}

impl Default for ReferenceValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Reference type enumeration for type checking (simplified from collector removal)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceType {
    Variable,
    StateRef,
    ObjectRef,
    ObjectField,
    SetRef,
}

impl ReferenceType {
    /// Get expected symbol type for validation
    pub fn expected_symbol_type(&self) -> &'static str {
        match self {
            Self::Variable => "variable",
            Self::StateRef => "state",
            Self::ObjectRef => "object",
            Self::ObjectField => "object_field",
            Self::SetRef => "set",
        }
    }

    /// Check if this reference type requires global scope
    pub fn requires_global_scope(&self) -> bool {
        matches!(self, Self::StateRef | Self::ObjectRef)
    }
}

/// Utility functions for working with validation results
/// Check if validation result meets SSDF compliance requirements
pub fn validate_ssdf_compliance(result: &ReferenceValidationResult) -> Result<(), String> {
    if !result.is_security_compliant() {
        return Err(format!(
            "SSDF compliance violation: {} security violations detected",
            result.stats.security_violations
        ));
    }

    if result.stats.max_reference_depth > MAX_REFERENCE_DEPTH {
        return Err(format!(
            "SSDF compliance violation: reference depth {} exceeds limit {}",
            result.stats.max_reference_depth, MAX_REFERENCE_DEPTH
        ));
    }

    if result.stats.total_relationships > MAX_RELATIONSHIPS_PER_PASS {
        return Err(format!(
            "SSDF compliance violation: relationship count {} exceeds limit {}",
            result.stats.total_relationships, MAX_RELATIONSHIPS_PER_PASS
        ));
    }

    Ok(())
}

/// Create validation statistics summary for external reporting
pub fn create_validation_summary(result: &ReferenceValidationResult) -> HashMap<String, String> {
    let mut summary = HashMap::new();

    summary.insert(
        "total_relationships".to_string(),
        result.stats.total_relationships.to_string(),
    );
    summary.insert(
        "validated_count".to_string(),
        result.stats.validated_count.to_string(),
    );
    summary.insert(
        "error_count".to_string(),
        result.stats.error_count.to_string(),
    );
    summary.insert("cycle_count".to_string(), result.cycles.len().to_string());
    summary.insert(
        "success_rate".to_string(),
        format!("{:.2}%", result.success_rate() * 100.0),
    );
    summary.insert(
        "security_status".to_string(),
        result.stats.security_compliance_status().to_string(),
    );
    summary.insert(
        "processing_time_ms".to_string(),
        result.stats.processing_time_ms.to_string(),
    );
    summary.insert(
        "production_ready".to_string(),
        result.is_production_ready().to_string(),
    );

    summary
}

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_stats_success_rate() {
        let mut stats = ValidationStats::new();
        assert_eq!(stats.success_rate(), 1.0); // Empty case

        stats.total_relationships = 10;
        stats.validated_count = 8;
        assert_eq!(stats.success_rate(), 0.8);
    }

    #[test]
    fn test_validation_stats_security_compliance() {
        let mut stats = ValidationStats::new();
        assert_eq!(stats.security_compliance_status(), "COMPLIANT");

        stats.security_violations = 1;
        assert_eq!(stats.security_compliance_status(), "NON_COMPLIANT");

        stats.security_violations = 0;
        stats.max_reference_depth = MAX_REFERENCE_DEPTH * 3 / 4 + 1; // Over warning threshold
        assert_eq!(stats.security_compliance_status(), "WARNING");
    }

    #[test]
    fn test_security_compliance_info() {
        let mut compliance = SecurityComplianceInfo::new();

        compliance.record_limit_check("test_limit", 80, 100);
        assert_eq!(compliance.warnings.len(), 1); // Should warn at 80%
        assert!(compliance.warnings[0].contains("test_limit"));

        compliance.record_limit_check("safe_limit", 50, 100);
        assert_eq!(compliance.warnings.len(), 1); // No additional warning
    }

    #[test]
    fn test_validation_result_creation() {
        let result = ReferenceValidationResult::new_with_compliance();
        assert_eq!(result.success_rate(), 1.0);
        assert!(!result.has_cycles());
        assert_eq!(result.error_count(), 0);
        assert!(result.is_security_compliant());

        // Should have initialized compliance checks
        assert!(result.security_compliance.limits_checked.len() >= 4);
    }

    #[test]
    fn test_validation_result_with_issues() {
        let mut result = ReferenceValidationResult::new();
        result.stats.error_count = 2;
        result.stats.security_violations = 1;
        result
            .cycles
            .push(vec!["A".to_string(), "B".to_string(), "A".to_string()]);

        assert!(result.has_critical_issues());
        assert!(!result.is_production_ready());

        let breakdown = result.issue_breakdown();
        assert_eq!(breakdown.get("undefined_references"), Some(&2));
        assert_eq!(breakdown.get("dependency_cycles"), Some(&1));
        assert_eq!(breakdown.get("security_violations"), Some(&1));
    }

    #[test]
    fn test_reference_type_properties() {
        assert_eq!(ReferenceType::Variable.expected_symbol_type(), "variable");
        assert!(!ReferenceType::Variable.requires_global_scope());

        assert_eq!(ReferenceType::StateRef.expected_symbol_type(), "state");
        assert!(ReferenceType::StateRef.requires_global_scope());

        assert_eq!(ReferenceType::ObjectRef.expected_symbol_type(), "object");
        assert!(ReferenceType::ObjectRef.requires_global_scope());
    }

    #[test]
    fn test_ssdf_compliance_validation() {
        let mut result = ReferenceValidationResult::new_with_compliance();
        result.stats.security_violations = 0;
        result.stats.max_reference_depth = 10;
        result.stats.total_relationships = 100;

        assert!(validate_ssdf_compliance(&result).is_ok());

        result.stats.security_violations = 1;
        assert!(validate_ssdf_compliance(&result).is_err());
    }

    #[test]
    fn test_audit_log_entry() {
        let mut result = ReferenceValidationResult::new_with_compliance();
        result.stats.total_relationships = 100;
        result.stats.validated_count = 95;
        result.stats.error_count = 5;
        result.stats.processing_time_ms = 1500;

        let audit_entry = result.audit_log_entry();
        assert!(audit_entry.contains("REFERENCE_VALIDATION_AUDIT"));
        assert!(audit_entry.contains("relationships=100"));
        assert!(audit_entry.contains("validated=95"));
        assert!(audit_entry.contains("errors=5"));
        assert!(audit_entry.contains("processing_time=1500ms"));
    }

    #[test]
    fn test_performance_metrics() {
        let mut stats = ValidationStats::new();
        stats.total_relationships = 1000;
        stats.validated_count = 950;
        stats.error_count = 50;
        stats.processing_time_ms = 2000;
        stats.security_checks_performed = 100;
        stats.security_violations = 2;
        stats.max_reference_depth = 25;

        let metrics = stats.performance_metrics();
        assert!(metrics.contains_key("validation_rate_per_ms"));
        assert!(metrics.contains_key("error_rate"));
        assert!(metrics.contains_key("security_check_efficiency"));
        assert!(metrics.contains_key("reference_depth_utilization"));

        // Check specific calculations
        assert_eq!(metrics["error_rate"], 0.05); // 50/1000
        assert_eq!(
            metrics["reference_depth_utilization"],
            25.0 / MAX_REFERENCE_DEPTH as f64
        );
    }
}
