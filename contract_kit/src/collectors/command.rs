//! Command-based data collector using SystemCommandExecutor
//!
//! Executes whitelisted system commands to gather compliance data for:
//! - RPM package information
//! - Systemd service status
//! - Sysctl kernel parameters
//! - SELinux enforcement mode

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::collections::HashMap;

/// Collector that executes system commands to gather compliance data
#[derive(Clone)]
pub struct CommandCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl CommandCollector {
    /// Create a new command collector with the given executor
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
        }
    }

    /// Parse RPM package info from rpm -q output
    /// Format: "package-version-release.arch"
    fn parse_rpm_output(&self, stdout: &str) -> Option<(String, String)> {
        let line = stdout.trim();
        if line.is_empty() || line.contains("not installed") {
            return None;
        }

        // Split on last '-' to separate version-release from name
        // Example: "openssl-3.0.7-27.el9.x86_64" -> ("openssl", "3.0.7-27.el9")
        let parts: Vec<&str> = line.rsplitn(2, '-').collect();
        if parts.len() == 2 {
            let version_release = parts.first()?;
            let name_part = parts.get(1)?;
            let name_arch: Vec<&str> = name_part.rsplitn(2, '-').collect();
            if name_arch.len() == 2 {
                let name = name_arch.get(1)?;
                return Some((name.to_string(), version_release.to_string()));
            }
        }

        // Fallback: just return the whole line as version
        Some((line.to_string(), "".to_string()))
    }

    /// Collect RPM package data for a single package
    /// Now supports BEHAVIOR hints for timeout configuration
    fn collect_rpm_package(
        &self,
        object: &ExecutableObject,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Extract package name from object
        let package_name = self.extract_field(object, "package_name")?;

        // Check for timeout behavior
        let timeout = hints
            .get_parameter_as_int("timeout")
            .map(|t| std::time::Duration::from_secs(t as u64));

        // Build the command string
        let command_str = format!("rpm -q {}", package_name);

        // Execute rpm query with optional timeout
        let output = self
            .executor
            .execute("rpm", &["-q", &package_name], timeout)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("RPM command failed: {}", e),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "rpm_package".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query RPM package information")
            .target(&package_name)
            .command(&command_str)
            .input("package_name", &package_name)
            .build();
        data.set_method(method);

        // Store package name
        data.add_field(
            "package_name".to_string(),
            ResolvedValue::String(package_name.clone()),
        );

        // Parse installation status and version
        let installed = output.exit_code == 0;
        data.add_field("installed".to_string(), ResolvedValue::Boolean(installed));

        if installed {
            if let Some((_name, version)) = self.parse_rpm_output(&output.stdout) {
                data.add_field("version".to_string(), ResolvedValue::String(version));
            }
        }

        Ok(data)
    }

    /// Collect systemd service status
    /// Now supports BEHAVIOR hints for timeout configuration
    fn collect_systemd_service(
        &self,
        object: &ExecutableObject,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        let service_name = self.extract_field(object, "service_name")?;

        // Check for timeout behavior
        let timeout = hints
            .get_parameter_as_int("timeout")
            .map(|t| std::time::Duration::from_secs(t as u64));

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "systemd_service".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query systemd service status")
            .target(&service_name)
            .command(format!(
                "systemctl is-active {}; systemctl is-enabled {}",
                service_name, service_name
            ))
            .input("service_name", &service_name)
            .build();
        data.set_method(method);

        data.add_field(
            "service_name".to_string(),
            ResolvedValue::String(service_name.clone()),
        );

        // Check if active
        let active_output = self
            .executor
            .execute("systemctl", &["is-active", &service_name], timeout)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("systemctl is-active failed: {}", e),
            })?;

        let active = active_output.exit_code == 0 && active_output.stdout.trim() == "active";
        data.add_field("active".to_string(), ResolvedValue::Boolean(active));

        // Check if enabled
        let enabled_output = self
            .executor
            .execute("systemctl", &["is-enabled", &service_name], timeout)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("systemctl is-enabled failed: {}", e),
            })?;

        let enabled = enabled_output.exit_code == 0 && enabled_output.stdout.trim() == "enabled";
        data.add_field("enabled".to_string(), ResolvedValue::Boolean(enabled));

        // Check if loaded
        data.add_field(
            "loaded".to_string(),
            ResolvedValue::Boolean(active || enabled),
        );

        Ok(data)
    }

    /// Collect sysctl kernel parameter value
    /// Now supports BEHAVIOR hints for timeout configuration
    fn collect_sysctl_parameter(
        &self,
        object: &ExecutableObject,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        let parameter_name = self.extract_field(object, "parameter_name")?;

        // Check for timeout behavior
        let timeout = hints
            .get_parameter_as_int("timeout")
            .map(|t| std::time::Duration::from_secs(t as u64));

        // Build command string
        let command_str = format!("sysctl -n {}", parameter_name);

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "sysctl_parameter".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query kernel sysctl parameter")
            .target(&parameter_name)
            .command(&command_str)
            .input("parameter_name", &parameter_name)
            .build();
        data.set_method(method);

        data.add_field(
            "parameter_name".to_string(),
            ResolvedValue::String(parameter_name.clone()),
        );

        // Execute sysctl
        let output = self
            .executor
            .execute("sysctl", &["-n", &parameter_name], timeout)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("sysctl failed: {}", e),
            })?;

        if output.exit_code == 0 {
            let value = output.stdout.trim().to_string();
            data.add_field("value".to_string(), ResolvedValue::String(value.clone()));

            // Try to parse as integer
            if let Ok(int_val) = value.parse::<i64>() {
                data.add_field("value_int".to_string(), ResolvedValue::Integer(int_val));
            }
        }

        Ok(data)
    }

    /// Collect SELinux enforcement status
    /// Now supports BEHAVIOR hints for timeout configuration
    fn collect_selinux_status(
        &self,
        object: &ExecutableObject,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Check for timeout behavior
        let timeout = hints
            .get_parameter_as_int("timeout")
            .map(|t| std::time::Duration::from_secs(t as u64));

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "selinux_status".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query SELinux enforcement status")
            .target("selinux")
            .command("getenforce")
            .build();
        data.set_method(method);

        // Execute getenforce
        let output = self
            .executor
            .execute("getenforce", &[], timeout)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("getenforce failed: {}", e),
            })?;

        if output.exit_code == 0 {
            let mode = output.stdout.trim().to_string();
            let enforcing = mode == "Enforcing";

            data.add_field("mode".to_string(), ResolvedValue::String(mode));
            data.add_field("enforcing".to_string(), ResolvedValue::Boolean(enforcing));
        }

        Ok(data)
    }

    /// Extract a required string field from object
    fn extract_field(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Result<String, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    match value {
                        ResolvedValue::String(s) => return Ok(s.clone()),
                        _ => {
                            return Err(CollectionError::InvalidObjectConfiguration {
                                object_id: object.identifier.clone(),
                                reason: format!(
                                    "Field '{}' must be a string, got {:?}",
                                    field_name, value
                                ),
                            })
                        }
                    }
                }
            }
        }

        Err(CollectionError::InvalidObjectConfiguration {
            object_id: object.identifier.clone(),
            reason: format!("Missing required field '{}'", field_name),
        })
    }
}

impl CtnDataCollector for CommandCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        contract.validate_behavior_hints(hints).map_err(|e| {
            CollectionError::CtnContractValidation {
                reason: e.to_string(),
            }
        })?;

        // Then existing code...
        match contract.ctn_type.as_str() {
            "rpm_package" => self.collect_rpm_package(object, hints),
            "systemd_service" => self.collect_systemd_service(object, hints),
            "sysctl_parameter" => self.collect_sysctl_parameter(object, hints),
            "selinux_status" => self.collect_selinux_status(object, hints),
            _ => Err(CollectionError::UnsupportedCtnType {
                ctn_type: contract.ctn_type.clone(),
                collector_id: self.id.clone(),
            }),
        }
    }

    fn collect_batch(
        &self,
        objects: Vec<&ExecutableObject>,
        contract: &CtnContract,
    ) -> Result<HashMap<String, CollectedData>, CollectionError> {
        use execution_engine::execution::extract_behavior_hints;

        match contract.ctn_type.as_str() {
            "rpm_package" => {
                // Extract hints from first object (batch operations use same hints)
                let hints = objects
                    .first()
                    .map(|obj| extract_behavior_hints(obj))
                    .unwrap_or_else(BehaviorHints::empty);

                // Check for timeout behavior
                let timeout = hints
                    .get_parameter_as_int("timeout")
                    .map(|t| std::time::Duration::from_secs(t as u64));

                // Execute rpm -qa ONCE for all packages
                let output = self
                    .executor
                    .execute("rpm", &["-qa"], timeout)
                    .map_err(|e| CollectionError::CollectionFailed {
                        object_id: "batch".to_string(),
                        reason: format!("RPM batch command failed: {}", e),
                    })?;

                // Parse all installed packages into a map
                let mut installed_packages: HashMap<String, String> = HashMap::new();
                for line in output.stdout.lines() {
                    if let Some((name, version)) = self.parse_rpm_output(line) {
                        installed_packages.insert(name, version);
                    }
                }

                // Match against requested packages
                let mut results = HashMap::new();
                for object in objects {
                    let package_name = self.extract_field(object, "package_name")?;

                    let mut data = CollectedData::new(
                        object.identifier.clone(),
                        "rpm_package".to_string(),
                        self.id.clone(),
                    );

                    // Set collection method for batch operation
                    let method = CollectionMethod::builder()
                        .method_type(CollectionMethodType::Command)
                        .description("Batch query RPM packages")
                        .target(&package_name)
                        .command("rpm -qa")
                        .input("package_name", &package_name)
                        .input("batch_mode", "true")
                        .build();
                    data.set_method(method);

                    data.add_field(
                        "package_name".to_string(),
                        ResolvedValue::String(package_name.clone()),
                    );

                    if let Some(version) = installed_packages.get(&package_name) {
                        data.add_field("installed".to_string(), ResolvedValue::Boolean(true));
                        data.add_field(
                            "version".to_string(),
                            ResolvedValue::String(version.clone()),
                        );
                    } else {
                        data.add_field("installed".to_string(), ResolvedValue::Boolean(false));
                    }

                    results.insert(object.identifier.clone(), data);
                }

                Ok(results)
            }
            _ => Err(CollectionError::UnsupportedCtnType {
                ctn_type: contract.ctn_type.clone(),
                collector_id: self.id.clone(),
            }),
        }
    }

    fn supports_batch_collection(&self) -> bool {
        true // Command execution benefits greatly from batching
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec![
            "rpm_package".to_string(),
            "systemd_service".to_string(),
            "sysctl_parameter".to_string(),
            "selinux_status".to_string(),
        ]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if !self.supported_ctn_types().contains(&contract.ctn_type) {
            return Err(CollectionError::CtnContractValidation {
                reason: format!("CTN type '{}' not supported", contract.ctn_type),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }
}
