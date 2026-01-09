//! Kubernetes Resource Collector
//!
//! Collects Kubernetes resources via kubectl and returns as RecordData.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

/// Collector for Kubernetes resources via kubectl
#[derive(Clone)]
pub struct K8sResourceCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl K8sResourceCollector {
    /// Create new collector with the given executor
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
        }
    }

    /// Extract required 'kind' field from object
    fn extract_kind(&self, object: &ExecutableObject) -> Result<String, CollectionError> {
        self.extract_string_field(object, "kind")?.ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'kind'".to_string(),
            }
        })
    }

    /// Extract optional string field from object
    fn extract_string_field(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Result<Option<String>, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    match value {
                        ResolvedValue::String(s) => return Ok(Some(s.clone())),
                        _ => {
                            return Err(CollectionError::InvalidObjectConfiguration {
                                object_id: object.identifier.clone(),
                                reason: format!("Field '{}' must be a string", field_name),
                            });
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Find kubeconfig path for out-of-cluster usage
    fn find_kubeconfig(&self) -> Option<String> {
        if let Ok(kubeconfig) = std::env::var("KUBECONFIG") {
            if std::path::Path::new(&kubeconfig).exists() {
                return Some(kubeconfig);
            }
        }

        if let Ok(home) = std::env::var("HOME") {
            let default_config = format!("{}/.kube/config", home);
            if std::path::Path::new(&default_config).exists() {
                return Some(default_config);
            }
        }

        None
    }

    /// Find kubectl binary path
    fn find_kubectl(&self) -> &'static str {
        for path in &["/usr/local/bin/kubectl", "/usr/bin/kubectl"] {
            if std::path::Path::new(path).exists() {
                return path;
            }
        }
        "kubectl" // Fall back to PATH lookup
    }

    /// Build kubectl command arguments
    fn build_kubectl_args(
        &self,
        kind: &str,
        namespace: Option<&str>,
        name: Option<&str>,
        label_selector: Option<&str>,
    ) -> Vec<String> {
        let mut args = vec![];

        // Check for in-cluster config first
        if let (Ok(host), Ok(port)) = (
            std::env::var("KUBERNETES_SERVICE_HOST"),
            std::env::var("KUBERNETES_SERVICE_PORT"),
        ) {
            // Running in-cluster - use explicit ServiceAccount auth
            args.push("--server".to_string());
            args.push(format!("https://{}:{}", host, port));

            if let Ok(token) =
                std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
            {
                args.push("--token".to_string());
                args.push(token.trim().to_string());
            }

            let ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
            if std::path::Path::new(ca_path).exists() {
                args.push("--certificate-authority".to_string());
                args.push(ca_path.to_string());
            }
        } else if let Some(kubeconfig) = self.find_kubeconfig() {
            // Running outside cluster - use kubeconfig
            args.push("--kubeconfig".to_string());
            args.push(kubeconfig);
        }

        args.push("get".to_string());
        args.push(kind.to_lowercase());

        // Add namespace or all-namespaces
        if let Some(ns) = namespace {
            args.push("-n".to_string());
            args.push(ns.to_string());
        } else if !is_cluster_scoped(kind) {
            args.push("--all-namespaces".to_string());
        }

        // Add exact name if specified
        if let Some(n) = name {
            args.push(n.to_string());
        }

        // Add label selector
        if let Some(selector) = label_selector {
            args.push("-l".to_string());
            args.push(selector.to_string());
        }

        // Output as JSON
        args.push("-o".to_string());
        args.push("json".to_string());

        args
    }

    /// Build command string for traceability
    fn build_command_string(&self, args: &[String]) -> String {
        let kubectl_path = self.find_kubectl();
        format!("{} {}", kubectl_path, args.join(" "))
    }

    /// Execute kubectl and parse response
    fn execute_kubectl(
        &self,
        args: &[String],
        timeout: Option<Duration>,
    ) -> Result<serde_json::Value, CollectionError> {
        // Convert args to &str slice
        let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let kubectl_path = self.find_kubectl();
        let output = self
            .executor
            .execute(kubectl_path, &args_str, timeout)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: "kubectl".to_string(),
                reason: format!("Failed to execute kubectl: {}", e),
            })?;

        if output.exit_code != 0 {
            // Check for "not found" which is not an error, just empty result
            if output.stderr.contains("not found") || output.stderr.contains("No resources found") {
                return Ok(serde_json::json!({"items": []}));
            }

            return Err(CollectionError::CollectionFailed {
                object_id: "kubectl".to_string(),
                reason: format!(
                    "kubectl failed (exit {}): {}",
                    output.exit_code, output.stderr
                ),
            });
        }

        serde_json::from_str(&output.stdout).map_err(|e| CollectionError::CollectionFailed {
            object_id: "kubectl".to_string(),
            reason: format!("Failed to parse kubectl JSON output: {}", e),
        })
    }

    /// Filter results by name_prefix
    fn filter_by_name_prefix(
        &self,
        json: &serde_json::Value,
        name_prefix: &str,
    ) -> Option<serde_json::Value> {
        // Handle list response
        if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
            for item in items {
                if let Some(name) = item
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(|n| n.as_str())
                {
                    if name.starts_with(name_prefix) {
                        return Some(item.clone());
                    }
                }
            }
            return None;
        }

        // Handle single resource response
        if let Some(name) = json
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
        {
            if name.starts_with(name_prefix) {
                return Some(json.clone());
            }
        }

        None
    }

    /// Get first item from list or return single resource
    fn get_first_resource(&self, json: &serde_json::Value) -> Option<serde_json::Value> {
        // Handle list response
        if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
            return items.first().cloned();
        }

        // Handle single resource (when name is specified)
        if json.get("metadata").is_some() {
            return Some(json.clone());
        }

        None
    }

    /// Count items in response
    fn count_resources(&self, json: &serde_json::Value) -> i64 {
        if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
            items.len() as i64
        } else if json.get("metadata").is_some() {
            1
        } else {
            0
        }
    }
}

/// Check if resource kind is cluster-scoped (no namespace)
fn is_cluster_scoped(kind: &str) -> bool {
    matches!(
        kind.to_lowercase().as_str(),
        "namespace" | "node" | "persistentvolume" | "clusterrole" | "clusterrolebinding"
    )
}

impl CtnDataCollector for K8sResourceCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate contract compatibility
        self.validate_ctn_compatibility(contract)?;

        // Extract object fields
        let kind = self.extract_kind(object)?;
        let namespace = self.extract_string_field(object, "namespace")?;
        let name = self.extract_string_field(object, "name")?;
        let name_prefix = self.extract_string_field(object, "name_prefix")?;
        let label_selector = self.extract_string_field(object, "label_selector")?;

        // Check for timeout hint
        let timeout = hints
            .get_parameter_as_int("timeout")
            .map(|t| Duration::from_secs(t as u64));

        // Build and execute kubectl command
        let args = self.build_kubectl_args(
            &kind,
            namespace.as_deref(),
            name.as_deref(),
            label_selector.as_deref(),
        );

        // Build command string for traceability
        let command_str = self.build_command_string(&args);

        let json_response = self.execute_kubectl(&args, timeout)?;

        // Count total resources
        let count = self.count_resources(&json_response);

        // Get the resource to return (with name_prefix filtering if specified)
        let resource = if let Some(prefix) = &name_prefix {
            self.filter_by_name_prefix(&json_response, prefix)
        } else {
            self.get_first_resource(&json_response)
        };

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "k8s_resource".to_string(),
            self.id.clone(),
        );

        // Build target string for traceability
        let target = format!(
            "{}{}{}",
            kind,
            namespace
                .as_ref()
                .map(|n| format!(":{}", n))
                .unwrap_or_default(),
            label_selector
                .as_ref()
                .map(|l| format!(":{}", l))
                .unwrap_or_default()
        );

        // Set collection method for traceability
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query Kubernetes API for resources")
            .target(&target)
            .command(&command_str)
            .input("kind", &kind);

        if let Some(ref ns) = namespace {
            method_builder = method_builder.input("namespace", ns);
        }
        if let Some(ref n) = name {
            method_builder = method_builder.input("name", n);
        }
        if let Some(ref prefix) = name_prefix {
            method_builder = method_builder.input("name_prefix", prefix);
        }
        if let Some(ref selector) = label_selector {
            method_builder = method_builder.input("label_selector", selector);
        }

        data.set_method(method_builder.build());

        let found = resource.is_some();
        data.add_field("found".to_string(), ResolvedValue::Boolean(found));
        data.add_field("count".to_string(), ResolvedValue::Integer(count));

        if let Some(res) = resource {
            let record_data = RecordData::from_json_value(res);
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );
        } else {
            // Return empty record if not found
            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["k8s_resource".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "k8s_resource" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'k8s_resource', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_cluster_scoped() {
        assert!(is_cluster_scoped("Namespace"));
        assert!(is_cluster_scoped("namespace"));
        assert!(is_cluster_scoped("Node"));
        assert!(!is_cluster_scoped("Pod"));
        assert!(!is_cluster_scoped("Service"));
    }

    #[test]
    fn test_build_kubectl_args_pod() {
        let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(30));
        executor.allow_commands(&["kubectl", "/usr/local/bin/kubectl"]);
        let collector = K8sResourceCollector::new("test", executor);

        let args = collector.build_kubectl_args(
            "Pod",
            Some("kube-system"),
            None,
            Some("component=kube-apiserver"),
        );

        assert!(args.contains(&"get".to_string()));
        assert!(args.contains(&"pod".to_string()));
        assert!(args.contains(&"-n".to_string()));
        assert!(args.contains(&"kube-system".to_string()));
        assert!(args.contains(&"-l".to_string()));
        assert!(args.contains(&"component=kube-apiserver".to_string()));
        assert!(args.contains(&"-o".to_string()));
        assert!(args.contains(&"json".to_string()));
    }

    #[test]
    fn test_build_kubectl_args_namespace() {
        let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(30));
        executor.allow_commands(&["kubectl", "/usr/local/bin/kubectl"]);
        let collector = K8sResourceCollector::new("test", executor);

        let args = collector.build_kubectl_args("Namespace", None, Some("default"), None);

        assert!(args.contains(&"get".to_string()));
        assert!(args.contains(&"namespace".to_string()));
        assert!(args.contains(&"default".to_string()));
        // Should NOT contain --all-namespaces for cluster-scoped
        assert!(!args.contains(&"--all-namespaces".to_string()));
    }
}
