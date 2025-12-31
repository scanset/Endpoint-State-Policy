//! # CTN Contracts Module
//!
//! Contract definitions specify the interface requirements for each CTN type:
//! - Object requirements: What fields objects must provide
//! - State requirements: What fields can be validated and with which operations
//! - Field mappings: How to map between ESP field names and collected data
//! - Collection strategy: Performance hints and capabilities

pub mod computed_values;
pub mod file_contracts;
pub mod json_contracts;
pub mod k8s_resource_contracts;
pub mod rpm_contracts;
pub mod selinux_contracts;
pub mod sysctl_contracts;
pub mod systemd_contracts;
pub mod tcp_listener_contracts;

pub use computed_values::create_computed_values_contract;
pub use file_contracts::{create_file_content_contract, create_file_metadata_contract};
pub use json_contracts::create_json_record_contract;
pub use k8s_resource_contracts::create_k8s_resource_contract;
pub use rpm_contracts::create_rpm_package_contract;
pub use selinux_contracts::create_selinux_status_contract;
pub use sysctl_contracts::create_sysctl_parameter_contract;
pub use systemd_contracts::create_systemd_service_contract;
pub use tcp_listener_contracts::create_tcp_listener_contract;
