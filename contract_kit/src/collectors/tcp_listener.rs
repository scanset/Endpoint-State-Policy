//! TCP Listener Collector
//!
//! Collects information about TCP ports in LISTEN state.
//! Reads /proc/net/tcp on Linux to determine if a port is listening.

use agent_core::execution::BehaviorHints;
use agent_core::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use agent_core::types::common::ResolvedValue;
use agent_core::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Collector for TCP listener information
pub struct TcpListenerCollector {
    id: String,
}

impl TcpListenerCollector {
    pub fn new() -> Self {
        Self {
            id: "tcp_listener_collector".to_string(),
        }
    }

    /// Extract port from object
    fn extract_port(&self, object: &ExecutableObject) -> Result<u16, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == "port" {
                    match value {
                        ResolvedValue::Integer(i) => {
                            if *i < 1 || *i > 65535 {
                                return Err(CollectionError::InvalidObjectConfiguration {
                                    object_id: object.identifier.clone(),
                                    reason: format!("Port {} out of range (1-65535)", i),
                                });
                            }
                            return Ok(*i as u16);
                        }
                        ResolvedValue::String(s) => {
                            let port: u16 = s.parse().map_err(|_| {
                                CollectionError::InvalidObjectConfiguration {
                                    object_id: object.identifier.clone(),
                                    reason: format!("Invalid port number: {}", s),
                                }
                            })?;
                            return Ok(port);
                        }
                        _ => {
                            return Err(CollectionError::InvalidObjectConfiguration {
                                object_id: object.identifier.clone(),
                                reason: format!("Port must be an integer, got {:?}", value),
                            });
                        }
                    }
                }
            }
        }

        Err(CollectionError::InvalidObjectConfiguration {
            object_id: object.identifier.clone(),
            reason: "Missing required field 'port'".to_string(),
        })
    }

    /// Extract optional host filter from object
    fn extract_host(&self, object: &ExecutableObject) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == "host" {
                    if let ResolvedValue::String(s) = value {
                        // "any" means no filtering
                        if s.to_lowercase() == "any" {
                            return None;
                        }
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }

    /// Check if port is listening by reading /proc/net/tcp
    fn check_port_listening(&self, port: u16, host_filter: Option<&str>) -> ListenerResult {
        let port_hex = format!("{:04X}", port);

        // Read /proc/net/tcp
        let file = match File::open("/proc/net/tcp") {
            Ok(f) => f,
            Err(e) => {
                return ListenerResult {
                    listening: false,
                    local_address: None,
                    error: Some(format!("Cannot open /proc/net/tcp: {}", e)),
                };
            }
        };

        let reader = BufReader::new(file);

        // Skip header line, then check each entry
        for line in reader.lines().skip(1) {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            if let Some(result) = self.parse_tcp_line(&line, &port_hex, host_filter) {
                return result;
            }
        }

        // Port not found listening
        ListenerResult {
            listening: false,
            local_address: None,
            error: None,
        }
    }

    /// Parse a line from /proc/net/tcp
    /// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
    /// Example: 0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ...
    fn parse_tcp_line(
        &self,
        line: &str,
        port_hex: &str,
        host_filter: Option<&str>,
    ) -> Option<ListenerResult> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        // local_address is in format ADDR:PORT (hex)
        let local_addr = parts[1];
        let addr_parts: Vec<&str> = local_addr.split(':').collect();
        if addr_parts.len() != 2 {
            return None;
        }

        let local_ip_hex = addr_parts[0];
        let local_port_hex = addr_parts[1];

        // Check if port matches
        if local_port_hex != port_hex {
            return None;
        }

        // Check state - 0A is LISTEN
        let state = parts[3];
        if state != "0A" {
            return None;
        }

        // Convert hex IP to dotted decimal
        let local_ip = self.hex_to_ipv4(local_ip_hex);

        // If host filter specified, check if it matches
        if let Some(filter) = host_filter {
            if local_ip != filter {
                // Special case: 0.0.0.0 matches any filter since it binds all interfaces
                if local_ip != "0.0.0.0" {
                    return None;
                }
            }
        }

        // Found a matching listener
        let port = u16::from_str_radix(local_port_hex, 16).unwrap_or(0);
        Some(ListenerResult {
            listening: true,
            local_address: Some(format!("{}:{}", local_ip, port)),
            error: None,
        })
    }

    /// Convert hex IP address (little-endian) to dotted decimal
    /// /proc/net/tcp stores IPv4 in little-endian hex format
    fn hex_to_ipv4(&self, hex: &str) -> String {
        if hex.len() != 8 {
            return "invalid".to_string();
        }

        // Parse as u32 and convert from little-endian
        let bytes: Vec<u8> = (0..4)
            .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
            .collect();

        if bytes.len() != 4 {
            return "invalid".to_string();
        }

        // /proc/net/tcp stores in little-endian, so reverse for display
        format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
    }
}

/// Result of checking a port
struct ListenerResult {
    listening: bool,
    local_address: Option<String>,
    #[allow(dead_code)]
    error: Option<String>,
}

impl Default for TcpListenerCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for TcpListenerCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate contract compatibility
        self.validate_ctn_compatibility(contract)?;

        // Extract port (required)
        let port = self.extract_port(object)?;

        // Extract host filter (optional)
        let host_filter = self.extract_host(object);

        // Check if port is listening
        let result = self.check_port_listening(port, host_filter.as_deref());

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "tcp_listener".to_string(),
            self.id.clone(),
        );

        data.add_field(
            "listening".to_string(),
            ResolvedValue::Boolean(result.listening),
        );

        if let Some(addr) = result.local_address {
            data.add_field("local_address".to_string(), ResolvedValue::String(addr));
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["tcp_listener".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "tcp_listener" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'tcp_listener', got '{}'",
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
    fn test_hex_to_ipv4() {
        let collector = TcpListenerCollector::new();

        // 00000000 = 0.0.0.0 (all interfaces)
        assert_eq!(collector.hex_to_ipv4("00000000"), "0.0.0.0");

        // 0100007F = 127.0.0.1 (localhost, little-endian)
        assert_eq!(collector.hex_to_ipv4("0100007F"), "127.0.0.1");

        // Invalid length
        assert_eq!(collector.hex_to_ipv4("0000"), "invalid");
    }

    #[test]
    fn test_port_extraction() {
        // This would require mocking ExecutableObject
        // For now, just verify the collector can be created
        let collector = TcpListenerCollector::new();
        assert_eq!(collector.collector_id(), "tcp_listener_collector");
    }
}
