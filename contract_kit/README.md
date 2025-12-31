# ESP Scanner SDK

**Production-ready compliance scanning framework for ESP (Endpoint State Policy) validation**

A complete implementation of platform-specific scanners for the ESP compliance validation framework, providing file system, package, service, kernel parameter, and structured data validation capabilities.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Components](#components)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [CTN Types](#ctn-types)
- [Extending the SDK](#extending-the-sdk)
- [Testing](#testing)
- [Performance](#performance)
- [Security](#security)
- [Contributing](#contributing)

---

## Overview

The **ESP Scanner SDK** (`esp_scanner_sdk`) is a command-line scanner application that validates Linux system compliance against ESP policy definitions. It provides production-ready implementations of:

- **File system validation** - Metadata and content checking
- **Package management** - RPM installation and version validation
- **System services** - Systemd service status checks
- **Kernel parameters** - Sysctl configuration validation
- **SELinux enforcement** - Security mode verification
- **JSON data** - Structured data validation with record checks

### Key Features

✅ **Production-Ready Implementations** - Battle-tested collectors and executors
✅ **RHEL 9 STIG Focus** - Optimized for Red Hat Enterprise Linux compliance
✅ **Security-Hardened** - Command whitelisting and timeout enforcement
✅ **Batch Optimization** - Efficient multi-object collection strategies
✅ **Behavior Support** - Fine-grained control via ESP BEHAVIOR directives
✅ **Contract-Based Design** - Clear interface specifications and field mappings

---

## Architecture

### Three-Layer System

```
┌─────────────────────────────────────────────────────────┐
│                    ESP Source Files                     │
│                      (.esp files)                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                    esp_compiler                         │
│  • Lexer, Parser, Multi-Pass Validation                │
│  • AST Generation, Symbol Resolution                   │
│  • Type Checking, Dependency Analysis                  │
└────────────────────┬────────────────────────────────────┘
                     │ AST
                     ▼
┌─────────────────────────────────────────────────────────┐
│                 esp_scanner_base                        │
│  • Resolution Engine (Variables, Sets, References)     │
│  • Execution Engine (Orchestration, TEST evaluation)   │
│  • Strategy Framework (Traits, Contracts, Registry)    │
│  • Result Generation (SIEM-compatible findings)        │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                 esp_scanner_sdk (THIS CRATE)            │
│  • CLI Application (main.rs)                           │
│  • Concrete Strategies (Collectors + Executors)        │
│  • CTN Contracts (Interface Specifications)            │
│  • Command Execution (RHEL 9 Whitelist)                │
└─────────────────────────────────────────────────────────┘
```

### Component Relationships

```
                    ┌──────────────────┐
                    │  Scanner Binary  │
                    │    (main.rs)     │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │     Registry     │
                    │  (lib.rs)        │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Contract │  │Collector │  │ Executor │
        │  (spec)  │  │ (gather) │  │(validate)│
        └──────────┘  └──────────┘  └──────────┘
              │              │              │
              └──────────────┴──────────────┘
                             │
                     ┌───────┴───────┐
                     │               │
              File System        Command
              - metadata         - rpm
              - content          - systemctl
              - json             - sysctl
                                - getenforce
```

---

## Project Structure

```
esp_scanner_sdk/
├── Cargo.toml                      # Binary crate configuration
├── README.md                       # This file
├── Scanner_Development_Guide.md   # Developer guide for extensions
│
├── src/
│   ├── main.rs                    # CLI entry point
│   ├── lib.rs                     # Registry creation and exports
│   │
│   ├── contracts/                 # CTN interface specifications
│   │   ├── mod.rs
│   │   ├── file_contracts.rs      # file_metadata, file_content
│   │   ├── json_contracts.rs      # json_record
│   │   ├── rpm_contracts.rs       # rpm_package
│   │   ├── systemd_contracts.rs   # systemd_service
│   │   ├── sysctl_contracts.rs    # sysctl_parameter
│   │   ├── selinux_contracts.rs   # selinux_status
│   │   └── computed_values.rs     # computed_values (testing)
│   │
│   ├── collectors/                # Data gathering implementations
│   │   ├── mod.rs
│   │   ├── filesystem.rs          # File I/O collector
│   │   ├── command.rs             # Command execution collector
│   │   └── computed_values.rs     # Pass-through collector
│   │
│   ├── executors/                 # Validation implementations
│   │   ├── mod.rs
│   │   ├── file_metadata.rs       # Permissions, owner, size
│   │   ├── file_content.rs        # String operations, patterns
│   │   ├── json_record.rs         # JSON field validation
│   │   ├── rpm_package.rs         # Package checks
│   │   ├── systemd_service.rs     # Service status
│   │   ├── sysctl_parameter.rs    # Kernel parameters
│   │   ├── selinux_status.rs      # SELinux enforcement
│   │   └── computed_values.rs     # Variable validation
│   │
│   └── commands/                  # Platform command configs
│       ├── mod.rs
│       └── rhel9.rs               # RHEL 9 command whitelist
│
└── tests/                         # Integration test suite
    ├── scanfiles/                 # Test data files
    │   ├── passwd
    │   ├── shadow
    │   ├── sudoers
    │   ├── sshd_config
    │   └── test_data.json
    │
    └── policies/                  # Test ESP files
        ├── file_metadata.esp
        ├── file_content.esp
        ├── set_operations.esp
        └── complex_logic_tree.esp
```

---

## Components

### 1. Contracts (`contracts/`)

**Purpose:** Define the interface specification for each CTN type

Contracts specify:
- **Object Requirements** - What fields OBJECT blocks must/may contain
- **State Requirements** - What fields STATE blocks can validate
- **Field Mappings** - How ESP names map to collected data field names
- **Collection Strategy** - Performance hints and capabilities
- **Supported Behaviors** - Optional features and their parameters

**Example Contract Structure:**

```rust
pub fn create_file_metadata_contract() -> CtnContract {
    let mut contract = CtnContract::new("file_metadata".to_string());

    // Object requirements
    contract.object_requirements.add_required_field(ObjectFieldSpec {
        name: "path".to_string(),
        data_type: DataType::String,
        description: "File system path".to_string(),
        example_values: vec!["/etc/sudoers".to_string()],
        validation_notes: Some("Supports VAR resolution".to_string()),
    });

    // State requirements
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "permissions".to_string(),
        data_type: DataType::String,
        allowed_operations: vec![Operation::Equals, Operation::NotEqual],
        description: "File permissions in octal".to_string(),
        example_values: vec!["0440".to_string(), "0644".to_string()],
        validation_notes: Some("4-digit octal format".to_string()),
    });

    // Field mappings: ESP name → collected data name
    contract.field_mappings.validation_mappings.state_to_data
        .insert("permissions".to_string(), "file_mode".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["file_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(5),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
```

**Key Contracts:**

- `file_metadata` - Fast stat()-based file checks
- `file_content` - Full file content reading and string validation
- `json_record` - Structured JSON validation with field paths
- `rpm_package` - RPM installation and version checks
- `systemd_service` - Service active/enabled/loaded status
- `sysctl_parameter` - Kernel parameter validation
- `selinux_status` - SELinux enforcement mode

---

### 2. Collectors (`collectors/`)

**Purpose:** Gather data from the system according to contract specifications

Collectors implement the `CtnDataCollector` trait:

```rust
pub trait CtnDataCollector {
    /// Collect data for a single object with behavior hints
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError>;

    /// Batch collect multiple objects (optional optimization)
    fn collect_batch(
        &self,
        objects: Vec<&ExecutableObject>,
        contract: &CtnContract,
    ) -> Result<HashMap<String, CollectedData>, CollectionError>;

    /// Return supported CTN types
    fn supported_ctn_types(&self) -> Vec<String>;

    /// Validate compatibility with contract
    fn validate_ctn_compatibility(&self, contract: &CtnContract)
        -> Result<(), CollectionError>;

    /// Unique identifier
    fn collector_id(&self) -> &str;

    /// Whether this collector supports batch collection
    fn supports_batch_collection(&self) -> bool;
}
```

**Key Collectors:**

#### FileSystemCollector

```rust
pub struct FileSystemCollector {
    id: String,
}

impl FileSystemCollector {
    // Metadata collection - fast stat() calls
    fn collect_metadata(&self, path: &str, object_id: &str)
        -> Result<CollectedData, CollectionError> {
        // Unix: permissions (mode), owner (UID), group (GID)
        // Cross-platform: exists, readable, size
    }

    // Content collection - full file read
    fn collect_content(&self, path: &str, object_id: &str)
        -> Result<CollectedData, CollectionError> {
        // UTF-8 text only, errors on binary
    }

    // JSON collection - parse as structured data
    fn collect_json_record(&self, path: &str, object_id: &str)
        -> Result<CollectedData, CollectionError> {
        // Parse JSON, return RecordData for field path queries
    }

    // Recursive collection - directory tree traversal
    fn collect_recursive(&self, ...)
        -> Result<CollectedData, CollectionError> {
        // Supports: max_depth, include_hidden, follow_symlinks
    }
}
```

**Supported Behaviors:**
- `recursive_scan` - Traverse directory trees
- `max_depth <int>` - Limit recursion depth (default: 3)
- `include_hidden` - Include dotfiles
- `follow_symlinks` - Follow symbolic links

#### CommandCollector

```rust
pub struct CommandCollector {
    id: String,
    executor: SystemCommandExecutor,  // Whitelisted commands only
}

impl CommandCollector {
    // RPM package collection
    fn collect_rpm_package(&self, object: &ExecutableObject, hints: &BehaviorHints)
        -> Result<CollectedData, CollectionError> {
        // Single: rpm -q <package>
        // Batch: rpm -qa (once for all packages)
    }

    // Systemd service collection
    fn collect_systemd_service(&self, object: &ExecutableObject, hints: &BehaviorHints)
        -> Result<CollectedData, CollectionError> {
        // systemctl is-active <service>
        // systemctl is-enabled <service>
    }

    // Sysctl parameter collection
    fn collect_sysctl_parameter(&self, object: &ExecutableObject, hints: &BehaviorHints)
        -> Result<CollectedData, CollectionError> {
        // sysctl -n <parameter>
        // Parse as string and/or integer
    }

    // SELinux status collection
    fn collect_selinux_status(&self, object: &ExecutableObject, hints: &BehaviorHints)
        -> Result<CollectedData, CollectionError> {
        // getenforce
        // Returns: Enforcing, Permissive, Disabled
    }
}
```

**Supported Behaviors:**
- `timeout <int>` - Command timeout in seconds (default: 5)
- `cache_results` - Cache command output for batch ops

**RHEL 9 Whitelisted Commands:**
- `rpm` - Package queries
- `systemctl` - Service management
- `sysctl` - Kernel parameters
- `getenforce` - SELinux status
- `auditctl` - Audit rules
- `id` - User information
- `stat` - File metadata
- `getent` - User/group database

---

### 3. Executors (`executors/`)

**Purpose:** Validate collected data against ESP STATE requirements

Executors implement the `CtnExecutor` trait with a standardized **three-phase validation pattern**:

```rust
fn execute_with_contract(&self, ...) -> Result<CtnExecutionResult, CtnExecutionError> {
    // Phase 1: EXISTENCE CHECK
    let objects_expected = criterion.expected_object_count();
    let objects_found = collected_data.len();
    let existence_passed = evaluate_existence_check(
        test_spec.existence_check,
        objects_found,
        objects_expected
    );

    if !existence_passed {
        return Ok(CtnExecutionResult::fail(...));
    }

    // Phase 2: STATE VALIDATION
    let mut state_results = Vec::new();
    for (object_id, data) in collected_data {
        for state in &criterion.states {
            for field in &state.fields {
                // Map ESP field name to collected data field name
                let data_field_name = contract
                    .field_mappings
                    .validation_mappings
                    .state_to_data
                    .get(&field.name)
                    .cloned()
                    .unwrap_or_else(|| field.name.clone());

                let actual_value = data.get_field(&data_field_name)?;

                // Compare using operation (=, !=, >, contains, etc.)
                let passed = self.compare_values(
                    &field.value,      // Expected
                    &actual_value,     // Actual
                    field.operation
                );

                // Record result
                all_field_results.push(FieldValidationResult { ... });
            }
        }

        // Combine field results using STATE operator (AND/OR)
        let combined = evaluate_state_operator(
            test_spec.state_operator,
            &field_results
        );

        state_results.push(StateValidationResult { ... });
    }

    // Phase 3: ITEM CHECK
    let objects_passing = state_results.iter().filter(|r| r.combined_result).count();
    let item_passed = evaluate_item_check(
        test_spec.item_check,
        objects_passing,
        state_results.len()
    );

    // Final result
    let final_status = if existence_passed && item_passed {
        ComplianceStatus::Pass
    } else {
        ComplianceStatus::Fail
    };

    Ok(CtnExecutionResult { ... })
}
```

**Key Executors:**

- **FileMetadataExecutor** - Validates permissions, owner, group, size
- **FileContentExecutor** - Uses `string::compare()` for all string operations
- **JsonRecordExecutor** - Uses `validate_record_checks()` for JSON validation
- **RpmPackageExecutor** - Validates package installation and versions
- **SystemdServiceExecutor** - Validates service status booleans
- **SysctlParameterExecutor** - Validates kernel parameter values
- **SelinuxStatusExecutor** - Validates SELinux enforcement mode

**Important:** Always use `esp_scanner_base::execution::comparisons::string::compare()` for string operations - it handles contains, starts, ends, pattern_match, and case-insensitive operations correctly.

---

### 4. Field Mappings

**Purpose:** Translate between ESP field names and internal data field names

Field mappings are bidirectional:

```rust
pub struct CtnFieldMappings {
    pub collection_mappings: CollectionFieldMappings,
    pub validation_mappings: ValidationFieldMappings,
}

// COLLECTION: ESP OBJECT fields → Collector parameters
pub struct CollectionFieldMappings {
    pub object_to_collection: HashMap<String, String>,
    pub required_data_fields: Vec<String>,
    pub optional_data_fields: Vec<String>,
}

// VALIDATION: ESP STATE fields → Collected data fields
pub struct ValidationFieldMappings {
    pub state_to_data: HashMap<String, String>,
    pub data_to_state: HashMap<String, String>,
}
```

**Example:**

```rust
// Contract definition
contract.field_mappings.validation_mappings.state_to_data
    .insert("permissions".to_string(), "file_mode".to_string());
    .insert("owner".to_string(), "file_owner".to_string());
    .insert("group".to_string(), "file_group".to_string());
```

**ESP Usage:**

```esp
STATE secure_perms
    permissions string = `0440`  # Maps to file_mode in collected data
    owner string = `0`           # Maps to file_owner in collected data
    group string = `0`           # Maps to file_group in collected data
STATE_END
```

**Why Mappings Matter:**

1. **ESP names are user-facing** - Clear, descriptive field names
2. **Internal names are implementation details** - May differ by platform
3. **Contracts provide abstraction** - Same ESP works across platforms
4. **Validation is explicit** - No guessing about field names

---

### 5. Behavior Hints

**Purpose:** Pass optional configuration from ESP to collectors

Behaviors are defined in contracts and used in ESP files:

**Contract Definition:**

```rust
contract.add_supported_behavior(SupportedBehavior {
    name: "recursive_scan".to_string(),
    behavior_type: BehaviorType::Flag,
    parameters: vec![
        BehaviorParameter {
            name: "max_depth".to_string(),
            data_type: DataType::Int,
            required: false,
            default_value: Some("3".to_string()),
            description: "Maximum directory depth".to_string(),
        }
    ],
    description: "Recursively scan directories".to_string(),
    example: "BEHAVIOR recursive_scan max_depth 5".to_string(),
});
```

**ESP Usage:**

```esp
OBJECT config_dir
    path `/etc/myapp/`

    BEHAVIOR recursive_scan
        max_depth 5
        include_hidden
    BEHAVIOR_END
OBJECT_END
```

**Collector Implementation:**

```rust
fn collect_for_ctn_with_hints(
    &self,
    object: &ExecutableObject,
    contract: &CtnContract,
    hints: &BehaviorHints,
) -> Result<CollectedData, CollectionError> {
    // Validate hints against contract
    contract.validate_behavior_hints(hints)?;

    // Check for flags
    if hints.has_flag("recursive_scan") {
        let max_depth = hints.get_parameter_as_int("max_depth").unwrap_or(3);
        let include_hidden = hints.has_flag("include_hidden");

        return self.collect_recursive(path, object_id, max_depth, include_hidden);
    }

    // Standard collection
    self.collect_metadata(path, object_id)
}
```

**Common Behaviors:**

- **File System:**
  - `recursive_scan` - Traverse directories
  - `max_depth <int>` - Recursion limit
  - `include_hidden` - Include dotfiles
  - `follow_symlinks` - Follow symlinks
  - `binary_mode` - Base64-encode binary files

- **Command Execution:**
  - `timeout <int>` - Command timeout (seconds)
  - `cache_results` - Cache command output

---

### 6. Registry (`lib.rs`)

**Purpose:** Central registry mapping CTN types to strategy pairs

The registry connects contracts, collectors, and executors:

```rust
pub fn create_scanner_registry() -> Result<CtnStrategyRegistry, StrategyError> {
    let mut registry = CtnStrategyRegistry::new();

    // File system strategies
    let metadata_contract = contracts::create_file_metadata_contract();
    let content_contract = contracts::create_file_content_contract();
    let json_contract = contracts::create_json_record_contract();

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::FileMetadataExecutor::new(metadata_contract)),
    )?;

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::FileContentExecutor::new(content_contract)),
    )?;

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::JsonRecordExecutor::new(json_contract)),
    )?;

    // Command-based strategies (shared command executor)
    let command_executor = commands::create_rhel9_command_executor();
    let command_collector = collectors::CommandCollector::new(
        "rhel9-command-collector",
        command_executor
    );

    let rpm_contract = contracts::create_rpm_package_contract();
    registry.register_ctn_strategy(
        Box::new(command_collector.clone()),
        Box::new(executors::RpmPackageExecutor::new(rpm_contract)),
    )?;

    let systemd_contract = contracts::create_systemd_service_contract();
    registry.register_ctn_strategy(
        Box::new(command_collector.clone()),
        Box::new(executors::SystemdServiceExecutor::new(systemd_contract)),
    )?;

    // ... additional strategies

    Ok(registry)
}
```

**Registry Features:**

- **Strategy Lookup** - Find collector/executor pair by CTN type
- **Contract Validation** - Ensure collector/executor match contract
- **Health Monitoring** - Track registration errors and compatibility
- **Statistics** - Report on registered CTN types and strategies

**Usage in Main:**

```rust
let registry = esp_scanner_sdk::create_scanner_registry()?;
let engine = ExecutionEngine::new(execution_context, Arc::new(registry));
let scan_result = engine.execute()?;
```

---

### 7. Command Execution (`commands/`)

**Purpose:** Platform-specific command whitelist configuration

```rust
pub fn create_rhel9_command_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(5));

    executor.allow_commands(&[
        "rpm",        // Package management
        "systemctl",  // Service status
        "getenforce", // SELinux status
        "sysctl",     // Kernel parameters
        "auditctl",   // Audit rules
        "id",         // User info
        "stat",       // File metadata
        "getent",     // User/group database
    ]);

    executor
}
```

**Security Features:**

- **Whitelist-Only** - Only explicitly allowed commands can execute
- **Timeout Enforcement** - Default 5 seconds, configurable via BEHAVIOR
- **No Shell Expansion** - Arguments passed directly, no shell involved
- **Exit Code Checking** - Failures reported as collection errors

**Command Execution:**

```rust
let output = executor.execute(
    "rpm",
    &["-q", "openssl"],
    Some(Duration::from_secs(10))
)?;

if output.exit_code == 0 {
    let installed = true;
    let version = parse_rpm_version(&output.stdout);
}
```

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/esp-scanner
cd esp-scanner/esp_scanner_sdk

# Build the scanner
cargo build --release

# The binary will be at: target/release/scanner
```

### Basic Usage

```bash
# Scan a single ESP file
./scanner policy.esp

# Scan all ESP files in a directory
./scanner /etc/esp/policies/

# View help
./scanner --help
```

### Example ESP File

```esp
META
    version `1.0.0`
    author `security-team`
    description `RHEL 9 STIG - File Permissions`
META_END

DEF
    VAR sudoers_path string `/etc/sudoers`

    OBJECT sudoers_file
        path VAR sudoers_path
    OBJECT_END

    STATE secure_perms
        permissions string = `0440`
        owner string = `0`
        group string = `0`
        exists boolean = true
    STATE_END

    CRI AND
        CTN file_metadata
            TEST all all
            STATE_REF secure_perms
            OBJECT_REF sudoers_file
        CTN_END
    CRI_END
DEF_END
```

### Running the Example

```bash
./scanner sudoers_check.esp

# Output:
# ✓ Compilation successful
# ✓ Resolution complete
# ✓ Registry initialized (8 strategies)
# ✓ Scan complete
#
# === Scan Results ===
# Status: COMPLIANT
# Total Criteria: 1
# Passed: 1
# Failed: 0
# Pass Rate: 100.0%
# Findings: 0
# Duration: 0.02s
#
# [OK] Results saved to: scan_result.json
```

---

## Usage

### Command-Line Interface

```
scanner <file.esp | directory>
scanner --help

EXAMPLES:
    scanner policy.esp
    scanner /etc/esp/policies/
```

### Single File Scan

```bash
./scanner file_check.esp
```

**Process:**
1. Parse ESP file (esp_compiler)
2. Resolve variables and references
3. Create execution context
4. Initialize scanner registry
5. Execute compliance scan
6. Generate JSON results

### Directory Batch Scan

```bash
./scanner /etc/esp/policies/
```

**Process:**
1. Discover all .esp files
2. Initialize shared registry (once)
3. Scan each file sequentially
4. Aggregate results
5. Generate batch results JSON

**Output:**

```
Scanning 5 ESP files...

[1/5] Scanning: file_permissions.esp
  ✓ COMPLIANT (3 criteria)

[2/5] Scanning: service_checks.esp
  ✓ COMPLIANT (2 criteria)

[3/5] Scanning: kernel_params.esp
  ✗ NON-COMPLIANT (1 finding)

[4/5] Scanning: selinux_enforcement.esp
  ✓ COMPLIANT (1 criteria)

[5/5] Scanning: package_validation.esp
  ✓ COMPLIANT (4 criteria)

=== Batch Scan Summary ===
Files Scanned: 5
Successful: 5
Failed: 0
Compliant: 4
Non-Compliant: 1
Duration: 0.15s

[OK] Results saved to: batch_results.json
```

### Output Format

**scan_result.json:**

```json
{
  "scan_id": "scan_20241105_123456",
  "esp_metadata": {
    "version": "1.0.0",
    "author": "security-team",
    "description": "File permissions check",
    "severity": "high",
    "platform": "linux"
  },
  "host": {
    "hostname": "web-server-01",
    "platform": "linux",
    "platform_version": "RHEL 9.2"
  },
  "results": {
    "passed": false,
    "check": {
      "total_criteria": 3,
      "passed_criteria": 2,
      "failed_criteria": 1,
      "pass_percentage": 66.7
    },
    "findings": [
      {
        "id": "finding_001",
        "severity": "high",
        "title": "File permissions non-compliant",
        "description": "File /etc/shadow has incorrect permissions",
        "expected": {"permissions": "0000"},
        "actual": {"permissions": "0644"},
        "field_path": "permissions",
        "remediation": "chmod 0000 /etc/shadow"
      }
    ]
  },
  "timestamps": {
    "scan_start": "2024-11-05T12:34:56Z",
    "scan_end": "2024-11-05T12:34:57Z",
    "duration_ms": 123
  }
}
```

---

## CTN Types

### Supported CTN Types

| CTN Type | Collector | Purpose | Platform |
|----------|-----------|---------|----------|
| `file_metadata` | FileSystemCollector | Fast stat() checks | All |
| `file_content` | FileSystemCollector | String validation | All |
| `json_record` | FileSystemCollector | JSON validation | All |
| `rpm_package` | CommandCollector | Package checks | RHEL/CentOS |
| `systemd_service` | CommandCollector | Service status | Linux |
| `sysctl_parameter` | CommandCollector | Kernel params | Linux |
| `selinux_status` | CommandCollector | SELinux mode | RHEL/CentOS |
| `computed_values` | ComputedValuesCollector | RUN validation | All |

### file_metadata

**Purpose:** Fast file metadata validation via stat()

**Object Fields:**
- `path` (required) - File path (string)
- `type` (optional) - Resource type (string)

**State Fields:**
- `permissions` (string) - Octal file mode (e.g., `0440`)
- `owner` (string) - Owner UID/username
- `group` (string) - Group GID/name
- `exists` (boolean) - File existence
- `readable` (boolean) - Read permission
- `size` (int) - File size in bytes

**Operations:** `=`, `!=`, `>`, `<`, `>=`, `<=`

**Example:**

```esp
STATE secure_perms
    permissions string = `0440`
    owner string = `0`
    exists boolean = true
STATE_END
```

### file_content

**Purpose:** Full file content validation with string operations

**Object Fields:**
- `path` (required) - File path (string)

**State Fields:**
- `content` (string) - File content

**Operations:** `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `pattern_match`

**Behaviors:**
- `recursive_scan` - Scan directories
- `max_depth <int>` - Recursion depth (default: 3)
- `include_hidden` - Include dotfiles
- `follow_symlinks` - Follow symlinks

**Example:**

```esp
STATE sshd_config
    content string contains `PermitRootLogin no`
    content string contains `PasswordAuthentication no`
STATE_END

OBJECT ssh_config
    path `/etc/ssh/sshd_config`
OBJECT_END
```

### json_record

**Purpose:** Structured JSON data validation with field paths

**Object Fields:**
- `path` (required) - JSON file path (string)

**State Fields:**
- Uses `record` blocks with field paths

**Record Checks:**
- Field path queries (e.g., `users[*].role`)
- Wildcard support (`*`)
- Entity checks (ALL, AT_LEAST_ONE, NONE, ONLY_ONE)

**Example:**

```esp
STATE admin_users
    record
        users[*].role string = `admin` entity_check ALL
        users[*].active boolean = true entity_check AT_LEAST_ONE
    record_end
STATE_END

OBJECT user_data
    path `scanfiles/test_data.json`
OBJECT_END
```

### rpm_package

**Purpose:** RPM package installation and version validation

**Object Fields:**
- `package_name` (required) - RPM package name (string)

**State Fields:**
- `installed` (boolean) - Installation status
- `version` (string) - Package version

**Operations:** `=`, `!=`, `>`, `<`, `>=`, `<=`

**Behaviors:**
- `timeout <int>` - Command timeout (default: 5 seconds)
- `cache_results` - Cache for batch operations

**Batch Optimization:** Single `rpm -qa` for all packages

**Example:**

```esp
STATE openssl_installed
    installed boolean = true
    version string >= `3.0.0`
STATE_END

OBJECT openssl_package
    package_name `openssl`
OBJECT_END
```

---

## Extending the SDK

See the comprehensive `Scanner_Development_Guide.md` for detailed instructions on adding new CTN types.

**Quick Overview:**

1. **Create Contract** - Define interface in `contracts/`
2. **Implement Collector** - Data gathering in `collectors/`
3. **Implement Executor** - Validation logic in `executors/`
4. **Register Strategy** - Add to registry in `lib.rs`
5. **Test** - Unit tests and integration tests

---

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_file_metadata_collection

# Run with output
cargo test -- --nocapture
```

### Integration Tests

```bash
# Test with ESP files
./scanner tests/policies/

# Individual file test
./scanner tests/policies/file_check.esp
```

---

## Performance

### Batch Collection Optimization

**RPM Packages:** 10-50x faster with batch collection
- Individual: 50 packages × 100ms = 5 seconds
- Batch: Single `rpm -qa` = 0.1 seconds

**File System:** Parallel I/O, minimal benefit from batching

### Behavior-Controlled Depth

```esp
OBJECT config_dir
    path `/etc/myapp/`
    BEHAVIOR recursive_scan
        max_depth 2  # Limit depth
    BEHAVIOR_END
OBJECT_END
```

---

## Security

### Command Execution Security

- **Whitelist-Only** - Only approved commands
- **Timeout Enforcement** - Default 5 seconds
- **No Shell Expansion** - Direct argument passing
- **Exit Code Checking** - Proper error handling

### File System Security

- **Permission Checking** - Respects file permissions
- **Binary File Handling** - Rejects non-UTF-8 files
- **Least Privilege** - Runs as non-root when possible

---

## Contributing

See `Scanner_Development_Guide.md` for contribution guidelines.

1. Fork the repository
2. Create feature branch
3. Implement changes with tests
4. Submit pull request

---

## Support

- **GitHub Issues:** https://github.com/CurtisSlone/Endpoint-State-Policy/issues
- **Documentation:** https://github.com/CurtisSlone/Endpoint-State-Policy
- **Email:** curtis.slone@gmail.com

---

## License

Licensed under workspace license terms.

---

**Version:** 0.1.0
**Last Updated:** November 5, 2025
**Maintainer:** ESP Team
**Status:** Production Ready
