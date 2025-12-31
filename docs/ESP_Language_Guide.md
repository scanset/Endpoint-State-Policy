# ESP Language Guide

A hands-on tutorial for learning the Endpoint State Policy language.

---

## Table of Contents

1. [Introduction & Setup](#part-1-introduction--setup)
2. [ESP Fundamentals](#part-2-esp-fundamentals)
3. [Building Your First Policy](#part-3-building-your-first-policy)
4. [Intermediate Patterns](#part-4-intermediate-patterns)
5. [Advanced Techniques](#part-5-advanced-techniques)
6. [Real-World Examples](#part-6-real-world-examples)
7. [Troubleshooting](#part-7-troubleshooting)
8. [Quick Reference](#part-8-quick-reference)
9. [CTN Type Reference](#part-9-ctn-type-reference)

---

## Part 1: Introduction & Setup

### What is ESP?

ESP (Endpoint State Policy) is a declarative language for expressing security and compliance rules. Unlike traditional compliance tools that mix policy and execution code, ESP treats policies as pure data definitions that can be:

- Validated automatically by compliance scanners
- Versioned and tracked like any other data
- Reused across different platforms and environments
- Audited and reviewed by humans

### Why Learn ESP?

| Benefit | Description |
|---------|-------------|
| Universal | Write once, apply everywhere (Linux, Windows, cloud, containers) |
| Declarative | Define WHAT should be true, not HOW to check it |
| Version Control | Track policy changes over time |
| Auditable | Human-readable policies that can be reviewed and approved |

### Learning Path

| Part | Time | Topics |
|------|------|--------|
| 1 | 30 min | Introduction and setup |
| 2 | 1 hour | Core concepts: Objects, States, Criteria |
| 3 | 1.5 hours | Building your first complete policy |
| 4 | 2 hours | Variables, multiple checks, logic operators |
| 5 | 2 hours | Sets, filters, runtime operations |
| 6 | 2 hours | Real-world STIG and CIS implementations |
| 7-8 | 1 hour | Troubleshooting and quick reference |

### Prerequisites

- Basic understanding of IT security concepts (file permissions, services, packages)
- Familiarity with compliance frameworks (STIG, CIS, NIST) — helpful but not required
- Docker Desktop or Docker Engine
- Visual Studio Code with Dev Containers extension
- Git

### Environment Setup

**Step 1: Clone the repository**

```bash
git clone https://github.com/CurtisSlone/Endpoint-State-Policy.git
cd Endpoint-State-Policy
```

**Step 2: Open in VS Code**

```bash
code .
```

**Step 3: Start the Dev Container**

When VS Code opens, click "Reopen in Container" or press `F1` and select "Dev Containers: Reopen in Container".

**Step 4: Verify installation**

```bash
cd agent
cargo run -- ../esp/set_test.esp
```

### Scanner Usage

```bash
# Single policy scan
cargo run -- path/to/policy.esp

# Batch directory scan
cargo run -- path/to/policies/
```

### Logging Levels

Control verbosity with `ESP_LOGGING_MIN_LEVEL`:

| Level | What You See |
|-------|--------------|
| `debug` | Everything (tokens, symbols, validation steps) |
| `info` | Phase completions, scan results (default) |
| `warning` | Potential issues, non-critical problems |
| `error` | Only critical errors |

```bash
# Linux/Mac
export ESP_LOGGING_MIN_LEVEL=debug
cargo run -- policy.esp

# Windows PowerShell
$env:ESP_LOGGING_MIN_LEVEL="debug"
cargo run -- policy.esp
```

---

## Part 2: ESP Fundamentals

### How ESP Works

| Step | What Happens |
|------|--------------|
| 1. Write Policy | Define what should be checked |
| 2. Parse | Scanner validates syntax |
| 3. Collect Data | Scanner gathers actual system state |
| 4. Compare | Scanner compares actual vs expected |
| 5. Report | You get PASS or FAIL for each check |

### Your First Policy

Check if `/etc/passwd` has secure permissions:

```esp
DEF
    STATE secure_permissions
        permissions string = `0644`
    STATE_END

    OBJECT etc_passwd
        path `/etc`
        filename `passwd`
    OBJECT_END

    CRI AND
        CTN file_metadata
            TEST all all
            STATE_REF secure_permissions
            OBJECT_REF etc_passwd
        CTN_END
    CRI_END
DEF_END
```

### Policy Structure

| Block | Purpose |
|-------|---------|
| `DEF...DEF_END` | Wraps the entire policy definition |
| `STATE...STATE_END` | Defines expected conditions |
| `OBJECT...OBJECT_END` | Identifies what to check |
| `CRI...CRI_END` | Groups criteria with logic (AND, OR) |
| `CTN...CTN_END` | A single compliance test connecting STATE + OBJECT |
| `TEST` | How to evaluate the check |

### Understanding Objects

Objects identify targets on your system (files, services, packages).

```esp
# File object
OBJECT ssh_config
    path `/etc/ssh`
    filename `sshd_config`
OBJECT_END

# Package object
OBJECT openssh_package
    package_name `openssh-server`
OBJECT_END

# Service object
OBJECT firewall_service
    service_name `firewalld`
OBJECT_END
```

### Understanding States

States define what should be true about an object.

```esp
STATE secure_file
    permissions string = `0600`
    owner string = `root`
STATE_END

STATE service_running
    status string = `active`
    enabled boolean = true
STATE_END

STATE required_config
    content string contains `PermitRootLogin no`
STATE_END
```

### Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `=` | Equals | `owner string = \`root\`` |
| `!=` | Not equals | `status string != \`disabled\`` |
| `>` | Greater than | `size int > 1000` |
| `<` | Less than | `size int < 5000` |
| `>=` | Greater or equal | `version string >= \`2.0\`` |
| `<=` | Less or equal | `count int <= 10` |
| `contains` | String contains | `content string contains \`error\`` |
| `not_contains` | String does not contain | `content string not_contains \`DEBUG\`` |
| `starts` | String starts with | `path string starts \`/etc\`` |
| `ends` | String ends with | `filename string ends \`.conf\`` |
| `not_starts` | Does not start with | `path string not_starts \`/tmp\`` |
| `not_ends` | Does not end with | `filename string not_ends \`.bak\`` |
| `ieq` | Case-insensitive equals | `status string ieq \`RUNNING\`` |
| `ine` | Case-insensitive not equals | `mode string ine \`DEBUG\`` |
| `pattern_match` | Regex pattern | `content string pattern_match \`^[0-9]+$\`` |
| `matches` | Regex (alias) | `name string matches \`^app-.*\`` |
| `subset_of` | Set subset | `tags string subset_of VAR allowed_tags` |
| `superset_of` | Set superset | `roles string superset_of VAR required_roles` |

### Connecting Objects and States with CTN

The CTN (Criterion) connects objects with states for validation:

```esp
CTN criterion_type
    TEST existence_check item_check [state_operator]
    STATE_REF state_identifier
    OBJECT_REF object_identifier
CTN_END
```

- `criterion_type` — The CTN type (e.g., `file_content`, `rpm_package`, `systemd_service`)
- `existence_check` — How many objects must exist
- `item_check` — How many objects must pass state validation
- `state_operator` — How to combine multiple state fields (optional)

**TEST options:**

| Part | Options | Meaning |
|------|---------|---------|
| Existence | `all` | Every object must exist |
| | `any` | At least one object exists |
| | `none` | No objects should exist |
| | `at_least_one` | One or more must exist |
| | `only_one` | Exactly one must exist |
| Item | `all` | All existing objects must pass |
| | `any` | At least one must pass |
| | `none` | None should pass (inverted check) |
| | `at_least_one` | One or more must pass |
| | `only_one` | Exactly one must pass |
| | `none_satisfy` | No objects satisfy the state |
| State Operator | `AND` | All state fields must match (default) |
| | `OR` | Any state field can match |
| | `ONE` | Exactly one state field must match |

**Example with state operator:**

```esp
CTN file_content
    TEST all all OR
    STATE_REF has_setting_a
    STATE_REF has_setting_b
    OBJECT_REF config_file
CTN_END
```

---

## Part 3: Building Your First Policy

### Scenario

Your security team requires SSH on all Linux servers to:

1. Have the OpenSSH package installed
2. Have the SSH service running
3. Disable root login
4. Use protocol version 2

### Complete SSH Hardening Policy

```esp
META
    version `1.0.0`
    author `security-team`
    platform `linux`
    description `SSH hardening policy`
    severity `high`
META_END

DEF
    # Objects
    OBJECT openssh_pkg
        package_name `openssh-server`
    OBJECT_END

    OBJECT sshd_service
        service_name `sshd`
    OBJECT_END

    OBJECT sshd_config
        path `/etc/ssh`
        filename `sshd_config`
    OBJECT_END

    # States
    STATE package_installed
        installed boolean = true
    STATE_END

    STATE service_active
        status string = `active`
    STATE_END

    STATE no_root_login
        content string contains `PermitRootLogin no`
    STATE_END

    STATE protocol_two
        content string contains `Protocol 2`
    STATE_END

    # Criteria - all checks must pass
    CRI AND
        CTN rpm_package
            TEST all all
            STATE_REF package_installed
            OBJECT_REF openssh_pkg
        CTN_END

        CTN systemd_service
            TEST all all
            STATE_REF service_active
            OBJECT_REF sshd_service
        CTN_END

        CTN file_content
            TEST all all
            STATE_REF no_root_login
            OBJECT_REF sshd_config
        CTN_END

        CTN file_content
            TEST all all
            STATE_REF protocol_two
            OBJECT_REF sshd_config
        CTN_END
    CRI_END
DEF_END
```

---

## Part 4: Intermediate Patterns

### Using Variables

Variables define values once for reuse throughout the policy.

```esp
DEF
    VAR config_dir string `/etc/app`
    VAR required_owner string `appuser`
    VAR min_perms string `0640`

    OBJECT app_config
        path VAR config_dir
        filename `config.ini`
    OBJECT_END

    STATE secure_config
        owner string = VAR required_owner
        permissions string = VAR min_perms
    STATE_END

    CRI AND
        CTN config_check
            TEST all all
            STATE_REF secure_config
            OBJECT_REF app_config
        CTN_END
    CRI_END
DEF_END
```

### Logic Operators: AND vs OR

| Operator | Logic | Use When |
|----------|-------|----------|
| `AND` | All checks must pass | Strict requirements |
| `OR` | At least one must pass | Alternative options |

**AND example** — all must pass:

```esp
CRI AND
    CTN pkg_check
        TEST all all
        STATE_REF package_installed
        OBJECT_REF security_pkg
    CTN_END

    CTN service_check
        TEST all all
        STATE_REF service_running
        OBJECT_REF security_service
    CTN_END
CRI_END
```

**OR example** — at least one must pass:

```esp
CRI OR
    CTN firewalld_check
        TEST all all
        STATE_REF service_active
        OBJECT_REF firewalld_service
    CTN_END

    CTN iptables_check
        TEST all all
        STATE_REF service_active
        OBJECT_REF iptables_service
    CTN_END
CRI_END
```

### Nested Logic

Combine AND and OR for complex requirements:

```esp
CRI OR
    # Option 1: firewalld installed AND active
    CRI AND
        CTN firewalld_pkg
            TEST all all
            STATE_REF pkg_installed
            OBJECT_REF firewalld_package
        CTN_END

        CTN firewalld_svc
            TEST all all
            STATE_REF svc_active
            OBJECT_REF firewalld_service
        CTN_END
    CRI_END

    # Option 2: iptables installed AND active
    CRI AND
        CTN iptables_pkg
            TEST all all
            STATE_REF pkg_installed
            OBJECT_REF iptables_package
        CTN_END

        CTN iptables_svc
            TEST all all
            STATE_REF svc_active
            OBJECT_REF iptables_service
        CTN_END
    CRI_END
CRI_END
```

---

## Part 5: Advanced Techniques

### Sets

Group multiple objects together with SET operations.

| Operation | Description |
|-----------|-------------|
| `union` | Combine objects (A + B + C) |
| `intersection` | Objects in all sets (A ∩ B) |
| `complement` | Remove objects (A - B) |

```esp
DEF
    OBJECT ssh_config
        path `/etc/ssh`
        filename `sshd_config`
    OBJECT_END

    OBJECT sudoers_file
        path `/etc`
        filename `sudoers`
    OBJECT_END

    OBJECT hosts_file
        path `/etc`
        filename `hosts`
    OBJECT_END

    SET critical_configs union
        OBJECT_REF ssh_config
        OBJECT_REF sudoers_file
        OBJECT_REF hosts_file
    SET_END

    STATE files_exist
        exists boolean = true
    STATE_END

    CRI AND
        CTN set_check
            TEST all all
            STATE_REF files_exist
            OBJECT
                SET_REF critical_configs
            OBJECT_END
        CTN_END
    CRI_END
DEF_END
```

### Filters

Narrow down which objects in a set should be checked.

| Filter | Behavior |
|--------|----------|
| `include` | Only check objects matching the filter state |
| `exclude` | Skip objects matching the filter state |

```esp
STATE is_large
    size int > 1000
STATE_END

SET large_log_files union
    OBJECT_REF log_file_1
    OBJECT_REF log_file_2
    OBJECT_REF log_file_3
    FILTER include
        STATE_REF is_large
    FILTER_END
SET_END
```

### Pattern Matching

Use `pattern_match` for regex validation:

```esp
STATE valid_ip_format
    content string pattern_match `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`
STATE_END
```

Common patterns:

| Use Case | Pattern |
|----------|---------|
| IPv4 address | `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$` |
| Email | `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` |
| Date (YYYY-MM-DD) | `^\d{4}-\d{2}-\d{2}$` |

### Record Checks

Validate structured configuration data (JSON, INI, etc.):

```esp
STATE json_config_valid
    record record_type
        field settings.enabled boolean = true
        field settings.timeout int > 30
        field users[*].role string = `admin` at_least_one
        field items[0].name string = `primary`
    record_end
STATE_END
```

**Field path syntax:**
- `settings.enabled` — Nested field access
- `users[*]` — Wildcard array (check all elements)
- `items[0]` — Specific array index

**Entity checks** (for array wildcards):
- `all` — All array elements must match
- `at_least_one` — At least one element must match
- `none` — No elements should match
- `only_one` — Exactly one element must match

**Direct record operation:**

```esp
STATE simple_record
    record string
        contains `required_value`
    record_end
STATE_END
```

### TEST Existence Checks

| Check | Passes When |
|-------|-------------|
| `all` | Every object exists and passes |
| `any` | At least one object exists and passes |
| `none` | No objects exist |
| `at_least_one` | One or more objects exist |
| `only_one` | Exactly one object exists and passes |

**Check for forbidden files:**

```esp
CTN backup_check
    TEST none all
    STATE_REF should_not_exist
    OBJECT_REF backup_files
CTN_END
```

### BEHAVIOR Directives

Control scanner behavior without changing what you check:

| Behavior | Purpose |
|----------|---------|
| `recursive_scan` | Scan directory recursively |
| `max_depth N` | Limit recursion depth |
| `include_hidden` | Include dotfiles |
| `follow_symlinks` | Follow symbolic links |
| `timeout N` | Command timeout in seconds |
| `cache_results` | Cache collection results |

```esp
OBJECT log_directory
    path `/var/log/app`
    behavior recursive_scan max_depth 3 include_hidden false
OBJECT_END
```

### Parameters Block

Pass parameters to collectors (e.g., command arguments, API options):

```esp
OBJECT process_list
    module_name `Microsoft.PowerShell.Management`
    verb `Get`
    noun `Process`

    parameters string
        Name `sshd`
        ErrorAction `SilentlyContinue`
    parameters_end
OBJECT_END
```

### Select Block

Specify which fields to collect from an object:

```esp
OBJECT config_file
    path `/etc/app`
    filename `config.json`

    select record
        content text
        owner uid
        permissions mode
        size bytes
    select_end
OBJECT_END
```

### Module Elements

For PowerShell and other module-based collectors:

| Field | Purpose |
|-------|---------|
| `module_name` | Full module name |
| `verb` | PowerShell verb (Get, Set, etc.) |
| `noun` | PowerShell noun |
| `module_id` | Module identifier |
| `module_version` | Required module version |

```esp
OBJECT security_policy
    module_name `SecurityPolicy`
    module_version `1.0.0`
    verb `Get`
    noun `SecuritySetting`

    parameters string
        Category `AccountPolicy`
    parameters_end
OBJECT_END
```

### Inline Definitions

CTN blocks can contain inline (local) states and objects that are not referenceable elsewhere:

```esp
CTN file_content
    TEST all all

    # Inline state (local to this CTN)
    STATE
        content string contains `secure=true`
        permissions string = `0600`
    STATE_END

    # Inline object (local to this CTN)
    OBJECT
        path `/tmp`
        filename `temp.conf`
    OBJECT_END
CTN_END
```

Inline definitions are useful for one-off checks that don't need to be reused.

### RUN Operations

Compute values at runtime:

| Operation | Purpose | Example Use |
|-----------|---------|-------------|
| `CONCAT` | Join strings | Build file paths |
| `SPLIT` | Split string into array | Parse delimited values |
| `SUBSTRING` | Extract portion of string | Get prefix/suffix |
| `REGEX_CAPTURE` | Extract via regex | Parse structured text |
| `ARITHMETIC` | Math operations | Calculate thresholds |
| `COUNT` | Count collection items | Validate array length |
| `UNIQUE` | Remove duplicates | Deduplicate values |
| `MERGE` | Combine collections | Join arrays |
| `EXTRACT` | Get field from object | Access collected data |
| `END` | Get string suffix | Extract file extension |

**CONCAT example:**

```esp
RUN full_path CONCAT
    VAR base_dir
    literal `/`
    VAR filename
RUN_END
```

**ARITHMETIC example:**

```esp
RUN computed_threshold ARITHMETIC
    literal 1024
    + 512
    * 2
RUN_END
```

**SPLIT example:**

```esp
RUN path_parts SPLIT
    VAR file_path
    delimiter `/`
RUN_END
```

**SUBSTRING example:**

```esp
RUN prefix SUBSTRING
    VAR hostname
    start 0
    length 3
RUN_END
```

**REGEX_CAPTURE example:**

```esp
RUN version_number REGEX_CAPTURE
    VAR version_string
    pattern `v([0-9]+\.[0-9]+)`
RUN_END
```

**EXTRACT example:**

```esp
RUN package_version EXTRACT
    OBJ openssl_pkg version
RUN_END
```

### String Literals

ESP uses backticks for string literals:

```esp
VAR path string `/etc/ssh/sshd_config`
```

**Escaping backticks:**

Use double backticks for a literal backtick character:

```esp
VAR message string `This has a ``backtick`` inside`
```

**Empty string:**

```esp
VAR empty string ``
```

**Raw strings** (no escape processing):

```esp
VAR regex string r`^\d{3}-\d{4}$`
```

**Multiline strings:**

```esp
VAR script string ```
#!/bin/bash
echo "Hello"
exit 0
```
```

### Type System

| Type | Purpose | Example |
|------|---------|---------|
| `string` | Text values | `/etc/passwd` |
| `int` | 64-bit signed integer | `1024` |
| `float` | 64-bit floating point | `3.14159` |
| `boolean` | True/false | `true` |
| `binary` | Raw byte data | File contents |
| `record` | Structured data | JSON/INI fields |
| `record_type` | Record type specifier | Used in record checks |
| `version` | Semantic version | `2.4.1` |
| `evr_string` | Package version (epoch:version-release) | `2:1.8.0-1.el9` |

---

## Part 6: Real-World Examples

### RHEL 9 STIG: Password Complexity

```esp
META
    version `1.0.0`
    control_framework `STIG`
    control `RHEL-09-611015`
    severity `medium`
    description `Password complexity requirements`
META_END

DEF
    VAR config_path string `/etc/security`

    OBJECT pwquality_conf
        path VAR config_path
        filename `pwquality.conf`
    OBJECT_END

    STATE complexity_requirements
        record record_type
            field minlen int >= 15
            field dcredit int = -1
            field ucredit int = -1
            field lcredit int = -1
            field ocredit int = -1
        record_end
    STATE_END

    CRI AND
        CTN file_content
            TEST all all
            STATE_REF complexity_requirements
            OBJECT_REF pwquality_conf
        CTN_END
    CRI_END
DEF_END
```

### CIS Benchmark: Firewall Configuration

```esp
META
    version `1.0.0`
    control_framework `CIS`
    control `3.5.1.1`
    severity `high`
META_END

DEF
    STATE pkg_installed
        installed boolean = true
    STATE_END

    STATE service_running
        status string = `active`
        enabled boolean = true
    STATE_END

    OBJECT firewalld_pkg
        package_name `firewalld`
    OBJECT_END

    OBJECT firewalld_svc
        service_name `firewalld`
    OBJECT_END

    CRI AND
        CTN rpm_package
            TEST all all
            STATE_REF pkg_installed
            OBJECT_REF firewalld_pkg
        CTN_END

        CTN systemd_service
            TEST all all
            STATE_REF service_running
            OBJECT_REF firewalld_svc
        CTN_END
    CRI_END
DEF_END
```

---

## Part 7: Troubleshooting

### Common Syntax Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Missing END marker | Forgot `DEF_END`, `STATE_END`, etc. | Add matching END |
| Undefined reference | `STATE_REF` points to non-existent state | Check spelling |
| Type mismatch | String operator on integer | Match operator to type |
| Invalid backticks | Unbalanced backticks | Escape with ` `` ` |

### Policy Always Fails

Common causes:
- Using `CRI AND` when one check is impossible
- Wrong operator (`!=` instead of `=`)
- Incorrect TEST specification

### Policy Always Passes

Common causes:
- Using `CRI OR` when all checks should be required
- Using `TEST any` when `TEST all` is needed
- State condition is too permissive

### Debugging Tips

1. **Start simple** — test each CTN individually
2. **Use debug logging** — `ESP_LOGGING_MIN_LEVEL=debug`
3. **Check references** — verify all `STATE_REF` and `OBJECT_REF` exist
4. **Validate types** — match operators to field types

---

## Part 8: Quick Reference

### Syntax Cheat Sheet

| Block | Syntax |
|-------|--------|
| Definition | `DEF ... DEF_END` |
| Metadata | `META ... META_END` |
| Variable | `VAR name type value` |
| Object | `OBJECT name ... OBJECT_END` |
| State | `STATE name ... STATE_END` |
| Criteria | `CRI AND/OR ... CRI_END` |
| Criterion | `CTN type ... CTN_END` |
| Set | `SET name union/intersection/complement ... SET_END` |
| Filter | `FILTER include/exclude ... FILTER_END` |
| Run | `RUN name operation ... RUN_END` |
| Parameters | `parameters type ... parameters_end` |
| Select | `select type ... select_end` |
| Record | `record type ... record_end` |

### Common Patterns

**File permission check:**

```esp
STATE secure_perms
    permissions string = `0600`
STATE_END

OBJECT file
    path `/etc`
    filename `shadow`
OBJECT_END
```

**Service running check:**

```esp
STATE service_active
    status string = `active`
    enabled boolean = true
STATE_END

OBJECT svc
    service_name `sshd`
OBJECT_END
```

**Package installed check:**

```esp
STATE pkg_present
    installed boolean = true
STATE_END

OBJECT pkg
    package_name `openssh-server`
OBJECT_END
```

**Configuration content check:**

```esp
STATE required_setting
    content string contains `PermitRootLogin no`
STATE_END

OBJECT config
    path `/etc/ssh`
    filename `sshd_config`
OBJECT_END
```

### Operators

| Category | Operators | Types |
|----------|-----------|-------|
| Comparison | `=` `!=` `>` `<` `>=` `<=` | All |
| String | `contains` `starts` `ends` `not_contains` `not_starts` `not_ends` | string |
| Case-insensitive | `ieq` `ine` | string |
| Pattern | `pattern_match` `matches` | string |
| Set | `subset_of` `superset_of` | Sets |

---

## Part 9: CTN Type Reference

### Available CTN Types

**File System:**

| Type | Purpose |
|------|---------|
| `file_metadata` | Permissions, owner, group, size, existence |
| `file_content` | Content validation (contains, pattern_match) |
| `json_record` | Structured JSON validation |

**System:**

| Type | Purpose |
|------|---------|
| `rpm_package` | Package installation and version |
| `systemd_service` | Service status (active, enabled, loaded) |
| `sysctl_parameter` | Kernel parameters |
| `selinux_status` | SELinux enforcement mode |

**Testing:**

| Type | Purpose |
|------|---------|
| `computed_values` | Validates RUN operations |

### Example Files

| File | Description |
|------|-------------|
| `set_test.esp` | SET operations |
| `ssh_config_check.esp` | SSH hardening |
| `passwd_shadow_content.esp` | System file content |
| `critical_file_permissions.esp` | File permissions |
| `variable_usage.esp` | Variable examples |

### Running Examples

```bash
# Single file
cargo run -- esp/ssh_config_check.esp

# With debug logging
ESP_LOGGING_MIN_LEVEL=debug cargo run -- esp/set_test.esp

# Batch scan
cargo run -- esp/
```

---

## Next Steps

You now have the knowledge to:

- Write basic and advanced ESP policies
- Use variables, logic operators, and sets
- Implement STIG and CIS compliance checks
- Debug and troubleshoot policy issues

**Resources:**

- [EBNF Grammar](EBNF.md) — Formal language specification
- [ESP Trust Model](ESP_Trust_Model.md) — Security boundaries
- [Scanner Development Guide](Scanner_Development_Guide.md) — Extending ESP
