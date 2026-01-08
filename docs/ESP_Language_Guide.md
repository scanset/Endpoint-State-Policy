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
7. [Cookbook: Common Patterns](#cookbook-common-patterns)
8. [Troubleshooting](#part-7-troubleshooting)
9. [Quick Reference](#part-8-quick-reference)
10. [CTN Type Reference](#part-9-ctn-type-reference)
11. [META Block Reference](#part-10-meta-block-reference)

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
make run ESP=esp/
```

### Scanner Usage

```bash
# Single policy scan
make run ESP=path/to/policy.esp

# Batch directory scan
make run ESP=path/to/policies/
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
make run ESP=esp/test_file_metadata.esp
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
META
    esp_scan_id `my-first-policy`
    platform `linux`
    criticality `high`
    control_mapping `CIS:6.1.1`
META_END

DEF
    STATE secure_permissions
        permissions string = `0644`
    STATE_END

    OBJECT etc_passwd
        path `/etc/passwd`
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
| `META...META_END` | Required metadata for attestations |
| `DEF...DEF_END` | Wraps the entire policy definition |
| `STATE...STATE_END` | Defines expected conditions |
| `OBJECT...OBJECT_END` | Identifies what to check |
| `CRI...CRI_END` | Groups criteria with logic (AND, OR) |
| `CTN...CTN_END` | A single compliance test connecting STATE + OBJECT |
| `TEST` | How to evaluate the check |

### Understanding Objects

Objects identify targets on your system. The fields required depend on the CTN type being used.

```esp
# File object (for file_metadata, file_content)
OBJECT ssh_config
    path `/etc/ssh/sshd_config`
OBJECT_END

# TCP port object (for tcp_listener)
OBJECT ssh_port
    port `22`
OBJECT_END

# Kubernetes resource (for k8s_resource)
OBJECT apiserver_pod
    kind `Pod`
    namespace `kube-system`
    label_selector `component=kube-apiserver`
OBJECT_END
```

**Important:** Each CTN type has specific object field requirements. See [contract_kit/docs/](../contract_kit/docs/) for complete specifications per CTN type.

### Understanding States

States define what should be true about an object.

```esp
STATE secure_file
    permissions string = `0600`
    owner string = `0`
STATE_END

STATE is_listening
    listening boolean = true
STATE_END

STATE required_config
    content string contains `PermitRootLogin no`
STATE_END
```

**Important:** Each CTN type supports specific state fields and operations. See [contract_kit/docs/](../contract_kit/docs/) for what fields are available per CTN type.

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

### Connecting Objects and States with CTN

The CTN (Criterion) connects objects with states for validation:

```esp
CTN criterion_type
    TEST existence_check item_check [state_operator]
    STATE_REF state_identifier
    OBJECT_REF object_identifier
CTN_END
```

- `criterion_type` — The CTN type (e.g., `file_metadata`, `file_content`, `tcp_listener`)
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
| | `at_least_one` | At least one must pass |
| | `only_one` | Exactly one must pass |
| | `none_satisfy` | No objects satisfy the state |
| State Operator | `AND` | All state fields must match (default) |
| | `OR` | Any state field can match |
| | `ONE` | Exactly one state field must match |

---

## Part 3: Building Your First Policy

### Example: File Metadata Validation

This example is from `esp/test_file_metadata.esp` — a complete policy that validates system file permissions.

```esp
META
    esp_scan_id `test-file-metadata-001`
    platform `linux`
    criticality `high`
    control_mapping `CIS:6.1.1,CIS:6.1.2,NIST-800-53:AC-6`
    title `Critical System File Permissions`
    description `Validates that critical system files have correct permissions and ownership`
    version `1.0.0`
    author `security-team`
    tags `file-permissions,linux,hardening`
META_END

DEF
    # Variables for reusable values
    VAR root_uid string `0`
    VAR root_gid string `0`
    VAR shadow_gid string `42`

    # Objects - System files to check
    OBJECT passwd_file
        path `/etc/passwd`
    OBJECT_END

    OBJECT group_file
        path `/etc/group`
    OBJECT_END

    OBJECT shadow_file
        path `/etc/shadow`
    OBJECT_END

    # States - Expected conditions
    STATE passwd_permissions
        exists boolean = true
        permissions string = `0644`
        owner string = VAR root_uid
        group string = VAR root_gid
    STATE_END

    STATE group_permissions
        exists boolean = true
        permissions string = `0644`
        owner string = VAR root_uid
        group string = VAR root_gid
    STATE_END

    STATE shadow_permissions
        exists boolean = true
        permissions string = `0640`
        owner string = VAR root_uid
        group string = VAR shadow_gid
    STATE_END

    # Criteria - All checks must pass
    CRI AND
        CTN file_metadata
            TEST all all
            STATE_REF passwd_permissions
            OBJECT_REF passwd_file
        CTN_END

        CTN file_metadata
            TEST all all
            STATE_REF group_permissions
            OBJECT_REF group_file
        CTN_END

        CTN file_metadata
            TEST all all
            STATE_REF shadow_permissions
            OBJECT_REF shadow_file
        CTN_END
    CRI_END
DEF_END
```

**Run this policy:**

```bash
make run ESP=esp/test_file_metadata.esp
```

**Key points:**

1. **META block** is required with `esp_scan_id`, `platform`, `criticality`, and `control_mapping`
2. **Variables** (`VAR`) let you reuse values like UIDs
3. **Objects** use `path` field for file-based CTN types (see [ctn_file_metadata.md](../contract_kit/docs/ctn_file_metadata.md))
4. **States** use fields supported by the CTN type
5. **CRI AND** means all checks must pass

---

## Part 4: Intermediate Patterns

### Example: File Content Validation

This example is from `esp/test_file_content.esp` — validates file contents using string operations.

```esp
META
    esp_scan_id `test-file-content-001`
    platform `linux`
    criticality `medium`
    control_mapping `CIS:5.4.1,NIST-800-53:AC-2`
    title `System Account Configuration Validation`
    description `Validates critical system file content for security compliance`
    version `1.0.0`
    author `security-team`
    tags `file-content,linux,accounts`
META_END

DEF
    OBJECT passwd_file
        path `/etc/passwd`
    OBJECT_END

    OBJECT group_file
        path `/etc/group`
    OBJECT_END

    # Verify root account has UID 0 and valid shell
    STATE root_account_valid
        content string contains `root:x:0:0:`
        content string pattern_match `^root:.*:/bin/bash$`
    STATE_END

    # Verify system accounts use nologin shell
    STATE daemon_nologin
        content string contains `daemon:x:1:1:`
        content string contains `/usr/sbin/nologin`
    STATE_END

    # Verify no accounts have empty password field
    STATE no_empty_passwords
        content string not_contains `::0:`
    STATE_END

    # Verify shadow group exists
    STATE shadow_group_exists
        content string contains `shadow:x:`
    STATE_END

    CRI AND
        CTN file_content
            TEST all all
            STATE_REF root_account_valid
            OBJECT_REF passwd_file
        CTN_END

        CTN file_content
            TEST all all
            STATE_REF daemon_nologin
            OBJECT_REF passwd_file
        CTN_END

        CTN file_content
            TEST all all
            STATE_REF no_empty_passwords
            OBJECT_REF passwd_file
        CTN_END

        CTN file_content
            TEST all all
            STATE_REF shadow_group_exists
            OBJECT_REF group_file
        CTN_END
    CRI_END
DEF_END
```

**Key techniques:**
- Multiple state fields with same name (`content`) using different operations
- `contains` for substring matching
- `pattern_match` for regex validation
- `not_contains` for negative assertions

See [ctn_file_content.md](../contract_kit/docs/ctn_file_content.md) for all supported operations.

### Using Variables

Variables define values once for reuse throughout the policy.

```esp
DEF
    VAR config_dir string `/etc/app`
    VAR required_owner string `0`
    VAR secure_perms string `0640`

    OBJECT app_config
        path VAR config_dir
    OBJECT_END

    STATE secure_config
        owner string = VAR required_owner
        permissions string = VAR secure_perms
    STATE_END
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
    CTN file_metadata
        TEST all all
        STATE_REF secure_permissions
        OBJECT_REF config_file
    CTN_END

    CTN tcp_listener
        TEST at_least_one all
        STATE_REF is_listening
        OBJECT_REF app_port
    CTN_END
CRI_END
```

**OR example** — at least one must pass:

```esp
CRI OR
    CTN tcp_listener
        TEST at_least_one all
        STATE_REF is_listening
        OBJECT_REF port_8080
    CTN_END

    CTN tcp_listener
        TEST at_least_one all
        STATE_REF is_listening
        OBJECT_REF port_8443
    CTN_END
CRI_END
```

### Nested Logic

Combine AND and OR for complex requirements:

```esp
CRI OR
    # Option 1: port 8080 available
    CRI AND
        CTN tcp_listener
            TEST at_least_one all
            STATE_REF is_listening
            OBJECT_REF port_8080
        CTN_END
    CRI_END

    # Option 2: port 8443 available
    CRI AND
        CTN tcp_listener
            TEST at_least_one all
            STATE_REF is_listening
            OBJECT_REF port_8443
        CTN_END
    CRI_END
CRI_END
```

---

## Part 5: Advanced Techniques

### Example: TCP Listener Validation

This example is from `esp/test_tcp_listener.esp` — validates network port states.

```esp
META
    esp_scan_id `test-tcp-listener-001`
    platform `linux`
    criticality `medium`
    control_mapping `CIS:3.4.1,NIST-800-53:CM-7`
    title `Network Service Port Validation`
    description `Validates expected TCP listeners and ensures prohibited ports are not listening`
    version `1.0.0`
    author `security-team`
    tags `network,tcp,ports,services`
META_END

DEF
    # Ports to check
    OBJECT port_2024
        port `2024`
    OBJECT_END

    OBJECT telnet_port
        port `23`
    OBJECT_END

    OBJECT ftp_port
        port `21`
    OBJECT_END

    OBJECT rsh_port
        port `514`
    OBJECT_END

    # States
    STATE is_listening
        listening boolean = true
    STATE_END

    STATE not_listening
        listening boolean = false
    STATE_END

    CRI AND
        # Verify expected service is listening
        CTN tcp_listener
            TEST at_least_one all
            STATE_REF is_listening
            OBJECT_REF port_2024
        CTN_END

        # Verify insecure services are NOT listening
        CTN tcp_listener
            TEST at_least_one all
            STATE_REF not_listening
            OBJECT_REF telnet_port
        CTN_END

        CTN tcp_listener
            TEST at_least_one all
            STATE_REF not_listening
            OBJECT_REF ftp_port
        CTN_END

        CTN tcp_listener
            TEST at_least_one all
            STATE_REF not_listening
            OBJECT_REF rsh_port
        CTN_END
    CRI_END
DEF_END
```

**Key techniques:**
- Checking that ports ARE listening (expected services)
- Checking that ports are NOT listening (prohibited services)
- Using `TEST at_least_one all` for port checks

See [ctn_tcp_listener.md](../contract_kit/docs/ctn_tcp_listener.md) for the complete tcp_listener specification.

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
        path `/etc/ssh/sshd_config`
    OBJECT_END

    OBJECT sudoers_file
        path `/etc/sudoers`
    OBJECT_END

    OBJECT hosts_file
        path `/etc/hosts`
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
        CTN file_metadata
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

Validate structured data (JSON, configuration files, API responses). Used with CTN types like `json_record` and `k8s_resource`.

```esp
STATE json_config_valid
    record
        field settings.enabled boolean = true
        field settings.timeout int > 30
        field users.*.role string = `admin` at_least_one
        field items.0.name string = `primary`
    record_end
STATE_END
```

**Field path syntax:**

| Syntax | Meaning | Example |
|--------|---------|---------|
| `name` | Simple field | `status` |
| `a.b.c` | Nested field | `settings.security.enabled` |
| `arr.0` | Array index (0-based) | `containers.0.image` |
| `arr.*` | Array wildcard | `containers.*.name` |
| `a.*.b` | Nested wildcard | `spec.containers.*.ports.*.containerPort` |

**Entity checks** (for wildcards/arrays):

| Check | Passes When |
|-------|-------------|
| `all` | All matching elements pass (default) |
| `at_least_one` | At least one element passes |
| `none` | No elements pass |
| `only_one` | Exactly one element passes |

See [ctn_json_record.md](../contract_kit/docs/ctn_json_record.md) and [ctn_k8s_resource.md](../contract_kit/docs/ctn_k8s_resource.md) for record check usage.

### BEHAVIOR Directives

Control scanner behavior without changing what you check:

| Behavior | Purpose |
|----------|---------|
| `recursive_scan` | Scan directory recursively |
| `max_depth N` | Limit recursion depth |
| `include_hidden` | Include dotfiles |
| `follow_symlinks` | Follow symbolic links |
| `timeout N` | Command timeout in seconds |

```esp
OBJECT log_directory
    path `/var/log/app`
    behavior recursive_scan max_depth 3 include_hidden false
OBJECT_END
```

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
| `EXTRACT` | Get field from object | Access collected data |

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

### String Literals

ESP uses backticks for string literals:

```esp
VAR path string `/etc/ssh/sshd_config`
```

**Escaping backticks:**

```esp
VAR message string `This has a ``backtick`` inside`
```

**Raw strings** (no escape processing):

```esp
VAR regex string r`^\d{3}-\d{4}$`
```

### Type System

| Type | Purpose | Example |
|------|---------|---------|
| `string` | Text values | `/etc/passwd` |
| `int` | 64-bit signed integer | `1024` |
| `float` | 64-bit floating point | `3.14159` |
| `boolean` | True/false | `true` |
| `binary` | Raw byte data | File contents |
| `record_data` | Structured data (JSON, etc.) | Nested fields |
| `version` | Semantic version | `2.4.1` |
| `evr_string` | Package version (epoch:version-release) | `2:1.8.0-1.el9` |

---

## Part 6: Real-World Examples

### Kubernetes: API Server RBAC Validation

```esp
META
    esp_scan_id `stig-v242382-rbac-auth`
    platform `kubernetes`
    criticality `high`
    control_mapping `DISA-STIG:V-242382,NIST-800-53:AC-6`
    title `Kubernetes API Server must have RBAC authorization enabled`
    tags `stig,kubernetes,apiserver,authorization,rbac`
META_END

DEF
    OBJECT apiserver_pod
        kind `Pod`
        namespace `kube-system`
        label_selector `component=kube-apiserver`
    OBJECT_END

    STATE uses_rbac
        record
            field spec.containers.0.command string contains `--authorization-mode=Node,RBAC` at_least_one
        record_end
    STATE_END

    CRI AND
        CTN k8s_resource
            TEST all all
            STATE_REF uses_rbac
            OBJECT_REF apiserver_pod
        CTN_END
    CRI_END
DEF_END
```

See [ctn_k8s_resource.md](../contract_kit/docs/ctn_k8s_resource.md) for Kubernetes resource validation.

### JSON Configuration Validation

```esp
META
    esp_scan_id `json-config-validation`
    platform `linux`
    criticality `medium`
    control_mapping `CIS:5.1.1`
    title `Application Configuration Validation`
META_END

DEF
    OBJECT app_config
        path `/etc/app/config.json`
    OBJECT_END

    STATE valid_config
        record
            field version string = `2.0`
            field database.host string = `localhost`
            field database.port int > 1024
            field security.enabled boolean = true
            field users.*.role string = `user` all
        record_end
    STATE_END

    CRI AND
        CTN json_record
            TEST all all
            STATE_REF valid_config
            OBJECT_REF app_config
        CTN_END
    CRI_END
DEF_END
```

See [ctn_json_record.md](../contract_kit/docs/ctn_json_record.md) for JSON validation.

---

## Cookbook: Common Patterns

### Pattern 1: ALL Files Must Have Correct Permissions

```esp
STATE secure_permissions
    permissions string = `0600`
STATE_END

SET sensitive_files union
    OBJECT_REF shadow_file
    OBJECT_REF gshadow_file
SET_END

CRI AND
    CTN file_metadata
        TEST all all          # ALL objects must exist AND ALL must pass
        STATE_REF secure_permissions
        SET_REF sensitive_files
    CTN_END
CRI_END
```

### Pattern 2: Verify Service is NOT Running

```esp
STATE not_listening
    listening boolean = false
STATE_END

OBJECT telnet_port
    port `23`
OBJECT_END

CRI AND
    CTN tcp_listener
        TEST at_least_one all
        STATE_REF not_listening
        OBJECT_REF telnet_port
    CTN_END
CRI_END
```

### Pattern 3: Multiple Conditions with OR Logic

```esp
STATE has_setting_a
    content string contains `SettingA=enabled`
STATE_END

STATE has_setting_b
    content string contains `SettingB=enabled`
STATE_END

CRI AND
    CTN file_content
        TEST all all OR          # States combined with OR
        STATE_REF has_setting_a
        STATE_REF has_setting_b
        OBJECT_REF config_file
    CTN_END
CRI_END
```

### Pattern 4: Using Variables for Reusability

```esp
VAR min_password_length int 15
VAR config_dir string `/etc/security`

STATE password_length
    minlen int >= VAR min_password_length
STATE_END

OBJECT pwquality
    path VAR config_dir
OBJECT_END
```

### Quick Reference: TEST Combinations

| Scenario | TEST Specification |
|----------|-------------------|
| All must exist and pass | `TEST all all` |
| Any can exist, all that exist must pass | `TEST any all` |
| Any can exist, at least one must pass | `TEST any at_least_one` |
| None should exist | `TEST none none_satisfy` |
| Exactly one must exist and pass | `TEST only_one only_one` |
| At least one must exist and pass | `TEST at_least_one at_least_one` |

---

## Part 7: Troubleshooting

### Common Syntax Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Missing END marker | Forgot `DEF_END`, `STATE_END`, etc. | Add matching END |
| Undefined reference | `STATE_REF` points to non-existent state | Check spelling |
| Type mismatch | String operator on integer | Match operator to type |
| Invalid backticks | Unbalanced backticks | Escape with ` `` ` |
| Missing META fields | Required attestation fields missing | Add `esp_scan_id`, `platform`, `criticality`, `control_mapping` |

### Policy Always Fails

Common causes:
- Using `CRI AND` when one check is impossible
- Wrong operator (`!=` instead of `=`)
- Incorrect TEST specification
- Object field names don't match CTN type requirements

**Solution:** Check [contract_kit/docs/](../contract_kit/docs/) for the correct field names and types for your CTN type.

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
5. **Read CTN docs** — see [contract_kit/docs/](../contract_kit/docs/) for field requirements

---

## Part 8: Quick Reference

### Syntax Cheat Sheet

| Block | Syntax |
|-------|--------|
| Metadata | `META ... META_END` |
| Definition | `DEF ... DEF_END` |
| Variable | `VAR name type value` |
| Object | `OBJECT name ... OBJECT_END` |
| State | `STATE name ... STATE_END` |
| Criteria | `CRI AND/OR ... CRI_END` |
| Criterion | `CTN type ... CTN_END` |
| Set | `SET name union/intersection/complement ... SET_END` |
| Filter | `FILTER include/exclude ... FILTER_END` |
| Run | `RUN name operation ... RUN_END` |
| Record | `record ... record_end` |

### Common Patterns

**File permission check:**

```esp
STATE secure_perms
    permissions string = `0600`
STATE_END

OBJECT file
    path `/etc/shadow`
OBJECT_END
```

**TCP port check:**

```esp
STATE is_listening
    listening boolean = true
STATE_END

OBJECT port
    port `22`
OBJECT_END
```

**File content check:**

```esp
STATE required_setting
    content string contains `PermitRootLogin no`
STATE_END

OBJECT config
    path `/etc/ssh/sshd_config`
OBJECT_END
```

---

## Part 9: CTN Type Reference

### Available CTN Types

| Type | Purpose | Documentation |
|------|---------|---------------|
| `file_metadata` | Permissions, owner, group, size, existence | [ctn_file_metadata.md](../contract_kit/docs/ctn_file_metadata.md) |
| `file_content` | Content validation (contains, pattern_match) | [ctn_file_content.md](../contract_kit/docs/ctn_file_content.md) |
| `json_record` | Structured JSON field validation | [ctn_json_record.md](../contract_kit/docs/ctn_json_record.md) |
| `tcp_listener` | TCP port listening state | [ctn_tcp_listener.md](../contract_kit/docs/ctn_tcp_listener.md) |
| `k8s_resource` | Kubernetes API resource validation | [ctn_k8s_resource.md](../contract_kit/docs/ctn_k8s_resource.md) |
| `computed_values` | Validates RUN operations | [ctn_computed_values.md](../contract_kit/docs/ctn_computed_values.md) |

**Important:** Before writing a policy, read the CTN type documentation to understand:
- Required object fields
- Available state fields and operations
- Collection behavior and performance characteristics

### Example Policies

| File | Description |
|------|-------------|
| `esp/test_file_metadata.esp` | File permissions and ownership validation |
| `esp/test_file_content.esp` | File content validation with string operations |
| `esp/test_tcp_listener.esp` | TCP port listening state validation |

### Running Examples

```bash
# File metadata validation
make run ESP=esp/test_file_metadata.esp

# File content validation
make run ESP=esp/test_file_content.esp

# TCP listener validation
make run ESP=esp/test_tcp_listener.esp

# All example policies
make run ESP=esp/
```

---

## Part 10: META Block Reference

The META block provides metadata about your policy. It is **required for attestation generation**.

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `esp_scan_id` | Unique policy identifier | `stig-v242382-rbac` |
| `platform` | Target platform | `linux`, `windows`, `kubernetes` |
| `criticality` | Severity level | `critical`, `high`, `medium`, `low`, `info` |
| `control_mapping` | Compliance framework mappings | `NIST-800-53:AC-6,CIS:5.1.1` |

### Optional Fields

| Field | Description | Example |
|-------|-------------|---------|
| `version` | Policy version | `1.2.0` |
| `author` | Author/team name | `security-team` |
| `title` | Short policy title | `SSH Root Login Disabled` |
| `description` | Human-readable description | Any text |
| `tags` | Comma-separated tags | `ssh,hardening,linux` |
| `weight` | Explicit weight (0.0-1.0) | `0.95` |

### Control Mapping Format

Format: `FRAMEWORK:CONTROL_ID` pairs separated by commas.

```esp
META
    control_mapping `NIST-800-53:AC-6,CIS:5.1.1,DISA-STIG:V-242382`
META_END
```

### Criticality Levels and Default Weights

| Criticality | Default Weight | Meaning |
|-------------|---------------|---------|
| `critical` | 1.0 | System compromise or data breach risk |
| `high` | 0.8 | Significant security impact |
| `medium` | 0.5 | Moderate security concern |
| `low` | 0.3 | Minor security improvement |
| `info` | 0.1 | Informational, best practice |

### Complete Example

```esp
META
    esp_scan_id `rhel9-stig-password-complexity`
    version `1.0.0`
    author `security-team`
    platform `linux`
    criticality `medium`
    control_mapping `DISA-STIG:RHEL-09-611015,NIST-800-53:IA-5`
    title `RHEL 9 Password Complexity Requirements`
    description `Ensures password complexity meets STIG requirements`
    tags `stig,password,authentication,rhel9`
META_END
```

---

## Next Steps

You now have the knowledge to:

- Write basic and advanced ESP policies
- Use variables, logic operators, and sets
- Implement compliance checks using various CTN types
- Debug and troubleshoot policy issues

**Resources:**

- [CTN Type Documentation](../contract_kit/docs/) — Complete field specifications for each CTN type
- [EBNF Grammar](EBNF.md) — Formal language specification
- [Scanner Development Guide](Scanner_Development_Guide.md) — Creating custom CTN types
- [Example Policies](../esp/) — Working policy examples
