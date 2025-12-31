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
| | `at_least_one` | At least one must pass |
| | `only_one` | Exactly one must pass |
| | `none_satisfy` | No objects satisfy the state |
| State Operator | `AND` | All state fields must match (default) |
| | `OR` | Any state field can match |
| | `ONE` | Exactly one state field must match |

**Note:** Item checks do NOT include `any` or `none` — use `at_least_one` or `none_satisfy` instead.

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

Validate structured data (JSON, configuration files, API responses):

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

**Record block syntax:**

```esp
record [data_type]
    field path type operation value [entity_check]
    ...
record_end
```

The data type after `record` is optional. When present, it specifies the expected data format.

**Note:** `field` is a context-sensitive identifier, not a keyword. It has special meaning only inside record blocks.

**Field path syntax:**

| Syntax | Meaning | Example |
|--------|---------|---------|
| `name` | Simple field | `status` |
| `a.b.c` | Nested field | `settings.security.enabled` |
| `arr.0` | Array index | `containers.0.image` |
| `arr.*` | Array wildcard | `containers.*.name` |
| `a.*.b` | Nested wildcard | `spec.containers.*.ports.*.containerPort` |

**Entity checks** (only valid on record fields with wildcards or arrays):

| Check | Passes When |
|-------|-------------|
| `all` | All matching elements pass (default) |
| `at_least_one` | At least one element passes |
| `none` | No elements pass |
| `only_one` | Exactly one element passes |

**Kubernetes example:**

```esp
STATE uses_rbac
    record
        field spec.containers.0.command string contains `--authorization-mode=Node,RBAC` at_least_one
    record_end
STATE_END
```

This checks if ANY element in the `command` array contains the RBAC flag.

**Direct record operation** (validate entire record):

```esp
STATE has_required_content
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

**Context-sensitive identifiers in RUN blocks:**

The following are identifiers with special meaning inside RUN blocks (not keywords):
- `literal` — Literal value parameter
- `pattern` — Regex pattern
- `delimiter` — Split delimiter
- `character` — Character specification
- `start` — Start position
- `length` — Length value

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
| `record_data` | Structured data (JSON, etc.) | Nested fields |
| `version` | Semantic version | `2.4.1` |
| `evr_string` | Package version (epoch:version-release) | `2:1.8.0-1.el9` |

Data types are identifiers, not keywords — they're parsed semantically based on context.

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
        record
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

### Kubernetes STIG: API Server RBAC

```esp
META
    esp_scan_id `stig-v242382-rbac-auth`
    control_framework `DISA-STIG`
    control `V-242382`
    title `Kubernetes API Server must have RBAC authorization enabled`
    platform `kubernetes`
    criticality `high`
    agent_type `controller`
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

This policy validates that the Kubernetes API server pod has RBAC authorization enabled by checking if any element in the container's command array contains the required flag.

---

## Cookbook: Common Patterns

This section provides copy-paste solutions for common compliance scenarios.

### Pattern 1: ALL Files Must Have Correct Permissions

**Question:** "I need to check that ALL sensitive files have mode 0600."

```esp
STATE secure_permissions
    permissions string = `0600`
STATE_END

OBJECT shadow_file
    path `/etc`
    filename `shadow`
OBJECT_END

OBJECT gshadow_file
    path `/etc`
    filename `gshadow`
OBJECT_END

SET sensitive_files union
    shadow_file
    gshadow_file
SET_END

CRI AND
    CTN file_metadata
        TEST all all          # ALL objects must exist AND ALL must pass
        STATE_REF secure_permissions
        SET_REF sensitive_files
    CTN_END
CRI_END
```

**Key insight:** `TEST all all` means "all objects must exist, and all must satisfy the state."

### Pattern 2: AT LEAST ONE Service Must Be Running

**Question:** "Either `firewalld` OR `iptables` must be running."

```esp
STATE service_active
    status string = `active`
STATE_END

OBJECT firewalld
    service_name `firewalld`
OBJECT_END

OBJECT iptables
    service_name `iptables`
OBJECT_END

CRI AND
    CTN systemd_service
        TEST any at_least_one    # Any can exist, at least one must pass
        STATE_REF service_active
        OBJECT_REF firewalld
        OBJECT_REF iptables
    CTN_END
CRI_END
```

**Key insight:** `TEST any at_least_one` means "any objects can exist, but at least one must satisfy the state."

### Pattern 3: NO Prohibited Software Exists

**Question:** "Ensure telnet is NOT installed."

```esp
STATE package_installed
    installed boolean = true
STATE_END

OBJECT telnet_pkg
    package_name `telnet`
OBJECT_END

CRI AND
    CTN rpm_package
        TEST none none_satisfy   # No objects should exist that satisfy the state
        STATE_REF package_installed
        OBJECT_REF telnet_pkg
    CTN_END
CRI_END
```

**Key insight:** `TEST none none_satisfy` means "no objects should exist, and if any do, none should satisfy the state."

### Pattern 4: EXACTLY ONE Configuration Value

**Question:** "There should be exactly one `authorized_keys` file for root."

```esp
STATE file_exists
    exists boolean = true
STATE_END

OBJECT root_authkeys
    path `/root/.ssh`
    filename `authorized_keys`
OBJECT_END

CRI AND
    CTN file_metadata
        TEST only_one only_one   # Exactly one must exist AND exactly one must pass
        STATE_REF file_exists
        OBJECT_REF root_authkeys
    CTN_END
CRI_END
```

**Key insight:** `TEST only_one only_one` means "exactly one object must exist and exactly one must pass."

### Pattern 5: Multiple Conditions with OR Logic

**Question:** "Config must have EITHER setting A OR setting B."

```esp
STATE has_setting_a
    content string contains `SettingA=enabled`
STATE_END

STATE has_setting_b
    content string contains `SettingB=enabled`
STATE_END

OBJECT config_file
    path `/etc`
    filename `app.conf`
OBJECT_END

CRI AND
    CTN file_content
        TEST all all OR          # All objects, all must pass, states combined with OR
        STATE_REF has_setting_a
        STATE_REF has_setting_b
        OBJECT_REF config_file
    CTN_END
CRI_END
```

**Key insight:** The `OR` state operator means "any of the referenced states can match."

### Pattern 6: Multiple Conditions with AND Logic (Default)

**Question:** "Config must have BOTH setting A AND setting B."

```esp
STATE has_setting_a
    content string contains `SettingA=enabled`
STATE_END

STATE has_setting_b
    content string contains `SettingB=enabled`
STATE_END

OBJECT config_file
    path `/etc`
    filename `app.conf`
OBJECT_END

CRI AND
    CTN file_content
        TEST all all             # AND is the default state operator
        STATE_REF has_setting_a
        STATE_REF has_setting_b
        OBJECT_REF config_file
    CTN_END
CRI_END
```

**Key insight:** When no state operator is specified, `AND` is the default — all states must match.

### Pattern 7: Filtering Objects Before Validation

**Question:** "Check permissions only on executable files."

```esp
STATE is_executable
    permissions string contains `x`
STATE_END

STATE secure_ownership
    owner string = `root`
STATE_END

OBJECT bin_files
    path `/usr/local/bin`
    pattern `*`
OBJECT_END

CRI AND
    CTN file_metadata
        TEST all all
        STATE_REF secure_ownership
        OBJECT bin_files
            FILTER include is_executable   # Only check files that are executable
        OBJECT_END
    CTN_END
CRI_END
```

**Key insight:** `FILTER include state_name` keeps only objects that satisfy the state before validation.

### Pattern 8: Excluding Objects from Validation

**Question:** "Check all config files EXCEPT backups."

```esp
STATE is_backup
    filename string ends `.bak`
STATE_END

STATE valid_syntax
    content string pattern_match `^[^#].*=.*`
STATE_END

OBJECT config_files
    path `/etc/myapp`
    pattern `*.conf`
OBJECT_END

CRI AND
    CTN file_content
        TEST all all
        STATE_REF valid_syntax
        OBJECT config_files
            FILTER exclude is_backup   # Skip backup files
        OBJECT_END
    CTN_END
CRI_END
```

**Key insight:** `FILTER exclude state_name` removes objects that satisfy the state.

### Pattern 9: Checking Array Elements (Entity Check)

**Question:** "ALL ports in the list must be above 1024."

```esp
STATE valid_port
    port int > 1024 ALL          # ALL elements must satisfy
STATE_END
```

**Question:** "AT LEAST ONE container must have resource limits."

```esp
STATE has_limits
    record
        field spec.containers.*.resources.limits string != `` AT_LEAST_ONE
    record_end
STATE_END
```

**Entity check options:**
- `ALL` — Every element must match
- `AT_LEAST_ONE` — At least one element must match
- `NONE` — No elements may match
- `ONLY_ONE` — Exactly one element must match

### Pattern 10: Complex Criteria Logic

**Question:** "Pass if (A AND B) OR (C AND D)."

```esp
CRI OR
    CRI AND
        CTN file_metadata
            TEST all all
            STATE_REF state_a
            OBJECT_REF object_a
        CTN_END
        CTN file_metadata
            TEST all all
            STATE_REF state_b
            OBJECT_REF object_b
        CTN_END
    CRI_END

    CRI AND
        CTN file_metadata
            TEST all all
            STATE_REF state_c
            OBJECT_REF object_c
        CTN_END
        CTN file_metadata
            TEST all all
            STATE_REF state_d
            OBJECT_REF object_d
        CTN_END
    CRI_END
CRI_END
```

**Key insight:** CRI blocks can be nested to create complex logic trees.

### Pattern 11: Negating Criteria

**Question:** "Pass only if the check FAILS."

```esp
CRI AND
    CRI NOT                      # Negate the result
        CTN file_metadata
            TEST all all
            STATE_REF should_not_exist
            OBJECT_REF bad_file
        CTN_END
    CRI_END
CRI_END
```

**Key insight:** `CRI NOT` inverts the result of its contents.

### Pattern 12: Using Variables for Reusability

**Question:** "Same threshold used in multiple states."

```esp
VAR min_password_length int 15
VAR config_dir string `/etc/security`

STATE password_length
    minlen int >= VAR min_password_length
STATE_END

STATE lockout_threshold
    deny int >= VAR min_password_length   # Reusing the same variable
STATE_END

OBJECT pwquality
    path VAR config_dir
    filename `pwquality.conf`
OBJECT_END
```

**Key insight:** Variables enable consistent values across your policy.

### Quick Reference: TEST Combinations

| Scenario | TEST Specification |
|----------|-------------------|
| All must exist and pass | `TEST all all` |
| Any can exist, all that exist must pass | `TEST any all` |
| Any can exist, at least one must pass | `TEST any at_least_one` |
| None should exist | `TEST none none_satisfy` |
| Exactly one must exist and pass | `TEST only_one only_one` |
| All must exist, at least one must pass | `TEST all at_least_one` |
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

## Part 10: META Block Reference

The META block provides metadata about your policy. It's optional for parsing but **required for attestation generation**.

### Required Fields

These four fields are **mandatory** for policies that will generate compliance attestations:

| Field | Description | Format | Example |
|-------|-------------|--------|---------|
| `esp_scan_id` | Unique policy identifier | String | `stig-v242382-rbac` |
| `platform` | Target platform | String | `linux`, `windows`, `kubernetes` |
| `criticality` | Severity level | Enum | `critical`, `high`, `medium`, `low`, `info` |
| `control_mapping` | Compliance framework mappings | `FRAMEWORK:CONTROL_ID,...` | `NIST-800-53:AC-6,CIS:5.1.1` |

### Optional Fields

| Field | Description | Format | Example |
|-------|-------------|--------|---------|
| `version` | Policy version | Semver | `1.2.0` |
| `esp_version` | Required ESP version | Semver | `1.0` |
| `author` | Author/team name | String | `security-team` |
| `date` | Creation/update date | ISO 8601 | `2024-01-15` |
| `description` | Human-readable description | String | Any text |
| `title` | Short policy title | String | `SSH Root Login Disabled` |
| `category` | Classification | String | `security`, `compliance` |
| `tags` | Comma-separated tags | String | `ssh,hardening,linux` |
| `agent_type` | Scanner agent type | String | `controller`, `node` |
| `weight` | Explicit weight (0.0-1.0) | Float | `0.95` |

### Control Mapping Format

The `control_mapping` field uses a specific format: `FRAMEWORK:CONTROL_ID` pairs separated by commas.

```esp
META
    control_mapping `NIST-800-53:AC-6,CIS:5.1.1,STIG:V-242382`
META_END
```

This maps the policy to:
- NIST 800-53 control AC-6
- CIS Benchmark control 5.1.1
- DISA STIG control V-242382

### Complete META Block Example

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
    agent_type `node`
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

### Custom Fields

The parser accepts any field name in the META block. Scanner implementations may define additional fields for platform-specific requirements:

```esp
META
    esp_scan_id `k8s-pod-security`
    platform `kubernetes`
    criticality `high`
    control_mapping `CIS:5.2.1`

    # Custom Kubernetes-specific fields
    namespace `kube-system`
    resource_type `Pod`
    api_version `v1`
META_END
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
