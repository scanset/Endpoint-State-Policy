# CTN Type Reference: `file_metadata`

## Overview

Fast metadata collection via `stat()` for file permissions, ownership, group, existence, and size validation.

**Platform:** Linux, macOS, Windows (partial)
**Use Case:** Security compliance validation of file permissions and ownership

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `path` | string | Yes | File system path (absolute or relative) | `/etc/sudoers`, `scanfiles/sudoers` |
| `type` | string | No | Resource type indicator (informational only) | `file` |

### Notes

- Supports VAR resolution in paths
- Both absolute and relative paths accepted

---

## Collected Data Fields (Output)

| Field | Type | Description |
|-------|------|-------------|
| `file_mode` | string | File permissions in 4-digit octal format (Unix only) |
| `file_owner` | string | File owner UID as string (Unix only) |
| `file_group` | string | File group GID as string (Unix only) |
| `exists` | boolean | Whether file exists |
| `readable` | boolean | Whether file is readable by current process |
| `file_size` | int | File size in bytes |

**Notes:**
- On non-Unix platforms, `file_mode`, `file_owner`, and `file_group` return empty strings
- If file doesn't exist, metadata fields return empty/default values

---

## State Fields (Validation)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `permissions` | string | `=`, `!=` | `file_mode` | File permissions in octal format |
| `owner` | string | `=`, `!=` | `file_owner` | File owner (UID as string) |
| `group` | string | `=`, `!=` | `file_group` | File group (GID as string) |
| `exists` | boolean | `=`, `!=` | `exists` | Whether file exists |
| `readable` | boolean | `=`, `!=` | `readable` | Whether file is readable |
| `size` | int | `=`, `!=`, `>`, `<`, `>=`, `<=` | `file_size` | File size in bytes |

---

## Collection Strategy

| Property | Value |
|----------|-------|
| Collector Type | `filesystem` |
| Collection Mode | Metadata |
| Required Capabilities | `file_access` |
| Expected Collection Time | ~5ms |
| Memory Usage | ~1MB |
| Network Intensive | No |
| CPU Intensive | No |
| Requires Elevated Privileges | No |

---

## ESP Examples

### Basic permissions check

```esp
OBJECT sudoers_file
    path `/etc/sudoers`
OBJECT_END

STATE secure_permissions
    exists boolean = true
    permissions string = `0440`
    owner string = `0`
    group string = `0`
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF secure_permissions
    OBJECT_REF sudoers_file
CTN_END
```

### Check file does NOT exist

```esp
OBJECT dangerous_file
    path `/etc/dangerous.conf`
OBJECT_END

STATE must_not_exist
    exists boolean = false
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF must_not_exist
    OBJECT_REF dangerous_file
CTN_END
```

### File size validation

```esp
OBJECT log_file
    path `/var/log/audit/audit.log`
OBJECT_END

STATE not_empty
    exists boolean = true
    size int > `0`
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF not_empty
    OBJECT_REF log_file
CTN_END
```

### Multiple files with same requirements

```esp
OBJECT passwd_file
    path `/etc/passwd`
OBJECT_END

OBJECT shadow_file
    path `/etc/shadow`
OBJECT_END

STATE root_owned
    exists boolean = true
    owner string = `0`
STATE_END

CTN file_metadata
    TEST all all
    STATE_REF root_owned
    OBJECT_REF passwd_file
    OBJECT_REF shadow_file
CTN_END
```

### Readable by current process

```esp
OBJECT config_file
    path `/etc/myapp/config.yml`
OBJECT_END

STATE must_be_readable
    exists boolean = true
    readable boolean = true
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF must_be_readable
    OBJECT_REF config_file
CTN_END
```

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| File does not exist | N/A | `exists` = false, other fields empty |
| Permission denied (stat) | `AccessDenied` | Error state |
| Invalid path | `InvalidObjectConfiguration` | Configuration error |
| Path field missing | `InvalidObjectConfiguration` | Configuration error |

---

## Platform Notes

### Linux / macOS (Unix)

- Uses `stat()` system call
- Permissions returned as 4-digit octal (e.g., `0644`)
- Owner/group returned as numeric UID/GID strings
- Full support for all fields

### Windows

- Limited support
- `file_mode`, `file_owner`, `file_group` return empty strings
- `exists`, `readable`, `file_size` work normally

---

## Security Considerations

- No elevated privileges required for most files
- Some system files may require root/admin access to stat
- Does not read file content (use `file_content` for that)

---

## Related CTN Types

| CTN Type | Relationship |
|----------|--------------|
| `file_content` | Content validation (more expensive) |
| `json_record` | Structured JSON file validation |
