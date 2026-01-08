# CTN Type Reference: `file_content`

## Overview

Full file content reading for string validation with support for pattern matching and recursive directory scanning.

**Platform:** Linux, macOS, Windows
**Use Case:** Configuration file validation, security policy verification

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

## Behaviors

| Behavior | Type | Parameters | Default | Description |
|----------|------|------------|---------|-------------|
| `recursive_scan` | Flag | `max_depth` (int) | 3 | Recursively scan directories for matching files |
| `include_hidden` | Flag | None | - | Include hidden files (starting with `.`) in scan |
| `binary_mode` | Flag | None | - | Collect binary files as base64-encoded data |
| `follow_symlinks` | Flag | None | - | Follow symbolic links during collection |

### Behavior Examples

```esp
OBJECT config_dir
    path `/etc/myapp/`
    BEHAVIOR recursive_scan max_depth 5
    BEHAVIOR include_hidden
OBJECT_END
```

---

## Collected Data Fields (Output)

| Field | Type | Description |
|-------|------|-------------|
| `file_content` | string | File content as UTF-8 string |
| `file_count` | int | Number of files collected (recursive mode only) |

**Notes:**
- Binary files will error unless `binary_mode` behavior is set
- Large files may impact memory usage

---

## State Fields (Validation)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `content` | string | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `pattern_match` | `file_content` | File content validation |

### String Operations

| Operation | Description | Example |
|-----------|-------------|---------|
| `=` | Exact match | `content string = \`exact text\`` |
| `!=` | Not equal | `content string != \`forbidden\`` |
| `contains` | Contains substring | `content string contains \`logfile=\`` |
| `not_contains` | Does not contain | `content string not_contains \`NOPASSWD\`` |
| `starts` | Starts with | `content string starts \`#!/bin/bash\`` |
| `ends` | Ends with | `content string ends \`# END CONFIG\`` |
| `pattern_match` | Regex match | `content string pattern_match \`^root:.*:0:0:\`` |

---

## Collection Strategy

| Property | Value |
|----------|-------|
| Collector Type | `filesystem` |
| Collection Mode | Content |
| Required Capabilities | `file_access` |
| Expected Collection Time | ~50ms |
| Memory Usage | ~10MB |
| Network Intensive | No |
| CPU Intensive | No |
| Requires Elevated Privileges | No |

---

## ESP Examples

### Check file contains required setting

```esp
OBJECT sshd_config
    path `/etc/ssh/sshd_config`
OBJECT_END

STATE no_root_login
    content string contains `PermitRootLogin no`
STATE_END

CTN file_content
    TEST at_least_one all
    STATE_REF no_root_login
    OBJECT_REF sshd_config
CTN_END
```

### Check file does NOT contain dangerous setting

```esp
OBJECT sudoers
    path `/etc/sudoers`
OBJECT_END

STATE no_nopasswd
    content string not_contains `NOPASSWD`
STATE_END

CTN file_content
    TEST at_least_one all
    STATE_REF no_nopasswd
    OBJECT_REF sudoers
CTN_END
```

### Pattern match validation

```esp
OBJECT passwd_file
    path `/etc/passwd`
OBJECT_END

STATE root_uid_zero
    content string pattern_match `^root:.*:0:0:`
STATE_END

CTN file_content
    TEST at_least_one all
    STATE_REF root_uid_zero
    OBJECT_REF passwd_file
CTN_END
```

### Recursive directory scan

```esp
OBJECT config_directory
    path `/etc/myapp/conf.d/`
    BEHAVIOR recursive_scan max_depth 2
    BEHAVIOR include_hidden
OBJECT_END

STATE no_debug_mode
    content string not_contains `DEBUG=true`
STATE_END

CTN file_content
    TEST at_least_one all
    STATE_REF no_debug_mode
    OBJECT_REF config_directory
CTN_END
```

### File starts with shebang

```esp
OBJECT script_file
    path `/usr/local/bin/myscript`
OBJECT_END

STATE valid_shebang
    content string starts `#!/bin/bash`
STATE_END

CTN file_content
    TEST at_least_one all
    STATE_REF valid_shebang
    OBJECT_REF script_file
CTN_END
```

### Multiple content checks (AND logic)

```esp
OBJECT nginx_config
    path `/etc/nginx/nginx.conf`
OBJECT_END

STATE secure_config
    content string contains `ssl_protocols TLSv1.2 TLSv1.3`
    content string not_contains `ssl_protocols SSLv3`
    content string not_contains `ssl_protocols TLSv1 `
STATE_END

CTN file_content
    TEST at_least_one all
    STATE_REF secure_config
    OBJECT_REF nginx_config
CTN_END
```

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| File does not exist | `ObjectNotFound` | Counted as missing for existence check |
| Permission denied | `AccessDenied` | Error state |
| File is binary (not UTF-8) | `CollectionFailed` | Error unless `binary_mode` set |
| Invalid path | `InvalidObjectConfiguration` | Configuration error |
| Path field missing | `InvalidObjectConfiguration` | Configuration error |

---

## Platform Notes

### Linux / macOS / Windows

- Full support on all platforms
- UTF-8 encoding expected for text files
- Binary files require `binary_mode` behavior

### Performance Considerations

- More expensive than `file_metadata` (reads full file)
- Memory usage scales with file size
- Recursive scanning can be slow for large directory trees
- Consider using `max_depth` parameter to limit recursion

---

## Security Considerations

- No elevated privileges required for most files
- Some system files may require root/admin access
- Large files may cause memory pressure
- Recursive scans should use depth limits

---

## Related CTN Types

| CTN Type | Relationship |
|----------|--------------|
| `file_metadata` | Metadata-only validation (faster) |
| `json_record` | Structured JSON file validation |
