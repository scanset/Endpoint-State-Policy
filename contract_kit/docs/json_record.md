# CTN Type Reference: `json_record`

## Overview

Validates structured JSON data from files using field path queries (record checks). Parses JSON files into RecordData for deep validation of nested structures.

**Platform:** All
**Use Case:** Configuration file validation, API response verification, structured data compliance

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `path` | string | Yes | Path to JSON file | `scanfiles/test_data.json`, `/etc/app/config.json` |

### Notes

- File must contain valid JSON
- Supports both objects and arrays as root elements
- UTF-8 encoding expected

---

## Collected Data Fields (Output)

| Field | Type | Description |
|-------|------|-------------|
| `json_data` | RecordData | Parsed JSON content as RecordData for field path queries |

**Notes:**
- The entire JSON structure is available for record check validation
- Nested objects and arrays are fully traversable

---

## State Fields (Validation)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `record` | RecordData | (record checks) | `json_data` | JSON path validation via record checks |

### Record Check Syntax

Use `record` blocks within STATE to validate specific field paths:

```esp
STATE valid_config
    record
        field settings.enabled boolean = true
        field nested.array.0.name string = `first_item`
        field users.*.role string = `admin` at_least_one
    record_end
STATE_END
```

### Supported Record Field Operations

| Operation | Description | Example |
|-----------|-------------|---------|
| `=` | Equals | `field version string = \`1.0\`` |
| `!=` | Not equals | `field env string != \`production\`` |
| `contains` | String contains | `field command string contains \`--secure\`` |
| `not_contains` | String does not contain | `field flags string not_contains \`--insecure\`` |
| `>` `<` `>=` `<=` | Numeric comparison | `field timeout int > 30` |

### Field Path Syntax

| Pattern | Description | Example |
|---------|-------------|---------|
| `name` | Simple field | `field status string = \`ok\`` |
| `a.b.c` | Nested field access | `field config.timeout int = 30` |
| `arr.0` | Array index (0-based) | `field items.0.name string = \`first\`` |
| `arr.*` | Array wildcard | `field users.*.role string = \`admin\` at_least_one` |
| `a.*.b` | Nested wildcard | `field spec.containers.*.image string contains \`nginx\`` |

### Entity Checks (for wildcards/arrays)

| Check | Passes When |
|-------|-------------|
| `all` | All matching elements pass (default) |
| `at_least_one` | At least one element passes |
| `none` | No elements pass |
| `only_one` | Exactly one element passes |

---

## Collection Strategy

| Property | Value |
|----------|-------|
| Collector Type | `filesystem` |
| Collection Mode | Content |
| Required Capabilities | `file_access`, `json_parsing` |
| Expected Collection Time | ~100ms |
| Memory Usage | ~10MB |
| Network Intensive | No |
| CPU Intensive | No |
| Requires Elevated Privileges | No |

---

## ESP Examples

### Basic JSON field validation

```esp
OBJECT app_config
    path `/etc/myapp`
    filename `config.json`
OBJECT_END

STATE valid_configuration
    record
        field version string = `2.0`
        field database.host string = `localhost`
        field database.port int = 5432
    record_end
STATE_END

CTN json_record
    TEST at_least_one all
    STATE_REF valid_configuration
    OBJECT_REF app_config
CTN_END
```

**Example JSON (`/etc/myapp/config.json`):**
```json
{
  "version": "2.0",
  "database": {
    "host": "localhost",
    "port": 5432
  }
}
```

### Array element validation

```esp
OBJECT users_file
    path `scanfiles`
    filename `users.json`
OBJECT_END

STATE admin_exists
    record
        field users.0.role string = `admin`
        field users.0.active boolean = true
    record_end
STATE_END

CTN json_record
    TEST at_least_one all
    STATE_REF admin_exists
    OBJECT_REF users_file
CTN_END
```

**Example JSON (`scanfiles/users.json`):**
```json
{
  "users": [
    { "name": "alice", "role": "admin", "active": true },
    { "name": "bob", "role": "user", "active": true }
  ]
}
```

### Security configuration check

```esp
OBJECT security_config
    path `/etc/app`
    filename `security.json`
OBJECT_END

STATE secure_settings
    record
        field tls.enabled boolean = true
        field tls.minVersion string = `TLSv1.2`
        field auth.method string != `none`
        field debug boolean = false
    record_end
STATE_END

CTN json_record
    TEST at_least_one all
    STATE_REF secure_settings
    OBJECT_REF security_config
CTN_END
```

### Wildcard array validation

```esp
OBJECT manifest_file
    path `.`
    filename `package.json`
OBJECT_END

STATE all_deps_valid
    record
        field dependencies.* string != `` all
    record_end
STATE_END

CTN json_record
    TEST at_least_one all
    STATE_REF all_deps_valid
    OBJECT_REF manifest_file
CTN_END
```

### At least one array element matches

```esp
OBJECT api_response
    path `scanfiles`
    filename `response.json`
OBJECT_END

STATE has_admin_user
    record
        field data.users.*.role string = `admin` at_least_one
    record_end
STATE_END

CTN json_record
    TEST at_least_one all
    STATE_REF has_admin_user
    OBJECT_REF api_response
CTN_END
```

### Multiple JSON files with same requirements

```esp
OBJECT config_dev
    path `config`
    filename `dev.json`
OBJECT_END

OBJECT config_prod
    path `config`
    filename `prod.json`
OBJECT_END

STATE no_debug_mode
    record
        field debug boolean = false
        field logging.level string != `debug`
    record_end
STATE_END

CTN json_record
    TEST all all
    STATE_REF no_debug_mode
    OBJECT_REF config_dev
    OBJECT_REF config_prod
CTN_END
```

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| File does not exist | `ObjectNotFound` | Counted as missing for existence check |
| Permission denied | `AccessDenied` | Error state |
| Invalid JSON syntax | `CollectionFailed` | Error state |
| File not UTF-8 | `CollectionFailed` | Error state |
| Path field missing | `InvalidObjectConfiguration` | Configuration error |
| json_data field missing | `MissingDataField` | Validation error |

---

## Platform Notes

### All Platforms

- Standard JSON parsing (RFC 8259)
- UTF-8 encoding required
- No size limit (bounded by memory)

### Performance Considerations

- Entire file loaded into memory
- Large JSON files may impact performance
- Consider file size when validating large datasets

---

## Security Considerations

- No elevated privileges required for most files
- Some system files may require root/admin access
- JSON parsing is safe (no code execution)

---

## Related CTN Types

| CTN Type | Relationship |
|----------|--------------|
| `file_content` | Raw file content validation (no JSON parsing) |
| `file_metadata` | File permissions/ownership (no content) |
| `k8s_resource` | Similar record check validation for Kubernetes resources |

---

## RecordData Type Details

The `json_data` field contains a `RecordData` structure that mirrors the JSON:

### JSON to RecordData Mapping

| JSON Type | RecordData Representation |
|-----------|---------------------------|
| `string` | String value |
| `number` (int) | Integer value |
| `number` (float) | Float value |
| `boolean` | Boolean value |
| `null` | Null marker |
| `object` | Nested RecordData |
| `array` | Indexed collection |

### Field Path Resolution

```json
{
  "server": {
    "host": "localhost",
    "ports": [8080, 8443]
  }
}
```

| Path | Resolves To |
|------|-------------|
| `server.host` | `"localhost"` |
| `server.ports.0` | `8080` |
| `server.ports.1` | `8443` |
| `server.ports.*` | All port values (with entity check) |
