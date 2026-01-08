# CTN Type Reference: `tcp_listener`

## Overview

Validates whether a TCP port is listening on the local system by reading `/proc/net/tcp`.

**Platform:** Linux
**Use Case:** Runtime validation of network services

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `port` | int | Yes | TCP port number to check | `22`, `10255`, `8080` |
| `host` | string | No | Bind address filter (default: any) | `0.0.0.0`, `127.0.0.1`, `any` |

### Notes

- Port range: 1-65535
- Use `any` or omit `host` to match any bind address

---

## Collected Data Fields (Output)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listening` | boolean | Yes | Whether port is in LISTEN state |
| `local_address` | string | No | Local address:port if listening (e.g., `0.0.0.0:22`) |

**Notes:**
- `listening` is `true` if any process is listening on the port
- `local_address` is only populated when port is listening

---

## State Fields (Validation)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `listening` | boolean | `=`, `!=` | `listening` | Whether port is in LISTEN state |

---

## Collection Strategy

| Property | Value |
|----------|-------|
| Collector Type | `tcp_listener` |
| Collection Mode | Metadata |
| Required Capabilities | `procfs_access` |
| Expected Collection Time | ~10ms |
| Memory Usage | ~1MB |
| Network Intensive | No |
| CPU Intensive | No |
| Requires Elevated Privileges | No |

---

## Data Source

Reads `/proc/net/tcp` on Linux systems.

**Format:** Each line contains socket information in hex format:
```
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
 0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
```

**State codes:**
- `0A` = LISTEN
- Other states indicate non-listening sockets

---

## ESP Examples

### Basic port listening check

```esp
OBJECT ssh_port
    port int `22`
OBJECT_END

STATE is_listening
    listening boolean = true
STATE_END

CTN tcp_listener
    TEST at_least_one all
    STATE_REF is_listening
    OBJECT_REF ssh_port
CTN_END
```

### Check port is NOT listening

```esp
OBJECT dangerous_port
    port int `23`
OBJECT_END

STATE not_listening
    listening boolean = false
STATE_END

CTN tcp_listener
    TEST at_least_one all
    STATE_REF not_listening
    OBJECT_REF dangerous_port
CTN_END
```

### Check specific bind address

```esp
OBJECT localhost_only
    port int `8080`
    host `127.0.0.1`
OBJECT_END

STATE bound_to_localhost
    listening boolean = true
STATE_END

CTN tcp_listener
    TEST at_least_one all
    STATE_REF bound_to_localhost
    OBJECT_REF localhost_only
CTN_END
```

### Multiple ports validation

```esp
OBJECT kubelet_port
    port int `10250`
OBJECT_END

OBJECT kubelet_readonly
    port int `10255`
OBJECT_END

STATE must_listen
    listening boolean = true
STATE_END

CTN tcp_listener
    TEST all all
    STATE_REF must_listen
    OBJECT_REF kubelet_port
    OBJECT_REF kubelet_readonly
CTN_END
```

---


## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| Cannot read `/proc/net/tcp` | `CollectionFailed` | Error state |
| Invalid port number (< 1 or > 65535) | `InvalidObjectConfiguration` | Configuration error |
| Port field missing | `InvalidObjectConfiguration` | Configuration error |

---

## Platform Notes

### Linux

- Reads `/proc/net/tcp` directly (no external commands)
- IPv4 addresses stored in little-endian hex format
- State `0A` indicates LISTEN state

### Windows

- Not supported by this collector
- Use Windows-specific network collectors for Windows systems

### macOS

- Not supported (`/proc/net/tcp` not available)
- Consider using `netstat` or `lsof` based collectors

---

## Security Considerations

- No elevated privileges required to read `/proc/net/tcp`
- Only reports listening status, not process information
- Does not reveal which process owns the socket (use `ss` or `netstat` for that)

---

## Related CTN Types

| CTN Type | Relationship |
|----------|--------------|
| `udp_listener` | Similar validation for UDP ports |
| `systemd_service` | Often used together to verify service + port |
| `file_metadata` | Validate socket files |
