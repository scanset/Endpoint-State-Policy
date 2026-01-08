# CTN Type Reference: `k8s_resource`

## Overview

Validates Kubernetes API resources using kubectl. Returns resource JSON as RecordData for field path validation using record checks.

**Platform:** Any with kubectl access
**Use Case:** Kubernetes cluster compliance validation, security policy enforcement

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `kind` | string | Yes | Kubernetes resource kind (case-sensitive) | `Pod`, `Namespace`, `Service`, `Deployment` |
| `namespace` | string | No | Namespace to query (omit for all or cluster-scoped) | `kube-system`, `default` |
| `name` | string | No | Exact resource name | `kube-apiserver-control-plane` |
| `name_prefix` | string | No | Resource name prefix filter | `kube-apiserver-` |
| `label_selector` | string | No | Kubernetes label selector | `component=kube-apiserver`, `app=nginx` |

### Notes

- `name` and `name_prefix` are mutually exclusive
- Omit `namespace` for cluster-scoped resources (Namespace, Node, PersistentVolume, ClusterRole, ClusterRoleBinding)
- `kind` is case-sensitive and must match Kubernetes API (e.g., `Pod` not `pod`)

### Cluster-Scoped Resources

These resources do not use namespaces:
- `Namespace`
- `Node`
- `PersistentVolume`
- `ClusterRole`
- `ClusterRoleBinding`

---

## Collected Data Fields (Output)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `found` | boolean | Yes | Whether matching resource was found |
| `count` | int | No | Number of matching resources (before name_prefix filtering) |
| `resource` | RecordData | Yes | Full resource JSON as RecordData (empty object if not found) |

---

## State Fields (Validation)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `found` | boolean | `=`, `!=` | `found` | Resource existence check |
| `count` | int | `=`, `!=`, `>`, `<`, `>=`, `<=` | `count` | Resource count validation |
| `record` | RecordData | (record checks) | `resource` | JSON path validation via record checks |

### Record Checks

Use `record` blocks within STATE to validate specific field paths in the resource:

```esp
STATE api_server_config
    record
        field spec.containers.0.command string contains `--authorization-mode=RBAC` at_least_one
        field spec.containers.0.command string not_contains `--authorization-mode=AlwaysAllow`
    record_end
STATE_END
```

---

## Collection Strategy

| Property | Value |
|----------|-------|
| Collector Type | `k8s_resource` |
| Collection Mode | Content |
| Required Capabilities | `kubectl_access` |
| Expected Collection Time | ~500ms |
| Memory Usage | ~10MB |
| Network Intensive | Yes |
| CPU Intensive | No |
| Requires Elevated Privileges | No (uses kubectl auth) |

---

## Command Execution

### Executor Configuration

```rust
SystemCommandExecutor::with_timeout(Duration::from_secs(30))
```

### Whitelisted Commands

| Command | Path | Description |
|---------|------|-------------|
| `kubectl` | PATH lookup | Standard kubectl |
| `/usr/local/bin/kubectl` | Absolute | Common container location |
| `/usr/bin/kubectl` | Absolute | Alternative location |

### Command Sandbox

Commands run in an isolated environment:
- **No inherited environment variables** - must be explicitly set
- **30 second timeout** - K8s API calls can be slower than local commands
- **Whitelisted only** - only approved commands can execute

### Authentication

The collector automatically handles authentication:

**In-Cluster (Pod running in Kubernetes):**
```
KUBERNETES_SERVICE_HOST + KUBERNETES_SERVICE_PORT → API server
/var/run/secrets/kubernetes.io/serviceaccount/token → Bearer token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt → CA certificate
```

**Out-of-Cluster:**
```
$KUBECONFIG → Custom kubeconfig path
~/.kube/config → Default kubeconfig
```

### Command Format

```bash
kubectl [auth-args] get <kind> [-n <namespace>] [<name>] [-l <selector>] -o json
```

**Example commands generated:**

```bash
# Pod in specific namespace
kubectl get pod -n kube-system -o json

# Pod with label selector
kubectl get pod -n kube-system -l component=kube-apiserver -o json

# Specific named resource
kubectl get namespace default -o json

# All pods (all namespaces)
kubectl get pod --all-namespaces -o json
```

### Output Format

kubectl returns JSON in two formats:

**List response (multiple resources):**
```json
{
  "apiVersion": "v1",
  "kind": "PodList",
  "items": [
    {
      "metadata": { "name": "pod-1", "namespace": "default" },
      "spec": { ... },
      "status": { ... }
    }
  ]
}
```

**Single resource (when name specified):**
```json
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": { "name": "my-pod", "namespace": "default" },
  "spec": { ... },
  "status": { ... }
}
```

---

## ESP Examples

### Check kube-apiserver has RBAC enabled

```esp
OBJECT api_server_pod
    kind `Pod`
    namespace `kube-system`
    label_selector `component=kube-apiserver`
OBJECT_END

STATE rbac_enabled
    found boolean = true
    record
        field spec.containers.0.command string contains `--authorization-mode=RBAC` at_least_one
    record_end
STATE_END

CTN k8s_resource
    TEST at_least_one all
    STATE_REF rbac_enabled
    OBJECT_REF api_server_pod
CTN_END
```

### Verify namespace exists

```esp
OBJECT kube_system_ns
    kind `Namespace`
    name `kube-system`
OBJECT_END

STATE namespace_exists
    found boolean = true
STATE_END

CTN k8s_resource
    TEST at_least_one all
    STATE_REF namespace_exists
    OBJECT_REF kube_system_ns
CTN_END
```

### Check namespace does NOT exist

```esp
OBJECT dangerous_namespace
    kind `Namespace`
    name `insecure-namespace`
OBJECT_END

STATE must_not_exist
    found boolean = false
STATE_END

CTN k8s_resource
    TEST at_least_one all
    STATE_REF must_not_exist
    OBJECT_REF dangerous_namespace
CTN_END
```

### Validate Pod security context

```esp
OBJECT privileged_pods
    kind `Pod`
    namespace `default`
OBJECT_END

STATE not_privileged
    found boolean = true
    record
        field spec.containers.0.securityContext.privileged boolean = false
    record_end
STATE_END

CTN k8s_resource
    TEST all all
    STATE_REF not_privileged
    OBJECT_REF privileged_pods
CTN_END
```

### Check resource count

```esp
OBJECT nginx_replicas
    kind `Pod`
    namespace `production`
    label_selector `app=nginx`
OBJECT_END

STATE minimum_replicas
    count int >= 3
STATE_END

CTN k8s_resource
    TEST at_least_one all
    STATE_REF minimum_replicas
    OBJECT_REF nginx_replicas
CTN_END
```

### Using name_prefix for control plane pods

```esp
OBJECT controller_manager
    kind `Pod`
    namespace `kube-system`
    name_prefix `kube-controller-manager-`
OBJECT_END

STATE controller_running
    found boolean = true
    record
        field status.phase string = `Running`
    record_end
STATE_END

CTN k8s_resource
    TEST at_least_one all
    STATE_REF controller_running
    OBJECT_REF controller_manager
CTN_END
```

### Validate all containers have resource limits

```esp
OBJECT app_deployment
    kind `Pod`
    namespace `production`
    label_selector `app=myapp`
OBJECT_END

STATE has_resource_limits
    found boolean = true
    record
        field spec.containers.*.resources.limits.memory string != `` all
        field spec.containers.*.resources.limits.cpu string != `` all
    record_end
STATE_END

CTN k8s_resource
    TEST all all
    STATE_REF has_resource_limits
    OBJECT_REF app_deployment
CTN_END
```

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| Resource not found | N/A | `found` = false, empty `resource` |
| kubectl not found | `CollectionFailed` | Error state |
| kubectl timeout (>30s) | `CollectionFailed` | Error state |
| Permission denied | `CollectionFailed` | Error state |
| Invalid kubeconfig | `CollectionFailed` | Error state |
| API server unreachable | `CollectionFailed` | Error state |
| Invalid kind | `CollectionFailed` | kubectl error |
| Invalid label selector | `CollectionFailed` | kubectl error |

---

## Platform Notes

### Running In-Cluster

- Uses ServiceAccount token automatically
- Requires appropriate RBAC permissions
- CA certificate mounted at `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`

### Running Out-of-Cluster

- Requires valid kubeconfig
- Checks `$KUBECONFIG` then `~/.kube/config`
- User must have appropriate cluster permissions

### Required RBAC Permissions

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: esp-scanner
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["pods", "services", "deployments", "namespaces", "nodes"]
  verbs: ["get", "list"]
```

---

## Security Considerations

- Commands run in isolated sandbox without inherited environment
- Only whitelisted kubectl paths allowed
- No shell expansion or injection possible
- ServiceAccount tokens are read-only
- Consider principle of least privilege for RBAC

---

## Related CTN Types

| CTN Type | Relationship |
|----------|--------------|
| `json_record` | Similar record check validation for local JSON files |
