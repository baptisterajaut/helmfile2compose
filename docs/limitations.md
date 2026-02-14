# Limitations

*We replaced the perfectly sane orchestra conductor with a hideously mutated chimpanzee sprouting tentacle appendices, and you're surprised the audience needs earplugs.*

Kubernetes is an orchestrator. Docker Compose is a list of containers. This document covers what gets lost in translation.

## What changes behavior

Things you need to know for the output to work correctly.

### Startup ordering

Kubernetes init containers block the main container until they complete. In compose, init containers become separate services with `restart: on-failure` - they retry until they succeed, but nothing prevents the main container from starting concurrently and crash-looping until its dependencies are ready.

This works in practice (everything eventually converges), but expect noisy logs on first boot.

Why not `depends_on`? nerdctl compose ignores it entirely. Docker compose supports `condition: service_completed_successfully`, but relying on it would break nerdctl compatibility. Brute force retry works everywhere.

Exception: sidecar containers use `depends_on` to ensure the main service's container exists before starting (required by `network_mode: container:<name>`). nerdctl compose respects the ordering even though it logs a warning about ignoring the directive.

### Sidecars and pod-level networking

Sidecar containers (`containers[1:]`) are converted to separate compose services sharing the main service's network namespace via `network_mode: container:<name>`. Both containers listen on the same hostname, each on its own port — same as a K8s pod.

Other compose services reach both the main container and its sidecars via the main service name, each on its own port.

Limitation: `emptyDir` volumes are not shared between the main container and its sidecars (same limitation as init containers — see [emptyDir volumes](#emptydir-volumes)).

### emptyDir volumes

K8s `emptyDir` volumes are shared between containers in the same pod. When init containers and the main container both mount the same `emptyDir` (e.g. to chmod a directory), compose converts them to anonymous volumes (`- /path`) which are NOT shared between services.

If an init container needs to prepare data for the main container via a shared volume, the `emptyDir` must be mapped to a named volume in `helmfile2compose.yaml` manually.

### Secrets

K8s Secrets are RBAC-gated and base64-encoded. In compose, secrets are resolved at generation time and injected as plain-text environment variables. The generated `compose.yml` contains secrets in clear text - do not commit it to version control.

### TLS between services

In Kubernetes, services can use mTLS (via service mesh or cert-manager) for internal communication. In compose, inter-service traffic is plain HTTP on the shared bridge network. Only the Caddy reverse proxy terminates TLS for external access.

Services that expect TLS certificates for internal endpoints (e.g. Kestrel HTTPS bindings) will need their config adjusted to use HTTP, or self-signed certs generated separately.

### Bind mount permissions (Linux / WSL)

Bitnami images (PostgreSQL, Redis, MongoDB) run as non-root (UID 1001) and expect Unix permissions on their data directories. The host directory is typically owned by your user (UID 1000), so the container can't write to it. This causes `mkdir: cannot create directory: Permission denied`.

This is handled automatically: helmfile2compose detects non-root containers (`securityContext.runAsUser`) with PVC bind mounts and generates a `fix-permissions` service that runs `chown -R <uid>` as root on first startup. No manual intervention needed.

## What is ignored

Safe to skip — these affect the cluster's operational behavior, not what the application does.

### Scaling and replicas

Compose runs one instance of each service. HPA, replica counts (other than 0, which auto-skips the workload), and PodDisruptionBudgets are ignored. DaemonSets are converted as regular services (one instance, no node affinity or scheduling). This is a single-machine tool.

### Resource limits

CPU/memory requests and limits are ignored. Compose supports `mem_limit` / `cpus`, but translating K8s resource semantics (requests vs limits, burstable QoS) into compose constraints is more misleading than helpful.

### Probes and healthchecks

Liveness, readiness, and startup probes are not converted to compose `healthcheck`. The semantics differ enough that a blind translation would cause more problems than it solves (compose healthcheck only affects `depends_on` with `condition: service_healthy`, which we don't use anyway).

### Network isolation

Kubernetes namespaces and NetworkPolicies provide network isolation between services. In compose, all services share a single bridge network. Everything can talk to everything.

### fieldRef (downward API)

Environment variables using `fieldRef` (e.g. `status.podIP`, `metadata.name`) are skipped with a warning. There is no compose equivalent for most of these. `status.podIP` could theoretically be replaced with the service name, but the semantics differ.

## What is not converted

Not supported, no workaround.

### CronJobs

Not converted. A CronJob would need an external scheduler or a `sleep`-loop wrapper, neither of which is a good idea.

### CRDs (Custom Resource Definitions)

Operator-managed resources (`Keycloak`, `KeycloakRealmImport`, Zalando `postgresql`, Strimzi `Kafka`, etc.) are skipped with a warning. The tool converts standard K8s kinds only.

CRD support via a converter plugin system is planned - see [future.md](future.md).

### Longhorn

Don't even think about it.
