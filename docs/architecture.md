# Architecture

## Pipeline

The same Helm charts used for Kubernetes are rendered into standard K8s manifests, then converted to compose:

```
Helm charts (helmfile / helm / kustomize)
    ↓  helmfile template / helm template / kustomize build
K8s manifests (Deployments, Services, ConfigMaps, Secrets, Ingress...)
    ↓  helmfile2compose.py
compose.yml + Caddyfile + configmaps/ + secrets/
```

A dedicated helmfile environment (e.g. `compose`) typically disables K8s-only infrastructure (cert-manager, ingress controller, reflector) and adjusts defaults for compose.

## What it converts

| K8s kind | Compose equivalent |
|----------|-------------------|
| Deployment / StatefulSet | `services:` (image, env, command, volumes, ports). Init containers become separate services with `restart: on-failure`. |
| Job | `services:` with `restart: on-failure` (migrations, superuser creation). Init containers converted the same way. |
| ConfigMap / Secret | Resolved inline into `environment:` + generated as files for volume mounts |
| Service (ClusterIP) | Hostname rewriting (K8s Service name → compose service name) |
| Service (ExternalName) | Resolved through alias chain (e.g. `docs-media` → minio) |
| Service (NodePort / LoadBalancer) | `ports:` mapping |
| Ingress | Caddy service + Caddyfile `reverse_proxy` blocks (path-rewrite annotations → `uri strip_prefix`) |
| PVC / volumeClaimTemplates | Host-path bind mounts (auto-registered in `helmfile2compose.yaml`) |
| securityContext (runAsUser) | Auto-generated `fix-permissions` service (`chown -R <uid>`) for non-root bind mounts |

### Not converted (warning emitted)

- CronJobs
- Sidecars (takes `containers[0]` only)
- Resource limits / requests, HPA, PDB

### Silently ignored (no compose equivalent)

- RBAC, ServiceAccounts, NetworkPolicies, CRDs, Certificates (Certificate, ClusterIssuer, Issuer), IngressClass, Webhooks, Namespaces
- Probes (liveness, readiness, startup) — no healthcheck generation
- Unknown kinds trigger a warning

## Config file (`helmfile2compose.yaml`)

Created on first run, preserved across re-runs. Edit it to control volume mappings and exclusions.

```yaml
helmfile2ComposeVersion: v1
name: my-platform           # compose project name (default: source dir basename)
volume_root: ./data         # prefix for bare host_path names (default: ./data)
caddy_email: admin@example.com  # optional — for Caddy automatic HTTPS

volumes:
  data-postgresql:
    driver: local          # named docker volume
  myapp-data:
    host_path: app         # → ./data/app (bare name = volume_root + name)
  other:
    host_path: ./custom    # explicit path (starts with ./ or /), used as-is

exclude:
  - prometheus-operator    # exact name
  - meet-celery-*          # wildcard (fnmatch syntax)

replacements:               # string replacements in generated files and env vars (port remaps are automatic)
  - old: 'path_style_buckets = false'
    new: 'path_style_buckets = true'

overrides:                  # shallow merge into generated services
  redis-master:
    image: redis:7-alpine
    command: ["redis-server", "--requirepass", "$secret:redis:redis-password"]
    volumes: ["$volume_root/redis:/data"]
    environment: null       # null deletes the key

services:                   # custom services (not from K8s manifests)
  minio-init:
    image: quay.io/minio/mc:latest
    restart: on-failure
    entrypoint: ["/bin/sh", "-c"]
    command:
      - mc alias set local http://minio:9000 $secret:minio:rootUser $secret:minio:rootPassword
        && mc mb --ignore-existing local/my-bucket
```

### Config sections

| Section | Description |
|---------|-------------|
| `name` | Compose project name. Auto-set to the source directory basename on first run. |
| `volume_root` | Base path for volume host mounts (default: `./data`). Bare names in `host_path` are prefixed with this. Paths starting with `./` or `/` are used as-is. Auto-discovered PVCs default to `host_path: <pvc_name>`. |
| `volumes` | Map PVCs to named volumes or host paths. |
| `exclude` | Skip workloads by name or wildcard pattern (`fnmatch` syntax: `*`, `?`, `[seq]`). Workloads with `replicas: 0` are also auto-skipped. |
| `replacements` | Global find/replace in generated ConfigMap/Secret files and env vars. Port remapping is automatic; still useful for non-port rewrites. |
| `overrides` | Shallow merge into generated services. Set a key to `null` to delete it. Useful for replacing bitnami images with vanilla ones. |
| `services` | Custom services not from K8s manifests. Combined with `restart: on-failure`, useful for one-shot init tasks. |
| `caddy_email` | If set, generates a global Caddy block `{ email <value> }` for automatic HTTPS. |

### Placeholders

- **`$secret:<name>:<key>`** — resolved from K8s Secret manifests at generation time. Usable in `overrides` and `services` values.
- **`$volume_root`** — resolved to the `volume_root` config value. Usable in `overrides` and `services` values.

On first run, K8s-only workloads (matching `cert-manager`, `ingress`, `reflector`) are auto-excluded with a warning to review.

## Differences from Kubernetes

| Aspect | Kubernetes | Compose |
|--------|-----------|---------|
| Reverse proxy | Ingress controller (HAProxy, nginx, traefik) | Caddy (auto-TLS, path routing) |
| TLS | cert-manager (selfsigned or Let's Encrypt) | Caddy (internal CA or Let's Encrypt) |
| Service discovery | K8s DNS (`.svc.cluster.local`) | Compose DNS (service names) |
| Secrets | K8s Secrets (base64, RBAC-gated) | Inline env vars (derived from seed) |
| Volumes | PVCs (dynamic provisioning) | Bind mounts or named volumes |
| Port exposure | hostNetwork / NodePort / LoadBalancer | Explicit port mappings |
| Scaling | HPA / replicas | Single instance |
| Namespace isolation | Per-service namespaces | Single compose network |
| Secret replication | Reflector (cross-namespace) | Not needed (single network) |

## Docker/Compose gotchas

These are Docker/Compose limitations, not conversion limitations. See [limitations.md](limitations.md) for what gets lost in translation.

- **Large port ranges** — K8s with `hostNetwork` handles thousands of ports natively. Docker creates one iptables/pf rule per port, so a range like 50000-60000 (e.g. WebRTC) will kill your network stack. Reduce the range in your compose environment values (e.g. 50000-50100).
- **hostNetwork** — K8s pods can bind directly to the host network. In Compose, every exposed port must be mapped explicitly.
- **S3 virtual-hosted style** — AWS SDKs default to virtual-hosted bucket URLs (`bucket-name.s3:9000`). Compose DNS can't resolve dotted hostnames. Configure your app to use path-style access and use a `replacement` to flip the setting.

### Handled automatically

- **Service port remapping** — K8s Service port → container port rewriting in env vars, configmap files, and Caddyfile upstreams.
- **K8s `$(VAR)` in commands** — Kubelet-style variable interpolation in container command/args resolved at generation time.
- **Shell `$VAR` escaping** — Shell variable references in command/entrypoint escaped (`$$`) so compose doesn't substitute them from host env.
- **K8s DNS rewriting** — `<svc>.<ns>.svc.cluster.local` rewritten to compose service names.
- **Bind mount permissions** — Non-root containers with PVC bind mounts get an auto-generated `fix-permissions` service.
