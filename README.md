# helmfile2compose

*For when you maintain a helmfile but people keep asking for a docker-compose.*

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-public%20domain-brightgreen)
![Vibe](https://img.shields.io/badge/vibe-coded-ff69b4)

Convert Kubernetes manifests to `compose.yml` + `Caddyfile`.

Takes standard K8s manifests and produces a working Docker Compose setup with Caddy as reverse proxy, so you can run your stack locally (or hobby-grade) without Kubernetes.

**The generated `compose.yml` is a build artifact — never edit it directly.** All configuration goes in `helmfile2compose.yaml`; re-run the script to regenerate.

Vibe-coded with Claude, because maintaining two deployment systems by hand wasn't happening.

### But why?

I love helmfile. I love Kubernetes. But people keep asking me for a docker-compose for my community projects, and I'm not going to maintain both by hand.

There are dozens of tools that go from Compose to Kubernetes ([Kompose](https://github.com/kubernetes/kompose), [Compose Bridge](https://docs.docker.com/compose/bridge/), [Move2Kube](https://move2kube.konveyor.io/), etc.) — that's the "normal" direction. Almost nothing goes the other way, because who would design their deployment in K8s first and then downgrade?

Well, me. My source of truth is the helmfile. The compose is a build artifact. And yes, using Kubernetes manifests as an intermediate representation to generate a docker-compose is absolutely using an ICBM to kill flies — which is exactly why I find it satisfying.

### Does it require helmfile?

No. Despite the name, the core of the tool converts **any Kubernetes manifests** to compose. Helmfile is just one way to produce them. `--from-dir` accepts any directory of `.yaml` files:

```bash
# From helmfile
helmfile -e local template --output-dir /tmp/manifests
# From helm
helm template myrelease mychart -f values.yaml --output-dir /tmp/manifests
# From kustomize
kustomize build ./overlay -o /tmp/manifests/
```

Then point the tool at it:

```bash
python3 helmfile2compose.py --from-dir /tmp/manifests --output-dir ./compose
```

The `--helmfile-dir` flag is a convenience shortcut that runs `helmfile template` for you — nothing more.

## Requirements

- Python 3.10+
- `pyyaml`
- `helmfile` + `helm` (only if rendering from helmfile directly)

## Usage

```bash
# From helmfile directly
python3 helmfile2compose.py --helmfile-dir ~/my-platform -e local --output-dir ./compose

# From pre-rendered manifests (skip helmfile)
helmfile -e local template --output-dir /tmp/rendered
python3 helmfile2compose.py --from-dir /tmp/rendered --output-dir ./compose
```

### Flags

| Flag | Description |
|------|-------------|
| `--helmfile-dir` | Directory containing `helmfile.yaml` or `helmfile.yaml.gotmpl` (default: `.`) |
| `-e`, `--environment` | Helmfile environment (e.g. `local`, `production`) |
| `--from-dir` | Skip helmfile, read pre-rendered YAML from this directory |
| `--output-dir` | Where to write output files (default: `.`) |
| `--compose-file` | Name of the generated compose file (default: `compose.yml`) |

### Output files

- `compose.yml` -- services (incl. Caddy reverse proxy), volumes
- `Caddyfile` -- reverse proxy config derived from Ingress manifests
- `helmfile2compose.yaml` -- persistent config (see below)
- `configmaps/` -- generated files from ConfigMap volume mounts
- `secrets/` -- generated files from Secret volume mounts

## What it converts

| K8s kind | Compose equivalent |
|----------|-------------------|
| Deployment / StatefulSet | `services:` (image, env, command, volumes, ports) |
| Job | `services:` with `restart: on-failure` (migrations, superuser creation) |
| ConfigMap / Secret | Resolved inline into `environment:` + generated as files for volume mounts |
| Service (ClusterIP) | Hostname rewriting (K8s Service name → compose service name) |
| Service (ExternalName) | Resolved through alias chain (e.g. `docs-media` → minio) |
| Service (NodePort / LoadBalancer) | `ports:` mapping |
| Ingress | Caddy service + Caddyfile `reverse_proxy` blocks (path-rewrite annotations → `uri strip_prefix`) |
| PVC | Named volumes in `helmfile2compose.yaml` |

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
        && mc mb --ignore-existing local/revolt-uploads
```

### Config sections

- **`name`** — compose project name. Auto-set to the source directory basename on first run.
- **`volume_root`** — base path for volume host mounts (default: `./data`). Bare names in `host_path` are prefixed with this. Paths starting with `./` or `/` are used as-is. Auto-discovered PVCs default to `host_path: <pvc_name>` (resolved via `volume_root`).
- **`volumes`** — map PVCs to named volumes or host paths.
- **`exclude`** — skip workloads by name or wildcard pattern (`fnmatch` syntax: `*`, `?`, `[seq]`). Workloads with `replicas: 0` are also auto-skipped.
- **`replacements`** — global find/replace in generated ConfigMap/Secret files and env vars. Port remapping is now automatic; still useful for non-port rewrites (e.g. `path_style_buckets`).
- **`overrides`** — shallow merge into generated services. Set a key to `null` to delete it. Useful for replacing bitnami images with vanilla ones, or injecting env vars.
- **`services`** — add custom services not derived from K8s manifests. Combined with `restart: on-failure`, useful for one-shot init tasks (e.g. creating S3 buckets) that complement converted K8s Jobs.
- **`$secret:<name>:<key>`** — placeholder syntax in `overrides` and `services` values, resolved from K8s Secret manifests at generation time.
- **`$volume_root`** — placeholder in `overrides` and `services` values, resolved to the `volume_root` config value.
- **`caddy_email`** — optional. If set, generates a global Caddy block `{ email <value> }` for automatic HTTPS certificate provisioning.

On first run, K8s-only workloads (matching `cert-manager`, `ingress`, `reflector`) are auto-excluded with a warning to review.

## Target projects

### [stoatchat-platform](https://github.com/baptisterajaut/stoatchat-platform)

Primary target. A chat platform (Revolt rebrand) deployed via helmfile: API, events, file server, proxy, web client, MongoDB, Redis, RabbitMQ, MinIO, LiveKit. **15/15 services running** via helmfile2compose.

Stoatchat-specific quirks handled via config:
- All app services mount `Revolt.toml` from a ConfigMap → auto-generated + bind-mounted
- K8s DNS (`*.svc.cluster.local`) rewritten to compose service names
- Redis overridden from bitnami to vanilla (`overrides:` + `$secret:` ref)
- MinIO bucket creation via one-shot `minio-init` service (`services:` + `restart: on-failure`)
- LiveKit internal URL port remapping now automatic (K8s Service port 80 → container 7880)
- S3 `path_style_buckets` flipped to `true` via `replacements:` (compose DNS can't resolve virtual-hosted bucket URLs)

### [suite-helmfile](https://github.com/suitenumerique) (La Suite)

A larger helmfile (~16 charts) for a collaborative suite (docs, drive, meet, people, conversations, keycloak, minio, postgresql, redis, livekit). **22 services + 11 init jobs running** via helmfile2compose. Validated automatic alias resolution, port remapping, Job conversion, K8s variable escaping, wildcard excludes, and replicas:0 auto-skip.

## Code quality

```bash
pylint helmfile2compose.py          # 9.57/10
pyflakes helmfile2compose.py        # clean
radon cc helmfile2compose.py -a -s  # average B (~6), no D/E/F
```

## Limitations

Not converted (warning emitted):
- CronJobs
- Init containers, sidecars (takes `containers[0]` only)
- Resource limits / requests, HPA, PDB

Silently ignored (no compose equivalent):
- RBAC, ServiceAccounts, NetworkPolicies, CRDs, Certificates (Certificate, ClusterIssuer, Issuer), IngressClass, Webhooks, Namespaces
- Probes (liveness, readiness, startup) — no healthcheck generation
- Unknown kinds trigger a warning

### Docker/Compose vs Kubernetes gotchas

Some K8s features don't translate to Compose and may require helmfile-side adjustments for the local environment:

- **Large port ranges** — K8s with `hostNetwork` handles thousands of ports natively. Docker creates one iptables/pf rule per port, so a range like 50000-60000 (e.g. WebRTC) will kill your network stack. Reduce the range in your helmfile local values (e.g. 50000-50100).
- **hostNetwork** — K8s pods can bind directly to the host network. In Compose, every exposed port must be mapped explicitly. Services relying on hostNetwork need their ports listed in the Service/NodePort manifest or they won't be reachable.
- **Pod-to-pod networking** — K8s gives each pod an IP; Compose uses a shared bridge network. This mostly works transparently (service names resolve), but multicast/broadcast or raw IP assumptions won't.
- **S3 virtual-hosted style** — AWS SDKs default to virtual-hosted bucket URLs (`bucket-name.s3:9000`). Compose DNS can't resolve dotted hostnames as aliases. Configure your app to use path-style access (`s3:9000/bucket-name`) and use a `replacement` to flip the setting.
- **Service port remapping** — Now automatic. K8s Service port → container port rewriting happens in env vars, configmap files, and Caddyfile upstreams.
- **K8s `$(VAR)` in commands** — Kubelet-style variable interpolation in container command/args is now resolved at generation time.
- **Shell `$VAR` escaping** — Shell variable references in command/entrypoint are escaped (`$$`) so compose doesn't substitute them from host env.
