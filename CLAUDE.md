# helmfile2compose

Convert `helmfile template` output to `compose.yml` + `Caddyfile`.

## Workflow

Lint often: run `pylint helmfile2compose.py` and `pyflakes helmfile2compose.py` after any change. Fix real issues (unused imports, actual bugs, f-strings without placeholders). Pylint style warnings (too-many-locals, line-too-long, etc.) are acceptable.

Complexity: run `radon cc helmfile2compose.py -a -s -n C` to check cyclomatic complexity. Target: no D/E/F ratings. Current: 4 C-rated functions (convert, convert_workload, main, _rewrite_env_values), average C (~15).

## What exists

Single script `helmfile2compose.py` (~1109 lines). No packages, no setup.py. Dependency: `pyyaml`.

### CLI

```bash
# From helmfile directly (needs helmfile + helm installed)
python3 helmfile2compose.py --helmfile-dir ~/stoat-platform -e local --output-dir .

# From pre-rendered manifests (skip helmfile)
python3 helmfile2compose.py --from-dir /tmp/rendered --output-dir .
```

Flags: `--helmfile-dir`, `-e`/`--environment`, `--from-dir`, `--output-dir`, `--compose-file`.

### What it does

- Parses multi-doc YAML from `helmfile template --output-dir` (recursive `.yaml` scan)
- Classifies manifests by `kind`
- Converts:
  - **Deployment/StatefulSet** → compose `services:` (image, env, command, volumes, ports)
  - **Job** → compose `services:` with `restart: on-failure` (migrations, superuser creation, etc.)
  - **ConfigMap/Secret** → resolved inline into `environment:` + generated as files for volume mounts (`configmaps/`, `secrets/`)
  - **Service (ClusterIP)** → hostname rewriting (K8s Service name → compose service name) in env vars, Caddyfile, configmap files
  - **Service (ExternalName)** → resolved through alias chain (e.g. `docs-media` → minio FQDN → `minio`)
  - **Service (NodePort/LoadBalancer)** → `ports:` mapping
  - **Ingress** → Caddy service + Caddyfile blocks (`reverse_proxy`), specific paths before catch-all
  - **PVC** → named volumes + `helmfile2compose.yaml` config
- Warns on stderr for: sidecars, resource limits, HPA, CronJob, PDB, unknown kinds
- Silently ignores: RBAC, ServiceAccounts, NetworkPolicies, CRDs, Certificates (Certificate, ClusterIssuer, Issuer), IngressClass, Webhooks, Namespaces
- Writes `compose.yml` (configurable via `--compose-file`), `Caddyfile`, `helmfile2compose.yaml`

### Config file (`helmfile2compose.yaml`)

Persistent, re-runnable. User edits are preserved across runs.

```yaml
helmfile2ComposeVersion: v1
name: my-platform
volume_root: ./data        # prefix for bare host_path names (default: ./data)
caddy_email: admin@example.com  # optional — for Caddy automatic HTTPS
volumes:
  data-postgresql:
    driver: local          # named docker volume
  myapp-data:
    host_path: app         # → ./data/app (bare name = volume_root + name)
  other:
    host_path: ./custom    # explicit path, used as-is
exclude:
  - prometheus-operator    # skip this workload
  - meet-celery-*          # wildcards supported (fnmatch)
replacements:             # string replacements in generated files and env vars (port remaps are automatic now)
  - old: 'path_style_buckets = false'
    new: 'path_style_buckets = true'
overrides:                # shallow merge into generated services (null deletes key)
  redis-master:
    image: redis:7-alpine
    command: ["redis-server", "--requirepass", "$secret:redis:redis-password"]
    volumes: ["$volume_root/redis:/data"]
    environment: null
services:                 # custom services added to compose (not from K8s)
  minio-init:
    image: quay.io/minio/mc:latest
    restart: on-failure
    entrypoint: ["/bin/sh", "-c"]
    command:
      - mc alias set local http://minio:9000 $secret:minio:rootUser $secret:minio:rootPassword
        && mc mb --ignore-existing local/revolt-uploads
```

- `$secret:<name>:<key>` — placeholders in `overrides` and `services` values, resolved from K8s Secret manifests at generation time. `null` values in overrides delete the key.
- `$volume_root` — placeholder in `overrides` and `services` values, resolved to the `volume_root` config value. Keeps all paths relative to a single configurable root.
- `caddy_email` — optional. If set, generates a global Caddy block `{ email <value> }` for automatic HTTPS certificate provisioning.

### Tested with

- Synthetic multi-doc YAML (Deployment, StatefulSet, ConfigMap, Secret, Service, Ingress, HPA, CronJob)
- Real `helmfile template` output from `~/stoat-platform` (`helmfile -e local template --output-dir /tmp/h2c-rendered` then `--from-dir`)
- Real `helmfile template` output from `~/suite-helmfile` (larger helmfile, ~16 charts)
- `docker compose config` validates generated output for both projects

## Out of scope (MVP)

CronJobs, sidecars (warning only — takes `containers[0]`), resource limits/requests, HPA, PDB, RBAC, ServiceAccounts, NetworkPolicies, probes→healthcheck.

## Recent fixes

- **Named ports** — K8s Service `targetPort` can be a string (e.g. `http`). Now resolved to numeric via container port definitions.
- **Secret base64 decoding** — K8s `Secret.data` values are base64-encoded. Now decoded before injecting into compose `environment:`. Handles both `data` (base64) and `stringData` (plain).
- **First-run auto-exclude** — When `helmfile2compose.yaml` doesn't exist, auto-excludes K8s-only workloads (matching `cert-manager`, `ingress`, `reflector` in name) and warns that manual review is needed.
- **Ingress port resolution** — Ingress backends reference Service ports, but compose talks directly to containers. Now resolves the full chain: Service port → targetPort → containerPort (e.g. livekit Service port 80 → named targetPort `http` → containerPort 7880).
- **ConfigMap/Secret volume mounts** — ConfigMaps and Secrets referenced as volumes are now generated as files under `configmaps/<name>/` and `secrets/<name>/`, then bind-mounted (with `subPath` and `items` support). Deduplicates across services (e.g. revolt-toml mounted by 8 services, generated once).
- **K8s DNS rewriting** — `<svc>.<ns>.svc.cluster.local` automatically rewritten to `<svc>` in env var values and generated ConfigMap files. Compose service names already match K8s service names.
- **Ingress path rewrite** — `haproxy.org/path-rewrite` and `nginx.ingress.kubernetes.io/rewrite-target` annotations are translated to Caddy `uri strip_prefix` directives in the Caddyfile.
- **Config versioning** — `helmfile2compose.yaml` now includes `helmfile2ComposeVersion: v1` and a repo URL in the header comment.
- **Service overrides** — `overrides:` section in config for shallow-merging into generated services. `null` deletes a key. Useful for replacing bitnami images with vanilla ones.
- **Custom services** — `services:` section for adding non-K8s services (e.g. one-shot init containers like `minio-init`). Combined with `restart: on-failure` for retry-until-ready pattern.
- **$secret references** — `$secret:<name>:<key>` placeholders in overrides and custom services, resolved from K8s Secret manifests at generation time.
- **String replacements** — `replacements:` section for global find/replace in generated ConfigMap/Secret files and env vars. Still useful for non-port rewrites (e.g. `path_style_buckets`).
- **restart: always** — default for all generated services.
- **volume_root** — configurable base path for host volumes (default `./data`). Bare `host_path` names are prefixed with it. Auto-discovered PVCs default to `host_path: <pvc_name>`. `$volume_root` placeholder resolved in overrides and custom services.
- **Service alias resolution** — K8s Services whose name differs from the workload (e.g. `keycloak-keycloakx-http` → `keycloak-keycloakx`) are automatically rewritten in env vars, Caddyfile upstreams, and configmap files. ExternalName services (e.g. `docs-media` → minio) are resolved through the alias chain. No `networks.default.aliases` generated — compatible with nerdctl compose.
- **Automatic port remapping** — K8s Services remap ports (e.g. port 80 → targetPort 8080). URLs with implicit ports (`http://svc` = port 80) or explicit K8s Service ports are automatically rewritten to use the actual container port. Eliminates manual `replacements` for port mismatches (keycloak 80→8080, livekit 80→7880, etc.).
- **Job conversion** — K8s Jobs (migrations, superuser creation, etc.) converted to compose services with `restart: on-failure`. One-shot retry-until-ready pattern. K8s-only Jobs (cert-manager, ingress CRDs) should be excluded.
- **K8s `$(VAR)` resolution** — Kubelet resolves `$(VAR_NAME)` in container command/args from the container's env vars. Now inlined at generation time.
- **Shell `$VAR` escaping for compose** — Shell variable references (`$VAR`) in command/entrypoint are escaped to `$$VAR` in compose YAML, preventing compose from interpreting them as host variable substitution. The container's shell expands them at runtime from its own environment.

- **Complexity refactoring** — Major functions refactored to reduce cyclomatic complexity: resolve_env (E→A), convert (D→B), _convert_volume_mounts (D→B), _build_alias_map (C→B), _build_service_port_map (C→B), _generate_secret_files (C→A), convert_workload (C→C), write_caddyfile (C→B). Shared helpers extracted (_index_workloads, _match_selector). Dead code removed (_get_network_aliases). Average complexity: B(8.59) → B(5.98).
- **Lint cleanup** — Constants grouped at top of file. Unused function parameters removed. Broad `except Exception` narrowed to specific types. All file writes use explicit `encoding="utf-8"`. Pylint 9.56/10, pyflakes clean.
- **Wildcard excludes** — `exclude:` patterns now support wildcards via `fnmatch` (e.g. `meet-celery-*`). Exact names still work.
- **replicas: 0 auto-skip** — Workloads with `spec.replicas: 0` are automatically skipped with a warning (e.g. disabled AI services in meet). No need to manually exclude them.
- **Init container conversion** — K8s init containers converted to separate compose services with `restart: on-failure`, named `{workload}-init-{container-name}`. Same brute-force retry pattern as Jobs. Shares pod-level volumes (PVC, ConfigMap, Secret) but not emptyDir (anonymous volumes, not shared between compose services).
- **volumeClaimTemplates** — StatefulSet VCTs now registered as PVC volumes. Previously only `persistentVolumeClaim` references in pod volumes were handled.
- **PVC pre-registration** — PVCs from both regular volumes and VCTs are pre-registered in config before workload conversion. Fixes first-run where PVCs were discovered too late and rendered as named volumes instead of host_path bind mounts.
- **Automatic fix-permissions** — Non-root containers (`securityContext.runAsUser > 0`) with PVC bind mounts automatically generate a `fix-permissions` service (busybox, root, `chown -R <uid>`) in compose.yml. No manual config needed. Fixes Bitnami images (PostgreSQL UID 1001, Redis UID 1001, MongoDB UID 1001) failing with `permission denied` on host-mounted data directories.

## Known gaps / next steps

- **S3 virtual-hosted style** — AWS SDK defaults to virtual-hosted bucket URLs (`bucket.host:port`). Compose DNS can't resolve dotted aliases. Fix app-side with `force_path_style` / `path_style_buckets = true`, then use a `replacement` to flip the value.
- **ConfigMap/Secret name collisions** — the manifest index is flat (no namespace). If two CMs share a name across namespaces with different content, last-parsed wins. Not a problem for reflector (same content by definition).
