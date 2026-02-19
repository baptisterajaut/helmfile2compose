# helmfile2compose (h2c-core)

Convert `helmfile template` output to `compose.yml` + `Caddyfile`.

Part of the [helmfile2compose](https://github.com/helmfile2compose) org. This repo contains the core converter script only. Related repos:
- [h2c-manager](https://github.com/helmfile2compose/h2c-manager) — package manager + extension registry (`extensions.json`)
- [helmfile2compose.github.io](https://github.com/helmfile2compose/helmfile2compose.github.io) — full documentation site
- Extension repos: [h2c-provider-keycloak](https://github.com/helmfile2compose/h2c-provider-keycloak), [h2c-provider-servicemonitor](https://github.com/helmfile2compose/h2c-provider-servicemonitor), [h2c-converter-cert-manager](https://github.com/helmfile2compose/h2c-converter-cert-manager), [h2c-converter-trust-manager](https://github.com/helmfile2compose/h2c-converter-trust-manager), [h2c-transform-bitnami](https://github.com/helmfile2compose/h2c-transform-bitnami)

## Package structure

Python package under `src/helmfile2compose/` with three layers:

- **`pacts/`** — public contracts for extensions (`ConvertContext`, `ConvertResult`, `IngressRewriter`, helpers). Stable API — extensions import from here (or from `helmfile2compose` directly via re-exports).
- **`core/`** — internal conversion engine (`constants`, `env`, `volumes`, `services`, `workloads`, `ingress`, `extensions`, `convert`). Not public API.
- **`io/`** — input/output (`parsing`, `config`, `output`). Not public API.
- **`cli.py`** — CLI entry point.

The single-file `helmfile2compose.py` is a **build artifact** produced by `build.py` (concat script). It is not committed — CI builds it on tag push and uploads as a release asset. Users and h2c-manager see no change.

```bash
# Development: run from package
PYTHONPATH=src python -m helmfile2compose --from-dir /tmp/rendered --output-dir .

# Build single-file distribution
python build.py
# → helmfile2compose.py (gitignored)

# Validate with testsuite
cd ../h2c-testsuite && ./run-tests.sh --local-core ../h2c-core/helmfile2compose.py
```

Dependency: `pyyaml`.

## Workflow

Lint often: run `pylint src/helmfile2compose/` and `pyflakes src/helmfile2compose/` after any change. Fix real issues (unused imports, actual bugs, f-strings without placeholders). Pylint style warnings (too-many-locals, line-too-long, etc.) are acceptable.

**Null-safe YAML access:** `.get("key", {})` returns `None` when the key exists with an explicit `null` value (Helm conditional blocks). Always use `.get("key") or {}` / `.get("key") or []` for fields that Helm may render as null (`annotations`, `ports`, `initContainers`, `data`, `rules`, `selector`, etc.).

### CLI

```bash
# From helmfile directly (needs helmfile + helm installed)
python3 helmfile2compose.py --helmfile-dir ~/my-platform -e compose --output-dir .

# From pre-rendered manifests (skip helmfile)
python3 helmfile2compose.py --from-dir /tmp/rendered --output-dir .

# With extensions
python3 helmfile2compose.py --helmfile-dir ~/my-platform -e compose \
  --extensions-dir .h2c/extensions --output-dir .
```

Flags: `--helmfile-dir`, `-e`/`--environment`, `--from-dir`, `--output-dir`, `--compose-file`, `--extensions-dir`.

**Doc note:** The primary workflow is `--helmfile-dir` (renders + converts in one step). `--from-dir` is for testing or when the caller controls rendering separately (e.g. `generate-compose.sh` in stoat/suite). Documentation should default to `--helmfile-dir` examples, not two-step `helmfile template` + `--from-dir`.

### What it does

- Parses multi-doc YAML from `helmfile template --output-dir` (recursive `.yaml` scan, malformed YAML skipped with warning)
- Classifies manifests by `kind`
- Converts:
  - **DaemonSet/Deployment/StatefulSet** → compose `services:` (image, env, command, volumes, ports)
  - **Job** → compose `services:` with `restart: on-failure` (migrations, superuser creation, etc.)
  - **ConfigMap/Secret** → resolved inline into `environment:` + generated as files for volume mounts (`configmaps/`, `secrets/`)
  - **Service (ClusterIP)** → hostname rewriting (K8s Service name → compose service name) in env vars, Caddyfile, configmap files
  - **Service (ExternalName)** → resolved through alias chain (e.g. `docs-media` → minio FQDN → `minio`)
  - **Service (NodePort/LoadBalancer)** → `ports:` mapping
  - **Ingress** → Caddy service + Caddyfile blocks (`reverse_proxy`), dispatched to `IngressRewriter` classes by `ingressClassName`. Backend SSL via TLS transport, specific paths before catch-all. `extra_directives` for raw Caddy directives. Built-in: `HAProxyRewriter`.
  - **PVC** → named volumes + `helmfile2compose.yaml` config
- **Init containers** → separate compose services with `restart: on-failure`, named `{workload}-init-{container-name}`
- **Sidecar containers** (`containers[1:]`) → separate compose services with `network_mode: container:<main>` (shared network namespace)
- **Fix-permissions** → auto-generated for non-root containers with PVC bind mounts (`chown -R <uid>`)
- **Hostname truncation** → services >63 chars get explicit `hostname:` to avoid sethostname failures
- Warns on stderr for: resource limits, HPA, CronJob, PDB, unknown kinds
- Silently ignores: RBAC, ServiceAccounts, NetworkPolicies, CRDs (unless claimed by a loaded extension), IngressClass, Webhooks, Namespaces
- Writes `compose.yml` (configurable via `--compose-file`), `Caddyfile` (or `Caddyfile-<project>` when `disableCaddy: true`), `helmfile2compose.yaml`

### External extensions (`--extensions-dir`)

Three extension types, loaded from the same `--extensions-dir`:

- **Converters** — classes with `kinds` and `convert()`. Produce synthetic resources and/or compose services from K8s manifests. Sorted by `priority` (lower = earlier, default 100), inserted before built-in converters. Naming convention: `h2c-converter-*` for resource-only, `h2c-provider-*` for service-producing.
- **Transforms** — classes with `transform(compose_services, caddy_entries, ctx)` and no `kinds`. Post-process the final compose output after alias injection. Sorted by `priority` (default 100).
- **Ingress rewriters** — classes with `name`, `match()`, and `rewrite()`. Translate controller-specific Ingress annotations to Caddy entries. Same `name` replaces built-in. Sorted by `priority` (default 100).

`--extensions-dir` points to a directory of `.py` files (or cloned repos with `.py` files one level deep). The loader detects each type automatically.

Extensions import `ConvertContext`/`ConvertResult`/`IngressRewriter` from `helmfile2compose`. `get_ingress_class(manifest, ingress_types)` and `resolve_backend(path_entry, manifest, ctx)` are public helpers for rewriters. `apply_replacements(text, replacements)` and `resolve_env(container, configmaps, secrets, workload_name, warnings, replacements=None, service_port_map=None)` are also public — available to extensions that need string replacement or env resolution. Available extensions:
- **keycloak** — provider: `Keycloak`, `KeycloakRealmImport` (priority 50)
- **cert-manager** — converter: `Certificate`, `ClusterIssuer`, `Issuer` (priority 10, requires `cryptography`, incompatible with flatten-internal-urls)
- **trust-manager** — converter: `Bundle` (priority 20, depends on cert-manager)
- **servicemonitor** — provider: `Prometheus`, `ServiceMonitor` (priority 60, requires `pyyaml`)
- **flatten-internal-urls** — transform: strip aliases, rewrite FQDNs (priority 200)
- **bitnami** — transform: Bitnami Redis, PostgreSQL, Keycloak workarounds (priority 150)
- **nginx** — ingress rewriter: Nginx annotations (rewrite-target, backend-protocol, CORS, proxy-body-size)
- **traefik** — ingress rewriter: Traefik annotations (router.tls, standard path rules). POC.

Install via h2c-manager: `python3 h2c-manager.py keycloak cert-manager trust-manager servicemonitor flatten-internal-urls bitnami nginx traefik`

### Config file (`helmfile2compose.yaml`)

Persistent, re-runnable. User edits are preserved across runs.

```yaml
helmfile2ComposeVersion: v1
name: my-platform
volume_root: ./data        # prefix for bare host_path names (default: ./data)
caddy_email: admin@example.com  # optional — for Caddy automatic HTTPS
caddy_tls_internal: true   # optional — force Caddy internal CA for all domains
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
replacements:             # string replacements in generated files, env vars, and Caddyfile upstreams
  - old: 'path_style_buckets = false'
    new: 'path_style_buckets = true'
overrides:                # deep merge into generated services (null deletes key)
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
- `$volume_root` — placeholder in `overrides` and `services` values, resolved to the `volume_root` config value.
- `caddy_email` — optional. Generates a global Caddy block `{ email <value> }`.
- `caddy_tls_internal` — optional. Adds `tls internal` to all Caddyfile host blocks.
- `ingressTypes` — optional. Maps custom `ingressClassName` values to canonical rewriter names (e.g. `haproxy-controller-internal: haproxy`). Without this, only exact matches work.
- `disableCaddy: true` — optional, manual only (never auto-generated). Skips Caddy service, writes Ingress rules to `Caddyfile-<project>`.
- `network: <name>` — optional. Overrides the default compose network with an external one.
- `core_version: v2.1.0` — optional. Pins the h2c-core version for h2c-manager (ignored by h2c-core itself).
- `depends: [keycloak, cert-manager==0.1.0, trust-manager]` — optional. Lists extensions for h2c-manager to auto-install (ignored by h2c-core itself).

### Automatic rewrites

- **Network aliases** — each service gets `networks.default.aliases` with K8s FQDN variants (`svc.ns.svc.cluster.local`, `svc.ns.svc`, `svc.ns`). FQDNs resolve natively via compose DNS — no hostname rewriting. Requires Docker Compose (nerdctl does not support network aliases). The `flatten-internal-urls` transform strips aliases and rewrites FQDNs to short names for nerdctl compatibility.
- **Service aliases** — K8s Services whose name differs from the workload get a short alias on the compose service
- **Port remapping** — K8s Service port → container port in URLs and env vars (FQDN variants also matched)
- **Kubelet `$(VAR)`** — resolved from container env vars at generation time
- **Shell `$VAR` escaping** — escaped to `$$VAR` for compose
- **String replacements** — user-defined `replacements:` applied to env vars, ConfigMap files, and Caddyfile upstreams
- **`status.podIP` fieldRef** — resolved to compose service name
- **Post-process env** — port remapping and replacements applied to all services including extension-produced ones (idempotent)

### Tested with

- Synthetic multi-doc YAML (Deployment, StatefulSet, ConfigMap, Secret, Service, Ingress, HPA, CronJob)
- Real `helmfile template` output from `~/stoat-platform` (~15 services)
- Real `helmfile template` output from `~/suite-helmfile` (~16 charts, 22 services + 11 init jobs)
- Real `helmfile template` output from pa-helm-deploy (operators, cert-manager, trust-manager, backend SSL)
- Real `helmfile template` output from mijn-bureau-infra (~30 services, nested helmfiles, Bitnami charts)
- `docker compose config` validates generated output for all projects
- Regression test suite: h2c-testsuite compares pinned reference versions against latest across all extension combos

## Out of scope

CronJobs, resource limits/requests, HPA, PDB, RBAC, ServiceAccounts, NetworkPolicies, probes→healthcheck.

## Known gaps

- **S3 virtual-hosted style** — AWS SDK defaults to virtual-hosted bucket URLs (`bucket.host:port`). Compose DNS can't resolve dotted aliases. Fix app-side with `force_path_style` / `path_style_buckets = true`, then use a `replacement` to flip the value.
- **ConfigMap/Secret name collisions** — the manifest index is flat (no namespace). If two CMs share a name across namespaces with different content, last-parsed wins. Not a problem for reflector (same content by definition).
- **emptyDir sharing** — K8s `emptyDir` volumes shared between init/sidecar containers and the main container are converted to anonymous volumes, not shared in compose. Manual named volume mapping needed.
