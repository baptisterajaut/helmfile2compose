# h2c-core

![vibe coded](https://img.shields.io/badge/vibe-coded-ff69b4)
![python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB)
![heresy: 9/10](https://img.shields.io/badge/heresy-9%2F10-8b0000)
![deity: Yog Sa'rath](https://img.shields.io/badge/deity-Yog%20Sa'rath-8b0000)
![public domain](https://img.shields.io/badge/license-public%20domain-brightgreen)

*The core converter script for [helmfile2compose](https://github.com/helmfile2compose). Patient zero.*

This is where it started — a single Python script, born from the unholy request to make Kubernetes run without Kubernetes. It worked. That was the worst possible outcome. From this aberration, an [entire ecosystem](https://github.com/helmfile2compose) grew: a package manager, CRD extensions, documentation — a temple built for the sole purpose of dismantling a greater and more beautiful one.

Core of the problem: feed it Kubernetes manifests (from `helmfile template`, `helm template`, `kustomize build`, whatever produced them) and it will spit out a `compose.yml` and a `Caddyfile`. Not Kubernetes-in-Docker — no cluster, no kubelet, no shim. Plain `docker compose up`.

## Quick start

Download `helmfile2compose.py` from the [latest release](https://github.com/helmfile2compose/h2c-core/releases/latest).

```bash
# Convert from helmfile
python3 helmfile2compose.py --helmfile-dir ~/my-platform -e compose --output-dir .

# Or from any K8s manifests
python3 helmfile2compose.py --from-dir /tmp/rendered --output-dir .

docker compose up -d
```

If your stack uses CRDs (Keycloak, cert-manager, trust-manager), grab the extension `.py` files from their repos, drop them in a directory, and pass `--extensions-dir` to the script. For managing extensions and automating downloads, see [h2c-manager](https://github.com/helmfile2compose/h2c-manager).

## Requirements

- Python 3.10+
- `pyyaml`
- `helmfile` + `helm` (only if rendering from helmfile directly)

## What it converts

| K8s kind | Compose equivalent |
|----------|-------------------|
| Deployment / StatefulSet / DaemonSet | `services:` (image, env, command, volumes, ports) |
| Job | `services:` with `restart: on-failure` |
| ConfigMap / Secret | Inline `environment:` + generated files for volume mounts |
| Service | Hostname/alias/port rewriting |
| Ingress | Caddy `reverse_proxy` (auto-TLS, path routing, backend SSL) |
| PVC / volumeClaimTemplates | Host-path bind mounts |

Init containers, sidecars, fix-permissions services, and hostname truncation are handled automatically.

CRDs (Keycloak, cert-manager, trust-manager) are handled by [external extensions](https://helmfile2compose.github.io/extensions/) via `--extensions-dir`.

## Output files

- `compose.yml` — services, volumes
- `Caddyfile` — reverse proxy config from Ingress manifests
- `helmfile2compose.yaml` — persistent config (volumes, excludes, overrides)
- `configmaps/` / `secrets/` — generated files from volume mounts

## Documentation

Full docs at [helmfile2compose.github.io](https://helmfile2compose.github.io).

## Related repos

| Repo | Description |
|------|-------------|
| [h2c-manager](https://github.com/helmfile2compose/h2c-manager) | Package manager + extension registry |
| [helmfile2compose.github.io](https://github.com/helmfile2compose/helmfile2compose.github.io) | Documentation site |
| [h2c-provider-keycloak](https://github.com/helmfile2compose/h2c-provider-keycloak) | Keycloak CRD provider |
| [h2c-converter-cert-manager](https://github.com/helmfile2compose/h2c-converter-cert-manager) | cert-manager CRD converter |
| [h2c-converter-trust-manager](https://github.com/helmfile2compose/h2c-converter-trust-manager) | trust-manager CRD converter |
| [h2c-provider-servicemonitor](https://github.com/helmfile2compose/h2c-provider-servicemonitor) | Prometheus & ServiceMonitor CRD provider |
| [h2c-transform-flatten-internal-urls](https://github.com/helmfile2compose/h2c-transform-flatten-internal-urls) | Strip aliases, rewrite FQDNs to short names |
| [h2c-rewriter-nginx](https://github.com/helmfile2compose/h2c-rewriter-nginx) | Nginx ingress annotation rewriter |
| [h2c-rewriter-traefik](https://github.com/helmfile2compose/h2c-rewriter-traefik) | Traefik ingress annotation rewriter (POC) |

## License

Public domain.
