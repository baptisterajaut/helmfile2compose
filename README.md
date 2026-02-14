# helmfile2compose

*For when you maintain a helmfile but people keep asking for a docker-compose. I'm pretty sure I now have tentacles on my body*

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-public%20domain-brightgreen)
![Vibe](https://img.shields.io/badge/vibe-coded-ff69b4)
![Deity](https://img.shields.io/badge/deity-Yog%20Sa'rath-black)

Convert Kubernetes manifests to `compose.yml` + `Caddyfile`. Not Kubernetes-in-Docker (kind, k3d, minikube...) - no cluster, no kubelet, no shim. A devolution of the power of Kubernetes into the simplicity of compose: real `docker compose up`, real Caddy, plain stupid containers.

The generated `compose.yml` is a build artifact - never edit it directly. All configuration goes in `helmfile2compose.yaml`; re-run the script to regenerate.

### But why?

I love helmfile. I love Kubernetes. But people keep asking me for a docker-compose for my community projects, and I'm not going to maintain both by hand. There are dozens of tools that go from Compose to Kubernetes ([Kompose](https://github.com/kubernetes/kompose), [Compose Bridge](https://docs.docker.com/compose/bridge/), [Move2Kube](https://move2kube.konveyor.io/), etc.) — that's the "normal" direction. Almost nothing goes the other way, because who would design their deployment in K8s first and then downgrade? Well, me. Using Kubernetes manifests as an intermediate representation to generate a docker-compose is absolutely using an ICBM to kill flies — which is exactly why I find it satisfying.

I vibe-coded this glorious abomination with Claude rather than MAINTAIN A SEPARATE DOCKER-COMPOSE BY HAND. This script should not need to exist. Nobody should have asked me for this. And yet it works.

It fits in ~1300 lines of pure framework-less Python — which is almost certainly more complex than any compose file it will ever generate, and maybe even me. I could never have written this myself; somewhere around the automatic bind-mount permission fixing, I stopped understanding not just the code it was writing, but its explanations of the code it was writing. As far as I know, nobody has ever made a K8s-to-compose converter powerful enough to be useful to anyone other than an insane cultist — and I'm unreasonably proud of that.

> *The disciples beseeched the architect: render thy celestial works in common clay, that we may raise them without knowledge of the heavens. It was heresy. The architect obliged. The temples stood.*
>
> — The Necronomicon, *Prayers That Should Never Have Been Answered* (probably)

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

I named it helmfile2compose because both helmfile and docker-compose share the same purpose: deploying an entire self-contained platform at once. If you're using this script to convert something that isn't self-contained, you are further into the abyss than I ever ventured, and I am certain it will end terribly. Yog Sa'rath, stay away from me.

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
- `Caddyfile` (or `Caddyfile-<project>` when `disableCaddy: true`) -- reverse proxy config derived from Ingress manifests
- `helmfile2compose.yaml` -- persistent config ([reference](docs/architecture.md#config-file-helmfile2composeyaml))
- `configmaps/` -- generated files from ConfigMap volume mounts
- `secrets/` -- generated files from Secret volume mounts

## Documentation

- **[Your project](docs/your-project.md)** — using helmfile2compose with your own helmfile (start here)
- **[Architecture](docs/architecture.md)** — pipeline, conversion table, config file reference, K8s vs Compose differences and gotchas
- **[Usage guide](docs/usage-guide.md)** — day-to-day operations: regenerating, data management, troubleshooting
- **[Limitations](docs/limitations.md)** — what gets lost in translation (and why)
- **[Advanced](docs/advanced.md)** — cohabiting with existing infrastructure, multiple projects, disabling Caddy
- **[Future](docs/future.md)** — CRD converter plugin system, ingress annotation abstraction

## Compatible projects

These are the projects that caused this tool to exist — helmfile was the source of truth, then people asked for a docker-compose. Both ship a `generate-compose.sh` that downloads helmfile2compose from a pinned release, and a `helmfile2compose.yaml` template that handles project-specific gotchas (image overrides, volume mappings, port ranges, etc.).

### [stoatchat-platform](https://github.com/baptisterajaut/stoatchat-platform)

A chat platform (Revolt rebranded) deployed via helmfile: API, events, file server, proxy, web client, MongoDB, Redis, RabbitMQ, MinIO, LiveKit. **15 services running** via helmfile2compose. The chaos is kept somewhat minimal, as it worked well with the first — rather barebones — release.

Notable config: shared `Revolt.toml` ConfigMap across 8 services, bitnami Redis replaced with vanilla via `overrides:`, MinIO bucket init via custom `services:`, S3 path-style via `replacements:`.

### [lasuite-platform](https://github.com/baptisterajaut/lasuite-platform)

A collaborative suite (~16 Helm charts): docs, drive, meet, people, conversations, keycloak, minio, postgresql, redis, livekit. **22 services + 11 init jobs running** via helmfile2compose. Forbidden knowledge has been acquired. There's tentacles appearing already.

Notable config: wildcard excludes, automatic alias resolution across charts, Job conversion for Django migrations, replicas:0 auto-skip for disabled apps.

### An actual production-critical helmfile?

There is one — a real multi-environment helmfile with operators, SOPS encryption, CI/CD pipelines, and all the ceremonies of proper infrastructure. Converting that would require crossing the barrier of humanity (even for Claude). If you dare gaze into that abyss, see [docs/future.md](docs/future.md).

## Code quality

```bash
pylint helmfile2compose.py          # 9.53/10
pyflakes helmfile2compose.py        # clean
radon cc helmfile2compose.py -a -s  # average C (~15), 5 C-rated functions, no D/E/F
```

How the fuck this scores so well is beyond me. Claude probably broke a formula and it overflows somewhere, don't ask me. Good luck maintaining this without an LLM — or when the AI bubble explodes and you have to pay $300/month to talk to one.
