# Using helmfile2compose with your own project

I'm sorry you're here. Truly. If you're reading this, it means you maintain a helmfile (or at least Helm charts), and someone — a colleague, a client, a mass of disciples — has asked you for a docker-compose. You have exhausted all diplomatic avenues. You have explained that Kubernetes exists for a reason. They do not care. They want `docker compose up` and they want it yesterday.

I've been there. Twice. This tool is the scar tissue.

From now on we will call this script **h2c**, because the concept is already mind-numbing enough — reading the full "helmfile2compose" every three words will certainly not help.

> *He who renders the celestial into the mundane does not ascend — he merely ensures that both realms now share his suffering equally.*  
>
> — *Necronomicon, On the Folly of Downward Translation (probably)*

For the dark and twisted ritual underlying the conversion — what gets converted, how, and what unholy transformations are applied — see [architecture.md](architecture.md).

## Preparing your helmfile

Create a dedicated environment (e.g. `compose`) that disables K8s-only infrastructure. These components have no meaning in compose and will be auto-excluded on first run anyway, but disabling them avoids rendering useless manifests:

```yaml
# environments/compose.yaml
certManager:
  enabled: false
ingress:
  enabled: false
reflector:
  enabled: false
```

Everything else stays enabled — the tool needs to see your Deployments, Services, ConfigMaps, Secrets, and Ingress resources to do its job.

## First run

```bash
python3 helmfile2compose.py --helmfile-dir ~/my-project -e compose --output-dir ./compose
cd ./compose
docker compose up -d
```

On first run, the tool creates `helmfile2compose.yaml` with sensible defaults:
- All PVCs registered as host-path bind mounts under `./data/`
- K8s-only workloads (cert-manager, ingress, reflector) auto-excluded
- Project name derived from the source directory

**Stop here and review `helmfile2compose.yaml`.** You will almost certainly need to:
- Adjust volume paths
- Exclude workloads that make no sense outside K8s (operators, CRD controllers, etc.)
- Add overrides for images that need replacing (e.g. bitnami → vanilla)

See [architecture.md — Config file](architecture.md#config-file-helmfile2composeyaml) for the full reference.

## What works well

- **Deployments, StatefulSets, DaemonSets, Jobs** — converted to compose services with the right image, env, command, volumes, and ports. Init containers and sidecars get their own services.
- **ConfigMaps and Secrets** — resolved inline into environment variables, or generated as files when volume-mounted.
- **Services** — hostname rewriting, alias resolution, port remapping. If your K8s Service remaps port 80 to targetPort 8080, the tool rewrites URLs and env vars automatically.
- **Ingress** — converted to a Caddy reverse proxy with automatic TLS. Path-based routing, host-based routing, catch-all backends.
- **PVCs** — registered in config as bind mounts. `volumeClaimTemplates` (StatefulSets) included.

## What needs manual help

- **CRDs and operators** — Keycloak CRs, Zalando PostgreSQL, Strimzi Kafka, etc. are skipped with a warning. You'll need to add equivalent services manually via the `services:` section in config. A plugin system is planned — see [future.md](future.md).
- **Bitnami images** — often need replacing with vanilla equivalents via `overrides:`. Bitnami images have opinions about environment variables, init scripts, and volume paths that don't always translate well.
- **S3 virtual-hosted style** — compose DNS can't resolve `bucket.minio:9000`. Force path-style in your app config and use a `replacement` if needed.
- **CronJobs** — not converted. Run them externally or use a sleep-loop wrapper (but please don't).

See [limitations.md](limitations.md) for the complete list of what gets lost in translation.

## Ingress annotations

The tool translates Ingress annotations to Caddy directives. **Only two annotation families are supported:**

- **`haproxy.org/*`** — path rewrite (`haproxy.org/path-rewrite`) translated to Caddy `uri strip_prefix`
- **`nginx.ingress.kubernetes.io/rewrite-target`** — same treatment, as a fallback

Any other controller's annotations (Traefik, Contour, Ambassador, etc.) are **silently ignored**. The Ingress `host`, `path`, and `backend` fields are always processed regardless of annotations — you'll get working routing, just no path rewriting or other annotation-driven behavior.

If your project uses a different controller, the annotation handling is localized enough to patch. See [future.md — Ingress annotation abstraction](future.md#ingress-annotation-abstraction) for the hypothetical clean version of this.

## Recommended workflow

1. **One helmfile, two environments.** Keep your K8s environment as-is. Add a `compose` environment that disables cluster-only components. Same charts, same values (mostly), different targets.

2. **Ship a `generate-compose.sh`.** A wrapper script that checks for python & pyyaml, downloads helmfile2compose from a pinned release, runs the conversion, and maybe generates secrets. See stoatchat-platform or lasuite-platform for examples.

3. **Ship a `helmfile2compose.yaml.template`.** Pre-configure excludes, overrides, and volume mappings that are specific to your project. Again, in my projects, the generate script copies it to `helmfile2compose.yaml` on first run. Users then customize their copy.

4. **Pin a release.** Don't point at `main`. The tool's behavior may change between releases (or mutate on its own, I don't know anything at this point).

## The two projects that caused this to exist

- **[stoatchat-platform](https://github.com/baptisterajaut/stoatchat-platform)** — 15 services. The first patient. Worked on the first try, which was the most dangerous outcome.
- **[lasuite-platform](https://github.com/baptisterajaut/lasuite-platform)** — 22 services + 11 init jobs. The second patient. Tentacles started appearing around the volumeClaimTemplates.

Both ship with `generate-compose.sh` and `helmfile2compose.yaml.template`. Reading their setup is probably more useful than anything I could write here.

## Garbage in, garbage out

h2c does **zero validation** of your helmfile output. If your manifests reference a ConfigMap that doesn't exist, a Secret with a missing key, or a Service pointing at a non-existent Deployment — h2c will crash with an ugly Python traceback, not a helpful error message.

This is by design. Error handling for malformed K8s manifests is not h2c's job — it would massively increase complexity for something that `helmfile lint`, `helm template --validate`, and `kubectl apply --dry-run` already do. h2c assumes its input is valid. If it isn't, the consequences are yours.

**Make sure your helmfile works on a real Kubernetes cluster first.** A real runtime — one with an actual apiserver, actual controllers, actual sanity — should have validated the output before h2c ever sees it. h2c is a downstream consumer, not a linter. Fix your helmfile, re-render, re-convert. Actions, consequences.

## Final warning

This tool works. It has been tested on real helmfiles with real users. But it is, fundamentally, an act of desecration — stripping Kubernetes of everything that makes it Kubernetes (scheduling, scaling, self-healing, network policies, RBAC) and leaving behind a flat list of containers. Every edge case you hit is a reminder that you are running something that was designed for orchestration on a machine that has no orchestra — and that the person who asked you for a docker-compose owes you a drink — or the psychiatric bill, whichever comes first.

> *The temple was not translated — it was dismantled, stone by stone, and rebuilt as a shed. The prayers still worked. The architect watched, powerless, as the faithful praised the shed.*  
>
> — *De Vermis Mysteriis, On Unnecessary Simplifications (probably, again)*
