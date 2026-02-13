# Advanced usage

## Cohabiting with existing infrastructure

Your server already has compose projects running, maybe its own reverse proxy, and you want to drop a helmfile2compose-generated stack into the mix. This is possible, inadvisable, and documented here for the brave.

### The problem

By default, helmfile2compose generates a Caddy service claiming ports 80 and 443. If anything else on the host already binds those ports, it won't start.

### The solution

1. Disable Caddy generation. In `helmfile2compose.yaml`, add:

```yaml
disableCaddy: true
```

This skips the Caddy service in `compose.yml` and writes the Ingress rules to `Caddyfile-<project>` instead of `Caddyfile`.

2. Configure your reverse proxy.

   - **If you already use Caddy** — you're in luck. Merge the contents of `Caddyfile-<project>` into your existing Caddyfile. When the project regenerates, diff the new fragment against your merged version and update accordingly. This will break on upgrades. At some point, actions have consequences.

   - **If you use something else** (nginx, Traefik, HAProxy, ...) — you have chosen poorly (by coming here in the first place), and you'll have to configure your reverse proxy by hand. The `Caddyfile-<project>` is still generated as a reference for which hosts and paths map to which upstream services.

3. Your existing compose projects and the helmfile2compose-generated one must share a Docker network so the reverse proxy can reach every service. In `helmfile2compose.yaml`, add:

```yaml
network: shared-infra
```

This overrides the default compose network with an external one. Create it once with `docker network create shared-infra` (or `nerdctl network create`), and reference the same network in your other compose files. Host port collisions from services that bind directly (livekit UDP ranges, game servers, etc.) are your problem — disable or exclude duplicates.

Note: the `generate-compose.sh` scripts shipped with stoatchat-platform and lasuite-platform check for drift between expected and actual output. Adding `disableCaddy` and `network` to `helmfile2compose.yaml` will trigger drift warnings on every run. This is expected — and deserved.


### Multiple helmfile2compose projects

Good news: running two (or more) helmfile2compose-generated stacks on the same host is no harder than running one alongside existing infrastructure. Apply the same recipe to each project — `disableCaddy: true`, same `network:`, merge the `Caddyfile-*` fragments — and you're done. Each project gets its own `compose.yml` and its own `helmfile2compose.yaml`, completely independent.

Watch out for host port collisions: if both projects expose the same ports directly (e.g. both have a livekit binding UDP ranges, or a game server on 25565), only one can win. Exclude or disable the duplicate in one of the projects.

### Do NOT use `docker compose -p`

If the project has sidecar containers, `docker compose -p` will break them.

Sidecars use `container_name` and `network_mode: container:<name>` to share their parent's network namespace. The container name is derived from the project name in `helmfile2compose.yaml`. When you override the project name with `-p`, compose generates different container names but the `network_mode` references still point to the original names. The sidecar can't find its parent, and everything fails.

> "To summon the inexplicable and the unspeakable into the same circle
> is to ensure that neither shall depart peaceably."
>
> — *Necronomicon, On Unnatural Affinities (probably)*

To rename a project: edit `name:` in `helmfile2compose.yaml`, delete `compose.yml`, regenerate.

If you want to use `docker compose -p` because it's convenient and you don't need to take everything down and yadda yadda yadda — next time use Kubernetes instead of summoning eldritch horrors, that will indeed be more convenient.

### What this looks like in practice

```
~/my-platform/
  compose.yml              ← no caddy service, external network
  Caddyfile-my-platform    ← ingress rules fragment
  helmfile2compose.yaml    ← disableCaddy: true, network: shared-infra

~/other-stuff/             ← your existing compose projects
  compose.yml              ← same external network
  ...

~/reverse-proxy/           ← you manage this (or your existing one)
  Caddyfile                ← includes rules from Caddyfile-my-platform
```
