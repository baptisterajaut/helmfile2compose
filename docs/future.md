# Future

Ideas that are too good (or too cursed) to forget but not urgent enough to implement now.

## Converter abstraction ("The Moldavian Scam gets a green card") [^1]

[^1]: "Moldavian Scam" (arnaque moldave) is a French Hearthstone community reference to pro player Torlk (a.k.a. "Jérémy Torlkany"), famous for pulling off improbably lucky plays in tournaments. Not a comment on Moldova.

### Problem

Custom CRDs (`Keycloak`, `KeycloakRealmImport`, Zalando `postgresql`, etc.) are skipped with a warning. For stacks that rely on operators, this means the most important services are missing from the compose output.

### The half-measure (Moldavian Scam)

CRD converters translate operator CRDs into synthetic standard K8s manifests (Deployment/Job), then the existing pipeline handles them. A `Keycloak` CR becomes a fake Deployment, a `KeycloakRealmImport` becomes a fake Job.

Problem: the scam stays moldavian. CRD modules depend on the built-in converter internals. Adding a new CRD means knowing how to forge a Deployment dict that the main code will accept. Fragile, undocumented contract.

### The real move (abstraction)

Refactor ALL kinds into converters behind the same interface. Built-in kinds (DaemonSet, Deployment, Job, StatefulSet, Ingress, Service, ConfigMap, Secret, PVC) and CRDs share the same protocol — no second-class citizens.

```python
class Converter(Protocol):
    kinds: list[str]

    def convert(self, manifests: list[dict], ctx: ConvertContext) -> ConvertResult:
        """Produces compose services, generated files, or both.
        ctx.kind tells which kind triggered the call (e.g. Job vs Deployment)."""
        ...
```

```
K8s manifests
    | parse + classify by kind
    | dispatch to converters (built-in or CRD, same interface)
    v
compose.yml + Caddyfile
```

CRD converters output compose services directly, not synthetic K8s manifests. No forgery, no two-pass pipeline, no reliance on internal Deployment dict format.

### Built-in converters (same file or extracted)

- `WorkloadConverter` — kinds: DaemonSet, Deployment, Job, StatefulSet. All flatten identically to compose services. The converter sets `restart: on-failure` for Jobs, `restart: always` for others (kind available in `ConvertContext`).
- `IngressConverter` — kinds: Ingress. Caddyfile blocks.
- `ServiceConverter` — kinds: Service. Hostname rewriting, alias resolution, port remapping.
- `ConfigSecretConverter` — kinds: ConfigMap, Secret. Inline env resolution + file generation.
- `PVCConverter` — kinds: PersistentVolumeClaim. Volume entries.

### CRD converters (`converters/` in repo, extras via `--extra-converters-dir`)

- `keycloak.py` — kinds: Keycloak, KeycloakRealmImport. Produces a Keycloak compose service (image from `spec.image`, DB env from `spec.db`, `--import-realm` flag) + realm JSON files mounted into `/opt/keycloak/data/import/`.
- Future: Zalando PostgreSQL, Strimzi Kafka, etc. Anyone writes ~50 lines of Python.

### OOP bonus

Currently each kind's conversion logic is a branch in big functions. Moving to classes reduces cyclomatic complexity and makes the code navigable. The CRD module system is a natural extension, not a bolted-on afterthought.

### Why not now → why soon

Single file simplicity is a feature, but two real CRD converters now justify the refactor:

1. **Keycloak** (`keycloak.py`) — produces a compose service + realm import files. Classic "forge a workload" pattern.
2. **cert-manager + trust-manager** (`certmanager.py`) — produces *no services at all*, only generated files and volume mounts injected into existing services. This proves `ConvertResult` must support heterogeneous outputs.

These two cover both shapes of CRD conversion: "CRD → workload" and "CRD → artifacts consumed by other workloads". The abstraction isn't speculative anymore.

Target: proprietary production helmfile, operators everywhere : Keycloak and cert-manager/trust-manager are the first converters.

## cert-manager + trust-manager converter

### Why this matters

The only compelling reason to author infrastructure as K8s manifests and convert to compose (rather than writing compose directly) is **cert-manager + trust-manager**. Declarative PKI is genuinely painful to set up manually — you declare a self-signed root CA, an intermediate CA signed by it, a ClusterIssuer backed by that intermediate, and then leaf Certificates. trust-manager assembles a Bundle (system CAs + custom CA) into a truststore ConfigMap. All of this is 20 lines of YAML in K8s. In compose, it's a nightmare of `openssl` commands, CA chains, and manual trust store assembly.

### How it works in K8s

1. `Certificate` (self-signed root-ca) → cert-manager creates a `Secret` with ca.crt/tls.crt/tls.key
2. `Certificate` (selfsigned-ca, signed by root-ca, `isCA: true`) → another `Secret`
3. `ClusterIssuer` backed by selfsigned-ca
4. Leaf `Certificate` resources issued by the ClusterIssuer → `Secret` per certificate
5. `Bundle` (trust-manager) → `ConfigMap` containing system CAs + selfsigned-ca
6. Pods mount the cert Secrets and truststore ConfigMap via standard `volumeMount`

### How it flattens

In the h2c model, operators don't exist — we emulate their *output*, not their runtime. cert-manager manifests are already in the `helmfile template` output (currently parsed and silently ignored). The converter:

1. Parses the `Certificate` chain to understand the PKI structure (CA hierarchy, issuers)
2. **Generates the actual PEM files at conversion time** — it's all self-signed, deterministic, no runtime CA needed
3. Parses `Bundle` resources to assemble the truststore (system CAs + custom CAs)
4. Writes certs to `certs/` (or `secrets/`), truststore to `configmaps/`
5. Services that reference these Secrets/ConfigMaps via `volumeMount` pick them up through the existing mount mechanism

No init service, no runtime CA, no `step-ca`. The "controller" is helmfile2compose itself. The crypto happens once at conversion time.

### ConvertResult shape

```python
# Keycloak converter returns:
ConvertResult(services={"keycloak": {...}}, files={"realm.json": ...}, mounts={})

# cert-manager converter returns:
ConvertResult(services={}, files={"certs/app-tls/tls.crt": ..., "certs/app-tls/tls.key": ...},
              mounts={"app": ["/path/to/certs/app-tls:/etc/ssl/app:ro"]})
```

This validates the heterogeneous `ConvertResult` design — a converter that produces zero services but injects mounts into other services.

## Ingress annotation abstraction

### Problem

Ingress annotation translation is currently hardcoded to `haproxy.org/*` annotations (path rewrite, backend config) with a fallback to `nginx.ingress.kubernetes.io/rewrite-target`. Any other controller's annotations are silently ignored. Both stoatchat-platform and lasuite-platform use HAProxy exclusively, so this covers all current use cases.

### What could be done

An `IngressRewriter` class (or similar) that defines a contract for translating a controller's annotations into Caddy directives. Each controller gets its own implementation:

```python
class IngressRewriter(Protocol):
    def get_path_rewrite(self, annotations: dict) -> str | None: ...
    def get_backend_options(self, annotations: dict) -> dict: ...
```

Implementations for HAProxy and nginx, dispatched based on `ingressClassName` or annotation prefixes. Adding Traefik/Contour/etc. would be ~20 lines each.

### Why not now

HAProxy is the only controller used by the two platforms this tool was built for. Adding an abstraction for a single implementation is over-engineering. If a third-party fork needs a different controller, the annotation handling is localized enough (~10 lines) to patch directly.

## The emulation boundary

### Three tiers

h2c is converging toward a K8s-to-compose emulator — taking declarative K8s representations and materializing them in a compose runtime. Not everything can cross that bridge.

**Tier 1 — Flattened.** K8s as a declaration language. We consume the intent and materialize it in compose. Workloads, ConfigMaps, Secrets, Services, Ingress, PVCs. Operator CRDs fall here too — we emulate the *output* of the controller (the resources it would create), not the controller itself. cert-manager Certificates become PEM files. Keycloak CRs become compose services. The operator's job happens at conversion time.

**Tier 2 — Ignored.** K8s operational features that don't change what the application *does*, only how K8s manages it. NetworkPolicies, HPA, PDB, RBAC, resource limits/requests, ServiceAccounts. Safe to skip — they affect the cluster's security posture and scaling behavior, not the application's functionality on a single machine.

**Tier 3 — The wall.** Anything that talks to the kube-apiserver at runtime. This is the hard limit. No emulation possible without rebuilding the K8s control plane.

### What's behind the wall

- **Operators themselves** — they watch the API for CRDs, reconcile state. But we don't need to *run* them, just emulate their output (tier 1).
- **Apps that use the K8s API** — service discovery via API instead of DNS, leader election via Lease objects, dynamic config via watching ConfigMaps.
- **Downward API** — pod name, namespace, node name, labels, annotations injected as env vars or files. Technically emulable (we know the service name, can forge values), but requires a runtime service in compose — not just conversion-time file generation. First step onto the slope toward micro-kubelet-in-Python.
- **In-cluster auth** — ServiceAccount tokens, RBAC-gated API calls. No API server, no tokens.

### The slope

> *He who flattens the world into files shall find that each file begets another, and each mount begets a service, until the flattening itself becomes a world — and the disciple realizes he has built not a bridge, but a second shore.*  
> — *Necronomicon, On the Limits of Flattening (probably²)*

The downward API is the canary. It's the first feature that can't be handled at conversion time — it needs a runtime component. If we build it, we're no longer a converter, we're a runtime. That's where h2c stops being a tool and starts being a project that needs its own operator.

Current stance: not in scope. If a workload genuinely needs downward API values to function, it probably needs the real thing.

## Next: the production helmfile

Keycloak + cert-manager/trust-manager are the first two CRD converters. Together they justify the converter abstraction and unlock the production helmfile — operators, SOPS/Age encryption, multi-environment configs. Beyond the barrier of stoat and suite.

The beautiful absurdity: minikube is a real K8s runtime (kubelet, etcd, apiserver) shoved into a container. h2c does the same job with zero runtime — just array manipulation and file traversal. No controllers, no reconciliation loops, no watch/list, no Go. A Python script that reads YAML and writes YAML. The entire "emulation" happens at conversion time and produces static files. The closest thing to a runtime is `openssl` generating certs.

> *Thus spoke the disciple unto the void: "Yog Sa'rath, my hour has come." And the void answered not — for even it knew that some invocations are answered not with knowledge, but with consequences.*  
> — *De Vermis Mysteriis, On the Hubris of the Disciple (don't quote me on this)*
