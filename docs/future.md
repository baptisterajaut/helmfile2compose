# Future

Ideas that are too good (or too cursed) to forget but not urgent enough to implement now.

## The emulation boundary

h2c is converging toward a K8s-to-compose emulator — taking declarative K8s representations and materializing them in a compose runtime. Not everything can cross that bridge.

### Three tiers

**Tier 1 — Flattened.** K8s as a declaration language. We consume the intent and materialize it in compose. Workloads, ConfigMaps, Secrets, Services, Ingress, PVCs. Operator CRDs fall here too — we emulate the *output* of the controller (the resources it would create), not the controller itself. cert-manager Certificates become PEM files. Keycloak CRs become compose services. The operator's job happens at conversion time.

**Tier 2 — Ignored.** K8s operational features that don't change what the application *does*, only how K8s manages it. NetworkPolicies, HPA, PDB, RBAC, resource limits/requests, ServiceAccounts. Safe to skip — they affect the cluster's security posture and scaling behavior, not the application's functionality on a single machine.

**Tier 3 — The wall.** Anything that talks to the kube-apiserver at runtime. This was the hard limit. Then someone built a fake apiserver. Consult the [maritime police most wanted list](https://github.com/baptisterajaut/h2c-api) for details.

### What's behind the wall

- **Operators themselves** — they watch the API for CRDs, reconcile state. But we don't need to *run* them, just emulate their output (tier 1).
- **Apps that use the K8s API** — service discovery via API instead of DNS, leader election via Lease objects, dynamic config via watching ConfigMaps. A suspect matching this description was last seen [here](https://github.com/baptisterajaut/h2c-api).
- **Downward API** — pod name, namespace, node name, labels injected as env vars or files. The same suspect forged these too. Annotations are still at large.
- **In-cluster auth** — ServiceAccount tokens, RBAC-gated API calls. The documents have been falsified. We don't talk about it.

### The slope

> *He who flattens the world into files shall find that each file begets another, and each mount begets a service, until the flattening itself becomes a world — and the disciple realizes he has built not a bridge, but a second shore.*
> — *Necronomicon, On the Limits of Flattening (probably²)*

The downward API is the canary. It's the first feature that can't be handled at conversion time — it needs a runtime component. If we build it, we're no longer a converter, we're a runtime. That's where h2c stops being a tool and starts being a project that needs its own operator.

Current stance: not in scope. If a workload genuinely needs downward API values to function, it probably needs the real thing. For everything else, see the wanted list above.

## The Moldavian Scam goes for the green card [^1]

[^1]: "Moldavian Scam" (arnaque moldave) is a French Hearthstone community reference to pro player Torlk (a.k.a. "Jérémy Torlkany"), famous for pulling off improbably lucky plays in tournaments. Not a comment on Moldova.

Custom CRDs (`Keycloak`, `KeycloakRealmImport`, Zalando `postgresql`, etc.) are skipped with a warning. For stacks that rely on operators, this means the most important services are missing from the compose output.

### The half-measure (regular Moldavian Scam)

CRD converters translate operator CRDs into synthetic standard K8s manifests (Deployment/Job), then the existing pipeline handles them. A `Keycloak` CR becomes a fake Deployment, a `KeycloakRealmImport` becomes a fake Job.

Problem: the scam stays moldavian. CRD modules depend on the built-in converter internals. Adding a new CRD means knowing how to forge a Deployment dict that the main code will accept. Fragile, undocumented contract.

### The real move (operation green card) — partially implemented

The converter abstraction for built-in kinds is now in place. `WorkloadConverter` and `IngressConverter` exist as classes with `kinds` attributes and `convert()` methods, dispatched via a registration loop in `convert()`. `ConvertContext` and `ConvertResult` are dataclasses. `CONVERTED_KINDS` is derived from converter registrations — no separate list to maintain. The interface is duck-typed (no formal `Protocol` yet).

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

Built-in converters:

- `WorkloadConverter` — kinds: DaemonSet, Deployment, Job, StatefulSet — **implemented**
- `IngressConverter` — kinds: Ingress — **implemented**
- `ServiceConverter` — kinds: Service — planned (Services are indexed for alias/port resolution, not dispatched)
- `ConfigSecretConverter` — kinds: ConfigMap, Secret — planned (indexed for env/volume resolution, not dispatched)
- `PVCConverter` — kinds: PersistentVolumeClaim — planned (indexed for volume config, not dispatched)

The remaining three (Service, ConfigMap/Secret, PVC) are consumed as lookup data by WorkloadConverter rather than producing compose output directly. Wrapping them as converters would formalize the indexing step and unify the dispatch, but there's no functional benefit until CRD converters need to participate in the same indexing.

CRD converters (`converters/` in repo, extras via `--extra-converters-dir`) — still future:

- `keycloak.py` — kinds: Keycloak, KeycloakRealmImport. Produces a compose service + realm JSON files.
- `certmanager.py` — kinds: Certificate, ClusterIssuer, Issuer, Bundle. Produces *no services*, only generated cert/truststore files and volume mounts injected into existing services.
- Future: Zalando PostgreSQL, Strimzi Kafka, etc. Anyone writes ~50 lines of Python.

The infrastructure is ready — adding a CRD converter means writing a class with `kinds` and `convert()`, returning a `ConvertResult`. The `ConvertResult` design with `files`/`mounts` fields for cert-manager is still aspirational:

```python
# Keycloak: CRD → workload
ConvertResult(services={"keycloak": {...}}, files={"realm.json": ...}, mounts={})

# cert-manager: CRD → artifacts consumed by other workloads
ConvertResult(services={}, files={"certs/app-tls/tls.crt": ..., "certs/app-tls/tls.key": ...},
              mounts={"app": ["/path/to/certs/app-tls:/etc/ssl/app:ro"]})
```

Both shapes covered: "CRD → workload" and "CRD → artifacts". The abstraction isn't speculative anymore — the dispatch loop and dataclasses exist, CRD converters just need to plug in.

### cert-manager deep dive

The only compelling reason to author infrastructure as K8s manifests and convert to compose (rather than writing compose directly) is **cert-manager + trust-manager**. Declarative PKI is genuinely painful to set up manually — you declare a self-signed root CA, an intermediate CA signed by it, a ClusterIssuer backed by that intermediate, and then leaf Certificates. trust-manager assembles a Bundle (system CAs + custom CA) into a truststore ConfigMap. All of this is 20 lines of YAML in K8s. In compose, it's a nightmare of `openssl` commands, CA chains, and manual trust store assembly.

How it works in K8s:

1. `Certificate` (self-signed root-ca) → cert-manager creates a `Secret` with ca.crt/tls.crt/tls.key
2. `Certificate` (selfsigned-ca, signed by root-ca, `isCA: true`) → another `Secret`
3. `ClusterIssuer` backed by selfsigned-ca
4. Leaf `Certificate` resources issued by the ClusterIssuer → `Secret` per certificate
5. `Bundle` (trust-manager) → `ConfigMap` containing system CAs + selfsigned-ca
6. Pods mount the cert Secrets and truststore ConfigMap via standard `volumeMount`

How it flattens — operators don't exist in h2c, we emulate their *output*. cert-manager manifests are already in the `helmfile template` output (currently silently ignored). The converter:

1. Parses the `Certificate` chain to understand the PKI structure (CA hierarchy, issuers)
2. **Generates the actual PEM files at conversion time** — it's all self-signed, deterministic, no runtime CA needed
3. Parses `Bundle` resources to assemble the truststore (system CAs + custom CAs)
4. Writes certs to `certs/` (or `secrets/`), truststore to `configmaps/`
5. Services that reference these Secrets/ConfigMaps via `volumeMount` pick them up through the existing mount mechanism

No init service, no runtime CA, no `step-ca`. The "controller" is helmfile2compose itself. The crypto happens once at conversion time.

### Caddy TLS trust

cert-manager generates the certs, but Caddy needs to *trust* them. If backend services listen on HTTPS with certs signed by the custom CA, `reverse_proxy https://service:port` fails unless Caddy knows the CA.

**Short-term (no converter abstraction needed):** a dedicated config block in `helmfile2compose.yaml`:

```yaml
caddy:
  trusted_ca: ./certs/selfsigned-ca/ca.crt   # mounted into caddy container
  backend_tls: true                            # reverse_proxy → https:// + tls_trusted_ca_certs
```

The script mounts the CA file into the caddy service (`/etc/caddy/trust/ca.crt:ro`), rewrites `reverse_proxy` upstreams to `https://`, and appends `tls_trusted_ca_certs /etc/caddy/trust/ca.crt` to each block. Same pattern as `caddy_email` — config-driven, no abstraction.

**Long-term (with converter abstraction):** the cert-manager converter emits Caddy hooks in its `ConvertResult` — extra volumes for the caddy service, TLS directives for reverse_proxy blocks. The manual config stays as a fallback/override. `ConvertResult` grows a `caddy` field (volumes, global options, per-upstream directives) that the pipeline merges into the Caddyfile and caddy service definition.

The manual config comes first because it works without the converter abstraction and covers non-cert-manager setups (e.g. pre-existing certs dropped into a directory). The converter hook is the automation layer on top.

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

## The production helmfile

Keycloak + cert-manager/trust-manager are the first two CRD converters. Together they justify the converter abstraction and unlock the production helmfile — operators, SOPS/Age encryption, multi-environment configs. Beyond the barrier of stoat and suite.

The beautiful absurdity: minikube is a real K8s runtime (kubelet, etcd, apiserver) shoved into a container. h2c does the same job with zero runtime — just array manipulation and file traversal. No controllers, no reconciliation loops, no watch/list, no Go. A Python script that reads YAML and writes YAML. The entire "emulation" happens at conversion time and produces static files. The closest thing to a runtime is `openssl` generating certs.

> *Thus spoke the disciple unto the void: "Yog Sa'rath, my hour has come." And the void answered not — for even it knew that some invocations are answered not with knowledge, but with consequences.*  
> — *De Vermis Mysteriis, On the Hubris of the Disciple (don't quote me on this)*
