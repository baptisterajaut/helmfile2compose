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

Refactor ALL kinds into converters behind the same interface. Built-in kinds (Deployment, StatefulSet, DaemonSet, Job, Ingress, Service, ConfigMap, Secret, PVC) and CRDs share the same protocol — no second-class citizens.

```python
class Converter(Protocol):
    kinds: list[str]

    def convert(self, manifests: list[dict], ctx: ConvertContext) -> ConvertResult:
        """Produces compose services, generated files, or both."""
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

- `WorkloadConverter` — kinds: Deployment, StatefulSet, DaemonSet. All flatten identically to compose services.
- `JobConverter` — kinds: Job. Compose service with `restart: on-failure`.
- `IngressConverter` — kinds: Ingress. Caddyfile blocks.
- `ServiceConverter` — kinds: Service. Hostname rewriting, alias resolution, port remapping.
- `ConfigSecretConverter` — kinds: ConfigMap, Secret. Inline env resolution + file generation.
- `PVCConverter` — kinds: PersistentVolumeClaim. Volume entries.

### CRD converters (`converters/` in repo, extras via `--extra-converters-dir`)

- `keycloak.py` — kinds: Keycloak, KeycloakRealmImport. Produces a Keycloak compose service (image from `spec.image`, DB env from `spec.db`, `--import-realm` flag) + realm JSON files mounted into `/opt/keycloak/data/import/`.
- Future: Zalando PostgreSQL, Strimzi Kafka, etc. Anyone writes ~50 lines of Python.

### OOP bonus

Currently each kind's conversion logic is a branch in big functions. Moving to classes reduces cyclomatic complexity and makes the code navigable. The CRD module system is a natural extension, not a bolted-on afterthought.

### Why not now

Single file simplicity is a feature. The refactor is worth doing when there are 2+ real CRD converters to justify it (Keycloak is the first). Init container support is done (generic, didn't require the full abstraction).
