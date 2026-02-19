"""Ingress rewriter base class and public helpers for extensions."""

from helmfile2compose.core.constants import _WELL_KNOWN_PORTS
from helmfile2compose.pacts.types import ConvertContext


class IngressRewriter:
    """Base class for ingress annotation rewriters.

    Subclass to support a specific ingress controller. Each rewriter
    translates controller-specific annotations into Caddy entries.
    """
    name: str = ""
    priority: int = 100

    def match(self, manifest: dict, ctx: ConvertContext) -> bool:
        """Return True if this rewriter handles this Ingress manifest."""
        return False

    def rewrite(self, manifest: dict, ctx: ConvertContext) -> list[dict]:
        """Convert one Ingress manifest to Caddy entries.

        Each entry dict must have: host, path, upstream, scheme.
        Optional: server_ca_secret, server_sni, strip_prefix, extra_directives.
        extra_directives is a list of raw Caddy directive strings.
        """
        return []


def get_ingress_class(manifest: dict,
                      ingress_types: dict[str, str] | None = None) -> str:
    """Extract the ingress class from a manifest (spec or annotation).

    If *ingress_types* is provided, custom class names are resolved to
    canonical rewriter names (e.g. ``haproxy-internal`` → ``haproxy``).
    """
    spec = manifest.get("spec") or {}
    cls = spec.get("ingressClassName", "")
    if not cls:
        cls = ((manifest.get("metadata") or {}).get("annotations") or {}).get(
            "kubernetes.io/ingress.class", "")
    cls = cls.lower()
    if ingress_types and cls in ingress_types:
        cls = ingress_types[cls].lower()
    return cls


def resolve_backend(path_entry: dict, manifest: dict,
                    ctx: ConvertContext) -> dict:
    """Resolve an Ingress path entry to upstream components.

    Returns a dict with: svc_name, compose_name, container_port,
    upstream (host:port string), ns.
    Handles both v1 and v1beta1 Ingress backend formats.
    """
    ns = manifest.get("metadata", {}).get("namespace", "")
    backend = path_entry.get("backend", {})
    if "service" in backend:
        svc_name = backend["service"].get("name", "")
        port = backend["service"].get("port", {})
        svc_port = port.get("number", port.get("name", 80))
    else:
        svc_name = backend.get("serviceName", "")
        svc_port = backend.get("servicePort", 80)

    compose_name = ctx.alias_map.get(svc_name, svc_name)
    container_port = ctx.service_port_map.get(
        (svc_name, svc_port), svc_port)
    # Resolve well-known named ports that survived the lookup
    if isinstance(container_port, str):
        resolved = _WELL_KNOWN_PORTS.get(container_port)
        if resolved is not None:
            container_port = resolved
        else:
            ctx.warnings.append(
                f"Ingress backend {svc_name}: unresolved named port '{container_port}'")
            container_port = 80

    svc_ns = ctx.services_by_selector.get(
        svc_name, {}).get("namespace", "") or ns
    if svc_ns:
        upstream_host = f"{svc_name}.{svc_ns}.svc.cluster.local"
    else:
        upstream_host = compose_name

    return {
        "svc_name": svc_name,
        "compose_name": compose_name,
        "container_port": container_port,
        "upstream": f"{upstream_host}:{container_port}",
        "ns": svc_ns or ns,
    }
