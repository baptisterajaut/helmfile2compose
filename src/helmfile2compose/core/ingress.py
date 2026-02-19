"""Ingress conversion — rewriter dispatch, IngressConverter."""

from helmfile2compose.pacts.types import ConvertContext, ConvertResult
from helmfile2compose.pacts.ingress import IngressRewriter
from helmfile2compose.core.haproxy import HAProxyRewriter


class _NullRewriter(IngressRewriter):
    """No-op fallback rewriter — returns empty entries."""
    name = "_null"

    def match(self, manifest, ctx):
        return True

    def rewrite(self, manifest, ctx):
        return []


# Rewriter instances — dispatched by IngressConverter per manifest
_REWRITERS: list[IngressRewriter] = []
_REWRITERS.append(HAProxyRewriter())


def _is_rewriter_class(obj, mod_name):
    """Check if obj is an ingress rewriter class defined in the given module."""
    return (isinstance(obj, type)
            and hasattr(obj, 'name') and isinstance(getattr(obj, 'name', None), str)
            and hasattr(obj, 'match') and callable(obj.match)
            and hasattr(obj, 'rewrite') and callable(obj.rewrite)
            and not hasattr(obj, 'kinds')
            and obj.__module__ == mod_name)


class IngressConverter:
    """Convert Ingress manifests to Caddy service + Caddyfile entries."""
    kinds = ["Ingress"]

    def convert(self, _kind: str, manifests: list[dict], ctx: ConvertContext) -> ConvertResult:
        """Convert all Ingress manifests."""
        entries = []
        for m in manifests:
            rewriter = self._find_rewriter(m, ctx)
            entries.extend(rewriter.rewrite(m, ctx))
        services = {}
        if entries and not ctx.config.get("disableCaddy"):
            volume_root = ctx.config.get("volume_root", "./data")
            caddy_volumes = [
                "./Caddyfile:/etc/caddy/Caddyfile:ro",
                f"{volume_root}/caddy:/data",
                f"{volume_root}/caddy-config:/config",
            ]
            # Mount CA secrets referenced by server-ca annotations
            ca_secrets = {e["server_ca_secret"] for e in entries
                          if e.get("server_ca_secret")}
            for secret_name in sorted(ca_secrets):
                caddy_volumes.append(
                    f"./secrets/{secret_name}"
                    f":/etc/caddy/certs/{secret_name}:ro")
            services["caddy"] = {
                "image": "caddy:2-alpine", "restart": "always",
                "ports": ["80:80", "443:443"],
                "volumes": caddy_volumes,
            }
        return ConvertResult(services=services, caddy_entries=entries)

    @staticmethod
    def _find_rewriter(manifest, ctx):
        """Find the first matching rewriter for an Ingress manifest."""
        for rw in _REWRITERS:
            if rw.match(manifest, ctx):
                return rw
        name = manifest.get("metadata", {}).get("name", "?")
        ctx.warnings.append(f"Ingress '{name}': no matching rewriter, skipped")
        return _NullRewriter()
