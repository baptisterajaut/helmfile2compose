"""Ingress conversion — HAProxy rewriter, IngressConverter, rewriter dispatch."""

import re

from helmfile2compose.pacts.types import ConvertContext, ConvertResult
from helmfile2compose.pacts.ingress import IngressRewriter, get_ingress_class, resolve_backend


class _NullRewriter(IngressRewriter):
    """No-op fallback rewriter — returns empty entries."""
    name = "_null"

    def match(self, manifest, ctx):
        return True

    def rewrite(self, manifest, ctx):
        return []


class HAProxyRewriter(IngressRewriter):
    """Rewrite haproxy.org ingress annotations to Caddy entries."""
    name = "haproxy"

    def match(self, manifest, ctx):
        ingress_types = ctx.config.get("ingressTypes", {})
        cls = get_ingress_class(manifest, ingress_types)
        if cls in ("haproxy", ""):
            return True
        annotations = manifest.get("metadata", {}).get("annotations") or {}
        return any(k.startswith("haproxy.org/") for k in annotations)

    def rewrite(self, manifest, ctx):
        entries = []
        annotations = (manifest.get("metadata") or {}).get("annotations") or {}
        spec = manifest.get("spec") or {}

        for rule in spec.get("rules") or []:
            host = rule.get("host", "")
            if not host:
                continue
            for path_entry in (rule.get("http") or {}).get("paths") or []:
                path = path_entry.get("path", "/")
                backend = resolve_backend(path_entry, manifest, ctx)

                # Backend SSL from haproxy annotations
                backend_ssl = (
                    annotations.get("haproxy.org/server-ssl", "").lower() == "true"
                )
                scheme = "https" if backend_ssl else "http"
                # Backend CA: haproxy.org/server-ca → "namespace/secretName"
                server_ca_ref = annotations.get("haproxy.org/server-ca", "")
                server_ca_secret = ""
                if backend_ssl and server_ca_ref:
                    server_ca_secret = server_ca_ref.split("/")[-1]
                server_sni = ""
                if backend_ssl and server_ca_ref:
                    server_sni = annotations.get("haproxy.org/server-sni", "")

                strip_prefix = self._extract_strip_prefix(annotations)
                entries.append({
                    "host": host,
                    "path": path,
                    "upstream": backend["upstream"],
                    "scheme": scheme,
                    "server_ca_secret": server_ca_secret,
                    "server_sni": server_sni,
                    "strip_prefix": strip_prefix,
                })
        return entries

    @staticmethod
    def _extract_strip_prefix(annotations):
        """Extract strip prefix from haproxy.org/path-rewrite annotation."""
        rewrite = annotations.get("haproxy.org/path-rewrite", "")
        if rewrite:
            parts = rewrite.split()
            if len(parts) == 2 and parts[1] in (r"/\1", "/$1"):
                prefix = re.sub(r'\(\.?\*\)$', '', parts[0])
                if prefix and prefix != "/":
                    return prefix.rstrip("/")
        return None


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
