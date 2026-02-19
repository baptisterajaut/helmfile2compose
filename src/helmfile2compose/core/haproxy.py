"""HAProxy ingress rewriter — built-in, structurally identical to external rewriters."""

import re

from helmfile2compose.pacts.ingress import IngressRewriter, get_ingress_class, resolve_backend


def _resolve_backend_ssl(annotations: dict) -> dict:
    """Extract backend SSL settings from haproxy.org annotations."""
    backend_ssl = annotations.get("haproxy.org/server-ssl", "").lower() == "true"
    if not backend_ssl:
        return {"scheme": "http", "server_ca_secret": "", "server_sni": ""}
    server_ca_ref = annotations.get("haproxy.org/server-ca", "")
    return {
        "scheme": "https",
        "server_ca_secret": server_ca_ref.split("/")[-1] if server_ca_ref else "",
        "server_sni": annotations.get("haproxy.org/server-sni", "") if server_ca_ref else "",
    }


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
                backend = resolve_backend(path_entry, manifest, ctx)
                ssl = _resolve_backend_ssl(annotations)
                entries.append({
                    "host": host,
                    "path": path_entry.get("path", "/"),
                    "upstream": backend["upstream"],
                    "strip_prefix": self._extract_strip_prefix(annotations),
                    **ssl,
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
