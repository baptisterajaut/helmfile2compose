"""Service indexer — populates ctx.services_by_selector, ctx.alias_map, ctx.service_port_map."""

from h2c.pacts.types import ConvertResult, IndexerConverter
from h2c.core.services import _build_alias_map, _build_service_port_map


class ServiceIndexer(IndexerConverter):
    """Index Service manifests and build alias/port maps."""
    name = "service"
    kinds = ["Service"]

    def convert(self, _kind, manifests, ctx):
        for svc_manifest in manifests:
            svc_meta = svc_manifest.get("metadata") or {}
            svc_spec = svc_manifest.get("spec") or {}
            svc_name = svc_meta.get("name", "")
            ctx.services_by_selector[svc_name] = {
                "name": svc_name,
                "namespace": svc_meta.get("namespace", ""),
                "selector": svc_spec.get("selector") or {},
                "type": svc_spec.get("type", "ClusterIP"),
                "ports": svc_spec.get("ports") or [],
            }
        ctx.alias_map.update(_build_alias_map(ctx.manifests, ctx.services_by_selector))
        ctx.service_port_map.update(
            _build_service_port_map(ctx.manifests, ctx.services_by_selector))
        return ConvertResult()
