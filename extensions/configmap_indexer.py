"""ConfigMap indexer — populates ctx.configmaps."""

from h2c.pacts.types import ConvertResult, IndexerConverter


class ConfigMapIndexer(IndexerConverter):
    """Index ConfigMap manifests by name for volume/env resolution."""
    name = "configmap"
    kinds = ["ConfigMap"]

    def convert(self, _kind, manifests, ctx):
        for m in manifests:
            meta = m.get("metadata") or {}
            name = meta.get("name", "")
            if name:
                ctx.configmaps[name] = m
        return ConvertResult()
