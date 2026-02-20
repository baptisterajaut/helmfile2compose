"""Secret indexer — populates ctx.secrets."""

from h2c.pacts.types import ConvertResult, IndexerConverter


class SecretIndexer(IndexerConverter):
    """Index Secret manifests by name for volume/env resolution."""
    name = "secret"
    kinds = ["Secret"]

    def convert(self, _kind, manifests, ctx):
        for m in manifests:
            meta = m.get("metadata") or {}
            name = meta.get("name", "")
            if name:
                ctx.secrets[name] = m
        return ConvertResult()
