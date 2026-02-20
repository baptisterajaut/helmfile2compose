"""PVC indexer — pre-registers PersistentVolumeClaim and workload PVC references."""

from h2c.pacts.types import ConvertResult, IndexerConverter
from h2c.core.constants import WORKLOAD_KINDS
from h2c.core.volumes import _register_pvc


class PVCIndexer(IndexerConverter):
    """Pre-register PVCs in config so volume conversion can resolve host_path on first run."""
    name = "pvc"
    kinds = ["PersistentVolumeClaim"]

    def convert(self, _kind, manifests, ctx):
        # Register explicit PVC manifests
        for m in manifests:
            claim = m.get("metadata", {}).get("name", "")
            _register_pvc(claim, ctx.config, ctx.pvc_names)
        # Scan workload manifests for volumeClaimTemplates and persistentVolumeClaim refs
        for wl_kind in WORKLOAD_KINDS:
            for m in ctx.manifests.get(wl_kind, []):
                spec = m.get("spec") or {}
                for vct in spec.get("volumeClaimTemplates") or []:
                    _register_pvc(vct.get("metadata", {}).get("name", ""),
                                  ctx.config, ctx.pvc_names)
                pod_vols = ((spec.get("template") or {}).get("spec") or {}).get("volumes") or []
                for v in pod_vols:
                    pvc = v.get("persistentVolumeClaim") or {}
                    _register_pvc(pvc.get("claimName", ""), ctx.config, ctx.pvc_names)
        return ConvertResult()
