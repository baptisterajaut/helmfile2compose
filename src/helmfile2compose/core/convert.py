"""Main conversion orchestration — convert(), indexing, overrides, fix-permissions."""

from helmfile2compose.pacts.types import ConvertContext
from helmfile2compose.pacts.helpers import _secret_value
from helmfile2compose.core.constants import (
    WORKLOAD_KINDS, UNSUPPORTED_KINDS, IGNORED_KINDS, _INDEXED_KINDS, _SECRET_REF_RE,
)
from helmfile2compose.core.env import _postprocess_env
from helmfile2compose.core.volumes import _resolve_host_path
from helmfile2compose.core.services import (
    _build_alias_map, _build_network_aliases, _build_service_port_map,
)
from helmfile2compose.core.workloads import WorkloadConverter
from helmfile2compose.core.ingress import IngressConverter, _REWRITERS

# Converter instances used by convert() — also drives CONVERTED_KINDS
_CONVERTERS = []
_CONVERTERS.extend([WorkloadConverter(), IngressConverter()])

# Transform instances — post-processing hooks that run after alias injection
_TRANSFORMS = []

# All kinds handled by the converter pipeline
CONVERTED_KINDS = _INDEXED_KINDS | {k for c in _CONVERTERS for k in c.kinds}


def _index_manifests(manifests: dict) -> tuple[dict, dict, dict]:
    """Index ConfigMaps, Secrets, and Services by name for quick lookup."""
    configmaps = {m["metadata"]["name"]: m for m in manifests.get("ConfigMap", [])
                  if "metadata" in m and "name" in m.get("metadata", {})}
    secrets = {m["metadata"]["name"]: m for m in manifests.get("Secret", [])
               if "metadata" in m and "name" in m.get("metadata", {})}
    services_by_selector: dict[str, dict] = {}
    for svc_manifest in manifests.get("Service", []):
        svc_meta = svc_manifest.get("metadata", {})
        svc_spec = svc_manifest.get("spec", {})
        svc_name = svc_meta.get("name", "")
        services_by_selector[svc_name] = {
            "name": svc_name,
            "namespace": svc_meta.get("namespace", ""),
            "selector": svc_spec.get("selector") or {},
            "type": svc_spec.get("type", "ClusterIP"),
            "ports": svc_spec.get("ports") or [],
        }
    return configmaps, secrets, services_by_selector


def _deep_merge(base: dict, overrides: dict) -> None:
    """Recursively merge overrides into base. None values delete keys."""
    for key, val in overrides.items():
        if val is None:
            base.pop(key, None)
        elif isinstance(val, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


def _resolve_volume_root(obj, volume_root: str):
    """Recursively resolve $volume_root placeholders in config values."""
    if isinstance(obj, str):
        return obj.replace("$volume_root", volume_root)
    if isinstance(obj, list):
        return [_resolve_volume_root(item, volume_root) for item in obj]
    if isinstance(obj, dict):
        return {k: _resolve_volume_root(v, volume_root) for k, v in obj.items()}
    return obj


def _resolve_secret_refs(obj, secrets: dict, warnings: list[str]):
    """Recursively resolve $secret:<name>:<key> placeholders in config values."""
    if isinstance(obj, str):
        def _replace(m):  # noqa: E301 — closure for re.sub callback
            """Resolve a single $secret:<name>:<key> match."""
            sec_name, sec_key = m.group(1), m.group(2)
            sec = secrets.get(sec_name)
            if sec is None:
                warnings.append(f"$secret ref: Secret '{sec_name}' not found")
                return m.group(0)
            val = _secret_value(sec, sec_key)
            if val is None:
                warnings.append(f"$secret ref: key '{sec_key}' not found in Secret '{sec_name}'")
                return m.group(0)
            return val
        return _SECRET_REF_RE.sub(_replace, obj)
    if isinstance(obj, list):
        return [_resolve_secret_refs(item, secrets, warnings) for item in obj]
    if isinstance(obj, dict):
        return {k: _resolve_secret_refs(v, secrets, warnings) for k, v in obj.items()}
    return obj


def _apply_overrides(compose_services: dict, config: dict,
                     secrets: dict, warnings: list[str]) -> None:
    """Apply service overrides and custom services from config."""
    volume_root = config.get("volume_root", "./data")
    for svc_name, overrides in config.get("overrides", {}).items():
        if svc_name not in compose_services:
            warnings.append(f"override for '{svc_name}' but no such generated service — skipped")
            continue
        resolved = _resolve_secret_refs(overrides, secrets, warnings)
        resolved = _resolve_volume_root(resolved, volume_root)
        _deep_merge(compose_services[svc_name], resolved)
    for svc_name, svc_def in config.get("services", {}).items():
        if svc_name in compose_services:
            warnings.append(f"custom service '{svc_name}' conflicts with generated service — overwritten")
        resolved = _resolve_secret_refs(svc_def, secrets, warnings)
        compose_services[svc_name] = _resolve_volume_root(resolved, volume_root)


def _generate_fix_permissions(fix_permissions: dict[str, int],
                              config: dict, compose_services: dict) -> None:
    """Generate a fix-permissions service for non-root bind-mounted volumes.

    fix_permissions maps PVC claim names to UIDs. Only PVCs with host_path
    binds (not named volumes) need fixing.
    """
    if not fix_permissions:
        return
    volume_root = config.get("volume_root", "./data")
    by_uid: dict[int, list[str]] = {}
    for claim, uid in sorted(fix_permissions.items()):
        vol_cfg = config.get("volumes", {}).get(claim)
        if vol_cfg and isinstance(vol_cfg, dict) and "host_path" in vol_cfg:
            resolved = _resolve_host_path(vol_cfg["host_path"], volume_root)
            by_uid.setdefault(uid, []).append(resolved)
    if not by_uid:
        return
    chown_cmds = []
    volumes = []
    for uid, paths in sorted(by_uid.items()):
        mount_paths = [f"/fixperm/{i}" for i in range(len(volumes), len(volumes) + len(paths))]
        chown_cmds.append(f"chown -R {uid} {' '.join(mount_paths)}")
        for host_path, mount_path in zip(paths, mount_paths):
            volumes.append(f"{host_path}:{mount_path}")
    compose_services["fix-permissions"] = {
        "image": "busybox", "restart": "no", "user": "0",
        "command": ["sh", "-c", " && ".join(chown_cmds)],
        "volumes": volumes,
    }


def _emit_kind_warnings(manifests: dict, warnings: list[str]) -> None:
    """Emit warnings for unsupported and unknown manifest kinds."""
    for kind in UNSUPPORTED_KINDS:
        for m in manifests.get(kind, []):
            warnings.append(f"{kind} '{m.get('metadata', {}).get('name', '?')}' not supported")
    known = set(CONVERTED_KINDS) | set(UNSUPPORTED_KINDS) | set(IGNORED_KINDS)
    for kind, items in manifests.items():
        if kind not in known:
            warnings.append(f"unknown kind '{kind}' ({len(items)} manifest(s)) — skipped")


def _preregister_pvcs(manifests: dict, config: dict) -> set[str]:
    """Pre-register PVCs in config so _convert_pvc_mount can resolve host_path on first run."""
    pvc_names: set[str] = set()
    for kind in WORKLOAD_KINDS:
        for m in manifests.get(kind, []):
            spec = m.get("spec", {})
            # StatefulSet volumeClaimTemplates
            for vct in spec.get("volumeClaimTemplates", []):
                claim = vct.get("metadata", {}).get("name", "")
                if claim and claim not in config.get("volumes", {}):
                    config.setdefault("volumes", {})[claim] = {"host_path": claim}
                    pvc_names.add(claim)
            # Regular PVC references in pod volumes
            pod_vols = ((spec.get("template") or {}).get("spec") or {}).get("volumes") or []
            for v in pod_vols:
                pvc = v.get("persistentVolumeClaim", {})
                claim = pvc.get("claimName", "")
                if claim and claim not in config.get("volumes", {}):
                    config.setdefault("volumes", {})[claim] = {"host_path": claim}
                    pvc_names.add(claim)
    return pvc_names


def convert(manifests: dict[str, list[dict]], config: dict,
            output_dir: str = ".") -> tuple[dict, list[dict], list[str]]:
    """Main conversion: returns (compose_services, caddy_entries, warnings)."""
    warnings: list[str] = []

    configmaps, secrets, services_by_selector = _index_manifests(manifests)
    replacements = config.get("replacements", [])
    alias_map = _build_alias_map(manifests, services_by_selector)
    service_port_map = _build_service_port_map(manifests, services_by_selector)
    pvc_names = _preregister_pvcs(manifests, config)

    # Build context
    ctx = ConvertContext(
        config=config, output_dir=output_dir,
        configmaps=configmaps, secrets=secrets,
        services_by_selector=services_by_selector,
        alias_map=alias_map, service_port_map=service_port_map,
        replacements=replacements, pvc_names=pvc_names,
        warnings=warnings, generated_cms=set(),
        generated_secrets=set(), fix_permissions={},
    )

    # Dispatch to converters
    compose_services: dict = {}
    caddy_entries: list[dict] = []
    for converter in _CONVERTERS:
        for kind in converter.kinds:
            result = converter.convert(kind, manifests.get(kind, []), ctx)
            compose_services.update(result.services)
            caddy_entries.extend(result.caddy_entries)

    # Post-process all services: port remapping and replacements.
    # Idempotent — safe on services already processed by WorkloadConverter.
    _postprocess_env(compose_services, ctx)

    # Add network aliases so K8s FQDNs resolve via compose DNS
    network_aliases = _build_network_aliases(ctx.services_by_selector, ctx.alias_map)
    for svc_name, svc_aliases in network_aliases.items():
        if svc_name in compose_services and "network_mode" not in compose_services[svc_name]:
            if svc_aliases:
                compose_services[svc_name]["networks"] = {"default": {"aliases": svc_aliases}}

    # Warn for generated services that have no FQDN aliases (missing namespace)
    for svc_name in compose_services:
        if "network_mode" in compose_services[svc_name]:
            continue  # sidecars don't get aliases
        aliases = network_aliases.get(svc_name, [])
        has_fqdn = any(".svc.cluster.local" in a for a in aliases)
        if not has_fqdn and svc_name in ctx.services_by_selector:
            warnings.append(
                f"service '{svc_name}' has no FQDN aliases (namespace unknown) — "
                f"other services referencing it by FQDN will fail to resolve. "
                f"Fix your helmfile: add {{{{ .Release.Namespace }}}} to the "
                f"chart's metadata.namespace, or use --helmfile-dir."
            )

    # Register discovered PVCs
    for pvc in sorted(pvc_names):
        if pvc not in config["volumes"]:
            config["volumes"][pvc] = {"host_path": pvc}

    _generate_fix_permissions(ctx.fix_permissions, config, compose_services)
    _emit_kind_warnings(manifests, warnings)
    _apply_overrides(compose_services, config, secrets, warnings)

    # Linux hostname limit is 63 chars; compose uses the service name as hostname.
    # Set an explicit shorter hostname to avoid sethostname failures.
    for svc_name, svc in compose_services.items():
        if len(svc_name) > 63 and "hostname" not in svc:
            svc["hostname"] = svc_name[:63]

    # Run transforms (post-processing hooks) after all alias injection
    for transform_cls in _TRANSFORMS:
        transform_cls.transform(compose_services, caddy_entries, ctx)

    return compose_services, caddy_entries, warnings
