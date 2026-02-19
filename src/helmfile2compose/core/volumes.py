"""Volume mount conversion — PVC, ConfigMap, Secret, emptyDir."""

import os

from helmfile2compose.pacts.helpers import apply_replacements, _secret_value
from helmfile2compose.core.env import _apply_port_remap


def _build_vol_map(pod_volumes: list,
                    volume_claim_templates: list | None = None) -> dict:
    """Build a map of volume name → volume source from pod spec volumes.

    For StatefulSets, volumeClaimTemplates define implicit PVC volumes
    whose name matches the template metadata.name.
    """
    vol_map = {}
    for vct in (volume_claim_templates or []):
        vname = vct.get("metadata", {}).get("name", "")
        if vname:
            vol_map[vname] = {"type": "pvc", "claim": vname}
    for v in pod_volumes:
        vname = v.get("name", "")
        if "persistentVolumeClaim" in v:
            vol_map[vname] = {"type": "pvc", "claim": v["persistentVolumeClaim"].get("claimName", "")}
        elif "configMap" in v:
            vol_map[vname] = {"type": "configmap", "name": v["configMap"].get("name", ""),
                              "items": v["configMap"].get("items")}
        elif "secret" in v:
            vol_map[vname] = {"type": "secret", "name": v["secret"].get("secretName", ""),
                              "items": v["secret"].get("items")}
        elif "emptyDir" in v:
            vol_map[vname] = {"type": "emptydir"}
        else:
            vol_map[vname] = {"type": "unknown"}
    return vol_map


def _resolve_host_path(host_path: str, volume_root: str) -> str:
    """Resolve host_path: bare names are prefixed with volume_root, explicit paths kept as-is."""
    if host_path.startswith(("/", "./", "../")):
        return host_path
    return f"{volume_root}/{host_path}"


def _convert_pvc_mount(claim: str, mount_path: str, pvc_names: set,
                       config: dict, warnings: list[str]) -> str:
    """Convert a PVC volume mount to a compose volume string."""
    pvc_names.add(claim)
    vol_cfg = config.get("volumes", {}).get(claim)
    if vol_cfg and isinstance(vol_cfg, dict) and "host_path" in vol_cfg:
        resolved = _resolve_host_path(vol_cfg["host_path"], config.get("volume_root", "./data"))
        return f"{resolved}:{mount_path}"
    if vol_cfg is not None:
        return f"{claim}:{mount_path}"
    warnings.append(f"PVC '{claim}' has no mapping in helmfile2compose.yaml — add it manually")
    return f"{claim}:{mount_path}"


def _generate_configmap_files(cm_name: str, cm_data: dict, output_dir: str,
                              generated_cms: set, warnings: list[str],
                              replacements: list[dict] | None = None,
                              service_port_map: dict | None = None) -> str:
    """Write ConfigMap data entries as files. Returns the directory path (relative)."""
    rel_dir = os.path.join("configmaps", cm_name)
    abs_dir = os.path.join(output_dir, rel_dir)
    if cm_name not in generated_cms:
        generated_cms.add(cm_name)
        os.makedirs(abs_dir, exist_ok=True)
        for key, value in cm_data.items():
            rewritten = str(value)
            if service_port_map:
                rewritten = _apply_port_remap(rewritten, service_port_map)
            if replacements:
                rewritten = apply_replacements(rewritten, replacements)
            file_path = os.path.join(abs_dir, key)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(rewritten)
    return f"./{rel_dir}"


def _resolve_secret_keys(secret: dict, items: list | None) -> list[tuple[str, str]]:
    """Return (key, output_filename) pairs for a Secret volume mount."""
    if items:
        keys = [item["key"] for item in items if "key" in item]
    else:
        keys = list((secret.get("data") or {}).keys()) + list((secret.get("stringData") or {}).keys())
    result = []
    for key in keys:
        out_name = key
        if items:
            for item in items:
                if item.get("key") == key and "path" in item:
                    out_name = item["path"]
                    break
        result.append((key, out_name))
    return result


def _generate_secret_files(sec_name: str, secret: dict, items: list | None,
                           output_dir: str, generated_secrets: set,
                           warnings: list[str],
                           replacements: list[dict] | None = None) -> str:
    """Write Secret data entries as files. Returns the directory path (relative)."""
    rel_dir = os.path.join("secrets", sec_name)
    abs_dir = os.path.join(output_dir, rel_dir)
    if sec_name not in generated_secrets:
        generated_secrets.add(sec_name)
        os.makedirs(abs_dir, exist_ok=True)
        for key, out_name in _resolve_secret_keys(secret, items):
            val = _secret_value(secret, key)
            if val is None:
                warnings.append(f"Secret '{sec_name}' key '{key}' could not be decoded — skipped")
                continue
            if replacements:
                val = apply_replacements(val, replacements)
            with open(os.path.join(abs_dir, out_name), "w", encoding="utf-8") as f:
                f.write(val)
    return f"./{rel_dir}"


def _convert_data_mount(data_dir: str, vm: dict) -> str:
    """Build a bind-mount string for a configmap/secret directory, with optional subPath."""
    mount_path = vm.get("mountPath", "")
    sub_path = vm.get("subPath")
    if sub_path:
        return f"{data_dir}/{sub_path}:{mount_path}:ro"
    return f"{data_dir}:{mount_path}:ro"


def _convert_volume_mounts(volume_mounts: list, pod_volumes: list, pvc_names: set,
                           config: dict, workload_name: str, warnings: list[str],
                           configmaps: dict | None = None, secrets: dict | None = None,
                           output_dir: str = ".", generated_cms: set | None = None,
                           generated_secrets: set | None = None,
                           replacements: list[dict] | None = None,
                           service_port_map: dict | None = None,
                           volume_claim_templates: list | None = None) -> list[str]:
    """Convert volumeMounts to docker-compose volume strings."""
    vol_map = _build_vol_map(pod_volumes, volume_claim_templates)
    result = []
    for vm in volume_mounts:
        source = vol_map.get(vm.get("name", ""), {})
        mount_path = vm.get("mountPath", "")
        vol_type = source.get("type")

        if vol_type == "pvc":
            result.append(_convert_pvc_mount(source["claim"], mount_path, pvc_names, config, warnings))
        elif vol_type == "emptydir":
            result.append(mount_path)
        elif vol_type == "configmap" and configmaps is not None:
            cm = configmaps.get(source["name"])
            if cm is None:
                warnings.append(f"ConfigMap '{source['name']}' referenced by {workload_name} not found")
                continue
            cm_dir = _generate_configmap_files(source["name"], cm.get("data") or {},
                                               output_dir, generated_cms, warnings,
                                               replacements=replacements,
                                               service_port_map=service_port_map)
            result.append(_convert_data_mount(cm_dir, vm))
        elif vol_type == "secret" and secrets is not None:
            sec = secrets.get(source["name"])
            if sec is None:
                warnings.append(f"Secret '{source['name']}' referenced by {workload_name} not found")
                continue
            sec_dir = _generate_secret_files(source["name"], sec, source.get("items"),
                                             output_dir, generated_secrets, warnings,
                                             replacements=replacements)
            result.append(_convert_data_mount(sec_dir, vm))

    return result
