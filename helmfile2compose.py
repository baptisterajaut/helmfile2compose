#!/usr/bin/env python3
"""helmfile2compose — convert helmfile template output to compose.yml + Caddyfile."""

import argparse
import base64
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Workload name patterns auto-excluded on first run (K8s-only infra)
AUTO_EXCLUDE_PATTERNS = ("cert-manager", "ingress", "reflector")

# K8s internal DNS → compose service name
_K8S_DNS_RE = re.compile(
    r'([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.'       # service name (captured)
    r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.'       # namespace (discarded)
    r'svc\.cluster\.local'
)

# Placeholder for referencing secrets in overrides/custom services: $secret:<name>:<key>
_SECRET_REF_RE = re.compile(r'\$secret:([^:]+):([^:}\s]+)')

# K8s kinds we warn about (not convertible to compose)
UNSUPPORTED_KINDS = (
    "CronJob", "HorizontalPodAutoscaler", "PodDisruptionBudget",
)

# K8s kinds silently ignored (no compose equivalent, no useful warning)
IGNORED_KINDS = (
    "Certificate", "ClusterIssuer", "Issuer",
    "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding",
    "CustomResourceDefinition", "IngressClass", "Namespace",
    "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
    "NetworkPolicy", "ServiceAccount",
)

# Kinds we actively convert (used to detect truly unknown kinds)
CONVERTED_KINDS = (
    "Deployment", "StatefulSet", "Job", "ConfigMap", "Secret",
    "Service", "Ingress", "PersistentVolumeClaim",
)

# K8s $(VAR) interpolation in command/args (kubelet resolves these from env vars)
_K8S_VAR_REF_RE = re.compile(r'\$\(([A-Za-z_][A-Za-z0-9_]*)\)')

# Regex boundary for URL port rewriting (matches end-of-string or path/whitespace/quote)
_URL_BOUNDARY = r'''(?=[/\s"']|$)'''


def _is_excluded(name: str, exclude_list: list[str]) -> bool:
    """Check if a workload name matches any exclude pattern (supports wildcards)."""
    return any(fnmatch.fnmatch(name, pattern) for pattern in exclude_list)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def run_helmfile_template(helmfile_dir: str, output_dir: str, environment: str | None = None) -> str:
    """Run helmfile template and return the path to rendered manifests."""
    rendered_dir = os.path.join(output_dir, ".helmfile-rendered")
    os.makedirs(rendered_dir, exist_ok=True)
    # helmfile auto-detects .gotmpl extension
    helmfile_path = os.path.join(helmfile_dir, "helmfile.yaml")
    if not os.path.exists(helmfile_path):
        gotmpl = helmfile_path + ".gotmpl"
        if os.path.exists(gotmpl):
            helmfile_path = gotmpl
    cmd = ["helmfile", "--file", helmfile_path]
    if environment:
        cmd.extend(["--environment", environment])
    cmd.extend(["template", "--output-dir", rendered_dir])
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, check=True)
    return rendered_dir


def parse_manifests(rendered_dir: str) -> dict[str, list[dict]]:
    """Load all YAML files from rendered_dir, classify by kind."""
    manifests: dict[str, list[dict]] = {}
    rendered = Path(rendered_dir)
    for yaml_file in sorted(rendered.rglob("*.yaml")):
        with open(yaml_file) as f:
            for doc in yaml.safe_load_all(f):
                if not doc or not isinstance(doc, dict):
                    continue
                kind = doc.get("kind", "Unknown")
                manifests.setdefault(kind, []).append(doc)
    return manifests


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Load helmfile2compose.yaml or return empty config."""
    if os.path.exists(path):
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}
    cfg.setdefault("helmfile2ComposeVersion", "v1")
    cfg.setdefault("volume_root", "./data")
    cfg.setdefault("volumes", {})
    cfg.setdefault("exclude", [])
    return cfg


def save_config(path: str, config: dict) -> None:
    """Write helmfile2compose.yaml."""
    header = "# Configuration descriptor for https://github.com/baptisterajaut/helmfile2compose\n\n"
    # Ensure version key comes first
    ordered = {"helmfile2ComposeVersion": config.get("helmfile2ComposeVersion", "v1")}
    for k, v in config.items():
        if k != "helmfile2ComposeVersion":
            ordered[k] = v
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.dump(ordered, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def _full_name(manifest: dict) -> str:
    """Return 'Kind/name' string for use in warning messages."""
    meta = manifest.get("metadata", {})
    return f"{manifest.get('kind', '?')}/{meta.get('name', '?')}"


def rewrite_k8s_dns(text: str) -> tuple[str, int]:
    """Replace <svc>.<ns>.svc.cluster.local with just <svc>. Returns (text, count)."""
    result, count = _K8S_DNS_RE.subn(r'\1', text)
    return result, count


def _resolve_host_path(host_path: str, volume_root: str) -> str:
    """Resolve host_path: bare names are prefixed with volume_root, explicit paths kept as-is."""
    if host_path.startswith(("/", "./", "../")):
        return host_path
    return f"{volume_root}/{host_path}"


def _apply_replacements(text: str, replacements: list[dict]) -> str:
    """Apply user-defined string replacements from config."""
    for r in replacements:
        text = text.replace(r["old"], r["new"])
    return text


def _apply_port_remap(text: str, service_port_map: dict) -> str:
    """Rewrite URLs to use container ports instead of K8s Service ports.

    In K8s, Services remap ports (e.g., Service port 80 → container port 8080).
    Compose has no service layer, so URLs must use the actual container port.
    """
    # Group by service name, skip identity mappings and named ports
    remaps: dict[str, list[tuple[int, int]]] = {}
    for (svc_name, svc_port), container_port in service_port_map.items():
        if not isinstance(svc_port, int) or svc_port == container_port:
            continue
        remaps.setdefault(svc_name, []).append((svc_port, container_port))

    for svc_name, port_pairs in remaps.items():
        escaped = re.escape(svc_name)
        for svc_port, container_port in port_pairs:
            # Explicit port: ://host:svc_port or @host:svc_port
            text = re.sub(
                r'(?<=[/@])' + escaped + ':' + str(svc_port) + _URL_BOUNDARY,
                f'{svc_name}:{container_port}',
                text,
            )
            # Implicit port: http://host (80) or https://host (443)
            if svc_port == 80:
                text = re.sub(
                    r'(http://)' + escaped + _URL_BOUNDARY,
                    r'\g<1>' + f'{svc_name}:{container_port}',
                    text,
                )
            elif svc_port == 443:
                text = re.sub(
                    r'(https://)' + escaped + _URL_BOUNDARY,
                    r'\g<1>' + f'{svc_name}:{container_port}',
                    text,
                )

    return text


def _apply_alias_map(text: str, alias_map: dict[str, str]) -> str:
    """Replace K8s Service names with compose service names in hostname positions.

    Matches aliases preceded by :// or @ (URLs, Redis URIs) and followed by
    / : whitespace, quotes, or end-of-string — so only hostnames are affected,
    not substrings like bucket names.
    """
    for alias, target in alias_map.items():
        text = re.sub(
            r'(?<=[/@])'          # preceded by / (in ://) or @
            + re.escape(alias)
            + r'''(?=[/:\s"']|$)''',  # followed by / : whitespace quotes or end
            target,
            text,
        )
    return text


def _resolve_k8s_var_refs(obj, env_dict: dict[str, str]):
    """Replace K8s $(VAR_NAME) references with actual env var values.

    Kubelet resolves $(VAR) in command/args from the container's env vars.
    Compose doesn't do this, so we inline the values at generation time.
    """
    if isinstance(obj, str):
        return _K8S_VAR_REF_RE.sub(lambda m: env_dict.get(m.group(1), m.group(0)), obj)
    if isinstance(obj, list):
        return [_resolve_k8s_var_refs(item, env_dict) for item in obj]
    return obj


def _escape_shell_vars_for_compose(obj):
    """Escape $VAR references in command/entrypoint so compose doesn't interpolate them.

    Compose treats $VAR and ${VAR} as variable substitution from host env / .env file.
    Container commands that use shell $VAR expansion need $$ escaping in compose YAML.
    """
    if isinstance(obj, str):
        return re.sub(r'\$(?=[A-Za-z_{])', '$$', obj)
    if isinstance(obj, list):
        return [_escape_shell_vars_for_compose(item) for item in obj]
    return obj


def _secret_value(secret: dict, key: str) -> str | None:
    """Get a decoded value from a K8s Secret (base64 data or plain stringData)."""
    # stringData is plain text (rare in rendered output, but possible)
    val = secret.get("stringData", {}).get(key)
    if val is not None:
        return val
    # data is base64-encoded
    val = secret.get("data", {}).get(key)
    if val is not None:
        try:
            return base64.b64decode(val).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return val  # fallback: return raw if decode fails
    return None


def _resolve_env_entry(entry: dict, configmaps: dict, secrets: dict,
                       workload_name: str, warnings: list[str]) -> dict | None:
    """Resolve a single K8s env entry (value, configMapKeyRef, or secretKeyRef)."""
    name = entry.get("name", "")
    if "value" in entry:
        return {"name": name, "value": entry["value"]}
    if "valueFrom" not in entry:
        return None
    vf = entry["valueFrom"]
    if "configMapKeyRef" in vf:
        ref = vf["configMapKeyRef"]
        val = configmaps.get(ref.get("name", ""), {}).get("data", {}).get(ref.get("key", ""))
        if val is not None:
            return {"name": name, "value": val}
        warnings.append(
            f"configMapKeyRef '{ref.get('name')}/{ref.get('key')}' "
            f"on {workload_name} could not be resolved"
        )
    elif "secretKeyRef" in vf:
        ref = vf["secretKeyRef"]
        val = _secret_value(secrets.get(ref.get("name", ""), {}), ref.get("key", ""))
        if val is not None:
            return {"name": name, "value": val}
        warnings.append(
            f"secretKeyRef '{ref.get('name')}/{ref.get('key')}' "
            f"on {workload_name} could not be resolved"
        )
    else:
        warnings.append(
            f"env var '{name}' on {workload_name} uses unsupported valueFrom — skipped"
        )
    return None


def _resolve_envfrom(envfrom_list: list, configmaps: dict, secrets: dict) -> list[dict]:
    """Resolve envFrom entries (configMapRef, secretRef) into flat env vars."""
    env_vars: list[dict] = []
    for ef in envfrom_list:
        if "configMapRef" in ef:
            cm = configmaps.get(ef["configMapRef"].get("name", ""), {})
            for k, v in cm.get("data", {}).items():
                env_vars.append({"name": k, "value": v})
        elif "secretRef" in ef:
            sec = secrets.get(ef["secretRef"].get("name", ""), {})
            for k in sec.get("data", {}):
                val = _secret_value(sec, k)
                if val is not None:
                    env_vars.append({"name": k, "value": val})
    return env_vars


def _rewrite_env_values(env_vars: list[dict], workload_name: str, warnings: list[str],
                        replacements: list[dict] | None = None,
                        alias_map: dict[str, str] | None = None,
                        service_port_map: dict | None = None) -> None:
    """Apply DNS rewriting, port remapping, alias resolution, and replacements to env values."""
    # Rewrite K8s internal DNS
    total_rewrites = 0
    for ev in env_vars:
        if ev["value"] is not None and isinstance(ev["value"], str):
            rewritten, count = rewrite_k8s_dns(ev["value"])
            if count:
                ev["value"] = rewritten
                total_rewrites += count
    if total_rewrites:
        warnings.append(
            f"{workload_name}: rewrote {total_rewrites} K8s DNS reference(s) "
            f"(*.svc.cluster.local → service name)"
        )

    # Apply transforms: port remap → alias resolve → user replacements
    transforms = []
    if service_port_map:
        transforms.append(lambda v: _apply_port_remap(v, service_port_map))
    if alias_map:
        transforms.append(lambda v: _apply_alias_map(v, alias_map))
    if replacements:
        transforms.append(lambda v: _apply_replacements(v, replacements))
    for ev in env_vars:
        if ev["value"] is not None and isinstance(ev["value"], str):
            for transform in transforms:
                ev["value"] = transform(ev["value"])


def resolve_env(container: dict, configmaps: dict[str, dict], secrets: dict[str, dict],
                workload_name: str, warnings: list[str],
                replacements: list[dict] | None = None,
                alias_map: dict[str, str] | None = None,
                service_port_map: dict | None = None) -> list[dict]:
    """Resolve env and envFrom into a flat list of {name: ..., value: ...}."""
    env_vars: list[dict] = []

    for e in (container.get("env") or []):
        resolved = _resolve_env_entry(e, configmaps, secrets, workload_name, warnings)
        if resolved:
            env_vars.append(resolved)

    env_vars.extend(_resolve_envfrom(container.get("envFrom") or [], configmaps, secrets))

    _rewrite_env_values(env_vars, workload_name, warnings,
                        replacements=replacements, alias_map=alias_map,
                        service_port_map=service_port_map)
    return env_vars


def _emit_container_warnings(pod_spec: dict, full: str, warnings: list[str]) -> None:
    """Warn about sidecars and init containers that aren't converted."""
    for c in pod_spec.get("containers", [])[1:]:
        warnings.append(f"sidecar container '{c.get('name', '?')}' on {full} ignored — only main container converted")
    for ic in pod_spec.get("initContainers", []):
        warnings.append(f"init container '{ic.get('name', '?')}' on {full} ignored — not supported")


def _convert_command(container: dict, env_dict: dict[str, str]) -> dict:
    """Convert K8s command/args to compose entrypoint/command with variable resolution."""
    result = {}
    if "command" in container:
        resolved = _resolve_k8s_var_refs(container["command"], env_dict)
        result["entrypoint"] = _escape_shell_vars_for_compose(resolved)
    if "args" in container:
        resolved = _resolve_k8s_var_refs(container["args"], env_dict)
        result["command"] = _escape_shell_vars_for_compose(resolved)
    return result


def convert_workload(manifest: dict, configmaps: dict[str, dict], secrets: dict[str, dict],
                     services_by_selector: dict, pvc_names: set, config: dict,
                     warnings: list[str], output_dir: str = ".",
                     generated_cms: set | None = None,
                     generated_secrets: set | None = None,
                     replacements: list[dict] | None = None,
                     alias_map: dict[str, str] | None = None,
                     service_port_map: dict | None = None,
                     restart_policy: str = "always") -> dict | None:
    """Convert a Deployment, StatefulSet, or Job to a docker-compose service definition."""
    meta = manifest.get("metadata", {})
    name = meta.get("name", "unknown")
    full = f"{manifest.get('kind', '?')}/{name}"

    if _is_excluded(name, config.get("exclude", [])):
        return None

    # Skip workloads scaled to zero (e.g. disabled AI services)
    replicas = manifest.get("spec", {}).get("replicas")
    if replicas is not None and replicas == 0:
        warnings.append(f"{full} has replicas: 0 — skipped")
        return None

    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    containers = pod_spec.get("containers", [])
    if not containers:
        warnings.append(f"{full} has no containers — skipped")
        return None

    _emit_container_warnings(pod_spec, full, warnings)
    container = containers[0]
    svc = {"restart": restart_policy}

    if container.get("image"):
        svc["image"] = container["image"]

    # Environment (resolve before command so $(VAR) refs can be inlined)
    env_list = resolve_env(container, configmaps, secrets, full, warnings,
                           replacements=replacements, alias_map=alias_map,
                           service_port_map=service_port_map)
    env_dict = {e["name"]: str(e["value"]) if e["value"] is not None else "" for e in env_list}

    svc.update(_convert_command(container, env_dict))
    if env_dict:
        svc["environment"] = env_dict

    # Ports
    exposed_ports = _get_exposed_ports(meta.get("labels", {}),
                                       container.get("ports", []), services_by_selector)
    if exposed_ports:
        svc["ports"] = exposed_ports

    # Volumes
    svc_volumes = _convert_volume_mounts(
        container.get("volumeMounts") or [], pod_spec.get("volumes") or [],
        pvc_names, config, full, warnings, configmaps=configmaps, secrets=secrets,
        output_dir=output_dir, generated_cms=generated_cms, generated_secrets=generated_secrets,
        replacements=replacements, alias_map=alias_map, service_port_map=service_port_map)
    if svc_volumes:
        svc["volumes"] = svc_volumes

    resources = container.get("resources", {})
    if resources.get("limits") or resources.get("requests"):
        warnings.append(f"resource limits on {full} ignored")

    return {name: svc}


def _resolve_named_port(name: str, container_ports: list) -> int | str:
    """Resolve a named port (e.g. 'http') to its numeric containerPort."""
    for cp in container_ports:
        if cp.get("name") == name:
            return cp["containerPort"]
    return name  # fallback: return as-is if not found


def _get_exposed_ports(workload_labels: dict, container_ports: list,
                       services_by_selector: dict) -> list[str]:
    """Determine which ports to expose based on K8s Service type."""
    ports = []
    for _sel_key, svc_info in services_by_selector.items():
        svc_labels = svc_info.get("selector", {})
        if not svc_labels:
            continue
        if all(workload_labels.get(k) == v for k, v in svc_labels.items()):
            svc_type = svc_info.get("type", "ClusterIP")
            if svc_type in ("NodePort", "LoadBalancer"):
                for sp in svc_info.get("ports", []):
                    target = sp.get("targetPort", sp.get("port"))
                    if isinstance(target, str):
                        target = _resolve_named_port(target, container_ports)
                    node_port = sp.get("nodePort", sp.get("port"))
                    if isinstance(node_port, str):
                        node_port = _resolve_named_port(node_port, container_ports)
                    ports.append(f"{node_port}:{target}")
    return ports



def _index_workloads(manifests: dict) -> list[tuple[dict, str]]:
    """Index workload labels → workload name for Deployments and StatefulSets."""
    result = []
    for kind in ("Deployment", "StatefulSet"):
        for m in manifests.get(kind, []):
            meta = m.get("metadata", {})
            result.append((meta.get("labels", {}), meta.get("name", "")))
    return result


def _match_selector(selector: dict, workloads: list[tuple[dict, str]]) -> str | None:
    """Find the workload name that matches a K8s Service selector."""
    for wl_labels, wl_name in workloads:
        if all(wl_labels.get(k) == v for k, v in selector.items()):
            return wl_name
    return None


def _build_alias_map(manifests: dict, services_by_selector: dict) -> dict[str, str]:
    """Build a map of K8s Service names → compose service names.

    Covers two cases:
    - ClusterIP services whose name differs from the workload they select
    - ExternalName services that alias another service
    """
    alias_map: dict[str, str] = {}
    workloads = _index_workloads(manifests)

    # ClusterIP services whose name differs from the workload
    for svc_name, svc_info in services_by_selector.items():
        selector = svc_info.get("selector", {})
        if not selector:
            continue
        wl_name = _match_selector(selector, workloads)
        if wl_name and svc_name != wl_name:
            alias_map[svc_name] = wl_name

    # ExternalName services: resolve target → compose service name
    known_workloads = {wl_name for _, wl_name in workloads}
    for svc_manifest in manifests.get("Service", []):
        spec = svc_manifest.get("spec", {})
        if spec.get("type") != "ExternalName":
            continue
        svc_name = svc_manifest.get("metadata", {}).get("name", "")
        target = _K8S_DNS_RE.sub(r'\1', spec.get("externalName", ""))
        compose_name = alias_map.get(target, target)
        if compose_name in known_workloads:
            alias_map[svc_name] = compose_name

    return alias_map


def _generate_configmap_files(cm_name: str, cm_data: dict, output_dir: str,
                              generated_cms: set, warnings: list[str],
                              replacements: list[dict] | None = None,
                              alias_map: dict[str, str] | None = None,
                              service_port_map: dict | None = None) -> str:
    """Write ConfigMap data entries as files. Returns the directory path (relative)."""
    rel_dir = os.path.join("configmaps", cm_name)
    abs_dir = os.path.join(output_dir, rel_dir)
    if cm_name not in generated_cms:
        generated_cms.add(cm_name)
        os.makedirs(abs_dir, exist_ok=True)
        for key, value in cm_data.items():
            rewritten, count = rewrite_k8s_dns(str(value))
            if count:
                warnings.append(
                    f"ConfigMap '{cm_name}' key '{key}': rewrote {count} K8s DNS reference(s)"
                )
            if service_port_map:
                rewritten = _apply_port_remap(rewritten, service_port_map)
            if alias_map:
                rewritten = _apply_alias_map(rewritten, alias_map)
            if replacements:
                rewritten = _apply_replacements(rewritten, replacements)
            file_path = os.path.join(abs_dir, key)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(rewritten)
    return f"./{rel_dir}"


def _resolve_secret_keys(secret: dict, items: list | None) -> list[tuple[str, str]]:
    """Return (key, output_filename) pairs for a Secret volume mount."""
    if items:
        keys = [item["key"] for item in items if "key" in item]
    else:
        keys = list(secret.get("data", {}).keys()) + list(secret.get("stringData", {}).keys())
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
                val = _apply_replacements(val, replacements)
            with open(os.path.join(abs_dir, out_name), "w", encoding="utf-8") as f:
                f.write(val)
    return f"./{rel_dir}"


def _build_vol_map(pod_volumes: list) -> dict:
    """Build a map of volume name → volume source from pod spec volumes."""
    vol_map = {}
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
                           alias_map: dict[str, str] | None = None,
                           service_port_map: dict | None = None) -> list[str]:
    """Convert volumeMounts to docker-compose volume strings."""
    vol_map = _build_vol_map(pod_volumes)
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
            cm_dir = _generate_configmap_files(source["name"], cm.get("data", {}),
                                               output_dir, generated_cms, warnings,
                                               replacements=replacements, alias_map=alias_map,
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


def _build_service_port_map(manifests: dict, services_by_selector: dict) -> dict:
    """Build a map of (service_name, service_port) → container_port.

    Ingress backends reference Service ports, but in compose we talk directly
    to containers.  This resolves the chain: service port → targetPort → containerPort.
    """
    # Index workload labels → container ports
    workload_ports: dict[str, list] = {}
    for kind in ("Deployment", "StatefulSet"):
        for m in manifests.get(kind, []):
            name = m.get("metadata", {}).get("name", "")
            containers = m.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
            workload_ports[name] = containers[0].get("ports", []) if containers else []

    workloads = _index_workloads(manifests)
    port_map: dict = {}
    for svc_name, svc_info in services_by_selector.items():
        selector = svc_info.get("selector", {})
        if not selector:
            continue
        wl_name = _match_selector(selector, workloads)
        matched_ports = workload_ports.get(wl_name, []) if wl_name else []

        for sp in svc_info.get("ports", []):
            svc_port_num = sp.get("port")
            target = sp.get("targetPort", svc_port_num)
            if isinstance(target, str):
                target = _resolve_named_port(target, matched_ports)
            port_map[(svc_name, svc_port_num)] = target
            if sp.get("name"):
                port_map[(svc_name, sp["name"])] = target

    return port_map


def _extract_strip_prefix(annotations: dict, path: str) -> str | None:
    """Extract a strip prefix from ingress rewrite annotations."""
    # haproxy.org/path-rewrite: /api/(.*) /\1  →  strip "/api"
    rewrite = annotations.get("haproxy.org/path-rewrite", "")
    if rewrite:
        parts = rewrite.split()
        if len(parts) == 2 and parts[1] in (r"/\1", "/$1"):
            # The prefix is the path without the regex capture group
            prefix = re.sub(r'\(\.?\*\)$', '', parts[0])
            if prefix and prefix != "/":
                return prefix.rstrip("/")
    # nginx.ingress.kubernetes.io/rewrite-target: /$1
    rewrite = annotations.get("nginx.ingress.kubernetes.io/rewrite-target", "")
    if rewrite in ("/$1", r"/\1"):
        prefix = re.sub(r'\(\.?\*\)$', '', path)
        if prefix and prefix != "/":
            return prefix.rstrip("/")
    return None


def convert_ingress(manifest: dict, service_port_map: dict,
                    alias_map: dict[str, str] | None = None) -> list[dict]:
    """Convert Ingress to Caddyfile entries."""
    entries = []
    meta = manifest.get("metadata", {})
    annotations = meta.get("annotations", {})
    spec = manifest.get("spec", {})
    rules = spec.get("rules", [])
    tls_hosts = set()
    for tls in spec.get("tls", []):
        for h in tls.get("hosts", []):
            tls_hosts.add(h)

    for rule in rules:
        host = rule.get("host", "")
        if not host:
            continue
        http = rule.get("http", {})
        for path_entry in http.get("paths", []):
            path = path_entry.get("path", "/")
            backend = path_entry.get("backend", {})
            # Handle both v1 and v1beta1 ingress backend format
            if "service" in backend:
                svc_name = backend["service"].get("name", "")
                port = backend["service"].get("port", {})
                svc_port = port.get("number", port.get("name", 80))
            else:
                svc_name = backend.get("serviceName", "")
                svc_port = backend.get("servicePort", 80)

            # Resolve K8s Service name → compose service name
            compose_name = (alias_map or {}).get(svc_name, svc_name)

            # Resolve to container port (Service port → targetPort → containerPort)
            container_port = service_port_map.get((svc_name, svc_port), svc_port)

            scheme = "https" if host in tls_hosts else "http"
            strip_prefix = _extract_strip_prefix(annotations, path)
            entries.append({
                "host": host,
                "path": path,
                "upstream": f"{compose_name}:{container_port}",
                "scheme": scheme,
                "strip_prefix": strip_prefix,
            })
    return entries


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


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

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
            "selector": svc_spec.get("selector", {}),
            "type": svc_spec.get("type", "ClusterIP"),
            "ports": svc_spec.get("ports", []),
        }
    return configmaps, secrets, services_by_selector


def _apply_overrides(compose_services: dict, config: dict,
                     secrets: dict, warnings: list[str]) -> None:
    """Apply service overrides and custom services from config."""
    volume_root = config.get("volume_root", "./data")
    for svc_name, overrides in config.get("overrides", {}).items():
        if svc_name not in compose_services:
            warnings.append(f"override for '{svc_name}' but no such generated service — skipped")
            continue
        for key, val in overrides.items():
            if val is None:
                compose_services[svc_name].pop(key, None)
            else:
                resolved = _resolve_secret_refs(val, secrets, warnings)
                compose_services[svc_name][key] = _resolve_volume_root(resolved, volume_root)
    for svc_name, svc_def in config.get("services", {}).items():
        if svc_name in compose_services:
            warnings.append(f"custom service '{svc_name}' conflicts with generated service — overwritten")
        resolved = _resolve_secret_refs(svc_def, secrets, warnings)
        compose_services[svc_name] = _resolve_volume_root(resolved, volume_root)


def _emit_kind_warnings(manifests: dict, warnings: list[str]) -> None:
    """Emit warnings for unsupported and unknown manifest kinds."""
    for kind in UNSUPPORTED_KINDS:
        for m in manifests.get(kind, []):
            warnings.append(f"{kind} '{m.get('metadata', {}).get('name', '?')}' not supported")
    known = set(CONVERTED_KINDS) | set(UNSUPPORTED_KINDS) | set(IGNORED_KINDS)
    for kind, items in manifests.items():
        if kind not in known:
            warnings.append(f"unknown kind '{kind}' ({len(items)} manifest(s)) — skipped")


def convert(manifests: dict[str, list[dict]], config: dict,
            output_dir: str = ".") -> tuple[dict, list[dict], list[str]]:
    """Main conversion: returns (compose_services, caddy_entries, warnings)."""
    warnings: list[str] = []
    compose_services: dict = {}
    caddy_entries: list[dict] = []
    pvc_names: set[str] = set()
    generated_cms: set[str] = set()
    generated_secrets: set[str] = set()

    configmaps, secrets, services_by_selector = _index_manifests(manifests)
    replacements = config.get("replacements", [])
    alias_map = _build_alias_map(manifests, services_by_selector)
    service_port_map = _build_service_port_map(manifests, services_by_selector)

    # Shared kwargs for convert_workload calls
    wl_kwargs = {"configmaps": configmaps, "secrets": secrets,
                  "services_by_selector": services_by_selector,
                  "pvc_names": pvc_names, "config": config, "warnings": warnings,
                  "output_dir": output_dir, "generated_cms": generated_cms,
                  "generated_secrets": generated_secrets, "replacements": replacements,
                  "alias_map": alias_map, "service_port_map": service_port_map}

    # Convert workloads (Deployments, StatefulSets, Jobs)
    for kind in ("Deployment", "StatefulSet"):
        for m in manifests.get(kind, []):
            result = convert_workload(m, **wl_kwargs)
            if result:
                compose_services.update(result)
    for m in manifests.get("Job", []):
        result = convert_workload(m, **wl_kwargs, restart_policy="on-failure")
        if result:
            compose_services.update(result)

    # Convert Ingresses
    for m in manifests.get("Ingress", []):
        caddy_entries.extend(convert_ingress(m, service_port_map,
                                             alias_map=alias_map))
    if caddy_entries:
        compose_services["caddy"] = {
            "image": "caddy:2-alpine", "restart": "always",
            "ports": ["80:80", "443:443"],
            "volumes": ["./Caddyfile:/etc/caddy/Caddyfile:ro",
                        "caddy-data:/data", "caddy-config:/config"],
        }

    # Register discovered PVCs
    for pvc in sorted(pvc_names):
        if pvc not in config["volumes"]:
            config["volumes"][pvc] = {"host_path": pvc}

    _emit_kind_warnings(manifests, warnings)
    _apply_overrides(compose_services, config, secrets, warnings)

    return compose_services, caddy_entries, warnings


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_compose(services: dict, config: dict, output_dir: str,
                  compose_file: str = "compose.yml") -> None:
    """Write compose file."""
    compose = {}
    if config.get("name"):
        compose["name"] = config["name"]
    compose["services"] = services

    # Add top-level named volumes
    named_volumes = {}
    for vol_name, vol_cfg in config.get("volumes", {}).items():
        if isinstance(vol_cfg, dict) and "host_path" not in vol_cfg:
            named_volumes[vol_name] = vol_cfg
    if "caddy" in services:
        named_volumes["caddy-data"] = None
        named_volumes["caddy-config"] = None
    if named_volumes:
        compose["volumes"] = named_volumes

    path = os.path.join(output_dir, compose_file)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Generated by helmfile2compose — do not edit manually\n")
        yaml.dump(compose, f, default_flow_style=False, sort_keys=False)
    print(f"Wrote {path}", file=sys.stderr)


def _write_caddy_host_block(f, host: str, host_entries: list[dict]) -> None:
    """Write a single Caddy host block (specific paths first, catch-all last)."""
    specific = [e for e in host_entries if e["path"] and e["path"] != "/"]
    catchall = [e for e in host_entries if not e["path"] or e["path"] == "/"]
    f.write(f"{host} {{\n")
    for entry in specific:
        f.write(f"\thandle {entry['path']}* {{\n")
        if entry.get("strip_prefix"):
            f.write(f"\t\turi strip_prefix {entry['strip_prefix']}\n")
        f.write(f"\t\treverse_proxy {entry['upstream']}\n")
        f.write("\t}\n")
    for entry in catchall:
        f.write(f"\treverse_proxy {entry['upstream']}\n")
    f.write("}\n\n")


def write_caddyfile(entries: list[dict], output_dir: str,
                    config: dict | None = None) -> None:
    """Write Caddyfile."""
    if not entries:
        return

    path = os.path.join(output_dir, "Caddyfile")
    by_host: dict[str, list[dict]] = {}
    for e in entries:
        by_host.setdefault(e["host"], []).append(e)

    with open(path, "w", encoding="utf-8") as f:
        f.write("# Generated by helmfile2compose — do not edit manually\n\n")
        caddy_email = (config or {}).get("caddy_email")
        if caddy_email:
            f.write(f"{{\n\temail {caddy_email}\n}}\n\n")
        for host, host_entries in by_host.items():
            _write_caddy_host_block(f, host, host_entries)
    print(f"Wrote {path}", file=sys.stderr)


def emit_warnings(warnings: list[str]) -> None:
    """Print all warnings to stderr."""
    for w in warnings:
        print(f"⚠ {w}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Convert helmfile template output to compose.yml + Caddyfile"
    )
    parser.add_argument(
        "--helmfile-dir", default=".",
        help="Directory containing helmfile.yaml (default: .)",
    )
    parser.add_argument(
        "-e", "--environment",
        help="Helmfile environment to use (e.g. local, production)",
    )
    parser.add_argument(
        "--from-dir",
        help="Skip helmfile template, read pre-rendered YAML from this directory",
    )
    parser.add_argument(
        "--output-dir", default=".",
        help="Where to write compose.yml, Caddyfile, and helmfile2compose.yaml (default: .)",
    )
    parser.add_argument(
        "--compose-file", default="compose.yml",
        help="Name of the generated compose file (default: compose.yml)",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Step 1: get rendered manifests
    if args.from_dir:
        rendered_dir = args.from_dir
    else:
        rendered_dir = run_helmfile_template(args.helmfile_dir, args.output_dir, args.environment)

    # Step 2: parse
    manifests = parse_manifests(rendered_dir)
    kinds = {k: len(v) for k, v in manifests.items()}
    print(f"Parsed manifests: {kinds}", file=sys.stderr)

    # Step 3: load config
    config_path = os.path.join(args.output_dir, "helmfile2compose.yaml")
    first_run = not os.path.exists(config_path)
    config = load_config(config_path)

    # On first run, set project name from source directory
    if first_run:
        source_dir = args.helmfile_dir if not args.from_dir else args.from_dir
        config["name"] = os.path.basename(os.path.realpath(source_dir))

    # On first run, auto-exclude K8s-only workloads
    if first_run:
        for kind in ("Deployment", "StatefulSet"):
            for m in manifests.get(kind, []):
                name = m.get("metadata", {}).get("name", "")
                if any(p in name for p in AUTO_EXCLUDE_PATTERNS):
                    if name not in config["exclude"]:
                        config["exclude"].append(name)
        if config["exclude"]:
            print(
                f"Auto-excluded K8s-only workloads: {', '.join(config['exclude'])}",
                file=sys.stderr,
            )

    # Step 4: convert
    services, caddy_entries, warnings = convert(manifests, config, output_dir=args.output_dir)

    # Step 5: emit warnings
    emit_warnings(warnings)

    # Step 6: write outputs
    if not services:
        print("No services generated — nothing to write.", file=sys.stderr)
        sys.exit(1)

    write_compose(services, config, args.output_dir, compose_file=args.compose_file)
    write_caddyfile(caddy_entries, args.output_dir, config=config)
    save_config(config_path, config)
    print(f"Wrote {config_path}", file=sys.stderr)

    if first_run:
        print(
            "\n⚠ First run — helmfile2compose.yaml was created and likely needs manual edits.\n"
            "  Review exclude list, volume mappings, and re-run.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
