"""Environment variable resolution, port remapping, and command conversion."""

import re

from helmfile2compose.pacts.helpers import apply_replacements, _secret_value
from helmfile2compose.core.constants import _K8S_VAR_REF_RE, _URL_BOUNDARY


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
        val = (configmaps.get(ref.get("name", ""), {}).get("data") or {}).get(ref.get("key", ""))
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
    elif "fieldRef" in vf:
        field_path = vf["fieldRef"].get("fieldPath", "")
        if field_path == "status.podIP":
            # In compose, the service name is the container's DNS address.
            svc_name = workload_name.split("/", 1)[-1] if "/" in workload_name else workload_name
            return {"name": name, "value": svc_name}
        warnings.append(
            f"env var '{name}' on {workload_name} uses unsupported fieldRef '{field_path}' — skipped"
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
            for k, v in (cm.get("data") or {}).items():
                env_vars.append({"name": k, "value": v})
        elif "secretRef" in ef:
            sec = secrets.get(ef["secretRef"].get("name", ""), {})
            for k in sec.get("data") or {}:
                val = _secret_value(sec, k)
                if val is not None:
                    env_vars.append({"name": k, "value": val})
    return env_vars


def _postprocess_env(services: dict, ctx) -> None:
    """Apply port remapping and replacements to all services.

    This catches operator-produced services that bypass WorkloadConverter's
    per-env-var rewriting. Safe to run on already-processed services (idempotent).
    """
    for _svc_name, svc in services.items():
        env = svc.get("environment")
        if not env or not isinstance(env, dict):
            continue
        for key in list(env):
            val = env[key]
            if not isinstance(val, str):
                continue
            original = val
            if ctx.service_port_map:
                val = _apply_port_remap(val, ctx.service_port_map)
            if ctx.replacements:
                val = apply_replacements(val, ctx.replacements)
            if val != original:
                env[key] = val


def _rewrite_env_values(env_vars: list[dict],
                        replacements: list[dict] | None = None,
                        service_port_map: dict | None = None) -> None:
    """Apply port remapping and replacements to env values."""
    # Apply transforms: port remap → user replacements
    transforms = []
    if service_port_map:
        transforms.append(lambda v: _apply_port_remap(v, service_port_map))
    if replacements:
        transforms.append(lambda v: apply_replacements(v, replacements))
    for ev in env_vars:
        if ev["value"] is not None and isinstance(ev["value"], str):
            for transform in transforms:
                ev["value"] = transform(ev["value"])


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
