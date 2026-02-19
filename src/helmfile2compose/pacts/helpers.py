"""Public helper functions available to extensions."""

import base64


def apply_replacements(text: str, replacements: list[dict]) -> str:
    """Apply user-defined string replacements from config."""
    for r in replacements:
        text = text.replace(r["old"], r["new"])
    return text


def _secret_value(secret: dict, key: str) -> str | None:
    """Get a decoded value from a K8s Secret (base64 data or plain stringData)."""
    # stringData is plain text (rare in rendered output, but possible)
    val = (secret.get("stringData") or {}).get(key)
    if val is not None:
        return val
    # data is base64-encoded
    val = (secret.get("data") or {}).get(key)
    if val is not None:
        try:
            return base64.b64decode(val).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return val  # fallback: return raw if decode fails
    return None


def resolve_env(container: dict, configmaps: dict[str, dict], secrets: dict[str, dict],
                workload_name: str, warnings: list[str],
                replacements: list[dict] | None = None,
                service_port_map: dict | None = None) -> list[dict]:
    """Resolve env and envFrom into a flat list of {name: ..., value: ...}."""
    # Import here to avoid circular dependency at module level
    from helmfile2compose.core.env import (
        _resolve_env_entry, _resolve_envfrom, _rewrite_env_values,
    )
    env_vars: list[dict] = []

    for e in (container.get("env") or []):
        resolved = _resolve_env_entry(e, configmaps, secrets, workload_name, warnings)
        if resolved:
            env_vars.append(resolved)

    env_vars.extend(_resolve_envfrom(container.get("envFrom") or [], configmaps, secrets))

    _rewrite_env_values(env_vars, replacements=replacements,
                        service_port_map=service_port_map)
    return env_vars
