#!/usr/bin/env python3
"""helmfile2compose — convert helmfile template output to compose.yml + Caddyfile."""
# pylint: disable=too-many-locals

import argparse
import base64
from dataclasses import dataclass, field
import fnmatch
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class ConvertContext:
    """Shared state passed to all converters during a conversion run."""
    config: dict
    output_dir: str
    configmaps: dict
    secrets: dict
    services_by_selector: dict
    alias_map: dict
    service_port_map: dict
    replacements: list
    pvc_names: set
    warnings: list
    generated_cms: set
    generated_secrets: set
    fix_permissions: dict


@dataclass
class ConvertResult:
    """Output of a single converter."""
    services: dict = field(default_factory=dict)
    caddy_entries: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Workload name patterns auto-excluded on first run (K8s-only infra)
AUTO_EXCLUDE_PATTERNS = ("cert-manager", "ingress", "reflector")

# K8s internal DNS → compose service name
_K8S_DNS_RE = re.compile(
    r'([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.'       # service name (captured)
    r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.'       # namespace (discarded)
    r'svc(?:\.cluster\.local)?'                    # svc[.cluster.local]
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

# K8s kinds that produce compose services (iterated together everywhere)
WORKLOAD_KINDS = ("DaemonSet", "Deployment", "Job", "StatefulSet")

# Kinds indexed during pre-processing (not dispatched to converters)
_INDEXED_KINDS = {"ConfigMap", "Secret", "Service", "PersistentVolumeClaim"}

# Converter instances used by convert() — also drives CONVERTED_KINDS
_CONVERTERS = []  # populated after class definitions (forward reference)

# Transform instances — post-processing hooks that run after alias injection
_TRANSFORMS = []

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

def _helmfile_list_namespaces(helmfile_path: str,
                              environment: str | None = None) -> dict[str, str]:
    """Run ``helmfile list`` and return a release-name → namespace mapping."""
    cmd = ["helmfile", "--file", helmfile_path]
    if environment:
        cmd.extend(["--environment", environment])
    cmd.extend(["list", "--output", "json"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        releases = json.loads(result.stdout)
        return {r["name"]: r.get("namespace", "") for r in releases if r.get("namespace")}
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as exc:
        print(f"⚠ helmfile list failed ({exc.__class__.__name__}), "
              f"namespace inference will rely on manifest metadata only",
              file=sys.stderr)
        return {}


def run_helmfile_template(helmfile_dir: str, output_dir: str,
                          environment: str | None = None) -> tuple[str, dict[str, str]]:
    """Run helmfile template and return (rendered_dir, release_ns_map)."""
    rendered_dir = os.path.join(output_dir, ".helmfile-rendered")
    if os.path.exists(rendered_dir):
        shutil.rmtree(rendered_dir)
    os.makedirs(rendered_dir)
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
    release_ns_map = _helmfile_list_namespaces(helmfile_path, environment)
    return rendered_dir, release_ns_map


def parse_manifests(rendered_dir: str) -> dict[str, list[dict]]:
    """Load all YAML files from rendered_dir, classify by kind.

    Each manifest gets an internal ``_h2c_release_dir`` annotation (the
    first path component relative to *rendered_dir*) so that downstream
    steps can group manifests by helmfile release.
    """
    manifests: dict[str, list[dict]] = {}
    rendered = Path(rendered_dir)
    for yaml_file in sorted(rendered.rglob("*.yaml")):
        # First path component relative to rendered_dir = release directory
        rel = yaml_file.relative_to(rendered)
        release_dir = rel.parts[0] if rel.parts else ""
        try:
            with open(yaml_file) as f:
                for doc in yaml.safe_load_all(f):
                    if not doc or not isinstance(doc, dict):
                        continue
                    doc["_h2c_release_dir"] = release_dir
                    kind = doc.get("kind", "Unknown")
                    manifests.setdefault(kind, []).append(doc)
        except yaml.YAMLError as exc:
            print(f"⚠ Skipping {yaml_file.name}: {exc.__class__.__name__}",
                  file=sys.stderr)
    return manifests


def _extract_release_name(release_dir: str) -> str:
    """Extract the release name from a helmfile output directory name.

    Directory format: ``helmfile.yaml-<hash>-<release-name>`` or just ``<name>``.
    """
    # "helmfile.yaml" prefix is constant, followed by 8-char hex hash
    # e.g. "helmfile.yaml-01df6c56-minio" → "minio"
    prefix = "helmfile.yaml-"
    if release_dir.startswith(prefix):
        rest = release_dir[len(prefix):]
        # Skip the hash part (first segment before '-')
        idx = rest.find("-")
        return rest[idx + 1:] if idx >= 0 else rest
    return release_dir


def _collect_known_namespaces(manifests: dict[str, list[dict]]) -> set[str]:
    """Collect all namespaces seen in manifests (declared + referenced)."""
    known = {m.get("metadata", {}).get("name", "")
             for m in manifests.get("Namespace", [])} - {""}
    for kind_list in manifests.values():
        for m in kind_list:
            ns = m.get("metadata", {}).get("namespace", "")
            if ns:
                known.add(ns)
    return known


def _infer_namespaces(manifests: dict[str, list[dict]],
                      release_ns_map: dict[str, str] | None = None) -> None:
    """Fill missing ``metadata.namespace`` from sibling manifests or *release_ns_map*.

    Strategy (each phase fills gaps left by the previous):
    1. Sibling inference — any manifest in the same release dir that has a namespace
    2. Namespace/release matching — match release name against known namespaces
    3. ``helmfile list`` data — from *release_ns_map* (only when using ``--helmfile-dir``)
    """
    # Single pass: collect release dirs + build sibling namespace map
    all_release_dirs: set[str] = set()
    dir_ns: dict[str, str] = {}
    for kind_list in manifests.values():
        for m in kind_list:
            rd = m.get("_h2c_release_dir", "")
            if rd:
                all_release_dirs.add(rd)
                ns = m.get("metadata", {}).get("namespace", "")
                if ns and rd not in dir_ns:
                    dir_ns[rd] = ns

    # Match unresolved dirs against known namespaces, then helmfile list
    known_ns = _collect_known_namespaces(manifests)
    for rd in all_release_dirs - dir_ns.keys():
        release_name = _extract_release_name(rd)
        if release_name in known_ns:
            dir_ns[rd] = release_name
        elif release_ns_map and release_name in release_ns_map:
            dir_ns[rd] = release_ns_map[release_name]

    # Inject into manifests missing namespace
    for kind_list in manifests.values():
        for m in kind_list:
            if not m.get("metadata", {}).get("namespace", ""):
                rd = m.get("_h2c_release_dir", "")
                if rd in dir_ns:
                    m.setdefault("metadata", {})["namespace"] = dir_ns[rd]


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


def _resolve_host_path(host_path: str, volume_root: str) -> str:
    """Resolve host_path: bare names are prefixed with volume_root, explicit paths kept as-is."""
    if host_path.startswith(("/", "./", "../")):
        return host_path
    return f"{volume_root}/{host_path}"


def apply_replacements(text: str, replacements: list[dict]) -> str:
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
    elif "fieldRef" in vf:
        field = vf["fieldRef"].get("fieldPath", "")
        if field == "status.podIP":
            # In compose, the service name is the container's DNS address.
            svc_name = workload_name.split("/", 1)[-1] if "/" in workload_name else workload_name
            return {"name": name, "value": svc_name}
        warnings.append(
            f"env var '{name}' on {workload_name} uses unsupported fieldRef '{field}' — skipped"
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


def resolve_env(container: dict, configmaps: dict[str, dict], secrets: dict[str, dict],
                workload_name: str, warnings: list[str],
                replacements: list[dict] | None = None,
                service_port_map: dict | None = None) -> list[dict]:
    """Resolve env and envFrom into a flat list of {name: ..., value: ...}."""
    env_vars: list[dict] = []

    for e in (container.get("env") or []):
        resolved = _resolve_env_entry(e, configmaps, secrets, workload_name, warnings)
        if resolved:
            env_vars.append(resolved)

    env_vars.extend(_resolve_envfrom(container.get("envFrom") or [], configmaps, secrets))

    _rewrite_env_values(env_vars, replacements=replacements,
                        service_port_map=service_port_map)
    return env_vars



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


def _get_run_as_user(pod_spec: dict, container: dict) -> int | None:
    """Extract runAsUser from container or pod securityContext (container wins)."""
    for ctx in (container.get("securityContext", {}), pod_spec.get("securityContext", {})):
        uid = ctx.get("runAsUser")
        if uid is not None:
            return int(uid)
    return None


def _build_aux_service(container: dict, pod_spec: dict, label: str,
                       ctx: ConvertContext, base: dict,
                       vcts: list | None = None) -> dict:
    """Build a compose service dict for an init or sidecar container."""
    svc = dict(base)
    if container.get("image"):
        svc["image"] = container["image"]
    env_list = resolve_env(container, ctx.configmaps, ctx.secrets, label, ctx.warnings,
                           replacements=ctx.replacements,
                           service_port_map=ctx.service_port_map)
    env_dict = {e["name"]: str(e["value"]) if e["value"] is not None else ""
                for e in env_list}
    svc.update(_convert_command(container, env_dict))
    if env_dict:
        svc["environment"] = env_dict
    volumes = _convert_volume_mounts(
        container.get("volumeMounts") or [], pod_spec.get("volumes") or [],
        ctx.pvc_names, ctx.config, label, ctx.warnings,
        configmaps=ctx.configmaps, secrets=ctx.secrets,
        output_dir=ctx.output_dir, generated_cms=ctx.generated_cms,
        generated_secrets=ctx.generated_secrets, replacements=ctx.replacements,
        service_port_map=ctx.service_port_map,
        volume_claim_templates=vcts)
    if volumes:
        svc["volumes"] = volumes
    return svc


def _convert_init_containers(pod_spec: dict, name: str, ctx: ConvertContext,
                             vcts: list | None = None) -> dict:
    """Convert init containers to separate compose services with restart: on-failure."""
    result = {}
    for ic in pod_spec.get("initContainers", []):
        ic_name = ic.get("name", "init")
        ic_svc_name = f"{name}-init-{ic_name}"
        if _is_excluded(ic_svc_name, ctx.config.get("exclude", [])):
            continue
        svc = _build_aux_service(ic, pod_spec, f"initContainer/{ic_svc_name}",
                                 ctx, {"restart": "on-failure"}, vcts)
        result[ic_svc_name] = svc
    return result


def _convert_sidecar_containers(pod_spec: dict, name: str, ctx: ConvertContext,
                                 restart_policy: str = "always",
                                 vcts: list | None = None) -> dict:
    """Convert sidecar containers to compose services sharing the main service's network."""
    result = {}
    project = ctx.config.get("name", "")
    cn = f"{project}-{name}" if project else name
    for sc in pod_spec.get("containers", [])[1:]:
        sc_name = sc.get("name", "sidecar")
        sc_svc_name = f"{name}-sidecar-{sc_name}"
        if _is_excluded(sc_svc_name, ctx.config.get("exclude", [])):
            continue
        base = {"restart": restart_policy, "network_mode": f"container:{cn}",
                "depends_on": [name]}
        svc = _build_aux_service(sc, pod_spec, f"sidecar/{sc_svc_name}",
                                 ctx, base, vcts)
        _collect_fix_permissions(pod_spec, sc, ctx.fix_permissions, vcts)
        result[sc_svc_name] = svc
    return result


def _collect_fix_permissions(pod_spec: dict, container: dict,
                             fix_permissions: dict | None,
                             vcts: list | None = None) -> None:
    """Collect PVC claims needing permission fixes for non-root containers."""
    if fix_permissions is None:
        return
    uid = _get_run_as_user(pod_spec, container)
    if not uid or uid <= 0:
        return
    vol_map = _build_vol_map(pod_spec.get("volumes") or [], vcts)
    for vm in container.get("volumeMounts") or []:
        source = vol_map.get(vm.get("name", ""), {})
        if source.get("type") == "pvc":
            fix_permissions[source["claim"]] = uid


class WorkloadConverter:
    """Convert DaemonSet, Deployment, Job, StatefulSet manifests to compose services."""
    kinds = list(WORKLOAD_KINDS)

    def convert(self, kind: str, manifests: list[dict], ctx: ConvertContext) -> ConvertResult:
        """Convert all manifests of the given workload kind."""
        services = {}
        restart = "on-failure" if kind == "Job" else "always"
        for m in manifests:
            result = self._convert_one(m, ctx, restart_policy=restart)
            if result:
                services.update(result)
        return ConvertResult(services=services)

    def _convert_one(self, manifest: dict, ctx: ConvertContext,
                     restart_policy: str = "always") -> dict | None:
        """Convert a single workload manifest to compose service(s)."""
        meta = manifest.get("metadata", {})
        name = meta.get("name", "unknown")
        full = f"{manifest.get('kind', '?')}/{name}"

        if _is_excluded(name, ctx.config.get("exclude", [])):
            return None

        # Skip workloads scaled to zero (e.g. disabled AI services)
        replicas = manifest.get("spec", {}).get("replicas")
        if replicas is not None and replicas == 0:
            ctx.warnings.append(f"{full} has replicas: 0 — skipped")
            return None

        spec = manifest.get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", {})
        vcts = spec.get("volumeClaimTemplates")  # StatefulSet only
        containers = pod_spec.get("containers", [])
        if not containers:
            ctx.warnings.append(f"{full} has no containers — skipped")
            return None

        result = _convert_init_containers(pod_spec, name, ctx, vcts=vcts)
        svc = self._build_service(containers[0], pod_spec, meta, full,
                                  ctx, restart_policy, vcts)
        result[name] = svc

        if len(containers) > 1:
            project = ctx.config.get("name", "")
            cn = f"{project}-{name}" if project else name
            svc["container_name"] = cn
            sidecar_result = _convert_sidecar_containers(
                pod_spec, name, ctx, restart_policy=restart_policy, vcts=vcts)
            result.update(sidecar_result)

        return result

    @staticmethod
    def _build_service(container: dict, pod_spec: dict, meta: dict, full: str,
                       ctx: ConvertContext, restart_policy: str,
                       vcts: list | None) -> dict:
        """Build a compose service dict from a K8s container spec."""
        svc = {"restart": restart_policy}

        if container.get("image"):
            svc["image"] = container["image"]

        # Environment (resolve before command so $(VAR) refs can be inlined)
        env_list = resolve_env(container, ctx.configmaps, ctx.secrets, full, ctx.warnings,
                               replacements=ctx.replacements,
                               service_port_map=ctx.service_port_map)
        env_dict = {e["name"]: str(e["value"]) if e["value"] is not None else ""
                    for e in env_list}

        svc.update(_convert_command(container, env_dict))
        if env_dict:
            svc["environment"] = env_dict

        # Ports
        exposed_ports = _get_exposed_ports(meta.get("labels", {}),
                                           container.get("ports", []),
                                           ctx.services_by_selector)
        if exposed_ports:
            svc["ports"] = exposed_ports

        # Volumes
        svc_volumes = _convert_volume_mounts(
            container.get("volumeMounts") or [], pod_spec.get("volumes") or [],
            ctx.pvc_names, ctx.config, full, ctx.warnings,
            configmaps=ctx.configmaps, secrets=ctx.secrets,
            output_dir=ctx.output_dir,
            generated_cms=ctx.generated_cms, generated_secrets=ctx.generated_secrets,
            replacements=ctx.replacements,
            service_port_map=ctx.service_port_map,
            volume_claim_templates=vcts)
        if svc_volumes:
            svc["volumes"] = svc_volumes

        resources = container.get("resources", {})
        if resources.get("limits") or resources.get("requests"):
            ctx.warnings.append(f"resource limits on {full} ignored")

        _collect_fix_permissions(pod_spec, container, ctx.fix_permissions, vcts)

        return svc


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
    for kind in WORKLOAD_KINDS:
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
                val = apply_replacements(val, replacements)
            with open(os.path.join(abs_dir, out_name), "w", encoding="utf-8") as f:
                f.write(val)
    return f"./{rel_dir}"


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
            cm_dir = _generate_configmap_files(source["name"], cm.get("data", {}),
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


def _build_network_aliases(services_by_selector: dict,
                           alias_map: dict[str, str]) -> dict[str, list[str]]:
    """Build Docker Compose network aliases for each compose service.

    For each K8s Service, resolve its compose service name (via alias_map or
    direct match) and add FQDN aliases (svc.ns.svc.cluster.local, svc.ns.svc,
    svc.ns) plus a short alias if the K8s Service name differs from the compose
    service name.

    Returns {compose_service_name: [alias1, alias2, ...]}.
    """
    aliases: dict[str, list[str]] = {}
    for svc_name, svc_info in services_by_selector.items():
        ns = svc_info.get("namespace", "")
        compose_name = alias_map.get(svc_name, svc_name)
        svc_aliases = aliases.setdefault(compose_name, [])
        # Short alias: K8s Service name if it differs from the compose service
        if svc_name != compose_name and svc_name not in svc_aliases:
            svc_aliases.append(svc_name)
        # FQDN variants (only if namespace is known)
        if ns:
            for fqdn in (f"{svc_name}.{ns}.svc.cluster.local",
                         f"{svc_name}.{ns}.svc",
                         f"{svc_name}.{ns}"):
                if fqdn not in svc_aliases:
                    svc_aliases.append(fqdn)
    return aliases


def _build_service_port_map(manifests: dict, services_by_selector: dict) -> dict:
    """Build a map of (service_name, service_port) → container_port.

    Ingress backends reference Service ports, but in compose we talk directly
    to containers.  This resolves the chain: service port → targetPort → containerPort.
    """
    # Index workload labels → container ports
    workload_ports: dict[str, list] = {}
    for kind in WORKLOAD_KINDS:
        for m in manifests.get(kind, []):
            name = m.get("metadata", {}).get("name", "")
            containers = m.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
            all_ports = []
            for c in containers:
                all_ports.extend(c.get("ports", []))
            workload_ports[name] = all_ports

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

    # Add FQDN variants so _apply_port_remap matches both "svc:80" and
    # "svc.ns.svc.cluster.local:80"
    fqdn_entries: dict = {}
    for (svc_name, svc_port), container_port in port_map.items():
        ns = services_by_selector.get(svc_name, {}).get("namespace", "")
        if not ns:
            continue
        for fqdn in (f"{svc_name}.{ns}.svc.cluster.local",
                     f"{svc_name}.{ns}.svc",
                     f"{svc_name}.{ns}"):
            fqdn_entries[(fqdn, svc_port)] = container_port
    port_map.update(fqdn_entries)

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


def _convert_one_ingress(manifest: dict, service_port_map: dict,
                         alias_map: dict[str, str] | None = None,
                         services_by_selector: dict | None = None) -> list[dict]:
    """Convert a single Ingress manifest to Caddyfile entries."""
    entries = []
    meta = manifest.get("metadata", {})
    annotations = meta.get("annotations", {})
    ns = meta.get("namespace", "")
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

            # Upstream uses FQDN: compose DNS resolves it via network aliases
            svc_ns = (services_by_selector or {}).get(svc_name, {}).get("namespace", "") or ns
            if svc_ns:
                upstream_host = f"{svc_name}.{svc_ns}.svc.cluster.local"
            else:
                upstream_host = compose_name

            # Upstream scheme: detect backend SSL from ingress annotations
            backend_ssl = (
                annotations.get("haproxy.org/server-ssl", "").lower() == "true"
                or annotations.get(
                    "nginx.ingress.kubernetes.io/backend-protocol", ""
                ).upper() == "HTTPS"
            )
            scheme = "https" if backend_ssl else "http"
            # Backend CA: haproxy.org/server-ca → "namespace/secretName"
            server_ca_ref = annotations.get("haproxy.org/server-ca", "")
            server_ca_secret = ""
            if backend_ssl and server_ca_ref:
                # Extract secret name (ignore namespace prefix)
                server_ca_secret = server_ca_ref.split("/")[-1]
            # TLS server name: only set when explicitly specified in annotation
            server_sni = ""
            if backend_ssl and server_ca_ref:
                server_sni = annotations.get("haproxy.org/server-sni", "")
            strip_prefix = _extract_strip_prefix(annotations, path)
            entries.append({
                "host": host,
                "path": path,
                "upstream": f"{upstream_host}:{container_port}",
                "scheme": scheme,
                "server_ca_secret": server_ca_secret,
                "server_sni": server_sni,
                "strip_prefix": strip_prefix,
            })
    return entries


class IngressConverter:
    """Convert Ingress manifests to Caddy service + Caddyfile entries."""
    kinds = ["Ingress"]

    def convert(self, _kind: str, manifests: list[dict], ctx: ConvertContext) -> ConvertResult:
        """Convert all Ingress manifests."""
        entries = []
        for m in manifests:
            entries.extend(_convert_one_ingress(m, ctx.service_port_map,
                                                alias_map=ctx.alias_map,
                                                services_by_selector=ctx.services_by_selector))
        services = {}
        if entries and not ctx.config.get("disableCaddy"):
            volume_root = ctx.config.get("volume_root", "./data")
            caddy_volumes = [
                "./Caddyfile:/etc/caddy/Caddyfile:ro",
                f"{volume_root}/caddy:/data",
                f"{volume_root}/caddy-config:/config",
            ]
            # Mount CA secrets referenced by server-ca annotations
            ca_secrets = {e["server_ca_secret"] for e in entries
                          if e.get("server_ca_secret")}
            for secret_name in sorted(ca_secrets):
                caddy_volumes.append(
                    f"./secrets/{secret_name}"
                    f":/etc/caddy/certs/{secret_name}:ro")
            services["caddy"] = {
                "image": "caddy:2-alpine", "restart": "always",
                "ports": ["80:80", "443:443"],
                "volumes": caddy_volumes,
            }
        return ConvertResult(services=services, caddy_entries=entries)


# Populate converter registry now that classes are defined
_CONVERTERS.extend([WorkloadConverter(), IngressConverter()])
CONVERTED_KINDS = _INDEXED_KINDS | {k for c in _CONVERTERS for k in c.kinds}


def _discover_extension_files(extensions_dir):
    """Find .py files in extensions dir + one level into subdirectories."""
    py_files = []
    for entry in sorted(os.listdir(extensions_dir)):
        full = os.path.join(extensions_dir, entry)
        if entry.startswith(('_', '.')):
            continue
        if entry.endswith('.py') and os.path.isfile(full):
            py_files.append(full)
        elif os.path.isdir(full):
            for sub in sorted(os.listdir(full)):
                sub_full = os.path.join(full, sub)
                if (sub.endswith('.py') and not sub.startswith(('_', '.'))
                        and os.path.isfile(sub_full)):
                    py_files.append(sub_full)
    return py_files


def _is_converter_class(obj, mod_name):
    """Check if obj is a converter class defined in the given module."""
    return (isinstance(obj, type)
            and hasattr(obj, 'kinds') and isinstance(obj.kinds, (list, tuple))
            and hasattr(obj, 'convert') and callable(obj.convert)
            and obj.__module__ == mod_name)


def _is_transform_class(obj, mod_name):
    """Check if obj is a transform class defined in the given module."""
    return (isinstance(obj, type)
            and hasattr(obj, 'transform') and callable(getattr(obj, 'transform'))
            and not hasattr(obj, 'kinds')
            and obj.__module__ == mod_name)


def _load_extensions(extensions_dir):
    """Load converter and transform classes from an extensions directory."""
    converters = []
    transforms = []
    for filepath in _discover_extension_files(extensions_dir):
        parent = str(Path(filepath).parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)
        mod_name = f"h2c_op_{Path(filepath).stem}"
        spec = importlib.util.spec_from_file_location(mod_name, filepath)
        if spec is None or spec.loader is None:
            continue
        try:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"Warning: failed to load {filepath}: {exc}", file=sys.stderr)
            continue
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if _is_converter_class(obj, mod_name):
                converters.append(obj())
            elif _is_transform_class(obj, mod_name):
                transforms.append(obj())

    # Sort by priority (lower = earlier). Default 100.
    converters.sort(key=lambda c: getattr(c, 'priority', 100))
    transforms.sort(key=lambda t: getattr(t, 'priority', 100))
    if converters:
        loaded = ", ".join(
            f"{type(c).__name__} ({', '.join(c.kinds)})" for c in converters)
        print(f"Loaded extensions: {loaded}", file=sys.stderr)
    if transforms:
        loaded = ", ".join(type(t).__name__ for t in transforms)
        print(f"Loaded transforms: {loaded}", file=sys.stderr)
    return converters, transforms


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
            "namespace": svc_meta.get("namespace", ""),
            "selector": svc_spec.get("selector", {}),
            "type": svc_spec.get("type", "ClusterIP"),
            "ports": svc_spec.get("ports", []),
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
            pod_vols = spec.get("template", {}).get("spec", {}).get("volumes") or []
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
    if named_volumes:
        compose["volumes"] = named_volumes

    # External network override
    ext_network = config.get("network")
    if ext_network:
        compose["networks"] = {"default": {"external": True, "name": ext_network}}

    has_sidecars = any("container_name" in s for s in services.values())

    path = os.path.join(output_dir, compose_file)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Generated by helmfile2compose — do not edit manually\n")
        if has_sidecars:
            f.write("# WARNING: Sidecar containers use container_name for network sharing.\n")
            f.write("# Do not use 'docker compose -p' — rename via helmfile2compose.yaml instead.\n")
        yaml.dump(compose, f, default_flow_style=False, sort_keys=False)
    print(f"Wrote {path}", file=sys.stderr)


def _write_caddy_reverse_proxy(f, entry: dict, indent: str = "\t") -> None:
    """Write a reverse_proxy directive, with TLS transport if upstream is HTTPS."""
    scheme = entry.get("scheme", "http")
    upstream = entry["upstream"]
    if scheme != "https":
        f.write(f"{indent}reverse_proxy {upstream}\n")
        return
    ca_secret = entry.get("server_ca_secret", "")
    f.write(f"{indent}reverse_proxy https://{upstream} {{\n")
    f.write(f"{indent}\ttransport http {{\n")
    if ca_secret:
        sni = entry.get("server_sni", "")
        if sni:
            f.write(f"{indent}\t\ttls_server_name {sni}\n")
        f.write(f"{indent}\t\ttls_trust_pool file"
                f" /etc/caddy/certs/{ca_secret}/ca.crt\n")
    else:
        f.write(f"{indent}\t\ttls_insecure_skip_verify\n")
    f.write(f"{indent}\t}}\n")
    f.write(f"{indent}}}\n")


def _write_caddy_host_block(f, host: str, host_entries: list[dict],
                            tls_internal: bool = False) -> None:
    """Write a single Caddy host block (specific paths first, catch-all last)."""
    specific = [e for e in host_entries if e["path"] and e["path"] != "/"]
    catchall = [e for e in host_entries if not e["path"] or e["path"] == "/"]
    f.write(f"{host} {{\n")
    if tls_internal:
        f.write("\ttls internal\n")
    for entry in specific:
        f.write(f"\thandle {entry['path']}* {{\n")
        if entry.get("strip_prefix"):
            f.write(f"\t\turi strip_prefix {entry['strip_prefix']}\n")
        _write_caddy_reverse_proxy(f, entry, indent="\t\t")
        f.write("\t}\n")
    for entry in catchall:
        _write_caddy_reverse_proxy(f, entry)
    f.write("}\n\n")


def write_caddyfile(entries: list[dict], output_dir: str,
                    config: dict | None = None,
                    filename: str = "Caddyfile") -> None:
    """Write Caddyfile."""
    if not entries:
        return

    path = os.path.join(output_dir, filename)
    replacements = (config or {}).get("replacements", [])
    by_host: dict[str, list[dict]] = {}
    for e in entries:
        # Apply replacements to upstream names (e.g. service alias rewrites)
        if replacements:
            for r in replacements:
                e["upstream"] = e["upstream"].replace(r["old"], r["new"])
        by_host.setdefault(e["host"], []).append(e)

    with open(path, "w", encoding="utf-8") as f:
        f.write("# Generated by helmfile2compose — do not edit manually\n\n")
        caddy_email = (config or {}).get("caddy_email")
        if caddy_email:
            f.write(f"{{\n\temail {caddy_email}\n}}\n\n")
        tls_internal = bool((config or {}).get("caddy_tls_internal"))
        for host, host_entries in by_host.items():
            _write_caddy_host_block(f, host, host_entries, tls_internal)
    print(f"Wrote {path}", file=sys.stderr)


def emit_warnings(warnings: list[str]) -> None:
    """Print all warnings to stderr."""
    for w in warnings:
        print(f"⚠ {w}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _init_first_run(config: dict, manifests: dict, args) -> None:
    """Set project name and auto-exclude K8s-only workloads on first run."""
    source_dir = args.helmfile_dir if not args.from_dir else args.from_dir
    config["name"] = os.path.basename(os.path.realpath(source_dir))
    for kind in WORKLOAD_KINDS:
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
    parser.add_argument(
        "--extensions-dir",
        help="Directory containing h2c extension modules (operators, ingress converters)",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Step 1: get rendered manifests
    release_ns_map: dict[str, str] | None = None
    if args.from_dir:
        rendered_dir = args.from_dir
    else:
        rendered_dir, release_ns_map = run_helmfile_template(
            args.helmfile_dir, args.output_dir, args.environment)

    # Step 2: parse
    manifests = parse_manifests(rendered_dir)
    _infer_namespaces(manifests, release_ns_map)
    kinds = {k: len(v) for k, v in manifests.items()}
    print(f"Parsed manifests: {kinds}", file=sys.stderr)

    # Step 3: load config
    config_path = os.path.join(args.output_dir, "helmfile2compose.yaml")
    first_run = not os.path.exists(config_path)
    config = load_config(config_path)

    if first_run:
        _init_first_run(config, manifests, args)

    # Step 3b: load extensions
    if args.extensions_dir:
        if not os.path.isdir(args.extensions_dir):
            print(f"Extensions directory not found: {args.extensions_dir}", file=sys.stderr)
            sys.exit(1)
        extra_converters, extra_transforms = _load_extensions(args.extensions_dir)
        _TRANSFORMS.extend(extra_transforms)
        # Check for duplicate kind claims between extensions
        ext_kind_owners: dict[str, str] = {}
        for c in extra_converters:
            for k in c.kinds:
                if k in ext_kind_owners:
                    print(f"Error: kind '{k}' claimed by both "
                          f"{ext_kind_owners[k]} and "
                          f"{type(c).__name__} (extensions)",
                          file=sys.stderr)
                    sys.exit(1)
                ext_kind_owners[k] = type(c).__name__
        # Extensions override built-in converters for the same kind
        overridden = set(ext_kind_owners)
        for c in _CONVERTERS:
            lost = overridden & set(c.kinds)
            if lost:
                c.kinds = [k for k in c.kinds if k not in overridden]
                print(f"Extension overrides built-in {type(c).__name__} "
                      f"for: {', '.join(sorted(lost))}")
        _CONVERTERS[0:0] = extra_converters
        CONVERTED_KINDS.update(k for c in extra_converters for k in c.kinds)

    # Step 4: convert
    services, caddy_entries, warnings = convert(manifests, config, output_dir=args.output_dir)

    # Step 5: emit warnings
    emit_warnings(warnings)

    # Step 6: write outputs
    if not services:
        print("No services generated — nothing to write.", file=sys.stderr)
        sys.exit(1)

    write_compose(services, config, args.output_dir, compose_file=args.compose_file)
    caddy_filename = "Caddyfile"
    if config.get("disableCaddy"):
        project = config.get("name", "project")
        caddy_filename = f"Caddyfile-{project}"
    write_caddyfile(caddy_entries, args.output_dir, config=config, filename=caddy_filename)
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
