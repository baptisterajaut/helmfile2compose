"""Workload conversion — Deployment, StatefulSet, DaemonSet, Job to compose services."""
# pylint: disable=too-many-locals

import fnmatch

from helmfile2compose.pacts.types import ConvertContext, ConvertResult
from helmfile2compose.pacts.helpers import resolve_env
from helmfile2compose.core.constants import WORKLOAD_KINDS
from helmfile2compose.core.env import _convert_command
from helmfile2compose.core.volumes import _convert_volume_mounts, _build_vol_map


def _is_excluded(name: str, exclude_list: list[str]) -> bool:
    """Check if a workload name matches any exclude pattern (supports wildcards)."""
    return any(fnmatch.fnmatch(name, pattern) for pattern in exclude_list)


def _resolve_named_port(name: str, container_ports: list) -> int | str:
    """Resolve a named port (e.g. 'http') to its numeric containerPort."""
    for cp in container_ports:
        if cp.get("name") == name:
            return cp["containerPort"]
    return name  # fallback: return as-is if not found


def _get_run_as_user(pod_spec: dict, container: dict) -> int | None:
    """Extract runAsUser from container or pod securityContext (container wins)."""
    for ctx in (container.get("securityContext") or {}, pod_spec.get("securityContext") or {}):
        uid = ctx.get("runAsUser")
        if uid is not None:
            return int(uid)
    return None


def _get_exposed_ports(workload_labels: dict, container_ports: list,
                       services_by_selector: dict) -> list[str]:
    """Determine which ports to expose based on K8s Service type."""
    ports = []
    for _sel_key, svc_info in services_by_selector.items():
        svc_labels = svc_info.get("selector") or {}
        if not svc_labels:
            continue
        if all(workload_labels.get(k) == v for k, v in svc_labels.items()):
            svc_type = svc_info.get("type", "ClusterIP")
            if svc_type in ("NodePort", "LoadBalancer"):
                for sp in svc_info.get("ports") or []:
                    target = sp.get("targetPort", sp.get("port"))
                    if isinstance(target, str):
                        target = _resolve_named_port(target, container_ports)
                    node_port = sp.get("nodePort", sp.get("port"))
                    if isinstance(node_port, str):
                        node_port = _resolve_named_port(node_port, container_ports)
                    ports.append(f"{node_port}:{target}")
    return ports


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
    for ic in pod_spec.get("initContainers") or []:
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
    for sc in (pod_spec.get("containers") or [])[1:]:
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

        spec = manifest.get("spec") or {}
        pod_spec = (spec.get("template") or {}).get("spec") or {}
        vcts = spec.get("volumeClaimTemplates")  # StatefulSet only
        containers = pod_spec.get("containers") or []
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
        exposed_ports = _get_exposed_ports(meta.get("labels") or {},
                                           container.get("ports") or [],
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
