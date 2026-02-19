"""K8s Service indexing — alias maps, port maps, network aliases."""

from helmfile2compose.core.constants import WORKLOAD_KINDS, _K8S_DNS_RE


def _index_workloads(manifests: dict) -> list[tuple[dict, str]]:
    """Index workload labels → workload name for Deployments and StatefulSets."""
    result = []
    for kind in WORKLOAD_KINDS:
        for m in manifests.get(kind, []):
            meta = m.get("metadata", {})
            result.append((meta.get("labels") or {}, meta.get("name", "")))
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
    from helmfile2compose.core.workloads import _resolve_named_port

    # Index workload labels → container ports
    workload_ports: dict[str, list] = {}
    for kind in WORKLOAD_KINDS:
        for m in manifests.get(kind, []):
            name = m.get("metadata", {}).get("name", "")
            containers = ((m.get("spec") or {}).get("template") or {}).get("spec") or {}
            containers = containers.get("containers") or []
            all_ports = []
            for c in containers:
                all_ports.extend(c.get("ports") or [])
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
            if svc_port_num is None:
                continue
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
