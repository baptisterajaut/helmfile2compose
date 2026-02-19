"""Constants, regexes, and kind lists used throughout the converter."""

import re

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
_WELL_KNOWN_PORTS = {"http": 80, "https": 443, "grpc": 50051}

# Kinds indexed during pre-processing (not dispatched to converters)
_INDEXED_KINDS = {"ConfigMap", "Secret", "Service", "PersistentVolumeClaim"}

# K8s $(VAR) interpolation in command/args (kubelet resolves these from env vars)
_K8S_VAR_REF_RE = re.compile(r'\$\(([A-Za-z_][A-Za-z0-9_]*)\)')

# Regex boundary for URL port rewriting (matches end-of-string or path/whitespace/quote)
_URL_BOUNDARY = r'''(?=[/\s"']|$)'''
