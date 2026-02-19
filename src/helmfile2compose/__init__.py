"""helmfile2compose — convert helmfile template output to compose.yml + Caddyfile.

Re-exports the public API for backwards compatibility with extensions.
Extensions can import directly from here or from helmfile2compose.pacts.
"""

from helmfile2compose.pacts.types import ConvertContext, ConvertResult
from helmfile2compose.pacts.ingress import IngressRewriter, get_ingress_class, resolve_backend
from helmfile2compose.pacts.helpers import apply_replacements, resolve_env, _secret_value

__all__ = [
    "ConvertContext",
    "ConvertResult",
    "IngressRewriter",
    "get_ingress_class",
    "resolve_backend",
    "apply_replacements",
    "resolve_env",
    "_secret_value",
]
