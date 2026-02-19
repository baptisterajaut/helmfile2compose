#!/usr/bin/env python3
"""Concatenate the helmfile2compose package into a single-file distribution."""

import re
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).parent / "src" / "helmfile2compose"
OUTPUT = Path(__file__).parent / "helmfile2compose.py"

# Module order respects the dependency graph (no forward references)
MODULES = [
    "core/constants.py",
    "pacts/types.py",
    "pacts/helpers.py",
    "pacts/ingress.py",
    "core/env.py",
    "core/volumes.py",
    "core/services.py",
    "core/workloads.py",
    "core/haproxy.py",
    "core/ingress.py",
    "core/extensions.py",
    "core/convert.py",
    "io/parsing.py",
    "io/config.py",
    "io/output.py",
    "cli.py",
]

# Imports to strip (internal cross-references, any indentation level)
INTERNAL_IMPORT_RE = re.compile(
    r'^\s*(?:from helmfile2compose[\w.]* import .+|import helmfile2compose[\w.]*)\s*$'
)

SHEBANG = "#!/usr/bin/env python3\n"
DOCSTRING = '"""helmfile2compose — convert helmfile template output to compose.yml + Caddyfile."""\n'
PYLINT_DISABLE = "# pylint: disable=too-many-locals\n"


def collect_imports_and_body(path: Path) -> tuple[list[str], list[str]]:
    """Split a module into stdlib/external imports and body lines."""
    imports = []
    body = []
    in_docstring = False
    docstring_delim = None
    in_internal_import = False  # inside a multi-line internal import

    for line in path.read_text().splitlines(keepends=True):
        stripped = line.strip()

        # Skip module docstrings
        if not in_docstring and not body and not imports:
            if stripped.startswith(('"""', "'''")):
                delim = stripped[:3]
                if stripped.count(delim) >= 2:
                    continue  # single-line docstring
                in_docstring = True
                docstring_delim = delim
                continue
        if in_docstring:
            if docstring_delim in stripped:
                in_docstring = False
            continue

        # Skip multi-line internal imports (continuation after opening paren)
        if in_internal_import:
            if ")" in stripped:
                in_internal_import = False
            continue

        # Skip internal imports (single-line or start of multi-line)
        if INTERNAL_IMPORT_RE.match(line):
            if "(" in stripped and ")" not in stripped:
                in_internal_import = True
            continue

        # Collect stdlib/external imports
        if stripped.startswith(("import ", "from ")) and not stripped.startswith("from ."):
            imports.append(line)
            continue

        body.append(line)

    return imports, body


def main():
    all_imports: dict[str, str] = {}  # dedup by stripped content
    all_bodies: list[str] = []

    for mod_path in MODULES:
        full_path = SRC / mod_path
        if not full_path.exists():
            print(f"Error: {full_path} not found", file=sys.stderr)
            sys.exit(1)

        imports, body = collect_imports_and_body(full_path)

        for imp in imports:
            key = imp.strip()
            if key and key not in all_imports:
                all_imports[key] = imp

        # Add section comment + body
        section = mod_path.replace(".py", "").replace("/", ".")
        all_bodies.append(f"\n# --- {section} ---\n")
        all_bodies.extend(body)

    # Assemble
    lines = [SHEBANG, DOCSTRING, PYLINT_DISABLE, "\n"]
    lines.extend(all_imports.values())
    lines.append("\n")
    lines.extend(all_bodies)

    # Add __main__ guard
    lines.append('\n\nif __name__ == "__main__":\n')
    lines.append("    main()\n")

    OUTPUT.write_text("".join(lines))
    print(f"Built {OUTPUT} ({sum(1 for l in lines if l.strip())} non-empty lines)")

    # Smoke test
    result = subprocess.run(
        [sys.executable, str(OUTPUT), "--help"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"Smoke test FAILED:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print("Smoke test passed (--help)")


if __name__ == "__main__":
    main()
