#!/usr/bin/env python3
"""Build helmfile2compose.py — full distribution (bare core + built-in extensions)."""

import argparse
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
OUTPUT = HERE / "helmfile2compose.py"

# Extensions to bundle (order respects dependency graph)
EXTENSIONS = [
    "extensions/workloads.py",
    "extensions/haproxy.py",
    "extensions/configmap_indexer.py",
    "extensions/secret_indexer.py",
    "extensions/service_indexer.py",
    "extensions/pvc_indexer.py",
    "extensions/caddy.py",
]

# Wiring code — registers built-in extension instances into core registries.
# Appended after extensions, references classes already defined in the concat body.
WIRING = """\

# --- distribution.wiring ---
_CONVERTERS.extend([
    ConfigMapIndexer(), SecretIndexer(), ServiceIndexer(), PVCIndexer(),
    WorkloadConverter(), CaddyProvider(),
])
CONVERTED_KINDS.update(k for c in _CONVERTERS for k in c.kinds)
_REWRITERS.append(HAProxyRewriter())
"""

# Same regex as h2c-core's build.py
INTERNAL_IMPORT_RE = re.compile(
    r'^\s*(?:from helmfile2compose[\w.]* import .+|import helmfile2compose[\w.]*)\s*$'
)

# h2c-core's MODULES list (for --core-dir local mode)
CORE_MODULES = [
    "core/constants.py",
    "pacts/types.py",
    "pacts/helpers.py",
    "pacts/ingress.py",
    "core/env.py",
    "core/volumes.py",
    "core/services.py",
    "core/ingress.py",
    "core/extensions.py",
    "core/convert.py",
    "io/parsing.py",
    "io/config.py",
    "io/output.py",
    "cli.py",
]

SHEBANG = "#!/usr/bin/env python3\n"
DOCSTRING = '"""helmfile2compose — convert helmfile template output to compose.yml + Caddyfile."""\n'
PYLINT_DISABLE = "# pylint: disable=too-many-locals\n"


def collect_imports_and_body(path: Path) -> tuple[list[str], list[str]]:
    """Split a module into stdlib/external imports and body lines."""
    imports = []
    body = []
    in_docstring = False
    docstring_delim = None
    in_internal_import = False

    for line in path.read_text().splitlines(keepends=True):
        stripped = line.strip()

        if not in_docstring and not body and not imports:
            if stripped.startswith(('"""', "'''")):
                delim = stripped[:3]
                if stripped.count(delim) >= 2:
                    continue
                in_docstring = True
                docstring_delim = delim
                continue
        if in_docstring:
            if docstring_delim in stripped:
                in_docstring = False
            continue

        if in_internal_import:
            if ")" in stripped:
                in_internal_import = False
            continue

        if INTERNAL_IMPORT_RE.match(line):
            if "(" in stripped and ")" not in stripped:
                in_internal_import = True
            continue

        if stripped.startswith(("import ", "from ")) and not stripped.startswith("from ."):
            imports.append(line)
            continue

        body.append(line)

    return imports, body


def fetch_core_release(version: str = "latest") -> str:
    """Download h2c.py from the h2c-core GitHub releases."""
    if version == "latest":
        url = "https://github.com/helmfile2compose/helmfile2compose/releases/latest/download/h2c.py"
    else:
        url = f"https://github.com/helmfile2compose/helmfile2compose/releases/download/{version}/h2c.py"
    print(f"Fetching h2c.py from {url}", file=sys.stderr)
    try:
        with urllib.request.urlopen(url) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:
        print(f"Error fetching h2c.py: {exc}", file=sys.stderr)
        sys.exit(1)


def strip_main_guard(text: str) -> str:
    """Remove the if __name__ == '__main__' block from the end of h2c.py."""
    lines = text.splitlines(keepends=True)
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip().startswith('if __name__'):
            return "".join(lines[:i])
    return text


def parse_flat_script(text: str) -> tuple[dict[str, str], list[str]]:
    """Parse a flat h2c.py into deduplicated imports + body lines.

    Skips shebang, module docstring, and pylint directives at the top.
    """
    all_imports: dict[str, str] = {}
    body: list[str] = []
    past_header = False
    in_imports = True

    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if not past_header:
            if (stripped.startswith("#!") or stripped.startswith('"""')
                    or stripped.startswith("# pylint") or not stripped):
                continue
            past_header = True

        if in_imports:
            if stripped.startswith(("import ", "from ")):
                key = stripped
                if key not in all_imports:
                    all_imports[key] = line
                continue
            if not stripped:
                continue  # blank lines between import groups
            in_imports = False

        body.append(line)

    return all_imports, body


def build_from_release(version: str) -> None:
    """CI mode: fetch h2c.py release, concat extensions, output helmfile2compose.py."""
    core_text = strip_main_guard(fetch_core_release(version))
    all_imports, core_body = parse_flat_script(core_text)

    all_bodies: list[str] = ["\n# --- core ---\n"]
    all_bodies.extend(core_body)

    # Process extensions
    for ext_path in EXTENSIONS:
        full_path = HERE / ext_path
        if not full_path.exists():
            print(f"Error: {full_path} not found", file=sys.stderr)
            sys.exit(1)
        imports, body = collect_imports_and_body(full_path)
        for imp in imports:
            key = imp.strip()
            if key and key not in all_imports:
                all_imports[key] = imp
        section = ext_path.replace(".py", "").replace("/", ".")
        all_bodies.append(f"\n# --- {section} ---\n")
        all_bodies.extend(body)

    all_bodies.append(WIRING)
    _assemble_and_write(all_imports, all_bodies)


def build_from_local(core_dir: Path) -> None:
    """Local dev mode: read core sources + concat extensions."""
    src_dir = core_dir / "src" / "helmfile2compose"
    if not src_dir.exists():
        print(f"Error: {src_dir} not found", file=sys.stderr)
        sys.exit(1)

    all_imports: dict[str, str] = {}
    all_bodies: list[str] = []

    # Process core modules (same logic as h2c-core's build.py)
    for mod_path in CORE_MODULES:
        full_path = src_dir / mod_path
        if not full_path.exists():
            print(f"Error: {full_path} not found", file=sys.stderr)
            sys.exit(1)
        imports, body = collect_imports_and_body(full_path)
        for imp in imports:
            key = imp.strip()
            if key and key not in all_imports:
                all_imports[key] = imp
        section = mod_path.replace(".py", "").replace("/", ".")
        all_bodies.append(f"\n# --- {section} ---\n")
        all_bodies.extend(body)

    # Process extensions
    for ext_path in EXTENSIONS:
        full_path = HERE / ext_path
        if not full_path.exists():
            print(f"Error: {full_path} not found", file=sys.stderr)
            sys.exit(1)
        imports, body = collect_imports_and_body(full_path)
        for imp in imports:
            key = imp.strip()
            if key and key not in all_imports:
                all_imports[key] = imp
        section = ext_path.replace(".py", "").replace("/", ".")
        all_bodies.append(f"\n# --- {section} ---\n")
        all_bodies.extend(body)

    all_bodies.append(WIRING)
    _assemble_and_write(all_imports, all_bodies)


def _assemble_and_write(all_imports: dict, all_bodies: list) -> None:
    """Sort imports, assemble final file, write + smoke test."""
    stdlib_imports = []
    thirdparty_imports = []
    for imp in all_imports.values():
        module = imp.strip().split()[1].split(".")[0]
        if module == "yaml":
            thirdparty_imports.append(imp)
        else:
            stdlib_imports.append(imp)

    lines = [SHEBANG, DOCSTRING, PYLINT_DISABLE, "\n"]
    lines.extend(stdlib_imports)
    if thirdparty_imports:
        lines.append("\n")
        lines.extend(thirdparty_imports)
    lines.append("\n")
    lines.extend(all_bodies)

    lines.append('\n\nif __name__ == "__main__":\n')
    lines.append("    main()\n")

    OUTPUT.write_text("".join(lines))
    print(f"Built {OUTPUT} ({sum(1 for l in lines if l.strip())} non-empty lines)")

    result = subprocess.run(
        [sys.executable, str(OUTPUT), "--help"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"Smoke test FAILED:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print("Smoke test passed (--help)")


def main():
    parser = argparse.ArgumentParser(description="Build helmfile2compose.py distribution")
    parser.add_argument("--core-dir", type=Path,
                        help="Path to local h2c-core repo (local dev mode)")
    parser.add_argument("--core-version", default="latest",
                        help="h2c-core release version to fetch (CI mode, default: latest)")
    args = parser.parse_args()

    if args.core_dir:
        print(f"Local dev mode: reading core from {args.core_dir}", file=sys.stderr)
        build_from_local(args.core_dir)
    else:
        print(f"CI mode: fetching h2c-core {args.core_version}", file=sys.stderr)
        build_from_release(args.core_version)


if __name__ == "__main__":
    main()
