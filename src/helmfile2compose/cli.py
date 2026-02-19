"""CLI entry point — argument parsing, orchestration."""

import argparse
import os
import sys

from helmfile2compose.core.constants import WORKLOAD_KINDS, AUTO_EXCLUDE_PATTERNS
from helmfile2compose.core.convert import (
    convert, _CONVERTERS, _TRANSFORMS, CONVERTED_KINDS,
)
from helmfile2compose.core.ingress import _REWRITERS
from helmfile2compose.core.extensions import _load_extensions, _register_extensions
from helmfile2compose.io.parsing import run_helmfile_template, parse_manifests, _infer_namespaces
from helmfile2compose.io.config import load_config, save_config
from helmfile2compose.io.output import write_compose, write_caddyfile, emit_warnings


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
        help="Directory containing h2c extension modules (converters, transforms, rewriters)",
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
        extra_converters, extra_transforms, extra_rewriters = _load_extensions(args.extensions_dir)
        _register_extensions(extra_converters, extra_transforms, extra_rewriters,
                             _CONVERTERS, _TRANSFORMS, _REWRITERS, CONVERTED_KINDS)

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
