"""Extension discovery and loading — converters, transforms, rewriters."""

import importlib.util
import os
import sys
from pathlib import Path

from helmfile2compose.pacts.ingress import IngressRewriter
from helmfile2compose.core.ingress import _is_rewriter_class


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
    """Load converter, transform, and rewriter classes from an extensions directory."""
    converters = []
    transforms = []
    rewriters = []
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
            elif _is_rewriter_class(obj, mod_name):
                rewriters.append(obj())
            elif _is_transform_class(obj, mod_name):
                transforms.append(obj())

    # Sort by priority (lower = earlier). Default 100.
    converters.sort(key=lambda c: getattr(c, 'priority', 100))
    transforms.sort(key=lambda t: getattr(t, 'priority', 100))
    rewriters.sort(key=lambda r: getattr(r, 'priority', 100))
    if converters:
        loaded = ", ".join(
            f"{type(c).__name__} ({', '.join(c.kinds)})" for c in converters)
        print(f"Loaded extensions: {loaded}", file=sys.stderr)
    if transforms:
        loaded = ", ".join(type(t).__name__ for t in transforms)
        print(f"Loaded transforms: {loaded}", file=sys.stderr)
    if rewriters:
        loaded = ", ".join(
            f"{type(r).__name__} ({r.name})" for r in rewriters)
        print(f"Loaded rewriters: {loaded}", file=sys.stderr)
    return converters, transforms, rewriters


def _register_extensions(extra_converters, extra_transforms, extra_rewriters,
                         converters, transforms, rewriters, converted_kinds):
    """Register loaded extensions into the provided registries."""
    transforms.extend(extra_transforms)
    # Rewriter override: external rewriter with same name replaces built-in
    if extra_rewriters:
        ext_rewriter_names = {rw.name for rw in extra_rewriters}
        overridden_rw = ext_rewriter_names & {rw.name for rw in rewriters}
        if overridden_rw:
            rewriters[:] = [rw for rw in rewriters if rw.name not in ext_rewriter_names]
            for name in sorted(overridden_rw):
                print(f"Rewriter overrides built-in: {name}", file=sys.stderr)
        rewriters[0:0] = extra_rewriters
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
    for c in converters:
        lost = overridden & set(c.kinds)
        if lost:
            c.kinds = [k for k in c.kinds if k not in overridden]
            print(f"Extension overrides built-in {type(c).__name__} "
                  f"for: {', '.join(sorted(lost))}", file=sys.stderr)
    converters[0:0] = extra_converters
    converted_kinds.update(k for c in extra_converters for k in c.kinds)
