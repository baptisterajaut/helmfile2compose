"""Configuration file handling — load/save helmfile2compose.yaml."""

import os

import yaml


def load_config(path: str) -> dict:
    """Load helmfile2compose.yaml or return empty config."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
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
    header = "# Configuration descriptor for https://github.com/helmfile2compose\n\n"
    # Ensure version key comes first
    ordered = {"helmfile2ComposeVersion": config.get("helmfile2ComposeVersion", "v1")}
    for k, v in config.items():
        if k != "helmfile2ComposeVersion":
            ordered[k] = v
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.dump(ordered, f, default_flow_style=False, sort_keys=False)
