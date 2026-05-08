"""Scanner registry — discover plug-ins by name.

Each scanner module under `scanners/<name>/scanner.py` exposes a class that
inherits from `Scanner`. The registry imports them lazily so unused
scanners (and their heavy dependencies, e.g. Docker-on-host) don't have to
be importable at startup.

Adding a new scanner is just two changes:
  1. Drop `scanners/<name>/scanner.py` with a `<Name>Scanner(Scanner)` class.
  2. Add an entry under `scanners.<name>` in `config.yaml` and append the
     `(name, module_path, class_name)` triple to `_SCANNERS` below.

There's no auto-discovery on filesystem walk because explicit registration
makes the supported set obvious from one place.
"""

from __future__ import annotations

import importlib
from typing import Dict, List, Tuple

from pipeline._shared import Config

from scanners.base import Scanner


# (name, module_path, class_name) — kept in pipeline order.
# `name` matches the `scanners.<name>` key in config.yaml.
_SCANNERS: List[Tuple[str, str, str]] = [
    ("static_rule", "scanners.static_rule.scanner", "StaticRuleScanner"),
    ("llm_filter",  "scanners.llm_filter.scanner",  "LLMFilterScanner"),
    ("alignment",   "scanners.alignment.scanner",   "AlignmentScanner"),
    ("behavioral",  "scanners.behavioral.scanner",  "BehavioralScanner"),
]


def list_scanners() -> List[str]:
    return [name for name, _, _ in _SCANNERS]


def load_scanner(name: str, config: Config) -> Scanner:
    """Instantiate a scanner by registry name. Raises KeyError if unknown.

    Reads its per-scanner block from `config.scanners.<name>`. Returning the
    Scanner instance unsetup; call `instance.setup()` before use.
    """
    for reg_name, mod_path, cls_name in _SCANNERS:
        if reg_name != name:
            continue
        module = importlib.import_module(mod_path)
        klass = getattr(module, cls_name)
        scanner_cfg = config.section(f"scanners.{name}") or {}
        instance = klass(config=config, scanner_config=scanner_cfg)
        return instance
    raise KeyError(
        f"Unknown scanner '{name}'. Registered: {list_scanners()}"
    )


def load_enabled_scanners(config: Config) -> List[Scanner]:
    """Load every scanner whose config block has `enabled: true`, in
    registry order so the orchestrator can chain them deterministically."""
    out: List[Scanner] = []
    for name, _, _ in _SCANNERS:
        cfg = config.section(f"scanners.{name}")
        if not cfg.get("enabled", False):
            continue
        out.append(load_scanner(name, config))
    return out
