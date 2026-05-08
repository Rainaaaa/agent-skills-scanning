"""Shared utilities for the agent-skills-scanning pipeline.

Three concerns live here:

1. **IO** — atomic JSON write, JSONL append/read, ensure_dir, time helpers.
2. **Config** — YAML loader with simple dotted-path access.
3. **Claude OAuth** — single chokepoint that calls the `claude` CLI so every
   scanner that needs an LLM verdict shares one well-tested entry point and
   one auth model (the credentials at `~/.claude/.credentials.json`, written
   by `claude login`).

Kept dependency-light (PyYAML + stdlib) so this module can be imported from
any scanner subpackage without import cycles.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None  # config loader will raise a nice error if PyYAML isn't installed


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------

def now_ts() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# JSON / JSONL
# ---------------------------------------------------------------------------

def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data: Any) -> None:
    """Atomic write via temp-file rename."""
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(path)


def append_jsonl(path: Path, item: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def iter_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# ---------------------------------------------------------------------------
# Config (YAML, dotted-path access)
# ---------------------------------------------------------------------------

class Config:
    """Lightweight YAML config wrapper.

    Supports `cfg.get("scanners.static_rule.enabled", default=False)`.
    """

    def __init__(self, data: Dict[str, Any], source: Optional[Path] = None):
        self._data = data
        self._source = source

    @classmethod
    def load(cls, path: Path) -> "Config":
        if yaml is None:
            raise RuntimeError("PyYAML is required: pip install pyyaml")
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data, source=path)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for key in dotted.split("."):
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                return default
        return node

    def section(self, dotted: str) -> Dict[str, Any]:
        v = self.get(dotted, {}) or {}
        if not isinstance(v, dict):
            raise TypeError(f"Config section '{dotted}' is not a dict")
        return v

    @property
    def raw(self) -> Dict[str, Any]:
        return self._data


# ---------------------------------------------------------------------------
# Claude OAuth — single chokepoint
# ---------------------------------------------------------------------------

class ClaudeAuthError(RuntimeError):
    """Raised when ~/.claude/.credentials.json is missing on the host."""


def claude_oauth_credentials_path() -> Path:
    return Path.home() / ".claude" / ".credentials.json"


def assert_claude_oauth_ready() -> None:
    """Fail fast if `claude login` hasn't been run on this host.

    All Claude-using scanners (llm_filter, alignment) call this at startup
    so the user gets one clear error instead of N opaque per-skill failures.
    """
    cred = claude_oauth_credentials_path()
    if not cred.exists():
        raise ClaudeAuthError(
            f"Missing {cred}. Run `claude login` on the host (or mount the "
            f"host's ~/.claude/ into the container at /root/.claude/) before "
            f"running this scanner."
        )


def call_claude(
    prompt: str,
    *,
    timeout: int = 120,
    output_format: str = "text",
) -> Tuple[bool, str]:
    """Invoke `claude -p <prompt>` and return (ok, response_text).

    Uses the OAuth credentials at `~/.claude/.credentials.json`. The CLI
    handles refresh/rotation; we just call it. Captures stdout; on failure
    `response_text` carries a short EXIT=… STDERR=… diagnostic.

    `output_format` is passed through to the CLI's --output-format flag
    ("text" | "stream-json" | "json"). Use "text" for free-form prompts
    where you'll parse the JSON yourself with `parse_json_response()`.
    """
    try:
        p = subprocess.run(
            ["claude", "-p", prompt, "--output-format", output_format],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return False, "ERROR: 'claude' CLI not on PATH. Install Claude Code first."
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    if p.returncode != 0:
        return False, f"EXIT={p.returncode} STDERR={(p.stderr or '')[:300]}"
    return True, (p.stdout or "").strip()


_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def parse_json_response(text: str) -> Optional[Dict[str, Any]]:
    """Extract the first JSON object from a Claude response.

    Tolerant of:
      - Leading/trailing prose
      - ```json fenced code blocks
      - Trailing whitespace
    Returns None if no parseable object is found.
    """
    if not text:
        return None
    cleaned = _CODE_FENCE_RE.sub("", text).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Skill loader — a small struct every scanner consumes
# ---------------------------------------------------------------------------

@dataclass
class SkillRecord:
    """One skill's identity + filesystem location.

    Scanners receive this and decide what to read from `package_dir`.
    """

    skill_id: str
    package_dir: Path
    repo_id: str = ""
    repo_key: str = ""
    relative_path: str = ""
    upstream_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def skill_md_path(self) -> Path:
        for name in ("SKILL.md", "skill.md"):
            p = self.package_dir / name
            if p.exists():
                return p
        return self.package_dir / "SKILL.md"  # may not exist

    @property
    def manifest_path(self) -> Path:
        return self.package_dir / "manifest.json"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["package_dir"] = str(self.package_dir)
        return d


# ---------------------------------------------------------------------------
# Scanner verdict — every scanner returns this shape
# ---------------------------------------------------------------------------

CLASS_SAFE = "SAFE"
CLASS_SUSPICIOUS = "SUSPICIOUS"
CLASS_MALICIOUS = "MALICIOUS"
CLASS_ERROR = "ERROR"

VALID_CLASSIFICATIONS = {CLASS_SAFE, CLASS_SUSPICIOUS, CLASS_MALICIOUS, CLASS_ERROR}


@dataclass
class ScannerVerdict:
    """The unit of truth flowing between scanners.

    `classification` is a coarse label; the per-scanner detail lives in
    `raw`. Downstream stages key off `classification` to decide whether to
    invoke the next, more expensive scanner.
    """

    scanner: str
    skill_id: str
    classification: str
    confidence: float = 0.0
    reasons: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    elapsed_sec: float = 0.0
    ts: int = field(default_factory=now_ts)

    def __post_init__(self) -> None:
        if self.classification not in VALID_CLASSIFICATIONS:
            self.classification = CLASS_ERROR
            self.reasons.insert(0, f"invalid classification normalized to ERROR")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
