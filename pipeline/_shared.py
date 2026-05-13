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
import os
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


# Substitution syntax inside YAML string values: ${NAME} or ${NAME:-default}.
# Used by Config.load to thread env vars through the config without forcing
# users to edit YAML for every new install.
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _interpolate_env(value: Any) -> Any:
    """Recursively expand ${VAR} / ${VAR:-default} in any string value
    nested inside a dict/list. Non-string leaves are passed through."""
    if isinstance(value, str):
        def repl(m: "re.Match[str]") -> str:
            name, default = m.group(1), m.group(2)
            return os.environ.get(name, default if default is not None else "")
        return _ENV_VAR_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(v) for v in value]
    return value


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
        """Load YAML and expand any ${VAR} / ${VAR:-default} placeholders
        in string values from the process environment. Lets users keep
        machine-specific paths out of the file (and out of git).
        """
        if yaml is None:
            raise RuntimeError("PyYAML is required: pip install pyyaml")
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(_interpolate_env(data), source=path)

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
    add_dirs: Optional[List[Path]] = None,
    scanner: str = "unknown",
    skill_id: str = "unknown",
) -> Tuple[bool, str]:
    """Invoke `claude -p <prompt>` and return (ok, response_text).

    Uses the OAuth credentials at `~/.claude/.credentials.json`. The CLI
    handles refresh/rotation; we just call it.

    Side effects:
      - Writes one row to the quota ledger
        (`pipeline.quota.ledger_path()`).
      - Before the call, blocks via `wait_for_quota()` if cumulative
        calls in the rolling 5h window are at/above the configured
        budget (default 0.9 × 900 = 810 for Claude Max 20x).
      - If Claude's response looks like a rate-limit signal, raises
        `pipeline.quota.RateLimitError` so the caller can convert it
        into an ERROR verdict; the next call will naturally wait at
        the quota gate.

    Args:
      add_dirs:      extra directories Claude's tools (Read/Glob/Grep/
                     Bash) are allowed to touch. Use this to grant
                     access to a specific skill's package_dir — the CLI's
                     default working-dir sandbox otherwise blocks reads
                     under /media/volume/skills/skills/ etc.
      scanner, skill_id: labels for the ledger row; harmless if omitted.
      output_format: caller-facing return shape: "text" returns the
                     `result` string; "json"/"stream-json" returns the
                     raw stdout (same as the pre-quota behavior).
                     Internally we always request JSON so we can read
                     usage + stop_reason for ledger and rate-limit detection.
    """
    from pipeline.quota import (
        RateLimitError,
        looks_rate_limited,
        record_call,
        wait_for_quota,
    )

    wait_for_quota()  # blocks if we're at/above 90% × MAX_CALLS_PER_5H

    cmd = ["claude", "-p", prompt, "--output-format", "json"]
    for d in (add_dirs or []):
        cmd += ["--add-dir", str(d)]

    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        record_call(scanner=scanner, skill_id=skill_id, ok=False,
                    rate_limited=False, elapsed_sec=time.time() - t0)
        return False, "ERROR: 'claude' CLI not on PATH. Install Claude Code first."
    except subprocess.TimeoutExpired:
        record_call(scanner=scanner, skill_id=skill_id, ok=False,
                    rate_limited=False, elapsed_sec=time.time() - t0)
        return False, "TIMEOUT"
    elapsed = time.time() - t0

    input_tokens = output_tokens = 0
    is_error = (p.returncode != 0)
    result_text = ""
    rate_limited = False
    raw_out = p.stdout or ""
    try:
        data = json.loads(raw_out)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, dict):
        usage = data.get("usage") or {}
        try:
            input_tokens = int(usage.get("input_tokens") or 0)
            output_tokens = int(usage.get("output_tokens") or 0)
        except (TypeError, ValueError):
            pass
        is_error = bool(data.get("is_error", is_error))
        result_text = (data.get("result") or "")
        stop_reason = data.get("stop_reason") or ""
        rate_limited = (
            looks_rate_limited(stop_reason)
            or (is_error and looks_rate_limited(result_text))
        )
    else:
        result_text = raw_out or (p.stderr or "")
        rate_limited = looks_rate_limited(result_text) or looks_rate_limited(p.stderr or "")

    record_call(
        scanner=scanner, skill_id=skill_id,
        ok=(not is_error) and (not rate_limited),
        rate_limited=rate_limited,
        input_tokens=input_tokens, output_tokens=output_tokens,
        elapsed_sec=elapsed,
    )

    if rate_limited:
        raise RateLimitError(
            f"[{scanner}/{skill_id}] claude rate-limit: {result_text[:240]}"
        )

    if output_format == "text":
        if is_error or p.returncode != 0:
            return False, (
                f"EXIT={p.returncode} STDERR={(p.stderr or '')[:160]} "
                f"RESULT={result_text[:160]}"
            )
        return True, result_text.strip()
    # output_format == "json" / "stream-json": return raw stdout
    if is_error or p.returncode != 0:
        return False, f"EXIT={p.returncode} STDERR={(p.stderr or '')[:300]}"
    return True, raw_out.strip()


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

# Alignment is a separate axis; binary by design.
# A skill is either "aligned" (description matches body) or "misaligned"
# (description and body disagree, possibly maliciously). Severity (low /
# medium / high) lives in the verdict's `raw` payload for downstream
# filtering, but the top-level classification is binary.
CLASS_ALIGNED = "ALIGNED"
CLASS_MISALIGNED = "MISALIGNED"

VALID_CLASSIFICATIONS = {
    CLASS_SAFE, CLASS_SUSPICIOUS, CLASS_MALICIOUS, CLASS_ERROR,
    CLASS_ALIGNED, CLASS_MISALIGNED,
}


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
