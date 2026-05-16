"""Claude OAuth quota tracking + halt-and-wait gate.

OAuth subscriptions have a rolling 5-hour message cap. The scanner uses
Claude Code via `claude -p ...` for every llm_filter and alignment call;
each one consumes one message from the window. This module:

  - appends every Claude call into `quota_ledger.jsonl` (one row per call)
  - `wait_for_quota()` blocks the worker if the number of calls in the
    last 5h is at or above THRESHOLD × MAX_CALLS_PER_5H (default
    0.9 × 900 = 810 for Claude Max 20x).
  - sleeps in `check_interval_sec` chunks, re-checking each time, until
    the rolling window drops below threshold. Resumes automatically.
  - records rate-limit responses so the operator can see why a worker
    paused.

Env vars (overridable from config later):

  CLAUDE_MAX_CALLS_PER_5H   default 900 (Max 20x). Set 45 for Pro,
                             225 for Max 5x.
  CLAUDE_QUOTA_THRESHOLD    default 0.9 (stop at 90% of cap).
  CLAUDE_QUOTA_LEDGER       default /media/volume/skills/AgentSkills-OSS/agent-skills-scanning/work/scanning_outputs/quota_ledger.jsonl
  CLAUDE_QUOTA_CHECK_SEC    poll interval when paused (default 60).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from threading import Lock
from typing import Optional


ROLLING_WINDOW_SEC = 5 * 3600  # 5 hours

_LEDGER_LOCK = Lock()
_STATUS_LOCK = Lock()
_LAST_STATUS_PRINTED: Optional[float] = None


class RateLimitError(Exception):
    """Raised when a claude call returns an explicit rate-limit signal."""


def ledger_path() -> Path:
    return Path(os.environ.get(
        "CLAUDE_QUOTA_LEDGER",
        "/media/volume/skills/AgentSkills-OSS/agent-skills-scanning/work/scanning_outputs/quota_ledger.jsonl",
    ))


def max_calls() -> int:
    return int(os.environ.get("CLAUDE_MAX_CALLS_PER_5H", "900"))


def threshold() -> float:
    return float(os.environ.get("CLAUDE_QUOTA_THRESHOLD", "0.9"))


def budget() -> int:
    return int(max_calls() * threshold())


def record_call(
    *,
    scanner: str,
    skill_id: str,
    ok: bool,
    rate_limited: bool,
    input_tokens: int = 0,
    output_tokens: int = 0,
    elapsed_sec: float = 0.0,
) -> None:
    entry = {
        "ts": time.time(),
        "scanner": scanner,
        "skill_id": skill_id,
        "ok": ok,
        "rate_limited": rate_limited,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "elapsed_sec": elapsed_sec,
    }
    p = ledger_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry) + "\n"
    with _LEDGER_LOCK:
        with p.open("a", encoding="utf-8") as f:
            f.write(line)


def calls_in_window(only_ok: bool = True) -> int:
    """Count of calls in the last ROLLING_WINDOW_SEC.

    By default counts only `ok=True` calls (real, model-served work).
    Errors and rate-limited rejections are excluded because they don't
    consume real Claude OAuth quota — the CLI replies in <5 s with
    "You've hit your limit · resets …" without contacting the model.
    Counting them was the bug that made the gate pause prematurely
    during the 2026-05-12 run after Claude rate-limited us.

    Set only_ok=False to get the full ledger count (useful for
    diagnostics or for users who want to be pessimistic about what
    consumes quota).
    """
    p = ledger_path()
    if not p.exists():
        return 0
    cutoff = time.time() - ROLLING_WINDOW_SEC
    n = 0
    try:
        with p.open() as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = r.get("ts")
                if not isinstance(ts, (int, float)) or ts < cutoff:
                    continue
                if only_ok:
                    if not r.get("ok") or r.get("rate_limited"):
                        continue
                n += 1
    except OSError:
        return 0
    return n


def _check_interval() -> int:
    return int(os.environ.get("CLAUDE_QUOTA_CHECK_SEC", "60"))


def wait_for_quota() -> None:
    """Block until current 5h-window call count is below budget threshold.

    Returns immediately if already below. Otherwise sleeps in
    check-interval chunks, printing periodic progress to stderr.
    Thread-safe — multiple workers can all call this concurrently;
    each one independently re-checks the shared ledger.
    """
    global _LAST_STATUS_PRINTED
    b = budget()
    mc = max_calls()
    interval = _check_interval()
    n = calls_in_window()
    if n < b:
        return

    with _STATUS_LOCK:
        # Only the first worker to discover the pause prints the banner.
        first_time = _LAST_STATUS_PRINTED is None or (time.time() - _LAST_STATUS_PRINTED) > 30
        if first_time:
            _LAST_STATUS_PRINTED = time.time()
            print(
                f"[quota] PAUSED: {n}/{mc} calls in last 5h "
                f"(budget={b}, threshold={threshold()*100:.0f}%). "
                f"Waiting for window to slide...",
                file=sys.stderr, flush=True,
            )

    waited = 0
    while True:
        time.sleep(interval)
        waited += interval
        n = calls_in_window()
        if n < b:
            with _STATUS_LOCK:
                if _LAST_STATUS_PRINTED is not None:
                    print(
                        f"[quota] RESUMED after {waited//60} min: "
                        f"{n}/{mc} now in window",
                        file=sys.stderr, flush=True,
                    )
                    _LAST_STATUS_PRINTED = None
            return
        if waited > 0 and waited % (10 * 60) < interval:
            with _STATUS_LOCK:
                print(
                    f"[quota] still paused: {n}/{mc} in window "
                    f"(waited {waited//60} min)",
                    file=sys.stderr, flush=True,
                )


_RATE_LIMIT_SUBSTRINGS = (
    "rate limit",
    "rate_limit",
    "429",
    "5-hour",
    "5 hour",
    "5h limit",
    "weekly limit",
    "try again",
    "too many requests",
    # Strings the Claude Code OAuth CLI actually emits when the
    # subscription's rolling-5h quota is hit (observed 2026-05-12):
    "hit your limit",
    "you've hit",
    "you have hit",
    "limit · resets",  # the literal "·" separator
    "limit . resets",
    " resets ",            # paired with a time — false-positive risk acceptable
)


def looks_rate_limited(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    return any(s in lower for s in _RATE_LIMIT_SUBSTRINGS)
