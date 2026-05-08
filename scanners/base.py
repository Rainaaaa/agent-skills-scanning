"""Scanner base class — the plug-in contract.

Every scanner subclass:
  1. Sets `name = "<unique_name>"` matching its config.yaml section.
  2. Implements `scan(skill: SkillRecord) -> ScannerVerdict`.
  3. Optionally overrides `setup()` for one-time init (model load, auth check, …).
  4. Optionally overrides `scan_batch()` for native batching.

The default `scan_batch()` parallelizes via ThreadPoolExecutor; override it
if you have a smarter execution model (e.g. a vectorized LLM batch API or
a single Docker container that processes many skills at once).

Adding a new scanner is therefore: create `scanners/<name>/scanner.py`,
subclass `Scanner`, register in `config.yaml`. No changes to the
orchestrator are needed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from pipeline._shared import (
    CLASS_ERROR,
    Config,
    ScannerVerdict,
    SkillRecord,
    append_jsonl,
    ensure_dir,
)


class Scanner(ABC):
    """Abstract scanner — every plug-in inherits from this."""

    #: Unique identifier; must match the key under `scanners.<name>` in config.yaml.
    name: str = "base"

    #: Classifications that this scanner consumes. The orchestrator only
    #: passes skills whose latest verdict is in this set. Empty set means
    #: "scan all skills" (entry-point scanners like static_rule).
    consumes_classifications: frozenset = frozenset()

    def __init__(self, config: Config, scanner_config: Dict[str, Any]):
        self.config = config
        self.scanner_config = scanner_config
        self.output_dir = Path(scanner_config.get("output_dir", f"./outputs/{self.name}")).resolve()
        ensure_dir(self.output_dir)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """Hook for one-time init: auth checks, model load, etc."""
        return

    def teardown(self) -> None:
        """Hook for one-time cleanup."""
        return

    # ------------------------------------------------------------------
    # Per-skill (required) and per-batch (optional) APIs
    # ------------------------------------------------------------------

    @abstractmethod
    def scan(self, skill: SkillRecord) -> ScannerVerdict:
        """Produce a verdict for a single skill. Must not raise — return
        a `classification=ERROR` verdict on failure instead."""

    def scan_batch(
        self,
        skills: Iterable[SkillRecord],
        *,
        workers: int = 4,
        verdicts_jsonl: Optional[Path] = None,
        on_done: Optional[callable] = None,
    ) -> Iterator[ScannerVerdict]:
        """Default batch implementation: parallel `scan` calls. Yields
        verdicts as they complete; appends each to `verdicts_jsonl` if
        provided so partial results survive a crash mid-batch."""
        skills_list: List[SkillRecord] = list(skills)
        if not skills_list:
            return
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self._safe_scan, s): s for s in skills_list}
            for fut in as_completed(futs):
                v = fut.result()
                if verdicts_jsonl is not None:
                    append_jsonl(verdicts_jsonl, v.to_dict())
                if on_done is not None:
                    on_done(v)
                yield v

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _safe_scan(self, skill: SkillRecord) -> ScannerVerdict:
        try:
            return self.scan(skill)
        except Exception as e:  # never let a single skill kill the run
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                confidence=0.0,
                reasons=[f"{type(e).__name__}: {e}"],
                raw={"package_dir": str(skill.package_dir)},
            )
