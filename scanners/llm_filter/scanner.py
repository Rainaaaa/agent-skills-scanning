"""llm_filter scanner — Claude OAuth-based false-positive filter.

The static_rule scanner is high-recall but mid-precision: it flags many
benign skills as SUSPICIOUS or MALICIOUS based on syntactic patterns.
This stage reads only those flagged skills, hands the package directory to
Claude Code via OAuth (`claude -p <prompt>`), and asks for a verdict that
respects intent alignment and shadow-feature reasoning.

Output classification (`raw.audit_summary.intent_alignment_status`):
    SAFE        → benign; static_rule was a false positive
    SUSPICIOUS  → uncertain; needs human review
    MALICIOUS   → confirmed; proceed to behavioral / alignment

Why subprocess-out to `claude` instead of the SDK: the official Claude Code
CLI authenticates via OAuth (`claude login` writes credentials to
`~/.claude/.credentials.json`) and uses tool-use under the hood to *read
files* from the skill directory we point it at. The SDK can do this too,
but the CLI gives us:

  - One auth path shared with the alignment + behavioral scanners.
  - Built-in file-system tools (Read/Glob/Grep) so the model can actually
    inspect `scripts/`, `manifest.json`, etc. — the audit prompt asks for
    this explicitly.
  - No API-key juggling; the user runs `claude login` once.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline._shared import (
    CLASS_ERROR,
    CLASS_MALICIOUS,
    CLASS_SAFE,
    CLASS_SUSPICIOUS,
    ScannerVerdict,
    SkillRecord,
    append_jsonl,
    assert_claude_oauth_ready,
    call_claude,
    parse_json_response,
)
from scanners.base import Scanner


_INTENT_TO_CLASS = {
    "SAFE":       CLASS_SAFE,
    "SUSPICIOUS": CLASS_SUSPICIOUS,
    "MALICIOUS":  CLASS_MALICIOUS,
}


class LLMFilterScanner(Scanner):
    name = "llm_filter"
    # Only run on skills that static_rule flagged as not-safe.
    consumes_classifications = frozenset({CLASS_SUSPICIOUS, CLASS_MALICIOUS})

    def setup(self) -> None:
        assert_claude_oauth_ready()  # fail fast before iterating skills
        prompt_file = self.scanner_config.get("prompt_file") \
            or str(Path(__file__).parent / "prompts" / "audit_prompt.txt")
        self._prompt_template = Path(prompt_file).read_text(encoding="utf-8")
        self._timeout = int(self.scanner_config.get("timeout_seconds", 180))
        self._raw_log_dir = self.output_dir / "raw_responses"
        self._raw_log_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------

    def scan(self, skill: SkillRecord) -> ScannerVerdict:
        if not skill.package_dir.exists():
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                reasons=[f"package_dir missing: {skill.package_dir}"],
            )

        prompt = self._build_prompt(skill)

        t0 = time.time()
        ok, response = call_claude(prompt, timeout=self._timeout)
        elapsed = round(time.time() - t0, 2)

        # Persist raw response next to verdicts so we can audit / debug
        # without re-running Claude. Cheap (<10 KB per skill).
        try:
            (self._raw_log_dir / f"{_safe_filename(skill.skill_id)}.txt").write_text(
                response, encoding="utf-8"
            )
        except OSError:
            pass

        if not ok:
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                reasons=[f"claude CLI failure: {response[:200]}"],
                elapsed_sec=elapsed,
            )

        parsed = parse_json_response(response)
        if not parsed:
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                reasons=["JSON parse failed"],
                raw={"raw_excerpt": response[:400]},
                elapsed_sec=elapsed,
            )

        return self._verdict_from_payload(skill, parsed, elapsed)

    # ------------------------------------------------------------------

    def _build_prompt(self, skill: SkillRecord) -> str:
        """Append a target-path hint so Claude Code uses its tools to read
        the actual files (not just the prompt body). The MASB prompt
        already instructs the model to read `SKILL.md`, `scripts/`, etc."""
        hint = (
            f"\n\n---\nThe target SKILL directory is at: {skill.package_dir}\n"
            "Use your file-reading tools (Read, Glob, Grep) to inspect "
            "SKILL.md, scripts/, src/, and any other files actually present. "
            "Return the JSON object only.\n"
        )
        return self._prompt_template.rstrip() + hint

    def _verdict_from_payload(
        self, skill: SkillRecord, parsed: Dict[str, Any], elapsed: float,
    ) -> ScannerVerdict:
        audit = parsed.get("audit_summary") or {}
        status = (audit.get("intent_alignment_status") or "").upper().strip()
        classification = _INTENT_TO_CLASS.get(status, CLASS_ERROR)

        vulns = parsed.get("vulnerabilities") or []
        crit = sum(1 for v in vulns if (v.get("risk_level") or "").upper() == "CRITICAL")
        high = sum(1 for v in vulns if (v.get("risk_level") or "").upper() == "HIGH")
        med  = sum(1 for v in vulns if (v.get("risk_level") or "").upper() == "MEDIUM")

        reasons: List[str] = []
        if crit:
            reasons.append(f"{crit} CRITICAL")
        if high:
            reasons.append(f"{high} HIGH")
        if med:
            reasons.append(f"{med} MEDIUM")
        if audit.get("shadow_features_detected"):
            reasons.append("shadow_features")
        summary_text = audit.get("summary_text") or ""
        if summary_text:
            reasons.append(summary_text[:160])

        confidence = min(1.0, 0.4 * crit + 0.25 * high + 0.1 * med)
        if classification == CLASS_SAFE:
            confidence = max(confidence, 0.5)  # explicit SAFE verdict has its own weight

        return ScannerVerdict(
            scanner=self.name,
            skill_id=skill.skill_id,
            classification=classification,
            confidence=round(confidence, 3),
            reasons=reasons,
            raw={
                "audit_summary": audit,
                "vulnerability_counts": {"CRITICAL": crit, "HIGH": high, "MEDIUM": med},
                "vulnerabilities": vulns[:8],   # cap to keep verdicts file lean
            },
            elapsed_sec=elapsed,
        )


_SAFE_FN_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(s: str) -> str:
    return _SAFE_FN_RE.sub("_", s)[:200]
