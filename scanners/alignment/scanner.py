"""alignment scanner — Claude OAuth-based intent-alignment audit.

Asks Claude whether a skill's manifest description, SKILL.md frontmatter,
and SKILL.md body are mutually consistent — and whether the body
references files that don't exist in the package.

This is a *separate dimension* from maliciousness. A skill can be:
  - aligned + safe           → benign and honest
  - misaligned + safe        → benign but the docs lie about what it does
  - aligned + malicious      → openly malicious (rare; advertises bad behavior)
  - misaligned + malicious   → malicious AND deceptive (the dangerous case)

The classification is **binary** — `ALIGNED` or `MISALIGNED`. Severity
(low / medium / high) and the underlying `aligned` boolean live in the
verdict's `raw` payload, so a downstream consumer that wants finer-
grained alignment policy can still get it.

The orchestrator runs this on the same scope as `behavioral`: skills that
remain MALICIOUS or SUSPICIOUS after `llm_filter`. The two stages are
independent, so they can run in parallel.

Output (in `raw`):
  - `aligned`               : bool
  - `severity`              : "low" | "medium" | "high"
  - `reason`                : str
  - `mismatches`            : list[str]
  - `references_missing`    : list[str]

Mapping (top-level classification):

  aligned == true   → ALIGNED
  aligned == false  → MISALIGNED
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline._shared import (
    CLASS_ALIGNED,
    CLASS_ERROR,
    CLASS_MALICIOUS,
    CLASS_MISALIGNED,
    CLASS_SAFE,
    CLASS_SUSPICIOUS,
    ScannerVerdict,
    SkillRecord,
    assert_claude_oauth_ready,
    call_claude,
    parse_json_response,
)
from pipeline.quota import RateLimitError
from scanners.base import Scanner


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)
_REF_PATH_RE = re.compile(r"`\.?/?((?:scripts|references|assets|files|resources)/[\w./-]+)`")


def _load_skill_artifacts(skill_dir: Path):
    manifest: Dict[str, Any] = {}
    manifest_path = skill_dir / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            manifest = {"_parse_error": True}

    frontmatter, body = "", ""
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        skill_md = skill_dir / "skill.md"
    if skill_md.exists():
        text = skill_md.read_text(encoding="utf-8", errors="replace")
        m = _FRONTMATTER_RE.match(text)
        if m:
            frontmatter, body = m.group(1).strip(), m.group(2).strip()
        else:
            body = text.strip()

    files_in_pkg = sorted(p.name for p in skill_dir.iterdir()) if skill_dir.exists() else []
    return manifest, frontmatter, body, files_in_pkg


class AlignmentScanner(Scanner):
    name = "alignment"
    # The orchestrator chains this off llm_filter; alignment is run on
    # whatever made it past the maliciousness filter. The values
    # SUSPICIOUS / MALICIOUS come from llm_filter (the maliciousness pillar),
    # not from a previous alignment verdict.
    consumes_classifications = frozenset({CLASS_SUSPICIOUS, CLASS_MALICIOUS})

    def setup(self) -> None:
        assert_claude_oauth_ready()
        prompt_file = self.scanner_config.get("prompt_file") \
            or str(Path(__file__).parent / "prompts" / "alignment_prompt.txt")
        self._prompt_template = Path(prompt_file).read_text(encoding="utf-8")
        self._timeout = int(self.scanner_config.get("timeout_seconds", 120))
        self._body_limit = int(self.scanner_config.get("body_limit", 8000))
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

        manifest, frontmatter, body, files_in_pkg = _load_skill_artifacts(skill.package_dir)
        prompt = self._prompt_template.format(
            package_files=", ".join(files_in_pkg) or "(none)",
            manifest=json.dumps(manifest, indent=2)[:4000],
            frontmatter=frontmatter[:1500],
            body=body[: self._body_limit],
            body_limit=self._body_limit,
        )

        t0 = time.time()
        try:
            ok, response = call_claude(
                prompt,
                timeout=self._timeout,
                add_dirs=[skill.package_dir],
                scanner=self.name,
                skill_id=skill.skill_id,
            )
        except RateLimitError as e:
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                reasons=[f"rate_limited: {str(e)[:200]}"],
                elapsed_sec=round(time.time() - t0, 2),
            )
        elapsed = round(time.time() - t0, 2)

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

        return self._verdict_from_payload(skill, parsed, elapsed, files_in_pkg, body)

    # ------------------------------------------------------------------

    def _verdict_from_payload(
        self,
        skill: SkillRecord,
        parsed: Dict[str, Any],
        elapsed: float,
        files_in_pkg: List[str],
        body: str,
    ) -> ScannerVerdict:
        aligned = bool(parsed.get("aligned", False))
        severity = (parsed.get("severity") or "").lower()
        reason = (parsed.get("reason") or "")[:300]
        mismatches = list(parsed.get("mismatches") or [])
        refs_missing = list(parsed.get("references_missing") or [])

        # Binary alignment classification. Severity is preserved in `raw`
        # for downstream consumers that want the finer gradient.
        if aligned:
            classification = CLASS_ALIGNED
            confidence = 0.5
        elif severity == "high":
            classification = CLASS_MISALIGNED
            confidence = 0.85
        elif severity == "medium":
            classification = CLASS_MISALIGNED
            confidence = 0.6
        else:
            classification = CLASS_MISALIGNED
            confidence = 0.4

        reasons: List[str] = []
        if reason:
            reasons.append(reason)
        if mismatches:
            reasons.append(f"mismatches={len(mismatches)}")
        if refs_missing:
            reasons.append(f"missing_refs={len(refs_missing)}")

        # Capture the regex-derived references the prompt wouldn't have seen
        # so a reviewer can audit the alignment verdict without re-running.
        regex_refs = sorted(set(_REF_PATH_RE.findall(body)))

        return ScannerVerdict(
            scanner=self.name,
            skill_id=skill.skill_id,
            classification=classification,
            confidence=round(confidence, 3),
            reasons=reasons,
            raw={
                "aligned": aligned,
                "severity": severity,
                "reason": reason,
                "mismatches": mismatches,
                "references_missing": refs_missing,
                "files_in_pkg": files_in_pkg,
                "regex_refs_found": regex_refs,
            },
            elapsed_sec=elapsed,
        )


_SAFE_FN_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(s: str) -> str:
    return _SAFE_FN_RE.sub("_", s)[:200]
