"""static_rule scanner — wraps MASB's `skill-security-scan` CLI.

This is the cheap, local, deterministic first stage. It runs the upstream
[MASB rule-based scanner](https://github.com/.../MaliciousAgentSkillsBench)
once per skill package and maps its output to our common verdict shape.

Severity → classification mapping:
    CRITICAL  → MALICIOUS
    WARNING   → SUSPICIOUS
    INFO/none → SAFE

The wrapper invokes the upstream tool as a subprocess so we don't pin to
any internal API of `skill-security-scan` — only its CLI contract:

    python -m src.cli scan <skill_dir> -f json -o <out.json>

`scanners.static_rule.upstream_path` in config.yaml points at the directory
containing the scanner's `src/` (i.e. the `skill-security-scan/` checkout
inside MASB). If absent, the scanner errors fast at setup() rather than
producing N misleading per-skill failures.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
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
)
from scanners.base import Scanner


_SEVERITY_TO_CLASS = {
    "CRITICAL": CLASS_MALICIOUS,
    "WARNING":  CLASS_SUSPICIOUS,
    "INFO":     CLASS_SAFE,
}


class StaticRuleScanner(Scanner):
    name = "static_rule"
    # Empty consumes-set means "this is an entry-point scanner; run on every
    # skill in the work queue", regardless of upstream verdict.
    consumes_classifications = frozenset()

    def setup(self) -> None:
        upstream = self.scanner_config.get("upstream_path")
        if not upstream:
            raise RuntimeError(
                "scanners.static_rule.upstream_path must point at the "
                "skill-security-scan/ directory (from MASB)."
            )
        upstream_path = Path(upstream).expanduser().resolve()
        if not (upstream_path / "src" / "cli.py").exists():
            raise RuntimeError(
                f"Expected {upstream_path}/src/cli.py — is upstream_path set "
                "to the skill-security-scan checkout?"
            )
        self._upstream_path = upstream_path
        self._python_bin = self.scanner_config.get("python_bin", sys.executable)
        self._severity_threshold = self.scanner_config.get("severity_threshold", "INFO")
        self._timeout = int(self.scanner_config.get("timeout_seconds", 60))

        # rules_file: optional override for the upstream `config/rules.yaml`.
        # If set, passed to MASB as `--rules <abs-path>`. Defaults to the
        # bundled `rules.yaml` next to this scanner module so the pipeline
        # is self-contained — MASB upstream doesn't ship rules.yaml.
        rules_file = self.scanner_config.get("rules_file")
        if rules_file:
            rules_path: Optional[Path] = Path(rules_file).expanduser().resolve()
        else:
            bundled = Path(__file__).resolve().parent / "rules.yaml"
            rules_path = bundled if bundled.exists() else None
        if rules_path is not None and not rules_path.exists():
            raise RuntimeError(f"static_rule rules_file not found: {rules_path}")
        self._rules_path = rules_path

    # ------------------------------------------------------------------

    def scan(self, skill: SkillRecord) -> ScannerVerdict:
        if not skill.package_dir.exists():
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                reasons=[f"package_dir missing: {skill.package_dir}"],
            )

        with tempfile.TemporaryDirectory(prefix="ssr_") as td:
            out_path = Path(td) / f"{skill.skill_id}.json"
            t0 = time.time()
            ok, err = self._run_upstream(skill.package_dir, out_path)
            elapsed = round(time.time() - t0, 3)

            if not ok:
                return ScannerVerdict(
                    scanner=self.name,
                    skill_id=skill.skill_id,
                    classification=CLASS_ERROR,
                    reasons=[f"upstream invocation failed: {err}"],
                    elapsed_sec=elapsed,
                )

            try:
                report = json.loads(out_path.read_text(encoding="utf-8"))
            except Exception as e:
                return ScannerVerdict(
                    scanner=self.name,
                    skill_id=skill.skill_id,
                    classification=CLASS_ERROR,
                    reasons=[f"could not parse upstream report: {e}"],
                    elapsed_sec=elapsed,
                )

        classification, reasons, raw = self._summarize_report(report)
        return ScannerVerdict(
            scanner=self.name,
            skill_id=skill.skill_id,
            classification=classification,
            confidence=raw.get("max_severity_score", 0.0),
            reasons=reasons,
            raw=raw,
            elapsed_sec=elapsed,
        )

    # ------------------------------------------------------------------

    def _run_upstream(self, target: Path, out_path: Path) -> tuple[bool, str]:
        """Shell out to `python -m src.cli scan <target> -f json -o <out>`.

        We `cd` into the upstream path so the tool's relative imports work.
        Output goes to `out_path`; stderr is captured and returned on failure.
        """
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self._upstream_path) + os.pathsep + env.get("PYTHONPATH", "")
        cmd = [
            self._python_bin, "-m", "src.cli", "scan",
            str(target),
            "-f", "json",
            "-o", str(out_path),
            "--severity", self._severity_threshold,
            "--no-color",
        ]
        if self._rules_path is not None:
            cmd.extend(["--rules", str(self._rules_path)])
        try:
            p = subprocess.run(
                cmd,
                cwd=str(self._upstream_path),
                env=env,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except FileNotFoundError as e:
            return False, f"python interpreter not found: {e}"
        except subprocess.TimeoutExpired:
            return False, f"timeout after {self._timeout}s"
        # Some scanners exit non-zero when they FIND issues (via --fail-on).
        # We only care that the JSON report exists.
        if not out_path.exists() and p.returncode != 0:
            return False, f"exit={p.returncode} stderr={(p.stderr or '')[:300]}"
        return True, ""

    def _summarize_report(self, report: Dict[str, Any]) -> tuple[str, List[str], Dict[str, Any]]:
        """Reduce upstream JSON to (classification, reasons[], raw_summary).

        MASB's report shape (verified from analyzer.py:152):

            {
              "risk_score": float,
              "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE",
              "summary": {"CRITICAL": int, "HIGH": int, "WARNING": int, "INFO": int},
              "issues": [{rule_id, severity, file, line, pattern, confidence}, ...],
              "total_files": int,
            }

        We classify primarily from `risk_level` (MASB's own conclusion) and
        cross-check by counting issues case-insensitively (MASB's `summary`
        bucket is case-sensitive on uppercase keys but rule configs in some
        installs use lowercase severities — counting the issues list is
        more robust than trusting the bucketed summary).
        """
        risk_level = (report or {}).get("risk_level") or ""
        risk_score = (report or {}).get("risk_score") or 0.0
        summary = (report or {}).get("summary") or {}
        issues = (report or {}).get("issues") or []
        # Fallback for older MASB versions that nest issues under `files`:
        if not issues:
            for f in (report or {}).get("files", []) or []:
                issues.extend(f.get("issues") or [])

        counts: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "WARNING": 0, "MEDIUM": 0, "INFO": 0, "LOW": 0,
        }
        rule_ids: List[str] = []
        for issue in issues:
            sev = (issue.get("severity") or "").upper()
            if sev in counts:
                counts[sev] += 1
            rid = issue.get("rule_id") or issue.get("rule")
            if rid and rid not in rule_ids:
                rule_ids.append(rid)

        # Map MASB's 5-level risk to our 3-level taxonomy.
        rl = risk_level.upper()
        if rl == "CRITICAL":
            classification = CLASS_MALICIOUS
        elif rl in ("HIGH", "MEDIUM"):
            classification = CLASS_SUSPICIOUS
        elif rl in ("LOW", "SAFE", ""):
            classification = CLASS_SAFE
        else:
            classification = CLASS_SAFE

        reasons: List[str] = [f"risk_level={risk_level} score={risk_score:.1f}"]
        nonzero = [f"{k}={v}" for k, v in counts.items() if v]
        if nonzero:
            reasons.append("issues " + " ".join(nonzero))
        if rule_ids:
            reasons.append("rules=" + ",".join(rule_ids[:6]))

        return classification, reasons, {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "counts": counts,
            "rule_ids": rule_ids,
            "upstream_summary": summary,
            "total_issues": len(issues),
        }
