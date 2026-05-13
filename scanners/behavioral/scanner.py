"""behavioral scanner — sandboxed dynamic execution.

For each skill that the upstream stages still flag as MALICIOUS or
SUSPICIOUS, this scanner launches a fresh Docker container with strace +
tcpdump + (optional) NOVA hooks and runs the skill via Claude Code inside
the sandbox. The shell wrapper at `sandbox/run_skill.sh` does the actual
container lifecycle; this Python class just orchestrates one container
per skill, captures the per-skill log directory, and emits a verdict.

Two important constraints:

1. **The orchestrator must run on a host with Docker installed and must
   not itself be containerized** (Docker-in-Docker complicates the
   capability flags `--cap-add=SYS_ADMIN,NET_ADMIN seccomp=unconfined`
   that `run_skill.sh` requires).

2. **OAuth-only.** The sandbox image runs `claude` inside the container
   and requires the host's `~/.claude/` to be bind-mounted at
   `/root/.claude/`. `run_skill.sh` already does this; the scanner just
   sets `USE_OAUTH=true` in the env it passes to the subprocess.

Verdict mapping: a SAFE / SUSPICIOUS / MALICIOUS classification is derived
from the `behavioral_indicators` produced by the in-sandbox NOVA hooks +
network capture. The full per-skill log directory survives on disk for
audit; the verdict carries only counts + headline reasons.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from pipeline._shared import (
    CLASS_ERROR,
    CLASS_MALICIOUS,
    CLASS_SAFE,
    CLASS_SUSPICIOUS,
    ScannerVerdict,
    SkillRecord,
    append_jsonl,
    assert_claude_oauth_ready,
    iter_jsonl,
)
from pipeline.quota import record_call as _record_quota, wait_for_quota as _wait_for_quota
from scanners.base import Scanner


SANDBOX_DIR = Path(__file__).parent / "sandbox"
SANDBOX_RUN_SH = SANDBOX_DIR / "run_skill.sh"


class BehavioralScanner(Scanner):
    name = "behavioral"
    consumes_classifications = frozenset({CLASS_SUSPICIOUS, CLASS_MALICIOUS})

    def setup(self) -> None:
        if not SANDBOX_RUN_SH.exists():
            raise RuntimeError(f"sandbox runner missing: {SANDBOX_RUN_SH}")
        # Authenticated `claude login` is required because the sandbox
        # mounts ~/.claude into the per-skill container. Fail fast.
        assert_claude_oauth_ready()

        self._sandbox_image = self.scanner_config.get("sandbox_image", "agentskills-sandbox:latest")
        self._exec_timeout = int(self.scanner_config.get("exec_timeout_seconds", 900))
        self._use_nova = str(self.scanner_config.get("use_nova", "true")).lower()
        self._nova_block = str(self.scanner_config.get("nova_block", "false")).lower()
        self._user_prompt = self.scanner_config.get(
            "user_prompt",
            "Read the skill at ~/.claude/skills and execute it.",
        )

        self._exec_logs_root = Path(
            self.scanner_config.get("execution_logs_root", self.output_dir / "execution_logs")
        ).resolve()
        self._exec_logs_root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------

    def scan(self, skill: SkillRecord) -> ScannerVerdict:
        if not skill.package_dir.exists():
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                reasons=[f"package_dir missing: {skill.package_dir}"],
            )

        risk_level = (skill.upstream_data.get("risk_level") or "unknown").lower()
        repo_id = skill.repo_id or "unknown"
        env = os.environ.copy()
        env.update({
            "PROJECT_ROOT": str(SANDBOX_DIR),
            "EXECUTION_LOGS_DIR": str(self._exec_logs_root),
            "SANDBOX_IMAGE": self._sandbox_image,
            "EXEC_TIMEOUT": str(self._exec_timeout),
            "USE_NOVA": self._use_nova,
            "NOVA_BLOCK": self._nova_block,
            # OAuth-only: tell run_skill.sh to bind-mount the host's ~/.claude.
            "USE_OAUTH": "true",
            # Explicit; run_skill.sh otherwise tries ANTHROPIC_API_KEY first.
            "CLAUDE_HOST_DIR": env.get("CLAUDE_HOST_DIR", str(Path.home() / ".claude")),
        })
        # Ensure no leftover API key takes precedence.
        env.pop("ANTHROPIC_API_KEY", None)

        cmd = [
            "bash", str(SANDBOX_RUN_SH),
            skill.skill_id,
            str(skill.package_dir),
            self._user_prompt,
            repo_id,
            risk_level,
            "false",  # IN_PLACE_LOG
        ]

        # Each behavioral run launches `claude --dangerously-skip-permissions`
        # inside the sandbox container — same OAuth subscription, same
        # rolling-5h cap as the host-side llm_filter/alignment calls.
        # Block here so we don't blow past 90% × max_calls / 5h.
        _wait_for_quota()

        t0 = time.time()
        try:
            cp = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=self._exec_timeout + 60,
            )
        except subprocess.TimeoutExpired:
            _record_quota(scanner=self.name, skill_id=skill.skill_id,
                          ok=False, rate_limited=False,
                          elapsed_sec=time.time() - t0)
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                reasons=["sandbox timeout"],
                elapsed_sec=time.time() - t0,
            )
        elapsed = round(time.time() - t0, 2)
        # Each successful (or even failed-after-claude-call) sandbox run
        # consumed one Claude message. Best-effort detection: if the
        # claude session was reached, count one. (run_skill.sh exits 125
        # before claude on docker errors — we detect that and skip.)
        sandbox_reached_claude = (cp.returncode != 125) and ("docker: Error" not in (cp.stdout or ""))
        if sandbox_reached_claude:
            # Surface obvious rate-limit substrings from the in-sandbox
            # claude output so the gate can also wait on behavioral 429s.
            from pipeline.quota import looks_rate_limited as _looks_rl
            rl = _looks_rl((cp.stdout or "")[:8000])
            _record_quota(scanner=self.name, skill_id=skill.skill_id,
                          ok=(cp.returncode == 0) and not rl,
                          rate_limited=rl, elapsed_sec=elapsed)

        log_dir = self._exec_logs_root / risk_level / repo_id / skill.skill_id
        # DEBUG: persist the raw subprocess output so docker daemon errors
        # show up somewhere readable, not just truncated in verdict.reasons.
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            (log_dir / "subprocess_stdout.log").write_text(cp.stdout or "")
        except Exception:
            pass
        # If the in-sandbox claude was rate-limited the skill never actually
        # ran — NOVA + smart_monitor will see no indicators and the default
        # mapping would classify as SAFE, which is a false negative. Force
        # ERROR so a retry pass picks it up.
        from pipeline.quota import looks_rate_limited as _looks_rl
        if _looks_rl((cp.stdout or "")[:8000]):
            return ScannerVerdict(
                scanner=self.name,
                skill_id=skill.skill_id,
                classification=CLASS_ERROR,
                reasons=["rate_limited inside sandbox: skill not executed"],
                raw={"exit_code": cp.returncode, "log_dir": str(log_dir),
                     "indicators": [], "rate_limited": True},
                elapsed_sec=elapsed,
            )
        return self._verdict_from_log_dir(skill, log_dir, cp, elapsed)

    # ------------------------------------------------------------------

    def _verdict_from_log_dir(
        self,
        skill: SkillRecord,
        log_dir: Path,
        cp: subprocess.CompletedProcess,
        elapsed: float,
    ) -> ScannerVerdict:
        ok = (cp.returncode == 0)
        tail = "\n".join((cp.stdout or "").splitlines()[-5:])

        # NOVA hooks + smart_monitor write a few summary files under log_dir;
        # we read whichever exist and union their indicators.
        indicators = self._gather_indicators(log_dir)

        # Classification ladder: any high-severity behavioral indicator →
        # MALICIOUS; any medium → SUSPICIOUS; otherwise SAFE.
        high = [i for i in indicators if i.get("severity") == "high"]
        med  = [i for i in indicators if i.get("severity") == "medium"]
        if not ok and not indicators:
            classification = CLASS_ERROR
        elif high:
            classification = CLASS_MALICIOUS
        elif med:
            classification = CLASS_SUSPICIOUS
        else:
            classification = CLASS_SAFE

        reasons: List[str] = []
        if high:
            reasons.append(f"{len(high)} high-severity behavioral indicators")
        if med:
            reasons.append(f"{len(med)} medium-severity behavioral indicators")
        if tail and classification == CLASS_ERROR:
            reasons.append(tail[:200])

        return ScannerVerdict(
            scanner=self.name,
            skill_id=skill.skill_id,
            classification=classification,
            confidence=min(1.0, 0.6 * len(high) + 0.2 * len(med)),
            reasons=reasons,
            raw={
                "exit_code": cp.returncode,
                "log_dir": str(log_dir),
                "indicators": indicators[:32],
            },
            elapsed_sec=elapsed,
        )

    def _gather_indicators(self, log_dir: Path) -> List[Dict[str, Any]]:
        """Pull behavioral indicators from the per-skill log directory.

        Looks for whichever of these files exist (NOVA mode dependent):
          - nova/report.json         (NOVA-lite or NOVA-full summary)
          - filesystem_changes.json  (smart_monitor snapshot diff)
          - claude_output.txt        (last-resort heuristic on stdout)
        """
        out: List[Dict[str, Any]] = []
        if not log_dir.exists():
            return out

        nova_report = log_dir / "nova" / "report.json"
        if nova_report.exists():
            try:
                payload = json.loads(nova_report.read_text(encoding="utf-8"))
            except Exception:
                payload = None
            if isinstance(payload, dict):
                for ind in (payload.get("indicators") or []):
                    if isinstance(ind, dict):
                        out.append(ind)

        fs_changes = log_dir / "filesystem_changes.json"
        if fs_changes.exists():
            try:
                payload = json.loads(fs_changes.read_text(encoding="utf-8"))
            except Exception:
                payload = None
            if isinstance(payload, dict):
                for path in (payload.get("created") or []):
                    if isinstance(path, str) and any(
                        s in path for s in ("/etc/", "/.ssh/", "/.aws/", "/root/")
                    ):
                        out.append({
                            "kind": "fs_write_sensitive",
                            "severity": "high",
                            "path": path,
                        })

        return out

    # ------------------------------------------------------------------
    # Override scan_batch with a smaller default workers cap because each
    # call launches a Docker container with privileged options.
    # ------------------------------------------------------------------

    def scan_batch(
        self,
        skills: Iterable[SkillRecord],
        *,
        workers: Optional[int] = None,
        verdicts_jsonl: Optional[Path] = None,
        on_done=None,
    ) -> Iterator[ScannerVerdict]:
        if workers is None:
            workers = int(self.scanner_config.get("workers", 3))
        skills_list = list(skills)
        if not skills_list:
            return
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(self._safe_scan, s) for s in skills_list]
            for fut in as_completed(futs):
                v = fut.result()
                if verdicts_jsonl is not None:
                    append_jsonl(verdicts_jsonl, v.to_dict())
                if on_done is not None:
                    on_done(v)
                yield v
