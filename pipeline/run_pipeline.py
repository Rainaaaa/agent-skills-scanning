#!/usr/bin/env python3
"""Orchestrator — run scanners in registry order, chained by classification.

Pipeline shape:

    work_queue.csv
        │
        ▼
    static_rule          (every skill in the queue)
        │  → outputs/static_rule/verdicts.jsonl
        │
        ▼ (skills classified SUSPICIOUS or MALICIOUS)
    llm_filter           (Claude OAuth false-positive filter)
        │  → outputs/llm_filter/verdicts.jsonl
        │
        ├──────────────┐ (skills still SUSPICIOUS or MALICIOUS)
        ▼              ▼
    alignment      behavioral     (parallel across scanners; intra-scanner
                                   parallelism inside each)

The two final stages (`alignment` and `behavioral`) operate on the same
input set and run concurrently. They report on **different dimensions**:
maliciousness (behavioral) and intent-alignment (alignment) — both end
up in the unified results table.

Each scanner appends to its own `verdicts.jsonl`; the orchestrator only
threads classification flow between stages and never rewrites a verdict.

Resume semantics: each scanner skips skills that already have a non-ERROR
verdict in its `verdicts.jsonl`, unless `--force` is passed.
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set

from pipeline._shared import (
    CLASS_ERROR,
    CLASS_MALICIOUS,
    CLASS_SAFE,
    CLASS_SUSPICIOUS,
    Config,
    ScannerVerdict,
    SkillRecord,
    append_jsonl,
    ensure_dir,
    iter_jsonl,
)
from scanners.base import Scanner
from scanners.registry import list_scanners, load_enabled_scanners, load_scanner


# Classifications that pass through to the next stage.
PROPAGATE = frozenset({CLASS_SUSPICIOUS, CLASS_MALICIOUS})


def _load_queue(queue_csv: Path) -> List[SkillRecord]:
    out: List[SkillRecord] = []
    with queue_csv.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            sid = (row.get("skill_id") or "").strip()
            pkg = (row.get("package_dir") or "").strip()
            if not sid or not pkg:
                continue
            out.append(SkillRecord(
                skill_id=sid,
                package_dir=Path(pkg),
                repo_id=(row.get("repo_id") or "").strip(),
                repo_key=(row.get("repo_key") or "").strip(),
                relative_path=(row.get("relative_path") or "").strip(),
                upstream_data={
                    "license_spdx_id": (row.get("license_spdx_id") or "").strip(),
                    "bench_classification": (row.get("bench_classification") or "").strip(),
                },
            ))
    return out


def _verdicts_path_for(scanner: Scanner) -> Path:
    return scanner.output_dir / "verdicts.jsonl"


def _existing_classifications(verdicts_path: Path) -> Dict[str, str]:
    """Return {skill_id: classification} for prior non-ERROR verdicts."""
    out: Dict[str, str] = {}
    for row in iter_jsonl(verdicts_path):
        sid = row.get("skill_id")
        cls = row.get("classification")
        if sid and cls and cls != CLASS_ERROR:
            out[sid] = cls
    return out


def _run_one_scanner(
    scanner: Scanner,
    skills: List[SkillRecord],
    *,
    workers: int,
    force: bool,
) -> Dict[str, ScannerVerdict]:
    """Run a scanner over a skill list. Returns {skill_id: verdict}."""
    verdicts_path = _verdicts_path_for(scanner)
    ensure_dir(verdicts_path.parent)

    already: Dict[str, str] = {} if force else _existing_classifications(verdicts_path)
    pending = [s for s in skills if s.skill_id not in already]
    print(
        f"[{scanner.name}] queue={len(skills)} pending={len(pending)} "
        f"already={len(already)} workers={workers}",
        flush=True,
    )

    results: Dict[str, ScannerVerdict] = {}
    # Carry already-computed verdicts forward so downstream stages can
    # filter on this scanner's classification consistently.
    for sid, cls in already.items():
        results[sid] = ScannerVerdict(
            scanner=scanner.name, skill_id=sid, classification=cls,
            reasons=["from cache"],
        )

    if not pending:
        return results

    scanner.setup()
    try:
        n = 0
        t0 = time.time()
        for v in scanner.scan_batch(
            pending, workers=workers, verdicts_jsonl=verdicts_path
        ):
            results[v.skill_id] = v
            n += 1
            if n % 25 == 0 or n == len(pending):
                elapsed = int(time.time() - t0)
                print(
                    f"[{scanner.name}] {n}/{len(pending)} elapsed={elapsed}s",
                    flush=True,
                )
    finally:
        scanner.teardown()

    return results


def _filter_for_next(
    skills: List[SkillRecord],
    verdicts: Dict[str, ScannerVerdict],
    pass_through: FrozenSet[str],
) -> List[SkillRecord]:
    """Keep only skills whose latest verdict's classification is in `pass_through`."""
    out: List[SkillRecord] = []
    for s in skills:
        v = verdicts.get(s.skill_id)
        if v and v.classification in pass_through:
            # Carry the latest classification forward so behavioral can use
            # it for log-dir bucketing (`risk_level`).
            s.upstream_data["risk_level"] = v.classification.lower()
            out.append(s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the scanning pipeline.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--queue", default=None,
                    help="Override pipeline.work_queue_csv from the config.")
    ap.add_argument("--only", default=None,
                    help="Comma-separated list of scanner names to run "
                         f"(otherwise: every enabled one in registry order). "
                         f"Available: {', '.join(list_scanners())}")
    ap.add_argument("--force", action="store_true",
                    help="Ignore existing verdicts and re-scan everything.")
    ap.add_argument("--limit", type=int, default=0,
                    help="Cap the work queue (smoke test).")
    ap.add_argument("--workers", type=int, default=None,
                    help="Override per-scanner workers (otherwise: scanner config).")
    args = ap.parse_args()

    cfg = Config.load(Path(args.config))
    queue_csv = Path(args.queue or cfg.get("pipeline.work_queue_csv", "./inputs/work_queue.csv"))
    if not queue_csv.exists():
        print(f"[ERROR] work queue not found: {queue_csv}", file=sys.stderr)
        print("        Run `python -m pipeline.prepare_inputs` first.", file=sys.stderr)
        return 1

    skills = _load_queue(queue_csv)
    if args.limit:
        skills = skills[: args.limit]
    print(f"[orchestrator] queue size: {len(skills)}", flush=True)

    # Decide which scanners run.
    if args.only:
        wanted = [n.strip() for n in args.only.split(",") if n.strip()]
        scanners = [load_scanner(n, cfg) for n in wanted]
    else:
        scanners = load_enabled_scanners(cfg)
    if not scanners:
        print("[ERROR] no scanners enabled. Set scanners.<name>.enabled = true in config.yaml.",
              file=sys.stderr)
        return 1
    print(f"[orchestrator] scanners: {[s.name for s in scanners]}", flush=True)

    # Workers per scanner: --workers overrides; else scanner config; else 4.
    def _w(s: Scanner) -> int:
        if args.workers is not None:
            return args.workers
        return int(s.scanner_config.get("workers", 4))

    # Stage 1 (entry): always runs on the full queue.
    head, *rest = scanners
    head_verdicts = _run_one_scanner(head, skills, workers=_w(head), force=args.force)

    # Carry skills + verdicts forward through the chain.
    current_skills = skills
    last_verdicts = head_verdicts

    # Determine downstream stages: those that share `consumes_classifications`
    # all run on the same filtered subset, in parallel.
    downstream = list(rest)
    while downstream:
        # The next "level" is one scanner if it's strictly chained, OR
        # multiple scanners if they all consume the same set (parallel level).
        first = downstream[0]
        same_level = [
            s for s in downstream
            if s.consumes_classifications == first.consumes_classifications
        ]
        downstream = downstream[len(same_level):]

        # Filter input for this level based on previous stage's verdicts.
        pass_through = first.consumes_classifications or PROPAGATE
        current_skills = _filter_for_next(current_skills, last_verdicts, pass_through)
        print(
            f"[orchestrator] feeding {len(current_skills)} skills into "
            f"level=[{', '.join(s.name for s in same_level)}]",
            flush=True,
        )
        if not current_skills:
            break

        # Run the same-level scanners in parallel (one ThreadPool slot each).
        # Inside each scanner, scan_batch does its own intra-scanner parallelism.
        if len(same_level) == 1:
            v = _run_one_scanner(same_level[0], current_skills,
                                 workers=_w(same_level[0]), force=args.force)
            last_verdicts = v
        else:
            # When multiple scanners are at the same level, aggregate
            # their verdicts; the next chain stage sees the most-recent
            # classification per skill across all of them.
            level_results: Dict[str, ScannerVerdict] = {}
            with ThreadPoolExecutor(max_workers=len(same_level)) as ex:
                futs = {
                    ex.submit(
                        _run_one_scanner, s, current_skills,
                        workers=_w(s), force=args.force,
                    ): s
                    for s in same_level
                }
                for fut in futs:
                    s = futs[fut]
                    res = fut.result()
                    print(f"[orchestrator] {s.name} done: {len(res)} verdicts", flush=True)
                    # Most-severe-wins merge: MALICIOUS > SUSPICIOUS > SAFE.
                    rank = {CLASS_MALICIOUS: 3, CLASS_SUSPICIOUS: 2, CLASS_SAFE: 1, CLASS_ERROR: 0}
                    for sid, v in res.items():
                        prev = level_results.get(sid)
                        if prev is None or rank.get(v.classification, 0) > rank.get(prev.classification, 0):
                            level_results[sid] = v
            last_verdicts = level_results

    print("[orchestrator] DONE", flush=True)
    print("[orchestrator] Run `python -m pipeline.aggregate_results` to build the unified CSV.",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
