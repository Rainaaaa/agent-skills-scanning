#!/usr/bin/env python3
"""Build the work queue from upstream `skill_status.csv` (downloader output).

Reads:
  - skill_status.csv (one row per downloaded skill, with `package_dir`,
    `skill_id`, `repo_key`, etc.)
  - optionally, a benchmark_dataset.csv (MASB ground truth) to attach
    `bench_classification` to each row for later evaluation.

Writes:
  - inputs/work_queue.csv with the columns every scanner needs.

The work queue is the single source of truth for "which skills do we
care about right now". Re-running scanners on a different subset is
just `prepare_inputs.py --filter ...` followed by `run_pipeline.py`.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

from pipeline._shared import Config, ensure_dir


def _read_csv(path: Path) -> Iterator[Dict[str, str]]:
    if not path.exists():
        return
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            yield row


def _load_benchmark_index(path: Optional[Path]) -> Dict[tuple, str]:
    """Return {(repo_lc, skill_name_lc): classification} from MASB CSV."""
    if not path or not path.exists():
        return {}
    out: Dict[tuple, str] = {}
    for row in _read_csv(path):
        repo = (row.get("repo") or "").strip().lower()
        name = (row.get("skill_name") or "").strip().lower()
        cls = (row.get("classification") or "").strip().lower()
        if repo and name and cls:
            out[(repo, name)] = cls
    return out


def _row_passes_filter(row: Dict[str, str], status_filter: List[str]) -> bool:
    if not status_filter:
        return True
    return (row.get("status") or "").strip().lower() in {s.lower() for s in status_filter}


def build_queue(
    skill_status_csv: Path,
    benchmark_csv: Optional[Path],
    out_csv: Path,
    *,
    status_filter: Optional[List[str]] = None,
    limit: int = 0,
) -> int:
    """Materialize the queue. Returns row count."""
    bench_index = _load_benchmark_index(benchmark_csv)

    rows_out: List[Dict[str, str]] = []
    for row in _read_csv(skill_status_csv):
        if not _row_passes_filter(row, status_filter or []):
            continue

        skill_id = (row.get("skill_id") or "").strip()
        if not skill_id:
            continue

        package_dir = (row.get("package_dir") or "").strip()
        repo_key = (row.get("repo_key") or "").strip()
        owner = (row.get("owner") or "").strip()
        repo = (row.get("repo") or "").strip()
        relative_path = (row.get("relative_path") or "").strip()
        skill_name = Path(relative_path or skill_id).name.lower()

        bench_cls = bench_index.get((repo.lower(), skill_name), "")

        rows_out.append({
            "skill_id":           skill_id,
            "package_dir":        package_dir,
            "repo_key":           repo_key,
            "repo_id":            f"{owner}/{repo}".strip("/"),
            "owner":              owner,
            "repo":               repo,
            "relative_path":      relative_path,
            "license_spdx_id":    (row.get("license_spdx_id") or "").strip(),
            "bench_classification": bench_cls,
            "downloader_status":  (row.get("status") or "").strip(),
        })

    if limit:
        rows_out = rows_out[:limit]

    ensure_dir(out_csv.parent)
    fields = list(rows_out[0].keys()) if rows_out else [
        "skill_id", "package_dir", "repo_key", "repo_id",
        "owner", "repo", "relative_path", "license_spdx_id",
        "bench_classification", "downloader_status",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows_out:
            w.writerow(r)
    return len(rows_out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the scanning pipeline work queue.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--skill_status_csv", default=None,
                    help="Override config.inputs.user_skill_status_csv.")
    ap.add_argument("--benchmark_csv", default=None,
                    help="Override config.inputs.benchmark_dataset_csv.")
    ap.add_argument("--out", default=None, help="Output CSV path.")
    ap.add_argument("--status_filter", default="ok",
                    help="Comma-separated downloader status values to keep (default: ok).")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    cfg = Config.load(Path(args.config))

    skill_status_csv = Path(args.skill_status_csv or cfg.get("inputs.user_skill_status_csv", ""))
    if not skill_status_csv or not skill_status_csv.exists():
        print(f"[ERROR] skill_status_csv not found: {skill_status_csv}", file=sys.stderr)
        return 1
    benchmark_csv = Path(args.benchmark_csv or cfg.get("inputs.benchmark_dataset_csv", "") or ".")
    if not benchmark_csv.exists():
        benchmark_csv = None

    out_csv = Path(args.out or cfg.get("pipeline.work_queue_csv", "./inputs/work_queue.csv"))
    status_filter = [s.strip() for s in (args.status_filter or "").split(",") if s.strip()]

    n = build_queue(
        skill_status_csv=skill_status_csv,
        benchmark_csv=benchmark_csv,
        out_csv=out_csv,
        status_filter=status_filter,
        limit=args.limit,
    )
    print(f"[OK] wrote {n} rows -> {out_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
