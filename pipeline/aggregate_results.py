#!/usr/bin/env python3
"""Aggregate per-scanner verdicts into one unified CSV.

Joins on `skill_id` across each scanner's `verdicts.jsonl` and emits
`outputs/unified_results.csv` with one row per skill and one
classification + reasons column per scanner. Bench ground truth (if
present in the work queue) is carried through.

The unified CSV is the file you hand to a downstream evaluation script
(precision/recall vs. ground truth, dataset cards, etc.).
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional

from pipeline._shared import Config, ensure_dir, iter_jsonl
from scanners.registry import list_scanners


def _index_verdicts(jsonl_path: Path) -> Dict[str, dict]:
    """Latest-wins index of {skill_id: verdict_row} from a verdicts.jsonl."""
    out: Dict[str, dict] = {}
    for row in iter_jsonl(jsonl_path):
        sid = row.get("skill_id")
        if not sid:
            continue
        prev = out.get(sid)
        if prev is None or (row.get("ts") or 0) >= (prev.get("ts") or 0):
            out[sid] = row
    return out


def _load_work_queue(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    cfg = Config.load(Path(args.config))
    queue_csv = Path(cfg.get("pipeline.work_queue_csv", "./inputs/work_queue.csv"))
    out_csv = Path(args.out or cfg.get("pipeline.unified_results_csv",
                                       "./outputs/unified_results.csv"))

    queue = _load_work_queue(queue_csv)
    if not queue:
        print(f"[ERROR] work queue not found or empty: {queue_csv}", file=sys.stderr)
        return 1

    # Pull each scanner's verdicts (those with a configured output_dir).
    per_scanner: Dict[str, Dict[str, dict]] = {}
    for name in list_scanners():
        cfg_block = cfg.section(f"scanners.{name}")
        out_dir = Path(cfg_block.get("output_dir", f"./outputs/{name}"))
        verdicts_path = out_dir / "verdicts.jsonl"
        per_scanner[name] = _index_verdicts(verdicts_path)
        print(f"[aggregate] {name}: {len(per_scanner[name])} verdicts "
              f"({verdicts_path})", flush=True)

    # Build rows.
    fields = [
        "skill_id", "repo_id", "repo_key", "package_dir", "relative_path",
        "license_spdx_id", "bench_classification",
    ]
    for name in list_scanners():
        fields += [f"{name}_class", f"{name}_confidence", f"{name}_reasons"]
    fields += ["overall_class"]  # most-severe maliciousness verdict across maliciousness scanners

    ensure_dir(out_csv.parent)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()

        rank = {"MALICIOUS": 3, "SUSPICIOUS": 2, "SAFE": 1, "ERROR": 0, "": -1}
        # Maliciousness pillar is static_rule + llm_filter + behavioral
        # (alignment is a separate axis).
        maliciousness_scanners = ["static_rule", "llm_filter", "behavioral"]

        for q in queue:
            sid = q.get("skill_id") or ""
            row = {
                "skill_id": sid,
                "repo_id": q.get("repo_id") or "",
                "repo_key": q.get("repo_key") or "",
                "package_dir": q.get("package_dir") or "",
                "relative_path": q.get("relative_path") or "",
                "license_spdx_id": q.get("license_spdx_id") or "",
                "bench_classification": q.get("bench_classification") or "",
            }

            best_class = ""
            for name in list_scanners():
                v = per_scanner.get(name, {}).get(sid)
                if not v:
                    row[f"{name}_class"] = ""
                    row[f"{name}_confidence"] = ""
                    row[f"{name}_reasons"] = ""
                    continue
                cls = v.get("classification") or ""
                conf = v.get("confidence")
                reasons = v.get("reasons") or []
                row[f"{name}_class"] = cls
                row[f"{name}_confidence"] = "" if conf is None else f"{conf:.3f}"
                row[f"{name}_reasons"] = " | ".join(str(r) for r in reasons)[:500]

                if name in maliciousness_scanners and rank.get(cls, -1) > rank.get(best_class, -1):
                    best_class = cls

            row["overall_class"] = best_class
            w.writerow(row)

    print(f"[OK] wrote unified_results -> {out_csv}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
