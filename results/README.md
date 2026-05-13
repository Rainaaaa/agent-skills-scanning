# Scanning results — Jetstream A100, 2026-05-13

End-to-end scanning pass against **1,136 skills** that BigRed's
`static_rule` stage had flagged as `SUSPICIOUS` or `MALICIOUS`. The
non-static stages (`llm_filter`, `alignment`, `behavioral`) ran on
the Jetstream A100 host using Claude OAuth, with the quota gate from
`pipeline/quota.py` paging through Claude Max 20x's rolling 5h
window.

## Files

| File | Rows | What |
| --- | --- | --- |
| `unified_results.csv` | 1,136 | One row per skill; columns from every scanner side-by-side + `overall_class` (worst of static + llm_filter + behavioral). The deliverable. |
| `llm_filter_verdicts.jsonl` | 1,842 | Append-only ledger of `llm_filter` runs (~1,134 unique skills, 1.6× rows due to retries across rolling-quota waves). |
| `alignment_verdicts.jsonl` | 421 | Append-only `alignment` runs over the 331 SUSPICIOUS/MALICIOUS skills that survived `llm_filter`. |
| `behavioral_verdicts.jsonl` | 331 | One row per behavioral sandbox launch on the chained subset. |

For the unique-skill view, the orchestrator's
`aggregate_results.py` already deduped into `unified_results.csv`
(latest non-ERROR verdict per `skill_id` wins). The raw `.jsonl`
files are kept for audit / retry tracing.

## Headline numbers (deduplicated by `skill_id`)

| Scanner | Unique skills | Coverage | Breakdown |
| --- | --- | --- | --- |
| `static_rule` (BigRed import) | 1,136 (queue) | 100 % | All flagged upstream |
| `llm_filter` | 1,136 | **99.8 %** | 803 SAFE, 298 SUSPICIOUS, 33 MALICIOUS, 2 ERROR |
| `alignment` | 331 | **100 %** | 137 ALIGNED, 194 MISALIGNED |
| `behavioral` | 331 | **99.7 %** | 330 SAFE, 1 ERROR |
| **`overall_class`** | 1,136 | — | 724 SUSPICIOUS, 412 MALICIOUS |

The `alignment_class` axis is **separate** from the maliciousness
axis by design — see the top-level README's "Why pluggable" /
"What goes into the unified CSV" sections.

## What's NOT here (kept on the scanning host)

- **`raw_responses/`** — full Claude responses (one `.txt` per skill,
  per LLM-using scanner). ~6 MB total for `llm_filter` + `alignment`.
- **`execution_logs/<risk>/<repo>/<skill>/`** — per-skill sandbox
  artifacts: `strace.log`, `network.pcap`, `claude_output.txt`,
  `filesystem_changes.json`, `nova/report.json`. ~1 GB total. Useful
  for re-deriving a verdict or debugging a specific skill; not
  committed because it's large, partly binary, and reproducible by
  re-running the same orchestrator command on the same inputs.

On the Jetstream host that produced these:

```
/media/volume/skills/scanning_outputs/
├── outputs/
│   ├── unified_results.csv                # → copied to results/
│   ├── llm_filter/{verdicts.jsonl, raw_responses/}
│   ├── alignment/{verdicts.jsonl, raw_responses/}
│   └── behavioral/{verdicts.jsonl, execution_logs/}
├── static_rule/verdicts.jsonl             # BigRed rsync; 125 MB
├── quota_ledger.jsonl                     # current 5h window
├── quota_ledger.pre-rescan-*.jsonl        # rotated backups (3 of them)
├── inputs/{skill_status.csv, work_queue.csv}
├── build_skill_status.py                  # one-off helper
└── .venv/                                 # pipeline env
```

## Reproducing

```bash
# On a host with Docker + Claude OAuth (~/.claude/.credentials.json):
git clone https://github.com/Rainaaaa/agent-skills-scanning.git
cd agent-skills-scanning
cp config.example.yaml config.yaml
$EDITOR config.yaml                      # point inputs/outputs at your filesystem
docker build -t agent-skills-scanning .   # OR pip install -r requirements.txt
cd scanners/behavioral/sandbox && \
    docker build --build-arg NOVA_MODE=lite -t agentskills-sandbox -f Dockerfile.sandbox . && \
    cd -

# Generate (or import) the skill_status.csv, then:
python -m pipeline.prepare_inputs --config config.yaml
CLAUDE_QUOTA_THRESHOLD=0.33 \
    python -m pipeline.run_pipeline --config config.yaml \
        --only llm_filter,alignment,behavioral
python -m pipeline.aggregate_results --config config.yaml
```

Quota notes: with Claude Max 20x, **`CLAUDE_QUOTA_THRESHOLD=0.33`**
(≈ 297 ok-calls per 5h) gave clean pause-and-resume behavior on this
dataset. The documented "900 messages/5h" number is for plain chats;
heavy tool-using audits like `llm_filter` consume roughly 3× more
real quota per call.
