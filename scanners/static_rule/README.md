# static_rule scanner

Cheap, deterministic, local-only first stage. Wraps the upstream
[`skill-security-scan`](https://github.com/.../MaliciousAgentSkillsBench)
CLI and maps its severity output to our common verdict shape:

| Upstream severity | Our classification |
| ----------------- | ------------------ |
| `CRITICAL`        | `MALICIOUS`        |
| `WARNING`         | `SUSPICIOUS`       |
| `INFO` / none     | `SAFE`             |

Runs on **every skill** in the work queue. The orchestrator then uses each
verdict to decide whether to invoke the more expensive downstream scanners
(`llm_filter`, `alignment`, `behavioral`).

## Config (in top-level `config.yaml`)

```yaml
scanners:
  static_rule:
    enabled: true
    upstream_path: /path/to/MaliciousAgentSkillsBench/code/scanner/skill-security-scan
    python_bin: python              # falls back to sys.executable
    severity_threshold: INFO        # lowest severity to record
    timeout_seconds: 60
    output_dir: ./outputs/static_rule
    workers: 8
```

## Why a subprocess wrapper

The upstream tool is a maintained third-party package; we don't want to
fork its rule definitions or pin to internal APIs. Shelling out per skill
gives us:

- **Update for free** when MASB ships new rules — point `upstream_path` at
  the new checkout, no code changes here.
- **Fault isolation** — a buggy rule that crashes the upstream process
  fails one skill, not the whole batch.
- **No import-time cost** — the orchestrator can iterate skills without
  importing the upstream's transitive dependencies.

## Output

Verdicts are appended to `outputs/static_rule/verdicts.jsonl` with the
shape:

```json
{
  "scanner": "static_rule",
  "skill_id": "...",
  "classification": "MALICIOUS",
  "confidence": 4.2,
  "reasons": ["3 CRITICAL", "patterns=cmd_injection,fs_exfil"],
  "raw": {
    "counts": {"CRITICAL": 3, "WARNING": 1, "INFO": 0},
    "patterns": ["cmd_injection", "fs_exfil"],
    "max_severity_score": 4.2,
    "upstream_summary": {...}
  },
  "elapsed_sec": 0.4
}
```
