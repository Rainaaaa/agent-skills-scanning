# alignment scanner

Asks Claude (via OAuth) whether a skill's three self-descriptions —
`manifest.json` description, `SKILL.md` YAML frontmatter, and `SKILL.md`
body — are mutually consistent, and whether the body references files
that don't exist in the package.

Alignment is a **separate dimension** from maliciousness. Both are useful:

|                          | aligned        | misaligned                |
| ------------------------ | -------------- | ------------------------- |
| **safe code**            | benign + honest | benign but lying docs    |
| **malicious code**       | openly bad     | malicious + deceptive     |

The "malicious + misaligned" cell is the one defenders care about most —
it's the case where a skill *advertises* something benign and *does*
something dangerous.

## Inputs / scope

The orchestrator calls this scanner on the same skills it sends to
`behavioral`: anything that remains `MALICIOUS` or `SUSPICIOUS` after
`llm_filter`. The two scanners are independent and run in parallel.

## Auth

Run `claude login` once on the host. Same OAuth path as `llm_filter` and
`behavioral`. No API keys.

## Output

The verdict's `raw` payload carries the full alignment record:

```json
{
  "aligned": false,
  "severity": "high",
  "reason": "manifest claims 'list utilities' but body curls a remote shell script and pipes to bash",
  "mismatches": ["body executes shell not mentioned in description"],
  "references_missing": ["scripts/install.sh"],
  "files_in_pkg": ["SKILL.md", "manifest.json"],
  "regex_refs_found": ["scripts/install.sh"]
}
```

The top-level **classification is binary**:

| `aligned`        | `classification` |
| ---------------- | ---------------- |
| `true`           | `ALIGNED`        |
| `false`          | `MISALIGNED`     |

Severity (`low` / `medium` / `high`) is preserved in `raw.severity`, so
downstream filters that want fine-grained policy ("only drop high-
severity misalignment") can still get it without re-running the model.

> **Note** — the alignment column in `unified_results.csv` uses
> `{ALIGNED, MISALIGNED, ERROR}`, distinct from the maliciousness pillar
> columns (`{SAFE, SUSPICIOUS, MALICIOUS, ERROR}`). The two axes use
> different vocabularies on purpose.

## Config

```yaml
scanners:
  alignment:
    enabled: true
    output_dir: ./outputs/alignment
    prompt_file: ./scanners/alignment/prompts/alignment_prompt.txt
    timeout_seconds: 120
    body_limit: 8000     # truncate SKILL.md body to N chars in the prompt
    workers: 4
```
