# llm_filter scanner

Claude OAuth-based **false-positive filter** that runs after `static_rule`.
The static scanner is high-recall but mid-precision — many of its
SUSPICIOUS / MALICIOUS hits turn out to be benign once a model reasons
about intent alignment and shadow features. This stage cuts those down.

## Inputs / outputs

| | |
|---|---|
| **Consumes** | skills classified `SUSPICIOUS` or `MALICIOUS` by `static_rule` |
| **Produces** | a verdict in `{SAFE, SUSPICIOUS, MALICIOUS, ERROR}` |
| **LLM**     | Claude Code CLI via OAuth (no API keys) |

## Auth

Run `claude login` once on the host. Credentials live at
`~/.claude/.credentials.json`. The scanner calls
`claude -p <prompt> --output-format text` per skill; the CLI uses its
built-in tools (Read, Glob, Grep) to inspect the skill package.

If you're running inside Docker, mount the host's `~/.claude/` into the
container at `/root/.claude/` (the compose file does this).

## Prompt

[`prompts/audit_prompt.txt`](prompts/audit_prompt.txt) is the MASB audit
prompt verbatim (intent alignment + shadow-feature detection + zero-
false-positive rules + strict JSON output schema).

The scanner appends a small **target-path hint** at the end so the model
knows *which* directory to inspect with its file tools.

## Output schema

The model returns this JSON; the wrapper extracts:

- `audit_summary.intent_alignment_status` → our `classification`
- `vulnerabilities[].risk_level` counts → `reasons` and `confidence`
- full `audit_summary` and capped `vulnerabilities` → `raw`

Raw responses are written verbatim to
`outputs/llm_filter/raw_responses/<skill_id>.txt` for audit.

## Config

```yaml
scanners:
  llm_filter:
    enabled: true
    output_dir: ./outputs/llm_filter
    prompt_file: ./scanners/llm_filter/prompts/audit_prompt.txt
    timeout_seconds: 180
    workers: 4         # claude CLI is single-threaded; tune to your rate limit
```

## Why subprocess instead of the SDK

Three reasons: shared OAuth path with the alignment + behavioral scanners;
the CLI provides file-reading tools the prompt requires; and avoiding
API-key juggling lets the user authenticate once with `claude login`.
