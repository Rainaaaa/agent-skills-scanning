# agent-skills-scanning

Pluggable security scanning pipeline for downloaded Claude Code skills.
Layered scanners feed into a single unified verdict CSV. Authentication
to Claude is **OAuth-only** (the credentials written by `claude login`)
— no API keys to juggle, one auth path shared by every LLM-using stage.

```
                 work_queue.csv
                       │
                       ▼
   ┌──────────────────────────────────────────┐
   │  static_rule   (MASB rules; cheap, every │
   │                skill in the queue)       │
   └────────────────┬─────────────────────────┘
                    │ SUSPICIOUS / MALICIOUS
                    ▼
   ┌──────────────────────────────────────────┐
   │  llm_filter    (Claude OAuth; intent     │
   │                alignment + shadow-feature│
   │                detection; cuts FP)       │
   └────────────────┬─────────────────────────┘
                    │ still SUSPICIOUS / MALICIOUS
        ┌───────────┴───────────┐
        ▼                       ▼
 ┌───────────────┐       ┌────────────────────┐
 │  alignment    │       │  behavioral        │
 │  (Claude OAuth│       │  (Docker sandbox + │
 │  consistency  │       │   strace / pcap /  │
 │  audit)       │       │   NOVA hooks; runs │
 │               │       │   the skill via    │
 │               │       │   claude inside)   │
 └───────────────┘       └────────────────────┘
        │                       │
        └──────────┬────────────┘
                   ▼
            unified_results.csv
```

`alignment` and `behavioral` measure **different dimensions** of the
same skill: one asks *"does the skill description match the body?"*,
the other asks *"what does the skill actually do at runtime?"*. Both
columns end up in the unified table.

The maliciousness pillar (`static_rule` + `llm_filter` + `behavioral`)
emits `{SAFE, SUSPICIOUS, MALICIOUS}`; the alignment axis emits a
binary `{ALIGNED, MISALIGNED}`. Mixing severity into alignment hid the
"the binary verdict is what trainers actually want" signal, so we
report severity only inside the verdict's `raw` payload.

## Why pluggable

A new scanner is two changes:

1. Drop `scanners/<your_name>/scanner.py` with a class that subclasses
   `Scanner` and implements `scan(skill: SkillRecord) -> ScannerVerdict`.
2. Add a `scanners.<your_name>` block to `config.yaml` with
   `enabled: true` and any per-scanner settings.

Then register one tuple in `scanners/registry.py`. No orchestrator
changes; the pipeline picks it up automatically. See
[`scanners/static_rule/README.md`](scanners/static_rule/README.md) for
a worked example (it wraps an external CLI tool).

## Layout

```
agent-skills-scanning/
├── README.md                    # this file
├── Dockerfile                   # Pipeline image (static + LLM stages)
├── docker-compose.yml           # prepare / scan / aggregate services
├── docker-entrypoint.sh
├── .dockerignore
├── .gitignore
├── requirements.txt
├── config.yaml                  # Pipeline + scanner registry
├── cleanup_local.sh
│
├── pipeline/                    # Top-level orchestration
│   ├── _shared.py               # IO + config + Claude OAuth wrapper
│   ├── prepare_inputs.py        # Build inputs/work_queue.csv
│   ├── run_pipeline.py          # Run scanners, chained by classification
│   └── aggregate_results.py     # Join verdicts → outputs/unified_results.csv
│
├── scanners/                    # Plug-in scanners (extensible)
│   ├── base.py                  # Scanner ABC + ScannerVerdict
│   ├── registry.py              # Scanner discovery
│   │
│   ├── static_rule/             # Cheap MASB rule-based first stage
│   ├── llm_filter/              # Claude OAuth false-positive filter
│   ├── alignment/               # Claude OAuth intent alignment
│   └── behavioral/              # Sandboxed dynamic execution
│       └── sandbox/             # Per-skill sandbox image
│
├── inputs/                      # gitignored
└── outputs/                     # gitignored
```

## First-time setup

Three steps the first time you clone the repo:

### 1. Authenticate Claude Code

```bash
# Install the CLI on the host (skip inside Docker — the image has it already).
npm install -g @anthropic-ai/claude-code

# Authenticate. Writes ~/.claude/.credentials.json.
claude login

# Sanity check.
claude -p "say hi"
```

After this, every LLM-using scanner (`llm_filter`, `alignment`, and the
`claude` invocation inside the `behavioral` sandbox) uses these
credentials. No API keys touched.

### 2. Make your local config

```bash
cp config.example.yaml config.yaml
```

`config.yaml` is gitignored — your machine-specific paths stay local.
Either edit the file or set the env vars it references:

| Env var                          | What it points at                                            | Required? |
| -------------------------------- | ------------------------------------------------------------ | --------- |
| `AGENTSKILLS_SKILL_STATUS_CSV`   | Downloader output (one row per skill with `package_dir`)      | yes       |
| `AGENTSKILLS_MASB_PATH`          | `MaliciousAgentSkillsBench/code/scanner/skill-security-scan` | yes       |
| `AGENTSKILLS_BENCH_CSV`          | MASB ground truth CSV (for evaluation)                        | optional  |
| `AGENTSKILLS_INPUTS_HOST`        | Host dir mounted at `/app/inputs` (compose only, default `./inputs`)  | optional  |
| `AGENTSKILLS_OUTPUTS_HOST`       | Host dir mounted at `/app/outputs` (compose only, default `./outputs`) | optional  |
| `AGENTSKILLS_MASB_HOST`          | Host MASB checkout mounted at `/opt/masb` (compose only)      | optional  |

The `${VAR:-default}` pattern in `config.example.yaml` means unset vars
fall back to relative paths like `./inputs/skill_status.csv` — useful
when you bind-mount your data over `/app/inputs` in Docker.

### 3. (Optional) Build the behavioral sandbox image

Skip if you only want `static_rule + llm_filter + alignment`. To
include `behavioral`, set `scanners.behavioral.enabled: true` in your
`config.yaml` and:

```bash
cd scanners/behavioral/sandbox
docker build --build-arg NOVA_MODE=lite -t agentskills-sandbox -f Dockerfile.sandbox .
```

## Running

### Local

```bash
pip install -r requirements.txt
python -m pipeline.prepare_inputs --config config.yaml
python -m pipeline.run_pipeline   --config config.yaml
python -m pipeline.aggregate_results --config config.yaml
```

`run_pipeline.py` accepts:

| Flag                | Effect                                                         |
| ------------------- | -------------------------------------------------------------- |
| `--only static_rule,alignment` | Run only the named scanners, ignore `enabled` flags |
| `--force`           | Re-scan everything (default: skip skills with prior verdicts)  |
| `--limit 50`        | Cap the queue (smoke test)                                     |
| `--workers N`       | Override per-scanner worker count                              |

### Docker (static / llm_filter / alignment only)

The image bundles Python 3.12, the click-based MASB scanner stack, and
the official Claude Code CLI. Mount the host's `~/.claude/` so the
container inherits your OAuth credentials.

```bash
docker build -t agent-skills-scanning .

docker compose run --rm prepare
docker compose run --rm scan          # all enabled scanners
docker compose run --rm scan --only static_rule
docker compose run --rm aggregate
```

The `behavioral` scanner is **not** runnable from this image — it
launches privileged Docker containers itself. Run it on a Docker host
directly, with this repo cloned and the env activated. See
[`scanners/behavioral/README.md`](scanners/behavioral/README.md) for
the host-side flow.

## What goes into the unified CSV

`outputs/unified_results.csv` has one row per skill and one
classification + reasons triplet per scanner:

| col                    | meaning                                                      |
| ---------------------- | ------------------------------------------------------------ |
| `skill_id`, `repo_id`  | identity                                                     |
| `package_dir`          | local path scanned                                           |
| `bench_classification` | MASB ground truth, if available (for evaluation)             |
| `static_rule_class`    | `SAFE` / `SUSPICIOUS` / `MALICIOUS` / `ERROR`                |
| `llm_filter_class`     | "                                                            |
| `alignment_class`      | `ALIGNED` / `MISALIGNED` / `ERROR` (binary; separate axis)   |
| `behavioral_class`     | `SAFE` / `SUSPICIOUS` / `MALICIOUS` / `ERROR`                |
| `<scanner>_confidence` | 0–1 float                                                    |
| `<scanner>_reasons`    | short strings (counts, patterns, summary text)               |
| `overall_class`        | most-severe across `static_rule + llm_filter + behavioral`   |

`alignment_class` is intentionally **not folded into `overall_class`**.
A skill can be malicious-and-aligned (rare; openly bad) or
benign-and-misaligned (the docs lie but the code is fine). Keeping the
columns separate lets downstream analysis do its own joining.

## Pipeline guarantees

- **Resumable.** Every scanner skips skills that already have a
  non-ERROR verdict in its `verdicts.jsonl`; pass `--force` to override.
- **Append-only outputs.** Per-scanner `verdicts.jsonl` and raw response
  logs only grow; rolled-up CSVs are written atomically.
- **Loose coupling.** Scanners communicate via the `ScannerVerdict`
  shape and per-scanner `verdicts.jsonl` files. Replacing one scanner
  never requires editing the others.
- **OAuth-only Claude.** `pipeline/_shared.assert_claude_oauth_ready()`
  fails fast if `~/.claude/.credentials.json` is missing — no opaque
  per-skill failures from a half-configured host.

## Configuring inputs

The pipeline expects a CSV from the upstream
[agent-skills-collection](https://github.com/Rainaaaa/agent-skills-collection)
download stage. Point at it via env var…

```bash
export AGENTSKILLS_SKILL_STATUS_CSV=/path/to/skill_status.csv
export AGENTSKILLS_BENCH_CSV=/path/to/MASB/data/skills_dataset.csv   # optional
export AGENTSKILLS_MASB_PATH=/path/to/MaliciousAgentSkillsBench/code/scanner/skill-security-scan
```

…or by editing your local `config.yaml` directly. Both styles work; the
env vars are interpolated at config-load time.

## License + ethics

This pipeline scans potentially malicious code. Run scanners on a
machine you trust to discard results from. The `behavioral` stage
executes the skill in a sandbox; the sandbox has reasonable defaults
but is not a hardened isolation boundary.
