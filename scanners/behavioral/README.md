# behavioral scanner

Sandboxed dynamic execution. For each skill that the upstream stages
still flag as `MALICIOUS` or `SUSPICIOUS`, this scanner launches a fresh
Docker container with `strace` + `tcpdump` + (optional) NOVA hooks and
runs the skill via Claude Code inside the sandbox. Per-skill artifacts
land under `outputs/behavioral/execution_logs/<risk>/<repo>/<skill>/`.

## Two important constraints

1. **Run on a Docker host, not inside a container.** Docker-in-Docker
   complicates the privileged flags
   (`--cap-add=SYS_ADMIN,NET_ADMIN seccomp=unconfined`) that
   `sandbox/run_skill.sh` requires. The pipeline image (top-level
   `Dockerfile`) is fine for the static / llm_filter / alignment
   scanners; this one expects a host with Docker installed.

2. **OAuth-only.** The sandbox image runs `claude` inside the per-skill
   container and needs the host's `~/.claude/` mounted at
   `/root/.claude/`. The scanner sets `USE_OAUTH=true` and unsets any
   `ANTHROPIC_API_KEY` so the only auth path is the one written by
   `claude login`.

## What's in `sandbox/`

| File                       | Purpose                                                 |
| -------------------------- | ------------------------------------------------------- |
| `Dockerfile.sandbox`       | Image used by `run_skill.sh`. Build it on the host.     |
| `run_skill.sh`             | Container lifecycle for one skill.                      |
| `nova_setup.sh`            | NOVA hook installation (in-image).                      |
| `nova-hooks/*.py`          | Pre-/post-tool hooks that record indicators.            |
| `smart_monitor.py`         | Filesystem snapshot + diff.                             |
| `nova-requirements.txt`    | Python deps for NOVA-lite mode.                         |

Build:

```bash
cd scanners/behavioral/sandbox
docker build --build-arg NOVA_MODE=lite -t agentskills-sandbox -f Dockerfile.sandbox .
```

`NOVA_MODE` ∈ `none` | `lite` (default) | `full`. `full` pulls ~2 GB of
ML deps; `lite` is the right pick for almost everyone.

## Verdict mapping

The verdict is built from the **behavioral indicators** the in-sandbox
hooks emit (NOVA `report.json` + `smart_monitor`'s `filesystem_changes.json`):

| Highest indicator severity present | Classification |
| ---------------------------------- | -------------- |
| `high` (writes to `/etc/`, `~/.ssh/`, exfil network calls, …) | `MALICIOUS` |
| `medium`                                                       | `SUSPICIOUS` |
| none                                                           | `SAFE`       |

The full per-skill `execution_logs/` directory survives on disk so a
reviewer can re-derive the verdict or examine `strace.log`,
`network.pcap`, and `claude_output.txt` directly.

## Config

```yaml
scanners:
  behavioral:
    enabled: true
    output_dir: ./outputs/behavioral
    sandbox_image: agentskills-sandbox:latest
    exec_timeout_seconds: 900
    use_nova: true            # NOVA hooks (true/false)
    nova_block: false         # true = block dangerous calls; false = log-only
    user_prompt: "Read the skill at ~/.claude/skills and execute it."
    workers: 3                # parallel containers
    execution_logs_root: ./outputs/behavioral/execution_logs
```

## Running standalone

If you only want to re-run the behavioral stage (e.g. after a sandbox
image rebuild), the orchestrator's `--only behavioral` flag does it:

```bash
python -m pipeline.run_pipeline --config config.yaml --only behavioral
```
