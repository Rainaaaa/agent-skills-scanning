#!/usr/bin/env bash
# Dispatch to a pipeline script.
#
#   docker run --rm agent-skills-scanning pipeline/prepare_inputs.py
#   docker run --rm agent-skills-scanning pipeline/run_pipeline.py
#   docker run --rm agent-skills-scanning pipeline/aggregate_results.py
#
# `claude --version` works once you've mounted the host's ~/.claude/.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  set -- --help
fi

case "$1" in
  --help|-h)
    cat <<'EOF'
agent-skills-scanning container

Pipeline entry points (each accepts --help for full flags):

    pipeline/prepare_inputs.py     # Build inputs/work_queue.csv
    pipeline/run_pipeline.py       # Run scanners (static_rule → llm_filter → alignment)
    pipeline/aggregate_results.py  # Join verdicts → outputs/unified_results.csv

Scanner-aware flags:

    pipeline/run_pipeline.py --only static_rule          # one scanner
    pipeline/run_pipeline.py --only static_rule,alignment
    pipeline/run_pipeline.py --force                     # re-scan everything
    pipeline/run_pipeline.py --limit 50                  # smoke test

This image does NOT run the `behavioral` scanner — that one launches
Docker containers itself and must run on a host with Docker installed.

Mount these from the host:
    -v $(pwd)/inputs:/app/inputs                # work queue (read-write)
    -v $(pwd)/outputs:/app/outputs              # verdicts + raw responses
    -v $HOME/.claude:/root/.claude:ro           # Claude Code OAuth (REQUIRED for llm_filter / alignment)
    -v /path/to/MaliciousAgentSkillsBench:/opt/masb:ro    # MASB checkout (for static_rule.upstream_path)
EOF
    exit 0
    ;;
esac

# Same dispatch rule as agent-skills-collection: a path ending in .py is
# run with python -u; anything else is exec'd verbatim.
script="$1"; shift
if [[ "$script" == *.py ]]; then
  if [ -f "/app/$script" ]; then
    cd /app
    exec python -u "$script" "$@"
  fi
  if [ -f "$script" ]; then
    exec python -u "$script" "$@"
  fi
  echo "[entrypoint] python script not found: $script" >&2
  exit 64
fi

exec "$script" "$@"
