#!/usr/bin/env bash
# Optional local cleanup — wipes inputs/outputs + any stray scanner caches
# the pipeline may have left around. Idempotent; safe to re-run.
#
#   bash cleanup_local.sh                # actually delete
#   DRYRUN=1 bash cleanup_local.sh       # preview only

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run() {
  if [ "${DRYRUN:-0}" = "1" ]; then
    echo "[dry-run] $*"
  else
    echo "[run] $*"
    "$@"
  fi
}

cd "$ROOT"

# Outputs (verdicts, raw responses, execution logs)
[ -d outputs ] && run rm -rf outputs && run mkdir -p outputs && run touch outputs/.gitkeep

# Generated work queue
[ -f inputs/work_queue.csv ] && run rm -f inputs/work_queue.csv

# Python + IDE caches
find . -name __pycache__   -type d -prune -exec rm -rf {} + 2>/dev/null || true
find . -name '.ipynb_checkpoints' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find . -name '*.pyc' -delete 2>/dev/null || true

# Backups + tmp
find . -name '*.bak' -delete 2>/dev/null || true
find . -name '*.tmp' -delete 2>/dev/null || true

# Local secrets (gitignored anyway, but wipe to be safe)
[ -f .env ] && run rm -f .env

# The previous skills_scanning/ pipeline tree has been replaced — if you
# have it sitting alongside, delete it manually:
PARENT="$(dirname "$ROOT")"
if [ -d "$PARENT/skills_scanning" ]; then
  cat <<EOF

NOTE: The pre-refactor skills_scanning/ tree still exists at:
    $PARENT/skills_scanning
This new agent-skills-scanning/ replaces it. Delete the old tree with:
    rm -rf $PARENT/skills_scanning
(skipped here so you can review first.)
EOF
fi

echo "[done] cleanup complete."
