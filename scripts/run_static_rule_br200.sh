#!/bin/bash
#SBATCH -J skills_scan_static_rule
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=16
#SBATCH --time=12:00:00
#SBATCH --mem=16G
#SBATCH -A r00954
#SBATCH --mail-type=END,FAIL
#SBATCH --mail-user=cz1@iu.edu
#SBATCH --output=/N/slate/cz1/GitHub/AgentSkills-OSS/agent-skills-scanning/log/%x_%j.log
#SBATCH --error=/N/slate/cz1/GitHub/AgentSkills-OSS/agent-skills-scanning/log/%x_%j.err

# Run only the cheap, rule-based static_rule scanner on BR200 against the
# already-downloaded skill packages at /N/project/AdversarialModeling/.
#
# This is the FILTER stage of the pipeline. It narrows ~264K skills down
# to whatever subset is SUSPICIOUS or MALICIOUS, which is what we ship to
# Jetstream for the expensive Claude-API + behavioral stages.
#
# Tunables (export via `sbatch --export=...`):
#   WORKERS    parallel scanner workers (default 16, matches --cpus-per-task)
#   LIMIT      cap the work queue for smoke testing (default: full corpus)
#   FORCE      1 = re-scan even skills with existing verdicts
#
# Examples:
#   sbatch run_static_rule_br200.sh
#   sbatch --export=WORKERS=24,LIMIT=1000 run_static_rule_br200.sh   # smoke
#   sbatch --export=FORCE=1 run_static_rule_br200.sh                 # force re-scan

set -uo pipefail

PROJECT_ROOT="/N/slate/cz1/GitHub/AgentSkills-OSS/agent-skills-scanning"

# Conda-free environment bootstrap (avoids `conda activate` hangs on Lustre).
ENV_PREFIX="/N/slate/cz1/conda/envs/AgentSkillsOSS"
export CONDA_PREFIX="${ENV_PREFIX}"
export CONDA_DEFAULT_ENV="AgentSkillsOSS"
export PATH="${ENV_PREFIX}/bin:${PATH}"
PYTHON_BIN="${ENV_PREFIX}/bin/python"

# Inputs — read from /N/project (where downloader landed the packages)
# without copying anything. The downloader's skill_status.csv already
# has absolute /N/project/... paths in `package_dir`.
export AGENTSKILLS_SKILL_STATUS_CSV="/N/slate/cz1/GitHub/AgentSkills-OSS/skills_download/output/skill_status.csv"
export AGENTSKILLS_MASB_PATH="/N/slate/cz1/GitHub/MaliciousAgentSkillsBench/code/scanner/skill-security-scan"

# Outputs land inside the scanning repo's outputs/ tree.
export AGENTSKILLS_WORK_QUEUE="${PROJECT_ROOT}/outputs/work_queue.csv"
export AGENTSKILLS_UNIFIED_RESULTS="${PROJECT_ROOT}/outputs/unified_results.csv"
export AGENTSKILLS_STATIC_RULE_OUT="${PROJECT_ROOT}/outputs/static_rule"

WORKERS="${WORKERS:-16}"
LIMIT="${LIMIT:-}"
FORCE="${FORCE:-0}"

mkdir -p "${PROJECT_ROOT}/outputs/static_rule" "${PROJECT_ROOT}/log"

cd "${PROJECT_ROOT}"

# -----------------------------------------------------------------------------
# Step 1 — build work_queue.csv from skill_status.csv
# -----------------------------------------------------------------------------
echo
echo "[STEP 1/2] prepare_inputs — build work_queue.csv"
echo "[INFO] $(date)"
PREP_ARGS=(--config config.yaml --out "${AGENTSKILLS_WORK_QUEUE}")
[ -n "${LIMIT}" ] && PREP_ARGS+=(--limit "${LIMIT}")

"${PYTHON_BIN}" -u -m pipeline.prepare_inputs "${PREP_ARGS[@]}"
PREP_RC=$?
echo "[STEP 1/2] prepare_inputs exit=${PREP_RC}"
[ ${PREP_RC} -ne 0 ] && exit ${PREP_RC}

echo "[INFO] queue rows: $(wc -l < ${AGENTSKILLS_WORK_QUEUE})"

# -----------------------------------------------------------------------------
# Step 2 — run only the static_rule scanner
# -----------------------------------------------------------------------------
echo
echo "[STEP 2/2] run_pipeline --only static_rule"
echo "[INFO] $(date)"
RUN_ARGS=(--config config.yaml --only static_rule --workers "${WORKERS}")
[ "${FORCE}" = "1" ] && RUN_ARGS+=(--force)
[ -n "${LIMIT}" ] && RUN_ARGS+=(--limit "${LIMIT}")

"${PYTHON_BIN}" -u -m pipeline.run_pipeline "${RUN_ARGS[@]}"
RUN_RC=$?
echo "[STEP 2/2] run_pipeline exit=${RUN_RC}"

echo
echo "[INFO] $(date) — static_rule pass finished."
echo "[INFO] verdicts: ${AGENTSKILLS_STATIC_RULE_OUT}/verdicts.jsonl"
echo
echo "[INFO] classification breakdown:"
"${PYTHON_BIN}" -c "
import json, collections, pathlib
p = pathlib.Path('${AGENTSKILLS_STATIC_RULE_OUT}/verdicts.jsonl')
if p.exists():
    counts = collections.Counter()
    for line in p.open():
        try: counts[json.loads(line).get('classification', '?')] += 1
        except Exception: counts['_bad_line'] += 1
    total = sum(counts.values())
    for k, v in counts.most_common():
        print(f'    {k:12s} {v:>8d}  ({100*v/total:.1f}%)')
    print(f'    {\"TOTAL\":12s} {total:>8d}')
else:
    print('    (no verdicts file)')
"

exit ${RUN_RC}
