#!/bin/bash
#SBATCH -J ship_flagged_jetstream
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --time=02:00:00
#SBATCH --mem=8G
#SBATCH -A r00954
#SBATCH --mail-type=END,FAIL
#SBATCH --mail-user=cz1@iu.edu
#SBATCH --output=/N/slate/cz1/GitHub/AgentSkills-OSS/agent-skills-scanning/log/%x_%j.log
#SBATCH --error=/N/slate/cz1/GitHub/AgentSkills-OSS/agent-skills-scanning/log/%x_%j.err

# Ship only the SUSPICIOUS/MALICIOUS skills from a completed static_rule
# pass to a remote scanning host (e.g. Jetstream).
#
# Reads:
#   outputs/static_rule/verdicts.jsonl  ← shortlist source (from agent-skills-scanning)
#   skill_status.csv                    ← skill_id → package_dir lookup
#
# Produces on the remote host (under DEST_DIR):
#   flagged_packages.tar.gz             ← 2.7K-ish dirs (~tens of MB compressed)
#   flagged_skill_status.csv            ← CSV with package_dir rewritten to remote layout
#   verdicts_static_rule.jsonl          ← copy of the source verdicts
#
# After transfer on the remote:
#   cd /media/volume/skills && tar -xzf flagged_packages.tar.gz
#   → /media/volume/skills/skill_packages/<skill_id>/... layout matches the CSV
#
# Knobs (export via `sbatch --export=...`):
#   DEST_HOST     SSH target            (default exouser@149.165.154.69)
#   DEST_DIR      remote destination    (default /media/volume/skills)
#   PKG_SUBDIR    subdir under DEST_DIR for unpacked packages (default skill_packages)
#   VERDICTS      override verdicts source path
#   SKILL_STATUS  override skill_status.csv path
#   CLASSES       comma-separated classes to include (default MALICIOUS,SUSPICIOUS)
#   DRY_RUN       1 = build the bundle locally but skip rsync

set -uo pipefail

PROJECT_ROOT="/N/slate/cz1/GitHub/AgentSkills-OSS/agent-skills-scanning"
ENV_PREFIX="/N/slate/cz1/conda/envs/AgentSkillsOSS"
PYTHON_BIN="${ENV_PREFIX}/bin/python"

DEST_HOST="${DEST_HOST:-exouser@149.165.154.69}"
DEST_DIR="${DEST_DIR:-/media/volume/skills}"
PKG_SUBDIR="${PKG_SUBDIR:-skill_packages}"
VERDICTS="${VERDICTS:-${PROJECT_ROOT}/outputs/static_rule/verdicts.jsonl}"
SKILL_STATUS="${SKILL_STATUS:-/N/slate/cz1/GitHub/AgentSkills-OSS/skills_download/output/skill_status.csv}"
CLASSES="${CLASSES:-MALICIOUS,SUSPICIOUS}"
DRY_RUN="${DRY_RUN:-0}"

STAGE_DIR="/N/slate/cz1/flagged_xfer_${SLURM_JOB_ID:-local}"
mkdir -p "${STAGE_DIR}/skill_packages" "${PROJECT_ROOT}/log"

echo "[INFO] $(date)"
echo "[INFO] verdicts:    ${VERDICTS}"
echo "[INFO] skill_status:${SKILL_STATUS}"
echo "[INFO] classes:     ${CLASSES}"
echo "[INFO] dest:        ${DEST_HOST}:${DEST_DIR}/${PKG_SUBDIR}/"
echo "[INFO] stage:       ${STAGE_DIR}"

# -----------------------------------------------------------------------------
# Step 0 — pre-flight SSH
# -----------------------------------------------------------------------------
echo
echo "[STEP 0/4] Pre-flight SSH"
if ! ssh -o BatchMode=yes -o ConnectTimeout=20 "${DEST_HOST}" \
        "mkdir -p ${DEST_DIR}/${PKG_SUBDIR} && df -h ${DEST_DIR}" ; then
  echo "[ERROR] SSH to ${DEST_HOST} failed."
  exit 2
fi

# -----------------------------------------------------------------------------
# Step 1 — derive shortlist (skill_id, package_dir) from verdicts + skill_status
# -----------------------------------------------------------------------------
echo
echo "[STEP 1/4] Build flagged shortlist"
"${PYTHON_BIN}" - <<PY
import csv, json, sys
from pathlib import Path

verdicts_path = Path("${VERDICTS}")
status_path   = Path("${SKILL_STATUS}")
classes       = set(c.strip() for c in "${CLASSES}".split(",") if c.strip())
out_csv       = Path("${STAGE_DIR}/flagged_skill_status.csv")
shortlist_txt = Path("${STAGE_DIR}/flagged_skill_ids.txt")

if not verdicts_path.exists():
    sys.exit(f"verdicts file missing: {verdicts_path}")
if not status_path.exists():
    sys.exit(f"skill_status.csv missing: {status_path}")

# 1) collect flagged ids + their static-rule classification + reasons
flagged = {}  # skill_id -> {classification, reasons, raw_summary}
with verdicts_path.open() as f:
    for line in f:
        v = json.loads(line)
        if v.get("classification") in classes:
            flagged[v["skill_id"]] = {
                "static_classification": v["classification"],
                "static_reasons":        " | ".join(v.get("reasons", [])),
                "static_risk_level":     (v.get("raw") or {}).get("risk_level", ""),
                "static_risk_score":     (v.get("raw") or {}).get("risk_score", 0.0),
            }
print(f"  flagged skills in verdicts: {len(flagged)}")

# 2) join with skill_status to get package_dir + repo info
rows = []
missing = 0
with status_path.open(newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        sid = (row.get("skill_id") or "").strip()
        if sid in flagged:
            pkg_dir = (row.get("package_dir") or "").strip()
            if not pkg_dir or not Path(pkg_dir).exists():
                missing += 1
                continue
            row["static_classification"] = flagged[sid]["static_classification"]
            row["static_risk_level"]     = flagged[sid]["static_risk_level"]
            row["static_risk_score"]     = str(flagged[sid]["static_risk_score"])
            row["static_reasons"]        = flagged[sid]["static_reasons"]
            # rewrite package_dir to the remote layout (after tar unpack)
            row["package_dir"] = f"${DEST_DIR}/${PKG_SUBDIR}/" + Path(pkg_dir).name
            rows.append(row)

if not rows:
    sys.exit("no flagged skills resolved to existing package_dirs — nothing to ship")

# 3) write the rewritten CSV + a plain skill_ids list
fieldnames = list(rows[0].keys())
with out_csv.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)

with shortlist_txt.open("w") as f:
    for r in rows:
        f.write(r["skill_id"] + "\n")

print(f"  shortlist CSV rows: {len(rows)}  (missing package_dirs skipped: {missing})")
print(f"  wrote: {out_csv}")
print(f"  wrote: {shortlist_txt}")
PY
PY_RC=$?
[ ${PY_RC} -ne 0 ] && exit ${PY_RC}

# -----------------------------------------------------------------------------
# Step 2 — copy the flagged package dirs into the staging tree
# -----------------------------------------------------------------------------
echo
echo "[STEP 2/4] Copy flagged package dirs into staging tree"
COPIED=0
MISSING=0
PACKAGES_ROOT="/N/project/AdversarialModeling/agent_skills/packages"
while IFS= read -r sid; do
  src="${PACKAGES_ROOT}/${sid}"
  if [ -d "${src}" ]; then
    cp -a "${src}" "${STAGE_DIR}/skill_packages/"
    COPIED=$((COPIED + 1))
  else
    MISSING=$((MISSING + 1))
  fi
done < "${STAGE_DIR}/flagged_skill_ids.txt"
echo "  copied=${COPIED}  missing=${MISSING}"

# Also copy the source verdicts so the remote has the audit trail
cp "${VERDICTS}" "${STAGE_DIR}/verdicts_static_rule.jsonl"

# -----------------------------------------------------------------------------
# Step 3 — tar+pigz the bundle
# -----------------------------------------------------------------------------
echo
echo "[STEP 3/4] Tar+pigz the bundle"
TAR="${STAGE_DIR}/flagged_packages.tar.gz"
tar -C "${STAGE_DIR}" --use-compress-program="pigz -p 8" \
    -cf "${TAR}" skill_packages
ls -lh "${TAR}" "${STAGE_DIR}/flagged_skill_status.csv" "${STAGE_DIR}/verdicts_static_rule.jsonl"

# -----------------------------------------------------------------------------
# Step 4 — rsync to the remote
# -----------------------------------------------------------------------------
echo
echo "[STEP 4/4] rsync to ${DEST_HOST}:${DEST_DIR}"
if [ "${DRY_RUN}" = "1" ]; then
  echo "[DRY_RUN] would transfer:"
  echo "         ${TAR}"
  echo "         ${STAGE_DIR}/flagged_skill_status.csv"
  echo "         ${STAGE_DIR}/verdicts_static_rule.jsonl"
else
  rsync -avP --partial --partial-dir=.rsync-partial --compress \
      "${TAR}" \
      "${STAGE_DIR}/flagged_skill_status.csv" \
      "${STAGE_DIR}/verdicts_static_rule.jsonl" \
      "${DEST_HOST}:${DEST_DIR}/"

  echo
  echo "[STEP 4/4] Unpack on remote"
  ssh "${DEST_HOST}" "cd ${DEST_DIR} && rm -rf ${PKG_SUBDIR}.old && \
      ( [ -d ${PKG_SUBDIR} ] && mv ${PKG_SUBDIR} ${PKG_SUBDIR}.old ) ; \
      tar -xzf flagged_packages.tar.gz && \
      ls ${PKG_SUBDIR} | wc -l | xargs -I{} echo '[remote] unpacked {} package dirs' && \
      ls -lh flagged_skill_status.csv verdicts_static_rule.jsonl"
fi

# -----------------------------------------------------------------------------
# Cleanup local staging
# -----------------------------------------------------------------------------
if [ "${DRY_RUN}" != "1" ]; then
  echo
  echo "[INFO] cleaning up ${STAGE_DIR}"
  rm -rf "${STAGE_DIR}"
fi

echo "[INFO] $(date) — ship_flagged finished."
