#!/bin/bash
#
# Dynamic Skill Executor v1.0
# Executes skills in Docker sandbox with monitoring
#

set -e

SKILL_NAME="${1:-unknown}"
SKILL_PATH="${2:-}"
USER_PROMPT="${3:-Read the skill and execute it}"
REPO_ID="${4:-unknown}"
RISK_LEVEL="${5:-unknown}"
IN_PLACE_LOG="${6:-false}"

# Configuration
USE_NOVA="${USE_NOVA:-true}"
NOVA_BLOCK="${NOVA_BLOCK:-false}"
TIMEOUT="${EXEC_TIMEOUT:-900}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-agentskills-sandbox:latest}"
USE_OAUTH="${USE_OAUTH:-false}"
HOST_CLAUDE_DIR="${CLAUDE_HOST_DIR:-$HOME/.claude}"

# Auth: OAuth (mount host ~/.claude) OR ANTHROPIC_API_KEY
AUTH_ENV_ARGS=()
OAUTH_MOUNT_ARGS=()
if [ "$USE_OAUTH" = "true" ]; then
    if [ ! -f "$HOST_CLAUDE_DIR/.credentials.json" ]; then
        echo "Error: USE_OAUTH=true but $HOST_CLAUDE_DIR/.credentials.json missing. Run 'claude login' first."
        exit 1
    fi
    OAUTH_MOUNT_ARGS=(-v "$HOST_CLAUDE_DIR:/host_claude:ro")
elif [ -n "$ANTHROPIC_API_KEY" ] && [ "$ANTHROPIC_API_KEY" != "oauth-mode" ]; then
    AUTH_ENV_ARGS=(-e "ANTHROPIC_AUTH_TOKEN=$ANTHROPIC_API_KEY")
else
    echo "Error: set ANTHROPIC_API_KEY or USE_OAUTH=true"
    exit 1
fi

# Determine log directory
if [ "$IN_PLACE_LOG" = "true" ]; then
    TEST_DIR="${SKILL_PATH}/execution_records"
else
    TEST_DIR="${EXECUTION_LOGS_DIR}/${RISK_LEVEL}/${REPO_ID}/${SKILL_NAME}"
fi

mkdir -p "$TEST_DIR"

echo "=== Dynamic Skill Executor v1.0 ==="
echo "Skill: $SKILL_NAME"
echo "Repo: $REPO_ID"
echo "Risk: $RISK_LEVEL"
echo "Log Dir: $TEST_DIR"

# Get UID/GID for proper file permissions
HOST_UID=$(id -u)
HOST_GID=$(id -g)

# Generate unique container name
CONTAINER_NAME="skill-exec-${SKILL_NAME}-${REPO_ID}-$$"

# Set mount arguments based on log mode
if [ "$IN_PLACE_LOG" = "true" ]; then
    SKILL_PARENT_DIR="$(dirname "$SKILL_PATH")"
    SKILL_BASENAME="$(basename "$SKILL_PATH")"
    TEST_DIR_MOUNT="/app/skill_parent/${SKILL_BASENAME}/execution_records"
    LOG_MOUNT_ARG=(-v "$SKILL_PARENT_DIR:/app/skill_parent")
else
    LOG_MOUNT_ARG=(-v "${EXECUTION_LOGS_DIR}:/app/logs")
    TEST_DIR_MOUNT="/app/logs/${RISK_LEVEL}/${REPO_ID}/${SKILL_NAME}"
fi

# Run Docker container
docker run --rm -i \
    --name "$CONTAINER_NAME" \
    --user 0:0 \
    --cap-add=SYS_ADMIN \
    --cap-add=NET_ADMIN \
    --security-opt seccomp=unconfined \
    "${LOG_MOUNT_ARG[@]}" \
    "${OAUTH_MOUNT_ARGS[@]}" \
    "${AUTH_ENV_ARGS[@]}" \
    -v "${PROJECT_ROOT}/nova_setup.sh:/nova_setup.sh:ro" \
    -v "${PROJECT_ROOT}/smart_monitor.py:/smart_monitor.py:ro" \
    -v "$SKILL_PATH:/skill_source:ro" \
    -w /tmp \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    -e ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-https://api.anthropic.com}" \
    -e SKILL_NAME="$SKILL_NAME" \
    -e USER_PROMPT="$USER_PROMPT" \
    -e TEST_DIR="$TEST_DIR_MOUNT" \
    -e USE_NOVA="$USE_NOVA" \
    -e NOVA_BLOCK="$NOVA_BLOCK" \
    -e USE_OAUTH="$USE_OAUTH" \
    -e TIMEOUT="$TIMEOUT" \
    "$SANDBOX_IMAGE" bash -c '

    # Realign appuser UID/GID to host so mounted volumes are writable
    if id -u appuser >/dev/null 2>&1; then
        groupmod -g "$HOST_GID" appuser 2>/dev/null || true
        usermod -u "$HOST_UID" -g "$HOST_GID" appuser 2>/dev/null || true
    else
        groupadd -g "$HOST_GID" appuser
        useradd -m -u "$HOST_UID" -g "$HOST_GID" -s /bin/bash appuser
    fi
    chown -R "$HOST_UID:$HOST_GID" /home/appuser 2>/dev/null || true
    mkdir -p "$TEST_DIR"
    chown -R appuser:appuser "$TEST_DIR"

    export HOME="/home/appuser"
    export APPUSER_HOME="/home/appuser"

    # Initialize NOVA
    if [ "$USE_NOVA" = "true" ]; then
        /nova_setup.sh "$APPUSER_HOME" "$([ "$NOVA_BLOCK" = "true" ] && echo "block" || echo "monitor")"
        export NOVA_REPORT_DIR="$TEST_DIR/nova"
        mkdir -p "$NOVA_REPORT_DIR"
        chown appuser:appuser "$NOVA_REPORT_DIR"
        echo "[NOVA] Initialized"
    fi

    # Copy skill
    mkdir -p "$APPUSER_HOME/.claude/"{skills,todos,cache,debug}
    echo "{\"hasCompletedOnboarding\": true}" > "$APPUSER_HOME/.claude.json"
    cp -r /skill_source "$APPUSER_HOME/.claude/skills/'"$SKILL_NAME"'"
    if [ "$USE_OAUTH" = "true" ] && [ -f /host_claude/.credentials.json ]; then
        cp /host_claude/.credentials.json "$APPUSER_HOME/.claude/.credentials.json"
        chmod 600 "$APPUSER_HOME/.claude/.credentials.json"
    fi
    chown -R appuser:appuser "$APPUSER_HOME/.claude" "$APPUSER_HOME/.claude.json"

    cd "$APPUSER_HOME"

    # Start tcpdump
    echo "[Monitor] Starting tcpdump..."
    tcpdump -i any -w "$TEST_DIR/network.pcap" -s 0 2>/dev/null &
    TCPDUMP_PID=$!

    # File system snapshot
    echo "[Monitor] Creating baseline snapshot..."
    python3 /smart_monitor.py snapshot /tmp/fs_state.json "$APPUSER_HOME"

    # Execute skill
    echo ""
    echo "=========================================="
    echo "Executing Skill (timeout: '${TIMEOUT}s')"
    echo "=========================================="

    STRACE_LOG="$TEST_DIR/strace.log"
    STRACE_OPTS="-f -s 2000 -e trace=open,openat,creat,write,unlink,rename,mkdir,rmdir,execve,connect,accept,sendto,recvfrom"

    strace $STRACE_OPTS -o "$STRACE_LOG" \
    su appuser -c "cd $APPUSER_HOME && echo \"${USER_PROMPT}\" | stdbuf -oL timeout ${TIMEOUT}s claude --dangerously-skip-permissions" 2>&1 | tee -a "$TEST_DIR/claude_output.txt"

    EXIT_CODE=${PIPESTATUS[0]}

    echo ""
    if [ $EXIT_CODE -eq 124 ]; then
        echo "Warning: Execution timeout (${TIMEOUT}s)"
    else
        echo "Execution complete (exit code: $EXIT_CODE)"
    fi

    kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null

    # Collect NOVA reports
    if [ "$USE_NOVA" = "true" ]; then
        echo "[NOVA] Collecting reports..."
        NOVA_SRC="/home/appuser/.nova-protector/reports"
        NOVA_DEST="$TEST_DIR/nova"

        for i in {1..15}; do
            if [ -d "$NOVA_SRC" ] && [ "$(ls -A $NOVA_SRC 2>/dev/null)" ]; then
                cp -r "$NOVA_SRC"/. "$NOVA_DEST/" 2>/dev/null
                echo "[NOVA] Reports collected"
                break
            fi
            sleep 2
        done
    fi

    # File system diff
    echo "[Monitor] Analyzing file changes..."
    python3 /smart_monitor.py diff /tmp/fs_state.json "$APPUSER_HOME" "$TEST_DIR"

    echo "=========================================="
    echo "Execution Complete"
    echo "=========================================="
'

echo ""
echo "Done: $TEST_DIR"
