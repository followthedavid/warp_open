#!/bin/bash
#
# Autonomous Developer Runner
#
# This script runs Claude Code in an infinite loop, processing tasks from:
# 1. task_queue.json (local queue)
# 2. ChatGPT (fetches new tasks when queue is empty)
#
# Usage:
#   ./run_autonomous.sh              # Run forever
#   ./run_autonomous.sh --once       # Run one task then exit
#   ./run_autonomous.sh --dry-run    # Show what would run without executing
#
# To stop: Ctrl+C or kill the process
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TASK_QUEUE="$SCRIPT_DIR/task_queue.json"
LOG_FILE="$SCRIPT_DIR/.autonomous.log"
THREAD_ID="693f18ee-0290-8329-956d-2f873f9308b4"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    local level=$1
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${msg}" | tee -a "$LOG_FILE"
}

# Check dependencies
check_deps() {
    if ! command -v claude &> /dev/null; then
        log "${RED}ERROR${NC}" "Claude Code CLI not found. Install with: npm install -g @anthropic-ai/claude-code"
        exit 1
    fi
    if ! command -v jq &> /dev/null; then
        log "${YELLOW}WARN${NC}" "jq not found. Install with: brew install jq"
        # Continue anyway, we can work without it
    fi
}

# Get next task from queue
get_next_task() {
    if command -v jq &> /dev/null; then
        local task=$(jq -r '.pending[0] // empty' "$TASK_QUEUE" 2>/dev/null)
        if [ -n "$task" ] && [ "$task" != "null" ]; then
            echo "$task"
        fi
    else
        # Fallback: grep for first pending task
        grep -A5 '"pending"' "$TASK_QUEUE" | grep '"title"' | head -1 | sed 's/.*"title": *"\([^"]*\)".*/\1/'
    fi
}

# Move task to in-progress
start_task() {
    local task_id=$1
    if command -v jq &> /dev/null; then
        local temp=$(mktemp)
        jq --arg id "$task_id" '
            .inProgress += [.pending[] | select(.id == $id)] |
            .pending = [.pending[] | select(.id != $id)]
        ' "$TASK_QUEUE" > "$temp" && mv "$temp" "$TASK_QUEUE"
    fi
}

# Move task to completed
complete_task() {
    local task_id=$1
    if command -v jq &> /dev/null; then
        local temp=$(mktemp)
        jq --arg id "$task_id" --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
            .completed += [.inProgress[] | select(.id == $id) | . + {completedAt: $time}] |
            .inProgress = [.inProgress[] | select(.id != $id)]
        ' "$TASK_QUEUE" > "$temp" && mv "$temp" "$TASK_QUEUE"
    fi
}

# Fetch new task from ChatGPT
fetch_from_chatgpt() {
    log "${BLUE}INFO${NC}" "Fetching next task from ChatGPT..."
    local response=$(node "$SCRIPT_DIR/chatgpt_thread_manager.cjs" send "$THREAD_ID" \
        "The task queue is empty. What's the next priority task for Warp_Open? Respond with a single, specific, actionable task." 2>&1)
    echo "$response"
}

# Run Claude Code with a task
run_claude() {
    local task_title="$1"
    local task_desc="$2"

    log "${GREEN}INFO${NC}" "Running Claude Code for: $task_title"

    local prompt="You are autonomously developing Warp_Open (Tauri + Vue 3 terminal app).

TASK: $task_title
DETAILS: $task_desc

Instructions:
1. Implement this task completely
2. Make reasonable decisions - do NOT ask questions
3. Run 'npm run build' and 'cargo build' to verify
4. Provide a summary when done

Current directory: $SCRIPT_DIR
Begin implementation now."

    # Run Claude with auto-accept permissions
    claude --dangerously-skip-permissions -p "$prompt"
}

# Main loop
main() {
    local run_once=false
    local dry_run=false

    for arg in "$@"; do
        case $arg in
            --once) run_once=true ;;
            --dry-run) dry_run=true ;;
        esac
    done

    check_deps

    log "${GREEN}INFO${NC}" "=== Autonomous Developer Started ==="
    log "${BLUE}INFO${NC}" "Project: $SCRIPT_DIR"
    log "${BLUE}INFO${NC}" "Task Queue: $TASK_QUEUE"

    while true; do
        # Get next task
        local task=$(get_next_task)

        if [ -z "$task" ]; then
            log "${YELLOW}INFO${NC}" "No pending tasks in queue"

            # Fetch from ChatGPT
            fetch_from_chatgpt

            sleep 30
            continue
        fi

        local task_id=$(echo "$task" | jq -r '.id // "unknown"' 2>/dev/null || echo "1")
        local task_title=$(echo "$task" | jq -r '.title // "Unknown task"' 2>/dev/null || echo "$task")
        local task_desc=$(echo "$task" | jq -r '.description // ""' 2>/dev/null || echo "")

        log "${GREEN}INFO${NC}" "Next task: $task_title (ID: $task_id)"

        if [ "$dry_run" = true ]; then
            log "${YELLOW}DRY-RUN${NC}" "Would execute: $task_title"
        else
            start_task "$task_id"
            run_claude "$task_title" "$task_desc"
            complete_task "$task_id"
        fi

        if [ "$run_once" = true ]; then
            log "${GREEN}INFO${NC}" "Single task mode, exiting."
            break
        fi

        log "${BLUE}INFO${NC}" "Waiting 10 seconds before next task..."
        sleep 10
    done
}

# Run
main "$@"
