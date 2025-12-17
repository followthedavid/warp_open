#!/bin/bash
#
# Start Autonomous Development Loop
#
# Runs two processes in parallel:
# 1. autonomous_loop.cjs - Talks to ChatGPT, gets new tasks, reports completions
# 2. claude_task_runner.cjs - Picks up tasks, runs Claude Code to implement them
#
# The loop is:
#   ChatGPT suggests tasks → task_queue.json → Claude implements → reports back → repeat
#
# Usage:
#   ./start_autonomous_dev.sh
#   ./start_autonomous_dev.sh --thread <thread_id>
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "═══════════════════════════════════════════════════════════"
echo "       Autonomous Development System"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  ChatGPT ←→ task_queue.json ←→ Claude Code"
echo ""
echo "  Starting two parallel processes:"
echo "    1. ChatGPT Loop (gets ideas, reports progress)"
echo "    2. Claude Runner (implements tasks)"
echo ""
echo "  Press Ctrl+C to stop both"
echo "───────────────────────────────────────────────────────────"
echo ""

# Parse arguments
THREAD_ARG=""
if [ "$1" = "--thread" ] || [ "$1" = "-t" ]; then
  THREAD_ARG="--thread $2"
fi

# Cleanup function
cleanup() {
  echo ""
  echo "Stopping autonomous development..."
  kill $LOOP_PID 2>/dev/null || true
  kill $RUNNER_PID 2>/dev/null || true
  exit 0
}

trap cleanup SIGINT SIGTERM

# Start ChatGPT loop in background
echo "Starting ChatGPT loop..."
node autonomous_loop.cjs $THREAD_ARG &
LOOP_PID=$!

# Give it a moment to initialize
sleep 3

# Start Claude runner in background
echo "Starting Claude task runner..."
node claude_task_runner.cjs &
RUNNER_PID=$!

echo ""
echo "Both processes running. PIDs: Loop=$LOOP_PID, Runner=$RUNNER_PID"
echo ""

# Wait for either to exit
wait $LOOP_PID $RUNNER_PID
