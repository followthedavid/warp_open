#!/usr/bin/env bash
#
# chatgptcli.sh
#
# Zero-API CLI wrapper for ChatGPT Desktop
# Tries multiple integration methods with automatic fallback
#
# Fallback chain:
#   1. HTTP API (port 9999) - fast but requires auth
#   2. AppleScript automation - slower but works
#
# Usage:
#   ./chatgptcli.sh "Your prompt here"
#
# Environment:
#   CHATGPT_TIMEOUT - Request timeout in seconds (default: 30)
#   CHATGPT_RETRIES - Number of retries for AppleScript (default: 3)
#   CHATGPT_DEBUG - Set to 1 for verbose logging

set -euo pipefail

PROMPT="${1:-}"
TIMEOUT="${CHATGPT_TIMEOUT:-30}"
RETRIES="${CHATGPT_RETRIES:-3}"
DEBUG="${CHATGPT_DEBUG:-0}"

# Logging helpers
log() {
  [[ "$DEBUG" == "1" ]] && echo "[chatgptcli] $*" >&2 || true
}

error() {
  echo "[chatgptcli ERROR] $*" >&2
}

# Validate input
if [[ -z "$PROMPT" ]]; then
  error "Usage: $0 \"Your prompt here\""
  exit 1
fi

# Method 1: Try HTTP API (fast path)
try_http() {
  log "Attempting HTTP API on port 9999..."

  # Check if port is open
  if ! lsof -Pi :9999 -sTCP:LISTEN -t >/dev/null 2>&1; then
    log "Port 9999 not listening"
    return 1
  fi

  # Try to send request
  local response
  response=$(curl -s -m "$TIMEOUT" \
    -X POST "http://127.0.0.1:9999/api/chat" \
    -H "Content-Type: application/json" \
    -d "{\"message\":\"$PROMPT\"}" 2>&1) || {
    log "HTTP request failed: $response"
    return 1
  }

  # Check for auth redirect
  if echo "$response" | grep -q "login\|auth\|302"; then
    log "HTTP API requires authentication"
    return 1
  fi

  # Try to extract response
  if command -v jq >/dev/null 2>&1; then
    local extracted
    extracted=$(echo "$response" | jq -r '.response // .message // .text // empty' 2>/dev/null)
    if [[ -n "$extracted" ]]; then
      echo "$extracted"
      return 0
    fi
  fi

  log "HTTP API returned unexpected format"
  return 1
}

# Method 2: AppleScript automation (reliable fallback)
try_applescript() {
  log "Attempting AppleScript automation..."

  # Check if ChatGPT is running
  if ! pgrep -x "ChatGPT" >/dev/null; then
    error "ChatGPT.app is not running"
    return 1
  fi

  # Check if desktop_automation.cjs exists
  local script_path
  script_path="$(dirname "$0")/desktop_automation.cjs"

  if [[ ! -f "$script_path" ]]; then
    error "desktop_automation.cjs not found at $script_path"
    return 1
  fi

  # Run automation with retries
  local result
  result=$(node "$script_path" \
    --app ChatGPT \
    --prompt "$PROMPT" 2>&1) || {
    error "AppleScript automation failed: $result"
    return 1
  }

  # Check if result contains error
  if echo "$result" | grep -q "^ERROR:"; then
    error "Automation error: $result"
    return 1
  fi

  echo "$result"
  return 0
}

# Main execution with fallback chain
main() {
  log "Processing prompt: ${PROMPT:0:50}..."

  # Try HTTP first (fast)
  if try_http; then
    log "Success via HTTP API"
    exit 0
  fi

  # Fallback to AppleScript
  log "HTTP failed, trying AppleScript..."
  if try_applescript; then
    log "Success via AppleScript automation"
    exit 0
  fi

  # All methods failed
  error "All integration methods failed"
  error "1. HTTP API (port 9999) - not available or requires auth"
  error "2. AppleScript automation - failed or app not running"
  error ""
  error "Troubleshooting:"
  error "- Ensure ChatGPT.app is running"
  error "- Check that desktop_automation.js is in the same directory"
  error "- Try setting CHATGPT_DEBUG=1 for verbose logging"
  exit 1
}

main
