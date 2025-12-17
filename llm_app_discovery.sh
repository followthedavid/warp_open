#!/bin/bash
set -e

APP_NAMES=("ChatGPT" "Claude" "Anthropic" "DeepSeek" "OpenAI" "GPT" "LLM")
OUT="discovery_report_$(date +%Y%m%d_%H%M%S).txt"

echo "🔍 LLM App Discovery Report" | tee "$OUT"
echo "Generated: $(date)" | tee -a "$OUT"
echo "----------------------------------------" | tee -a "$OUT"

############################################
# SECTION 1 — FIND RUNNING PROCESSES
############################################
echo -e "\n📌 PROCESSES" | tee -a "$OUT"

for name in "${APP_NAMES[@]}"; do
  echo -e "\n--- Processes matching '$name' ---" | tee -a "$OUT"
  pgrep -fl "$name" | tee -a "$OUT" || echo "(none)" | tee -a "$OUT"
done

############################################
# SECTION 2 — PORT SCAN FOR LOCAL LISTENERS
############################################
echo -e "\n📡 LOCAL PORTS (LISTENING)" | tee -a "$OUT"
sudo lsof -nP -iTCP -sTCP:LISTEN | tee -a "$OUT"

############################################
# SECTION 3 — UNIX DOMAIN SOCKETS
############################################
echo -e "\n🔌 UNIX SOCKETS" | tee -a "$OUT"
sudo lsof -U | grep -E 'ChatGPT|Claude|openai|anthropic|deepseek' || echo "(none)" | tee -a "$OUT"

############################################
# SECTION 4 — OPEN FILE HANDLES FOR TARGET PROCESSES
############################################
echo -e "\n📂 FILE HANDLES (fs-usage style)" | tee -a "$OUT"

for name in "${APP_NAMES[@]}"; do
  PID=$(pgrep -f "$name" | head -n 1)
  if [[ -n "$PID" ]]; then
    echo -e "\n--- File handles for PID $PID ($name) ---" | tee -a "$OUT"
    sudo lsof -p "$PID" | tee -a "$OUT"
  fi
done

############################################
# SECTION 5 — APPLICATION BUNDLES
############################################
echo -e "\n📦 APPLICATION BUNDLES" | tee -a "$OUT"

for name in "${APP_NAMES[@]}"; do
  APP_PATH=$(mdfind "kMDItemDisplayName == '$name'" | grep ".app$" | head -n 1)
  if [[ -n "$APP_PATH" ]]; then
    echo -e "\n--- Found app: $APP_PATH ---" | tee -a "$OUT"

    echo "- MacOS Executables:" | tee -a "$OUT"
    ls -la "$APP_PATH/Contents/MacOS" | tee -a "$OUT"

    echo "- Resources:" | tee -a "$OUT"
    ls -la "$APP_PATH/Contents/Resources" | tee -a "$OUT"

    echo "- Searching for node/go/python/js binaries…" | tee -a "$OUT"
    find "$APP_PATH" -type f -maxdepth 5 -name "node" -o -name "*.js" -o -name "server*" | tee -a "$OUT"

    echo "- Strings indicating local servers:" | tee -a "$OUT"
    strings "$APP_PATH/Contents/MacOS/"* 2>/dev/null | grep -Ei "localhost|127\.0\.0\.1|listen|port|socket" | head -n 40 | tee -a "$OUT"

    echo "- XPC Services:" | tee -a "$OUT"
    ls -la "$APP_PATH/Contents/XPCServices" 2>/dev/null || echo "(none)" | tee -a "$OUT"
  fi
done

############################################
# SECTION 6 — USER CONFIG & LOGS
############################################
echo -e "\n🗄  USER CONFIG & LOG FOLDERS" | tee -a "$OUT"

for folder in ~/Library/Application\ Support/*; do
  LOWER=$(echo "$folder" | tr '[:upper:]' '[:lower:]')
  if echo "$LOWER" | grep -qE "chatgpt|claude|anthropic|openai|deepseek"; then
    echo -e "\n--- $folder ---" | tee -a "$OUT"
    ls -la "$folder" | tee -a "$OUT"
  fi
done

echo -e "\n📘 LOGS" | tee -a "$OUT"
grep -R "error" ~/Library/Logs/* 2>/dev/null | grep -Ei "chatgpt|claude|anthropic" || echo "(none)"

echo -e "\n----------------------------------------" | tee -a "$OUT"
echo "🎉 Discovery complete! Output saved to $OUT"
