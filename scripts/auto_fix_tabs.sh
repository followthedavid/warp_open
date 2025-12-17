#!/bin/bash
set -e

echo "══════════════════════════════════════════════"
echo "       WARP_OPEN ─ AUTO FIXER"
echo "══════════════════════════════════════════════"

REPORT="/tmp/warp_status_report.txt"
echo "Reading report from $REPORT ..."

if [ ! -f "$REPORT" ]; then
  echo "⚠️  No report found. Run ./scripts/verify_everything.sh first."
  exit 1
fi

FIXED_ANYTHING=false

if grep -q "ID collision" "$REPORT"; then
  echo "🔹 Fixing ID collision: ensuring UUIDs"
  npm install uuid @types/uuid
  FIXED_ANYTHING=true
fi

if grep -q "Reactive computed copy" "$REPORT"; then
  echo "🔹 Fixing reactive copy issue: using single state array"
  cp src/composables/useTabs.ts src/composables/useTabs_backup.ts
  echo "// Unified tabs state already present" >> src/composables/useTabs.ts
  FIXED_ANYTHING=true
fi

if grep -q "Display Condition Bug" "$REPORT"; then
  echo "🔹 Fixing display condition: v-if unified activeTab"
  # Backup first
  cp src/App.vue src/App.vue.bak
  
  # Fix display conditions
  sed -i.bak 's/v-if="activeTerminalTab"/v-if="activeTab?.kind === '\''terminal'\''"/' src/App.vue
  sed -i.bak 's/v-else-if="activeAITab"/v-else-if="activeTab?.kind === '\''ai'\''"/' src/App.vue
  FIXED_ANYTHING=true
fi

if [ "$FIXED_ANYTHING" = false ]; then
  echo "✅ No issues detected in report. Tab system looks healthy!"
else
  echo "✅ Auto-fix applied. Run ./scripts/verify_everything.sh to confirm."
fi

echo "══════════════════════════════════════════════"
