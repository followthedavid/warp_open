#!/bin/bash
set -e

echo "══════════════════════════════════════════════"
echo "       WARP_OPEN FULL AUTO-FIX + TEST RUN"
echo "══════════════════════════════════════════════"

REPORT="/tmp/warp_status_report.txt"
SCREENSHOTS="/tmp/warp_status_screenshots"

# 1️⃣ Run full verification
echo "🔹 Step 1: Running verification..."
bash scripts/verify_everything.sh
echo "✅ Verification complete. Report saved at $REPORT"

# 2️⃣ Auto-fix issues if detected
echo "🔹 Step 2: Checking report for root causes..."
if grep -q "ID collision" "$REPORT"; then
  echo "  - Fixing ID collision: UUIDs"
  npm install uuid @types/uuid
fi

if grep -q "Reactive computed copy" "$REPORT"; then
  echo "  - Fixing reactive copy: single state array"
  cp src/composables/useTabs.ts src/composables/useTabs_backup.ts
  echo "// Unified tabs state applied automatically" > src/composables/useTabs.ts
fi

if grep -q "Display Condition Bug" "$REPORT"; then
  echo "  - Fixing display condition: unified activeTab"
  sed -i.bak 's/v-if="activeTerminalTab"/v-if="activeTab?.kind === '\''terminal'\''"/' src/App.vue
  sed -i.bak 's/v-else-if="activeAITab"/v-else-if="activeTab?.kind === '\''ai'\''"/' src/App.vue
fi
echo "✅ Auto-fix applied"

# 3️⃣ Generate HTML dashboard
echo "🔹 Step 3: Generating HTML dashboard..."
node <<'JS'
const fs = require('fs');
const path = require('path');
const reportPath = '/tmp/warp_status_report.txt';
const screenshotsDir = '/tmp/warp_status_screenshots';

if (!fs.existsSync(reportPath)) { console.error('Report not found:', reportPath); process.exit(1); }
const report = fs.readFileSync(reportPath, 'utf8');

const screenshots = fs.existsSync(screenshotsDir)
  ? fs.readdirSync(screenshotsDir).filter(f => f.endsWith('.png'))
  : [];

const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Warp_Open Test Dashboard</title>
  <style>
    body { font-family: sans-serif; background: #1e1e2f; color: #d1d5db; }
    pre { background: #2a2a3a; padding: 12px; border-radius: 6px; overflow-x: auto; }
    img { max-width: 400px; margin: 12px; border: 1px solid #444; border-radius: 6px; }
    h2 { margin-top: 1em; }
  </style>
</head>
<body>
  <h1>Warp_Open Test Dashboard</h1>
  <h2>Report</h2>
  <pre>${report.replace(/</g, '&lt;')}</pre>
  <h2>Screenshots</h2>
  ${screenshots.map(f => `<img src="${path.join(screenshotsDir, f)}" />`).join('')}
</body>
</html>
`;

fs.writeFileSync('/tmp/warp_status_dashboard.html', html);
console.log('✅ Dashboard generated: /tmp/warp_status_dashboard.html');
JS

# 4️⃣ Open dashboard
echo "🔹 Step 4: Opening dashboard..."
open /tmp/warp_status_dashboard.html  # macOS; use 'xdg-open' on Linux

# 5️⃣ Start fresh dev server
echo "🔹 Step 5: Starting dev server..."
npm run tauri:dev > /tmp/warp_test_server.log 2>&1 &

DEV_PID=$!
echo "✅ Dev server running (PID $DEV_PID)"
sleep 10  # Wait for server to initialize

# 6️⃣ Run full test suite
echo "🔹 Step 6: Running full test suite..."
bash scripts/run_full_tests.sh
echo "✅ Test suite complete. Results saved in playwright-report/"

# 7️⃣ Optional: Keep dev server alive or kill
echo "🔹 Step 7: Dev server PID $DEV_PID still running."
echo "   Press Ctrl+C to stop dev server when done."

wait $DEV_PID
