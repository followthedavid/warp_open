# Warp_Open Quick Command Reference

## 🚀 Main Commands

```bash
# Full automation (recommended)
./scripts/warp_full_auto.sh

# Verification only
./scripts/verify_everything.sh

# Auto-fix issues
./scripts/auto_fix_tabs.sh

# Health check + dev server
./scripts/warp_health_dev.sh

# Generate dashboard
node scripts/dashboard.js && open /tmp/warp_status_dashboard.html
```

## 📊 View Results

```bash
# Dashboard (visual)
open /tmp/warp_status_dashboard.html

# Text report
cat /tmp/warp_status_report.txt

# Screenshots
open /tmp/warp_status_screenshots

# Server logs
tail -f /tmp/warp_status_logs/dev_server.log
```

## 🧪 Manual Testing

```bash
# Start dev server
npm run tauri:dev

# Run Rust tests only
cd src-tauri && cargo test --tests

# Run UI tests only
npx playwright test tests/ui/warp_tabs.spec.ts

# Run specific test
npx playwright test -g "should create new terminal tab"
```

## 🔧 Troubleshooting

```bash
# Kill all processes
pkill -9 -f "tauri|vite"

# Clean and reinstall
rm -rf node_modules package-lock.json
npm install

# Check port usage
lsof -i :5173

# View Playwright report
npx playwright show-report
```

## 📝 Git Workflow

```bash
# Before commit
./scripts/verify_everything.sh

# If issues found
./scripts/auto_fix_tabs.sh

# Full pre-production check
./scripts/warp_full_auto.sh
```

## 🎯 One-Liner Status Check

```bash
./scripts/verify_everything.sh && echo "✅ All tests passed!" || echo "❌ Tests failed - check /tmp/warp_status_report.txt"
```

---

**Docs:** See `VERIFICATION_SYSTEM.md` for complete documentation
