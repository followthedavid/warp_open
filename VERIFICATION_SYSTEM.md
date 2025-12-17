# Warp_Open Verification & Auto-Fix System

This document describes the complete verification and auto-fix system for Warp_Open's unified UUID-based tab system.

## 🎯 System Overview

The verification system provides:
- **Full automated testing** (Rust backend + Playwright UI tests)
- **Automatic detection** of the 3 root causes of tab bugs
- **Auto-fix capabilities** for detected issues
- **Visual dashboard** with screenshots and test reports
- **CI/CD integration** via GitHub Actions

## 📂 Components

### Scripts

| Script | Purpose |
|--------|---------|
| `verify_everything.sh` | Full verification: deps + Rust tests + dev server + UI tests |
| `auto_fix_tabs.sh` | Detects and fixes the 3 root causes from verification report |
| `warp_health_dev.sh` | Verify + auto-fix + dashboard + restart dev server |
| `warp_full_auto.sh` | Complete automation: verify + fix + dashboard + rerun tests |
| `dashboard.js` | Standalone dashboard generator |

### GitHub Actions

- `.github/workflows/warp_ci.yml` - Runs full verification on every push/PR

## 🚀 Quick Start

### Option 1: Full Automated Run (Recommended)

This runs verification, applies fixes if needed, generates dashboard, restarts dev server, and reruns tests:

```bash
./scripts/warp_full_auto.sh
```

**What it does:**
1. ✅ Runs full verification (Rust + UI tests)
2. ✅ Detects and auto-fixes the 3 root causes
3. ✅ Generates HTML dashboard at `/tmp/warp_status_dashboard.html`
4. ✅ Opens dashboard in browser
5. ✅ Restarts dev server
6. ✅ Reruns full test suite
7. ✅ Keeps dev server running for manual testing

### Option 2: Health Check + Dev Server

This verifies, fixes, shows dashboard, and leaves dev server running:

```bash
./scripts/warp_health_dev.sh
```

**What it does:**
1. ✅ Runs verification
2. ✅ Auto-fixes issues
3. ✅ Opens dashboard
4. ✅ Starts dev server in foreground

Press `Ctrl+C` to stop the dev server when done.

### Option 3: Verification Only

Just run tests and generate report:

```bash
./scripts/verify_everything.sh
```

**Outputs:**
- `/tmp/warp_status_report.txt` - Full test report
- `/tmp/warp_status_screenshots/` - UI test screenshots
- `/tmp/warp_status_logs/` - Dev server logs

### Option 4: Manual Fix + Dashboard

If you already have a report and want to apply fixes:

```bash
./scripts/auto_fix_tabs.sh
node scripts/dashboard.js
open /tmp/warp_status_dashboard.html
```

## 🔍 What Gets Verified

### Rust Backend Tests (8 tests)
- ✅ PTY spawn/close
- ✅ PTY read/write
- ✅ PTY resize
- ✅ Multiple PTY instances

### UI Tests (11 tests)
- ✅ Initial tab renders
- ✅ New terminal tab button works
- ✅ New AI tab button works
- ✅ Tab switching
- ✅ Tab closing
- ✅ Terminal xterm renders
- ✅ AI chat interface renders
- ✅ AI message send
- ✅ Multiple tabs coexist
- ✅ Tab persistence after switching
- ✅ No duplicate #app elements

## 🛠️ The 3 Root Causes

The auto-fix system detects and resolves:

### 1. ID Collision
**Problem:** Terminal tabs use auto-increment IDs, AI tabs use `Date.now()` → collisions  
**Fix:** Install `uuid` + `@types/uuid` packages  
**Detection:** Searches for "ID collision" in report

### 2. Reactive Computed Copy
**Problem:** Computed arrays create new objects → Vue remounts tabs  
**Fix:** Use single reactive `state.value.tabs` array  
**Detection:** Searches for "Reactive computed copy" in report

### 3. Display Condition Bug
**Problem:** Separate `activeTerminalTab` and `activeAITab` → multiple #app elements  
**Fix:** Unified `activeTab?.kind === 'terminal'` condition  
**Detection:** Searches for "Display Condition Bug" in report

## 📊 Dashboard

The HTML dashboard (`/tmp/warp_status_dashboard.html`) shows:
- 📋 Full test report with pass/fail status
- 📸 Screenshots from UI tests
- ℹ️ Metadata (paths, timestamps)

Generate anytime with:
```bash
node scripts/dashboard.js
```

## 🤖 CI/CD Integration

GitHub Actions workflow runs automatically on:
- Push to `main` branch
- Pull requests

**Workflow:** `.github/workflows/warp_ci.yml`

### What CI Does:
1. Checks out code
2. Installs Node.js + Rust
3. Installs Playwright browsers
4. Runs `verify_everything.sh`
5. Uploads test artifacts (report, screenshots, Playwright report)

### View CI Results:
- GitHub Actions tab in repository
- Download artifacts from completed workflow runs

## 📁 Output Files

| File | Description |
|------|-------------|
| `/tmp/warp_status_report.txt` | Full verification report |
| `/tmp/warp_status_dashboard.html` | Visual dashboard |
| `/tmp/warp_status_screenshots/*.png` | UI test screenshots |
| `/tmp/warp_status_logs/dev_server.log` | Dev server output |
| `playwright-report/` | Playwright HTML report |

## 🔧 Troubleshooting

### Tests fail even after auto-fix
1. Check `/tmp/warp_status_report.txt` for specific errors
2. Inspect `/tmp/warp_status_logs/dev_server.log` for runtime errors
3. Open dashboard to see screenshots: `open /tmp/warp_status_dashboard.html`
4. Manually test in browser: `npm run tauri:dev` then visit `http://localhost:5173`

### Dev server won't start
```bash
# Kill all processes
pkill -9 -f "tauri|vite"

# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Try again
npm run tauri:dev
```

### Playwright tests timeout
- Increase sleep time in `verify_everything.sh` (line 38)
- Check if port 5173 is already in use: `lsof -i :5173`
- Verify dev server actually starts: `curl http://localhost:5173`

## 📚 Additional Resources

- **Main Test Suite:** `scripts/run_full_tests.sh`
- **Playwright Tests:** `tests/ui/warp_tabs.spec.ts`
- **Unified Tab System:** `src/composables/useTabs.ts`
- **App Component:** `src/App.vue`

## ✅ Success Criteria

System is healthy when:
- ✅ All 8 Rust backend tests pass
- ✅ All 11 Playwright UI tests pass
- ✅ Tabs render correctly in browser
- ✅ No ID collisions
- ✅ Tabs don't remount on every render
- ✅ Single #app element always

## 🎯 Recommended Workflow

**Daily Development:**
```bash
# Quick check
./scripts/verify_everything.sh

# If issues found
./scripts/auto_fix_tabs.sh

# Full test with dev server
./scripts/warp_health_dev.sh
```

**Pre-Commit:**
```bash
./scripts/warp_full_auto.sh
```

**CI automatically runs on push to verify everything**

---

**System Status:** ✅ Production Ready  
**Tab System:** ✅ Unified UUID-based  
**Auto-Fix:** ✅ Enabled  
**CI/CD:** ✅ Configured
