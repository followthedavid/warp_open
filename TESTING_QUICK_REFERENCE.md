# Phase 1-6 Testing Quick Reference

## Quick Commands

### Run Rust Integration Test (Recommended)
```bash
cd src-tauri
cargo test --test full_phase1_6_integration -- --nocapture
```
⏱️ **Runtime**: ~10ms  
✅ **Best for**: Fast, reliable verification during development

### Run Automated Shell Wrapper
```bash
./run_phase1_6_local_auto.sh
```
⏱️ **Runtime**: ~45s  
✅ **Best for**: Full-stack testing with UI verification

### Run Interactive HTML Tester (Manual)
```bash
npm run tauri dev
# Open: http://localhost:1420/test_phase1_6_interactive.html
```
⏱️ **Runtime**: Manual  
✅ **Best for**: Exploratory testing and debugging

### Run Interactive HTML Tester (Auto-run)
```bash
npm run tauri dev
# Open: http://localhost:1420/test_phase1_6_interactive.html?autorun=true
```
⏱️ **Runtime**: ~3-5s after page load  
✅ **Best for**: Automated UI testing

## Expected Output

### Success Indicator (Rust)
```
╔════════════════════════════════════════╗
║ PHASE 1→6 INTEGRATION TEST COMPLETE ✅ ║
╚════════════════════════════════════════╝

📊 Test Results:
  ✅ Phase 1: Single tool execution
  ✅ Phase 2: Batch workflow
  ✅ Phase 3: Autonomy & dependencies
  ✅ Phase 4: Telemetry & ML (1 event stored)
  ✅ Phase 5: Policy & multi-agent (2 agents, 1 rule)
  ✅ Phase 6: Long-term planning (1 plan completed)

🎉 All phases integrated successfully!
test result: ok. 2 passed; 0 failed
```

### Success Indicator (Shell Wrapper)
```
╔════════════════════════════════════════╗
║ Phase 1-6 Test Execution Complete ✅   ║
╚════════════════════════════════════════╝
Test URL: http://localhost:1420/test_phase1_6_interactive.html?autorun=true
Dev logs: /tmp/warp_phase1_6_dev.log
Check the browser console for detailed test results
```

### Success Indicator (Interactive HTML)
All panels show:
- ✅ Connected status at top
- ✅ Green checkmarks in logs after running tests
- No ❌ error messages

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Cargo.toml not found | Run from `src-tauri` directory |
| Test page shows "Disconnected ❌" | Wait 10-15s, then refresh page |
| Port already in use (5173, 1420) | Kill existing: `pkill -f 'cargo-tauri'` |
| SQLite errors in Rust test | Check `/tmp` permissions |
| Browser won't open automatically | Manually open test URL |

## Database Inspection

```bash
# View telemetry events
sqlite3 ~/.warp_open/warp_telemetry.sqlite "SELECT * FROM events LIMIT 5;"

# View policy rules
sqlite3 ~/.warp_open/warp_policy.sqlite "SELECT * FROM rules;"

# View plans
sqlite3 ~/.warp_open/warp_plans.sqlite "SELECT plan_id, status FROM plans;"

# Check database sizes
du -h ~/.warp_open/*.sqlite
```

## Log Files

```bash
# Dev log (shell wrapper)
tail -f /tmp/warp_phase1_6_dev.log

# Tauri app log
npm run tauri dev  # stderr/stdout shows directly
```

## Test Coverage Summary

| Phase | Component | Status |
|-------|-----------|--------|
| 1 | ConversationState | ✅ Tested |
| 2 | Batch Workflow | ✅ Tested |
| 3 | Autonomy | ✅ Tested |
| 4 | TelemetryStore | ✅ Tested |
| 5 | PolicyStore + AgentCoordinator | ✅ Tested |
| 6 | PlanStore + MonitoringState | ✅ Tested |
| - | Cross-phase dependencies | ✅ Tested |

## Files Created

1. **src-tauri/tests/full_phase1_6_integration.rs** (203 lines)
2. **src-tauri/tests/test_phase1_6_local.js** (190 lines)
3. **public/test_phase1_6_interactive.html** (490 lines)
4. **run_phase1_6_local_auto.sh** (106 lines, executable)
5. **PHASE_1_6_TESTING.md** (339 lines)
6. **PHASE_1_6_COMPLETE.md** (348 lines)
7. **TESTING_QUICK_REFERENCE.md** (this file)

## One-Liner Health Check

```bash
cd src-tauri && cargo test --test full_phase1_6_integration --no-fail-fast 2>&1 | grep -E "(PASSED|FAILED|test result)"
```

Expected output:
```
[PHASE 1] ✅ PASSED - Single tool execution
[PHASE 2] ✅ PASSED - Batch workflow state management
[PHASE 3] ✅ PASSED - Autonomy & dependencies
[PHASE 4] ✅ PASSED - Telemetry & ML integration
[PHASE 5] ✅ PASSED - Policy learning & multi-agent coordination
[PHASE 6] ✅ PASSED - Long-term planning & live monitoring
test result: ok. 2 passed; 0 failed
```

---

**Status**: ✅ All tests passing  
**Last Verified**: November 24, 2025
