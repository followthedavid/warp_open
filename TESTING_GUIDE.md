# Phase 1-3 Testing Guide

Quick reference for running all autonomy tests in Warp_Open.

---

## Test Scripts Overview

| Script | Purpose | Time | Type |
|--------|---------|------|------|
| `test_full_autonomy.sh` | Verify all phases (1→3) | ~30s | Automated |
| `test_phase3_auto.sh` | Verify Phase 3 only | ~20s | Automated |
| `run_phase3_test.sh` | Runtime Phase 3 test | ~5s | Automated |
| `test_phase3_interactive.html` | Manual testing UI | - | Interactive |

---

## Quick Start

### 1. Full Verification (Recommended)
Tests all 3 phases + compilation:
```bash
./test_full_autonomy.sh
```

**What it checks:**
- ✅ Phase 1: Single tool execution, safety classification
- ✅ Phase 2: Batch structure, approval workflow, execution
- ✅ Phase 3: AI parser, auto-batch, auto-approval, dependencies, rollback
- ✅ Frontend: All Vue components have required features
- ✅ Compilation: Rust code builds without errors

**Expected output:** 25+ green checkmarks, exit code 0

---

### 2. Phase 3 Quick Check
If you only need to verify Phase 3:
```bash
./test_phase3_auto.sh
```

**What it checks:**
- AI parser module exists and integrated
- Rollback mechanism present
- Batch structure has Phase 3 fields
- AutonomySettings struct defined
- Tauri commands registered
- Frontend components have Phase 3 features
- Code compiles

---

### 3. Interactive Testing
For manual verification and debugging:

**Start the app:**
```bash
npm run tauri dev
```

**Option A: GUI Tester**
1. Open `public/test_phase3_interactive.html` in the app
2. Click buttons to:
   - Create test batches
   - Test auto-approval
   - Test dependency chains
   - Test rollback
3. Watch activity log for results

**Option B: DevTools Console**
1. Press `Cmd+Option+I` to open DevTools
2. Run test command:
```javascript
await window.__TAURI__.invoke('test_phase3_workflow')
```
3. Check console output for results

---

## Test Scenarios

### Scenario 1: Test Auto-Approval
```javascript
// In DevTools console
const settings = await window.__TAURI__.invoke('get_autonomy_settings');
console.log('Auto-approve enabled:', settings.auto_approve_enabled);

// Create batch with safe commands
const bid = await window.__TAURI__.invoke('create_batch', {
  tabId: 1,
  entries: [
    { tool: 'execute_shell', args: { command: 'echo test' } },
    { tool: 'execute_shell', args: { command: 'pwd' } }
  ]
});

// Should auto-approve if all commands safe
const batches = await window.__TAURI__.invoke('get_batches');
console.log('Batch auto-approved:', batches[0].auto_approved);
```

### Scenario 2: Test Dependencies
```javascript
// Create parent batch
const parentId = await window.__TAURI__.invoke('create_batch', {
  tabId: 1,
  entries: [{ tool: 'execute_shell', args: { command: 'echo parent' } }]
});

// Create child batch
const childId = await window.__TAURI__.invoke('create_batch', {
  tabId: 1,
  entries: [{ tool: 'execute_shell', args: { command: 'echo child' } }]
});

// Set dependency
await window.__TAURI__.invoke('set_batch_dependency', {
  batchId: childId,
  parentId: parentId
});

// Child should be blocked until parent completes
const batches = await window.__TAURI__.invoke('get_batches');
console.log('Child depends on:', batches.find(b => b.id === childId).depends_on);
```

### Scenario 3: Test Rollback
```javascript
// Create and run a batch
const bid = await window.__TAURI__.invoke('create_batch', {
  tabId: 1,
  entries: [
    { tool: 'execute_shell', args: { command: 'echo before' } }
  ]
});

await window.__TAURI__.invoke('approve_batch', { batchId: bid, autonomyToken: null });
await window.__TAURI__.invoke('run_batch', { batchId: bid, autonomyToken: null });

// Wait for completion, then rollback
setTimeout(async () => {
  await window.__TAURI__.invoke('rollback_batch', { 
    batchId: bid, 
    autonomyToken: null 
  });
  console.log('Rollback complete');
}, 2000);
```

---

## Troubleshooting

### Test fails: "Warp app is not running"
**Solution:**
```bash
npm run tauri dev
```
Wait for app to fully start, then re-run test.

### Test fails: Compilation errors
**Solution:**
```bash
cd src-tauri
cargo check
cargo build
```
Fix any errors shown, then re-run test.

### Test fails: Phase 3 commands not registered
**Check:** `src-tauri/src/main.rs` should have:
```rust
.invoke_handler(tauri::generate_handler![
    // ... other commands ...
    get_autonomy_settings,
    update_autonomy_settings,
    set_batch_dependency,
    rollback_batch,
    test_phase3_workflow
])
```

### Interactive HTML doesn't load
**Solution:**
- Make sure file is in `public/` directory
- Check browser console for errors
- Verify Tauri API is available: `window.__TAURI__`

---

## Audit Logs

Tests create audit logs at:
- `~/PHASE1_AUDIT.log`
- `~/PHASE2_AUDIT.log`
- `~/PHASE3_AUDIT.log`

**View logs:**
```bash
cat ~/PHASE3_AUDIT.log
```

**Clear logs:**
```bash
> ~/PHASE1_AUDIT.log
> ~/PHASE2_AUDIT.log
> ~/PHASE3_AUDIT.log
```

---

## CI/CD Integration

To add to CI pipeline:

**GitHub Actions:**
```yaml
- name: Run Autonomy Tests
  run: |
    npm run tauri dev &
    sleep 10
    ./test_full_autonomy.sh
```

**Manual Pre-Commit:**
```bash
# Add to .git/hooks/pre-commit
#!/bin/bash
./test_full_autonomy.sh || exit 1
```

---

## Next Steps After Testing

Once all tests pass:
1. ✅ Review `PHASE3_VERIFIED.md` for detailed results
2. ✅ Commit verified code
3. ✅ Move to Phase 4: Learning System

---

## Quick Reference Commands

```bash
# Full test suite
./test_full_autonomy.sh

# Phase 3 only
./test_phase3_auto.sh

# Start app for interactive testing
npm run tauri dev

# Check logs
tail -f ~/PHASE3_AUDIT.log

# Clean slate
rm ~/PHASE*.log && ./test_full_autonomy.sh
```

---

**Last Updated**: November 23, 2025  
**For**: Warp_Open Phase 1-3 Autonomy System
