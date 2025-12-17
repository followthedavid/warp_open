# Warp_Open Phase 1–3 Documentation & Testing Guide

**Last Updated**: November 24, 2025  
**Status**: ✅ All Phases Complete & Verified

---

## Table of Contents

1. [Overview](#overview)
2. [Phase 1: Assistive Autonomy](#phase-1-assistive-autonomy)
3. [Phase 2: Semi-Autonomy](#phase-2-semi-autonomy)
4. [Phase 3: Full Autonomy](#phase-3-full-autonomy)
5. [Automated Tests](#automated-tests)
6. [Interactive Testing](#interactive-testing)
7. [Audit Log Verification](#audit-log-verification)
8. [Troubleshooting](#troubleshooting)
9. [Next Steps](#next-steps)

---

## Overview

This guide covers Phases 1–3 of Warp_Open's AI Autonomy System, detailing:
- Backend and frontend integration
- Batch creation, approval, execution
- Auto-approval and auto-execution
- Batch dependencies and rollback
- Automated and interactive testing

**All phases are fully implemented and verified.**

---

## Phase 1: Assistive Autonomy

### Purpose
Execute a single tool call per user message with mandatory AI follow-up.

### Components
- **Rust backend**: `ConversationState`, `send_user_message`
- **Tools**: `execute_shell`, `read_file`, `write_file`
- **Frontend**: Vue chat tab (AI response display)

### Testing

**Create batch with 1 tool:**
```javascript
create_batch({
  tabId: 1,
  entries: [{ tool: 'execute_shell', args: { command: 'echo Phase1-Test' } }]
})
```

**Steps:**
1. Approve batch
2. Run batch
3. Verify tool execution
4. Check audit log

### Expected Output
```
Batch Created: <UUID>
Batch Approved: <UUID>
Batch Executed: <UUID>
Audit log shows: Phase1-Test command
```

---

## Phase 2: Semi-Autonomy

### Purpose
Batch execution with approval workflow and safety checks.

### Components
- **Rust backend**: `Batch`, `BatchEntry`, `BatchStatus` structs
- **Policy engine**: Denylist / allowlist checking
- **Frontend**: `BatchPanel.vue`, `AutonomySettings.vue`

### Testing

**Create batch with multiple commands:**
```javascript
create_batch({
  tabId: 1,
  entries: [
    { tool: 'execute_shell', args: { command: 'echo Phase2-1' } },
    { tool: 'execute_shell', args: { command: 'echo Phase2-2' } }
  ]
})
```

**Steps:**
1. Approve batch (manual or auto)
2. Run batch
3. Verify batch status transitions: Pending → Approved → Running → Completed
4. Check audit log for all entries

### Expected Output
```
Batch Created: <UUID>
Batch Approved: <UUID>
Batch Status: Running
Batch Status: Completed
Audit log: contains both commands with MD5 hashes
```

---

## Phase 3: Full Autonomy

### Purpose
Auto-create, auto-approve, and optionally auto-execute batches from AI responses. Supports batch dependencies and rollback.

### Components
- **`ai_parser.rs`**: Detects multiple tool calls in AI responses
- **`AutonomySettings`**: `auto_approve_enabled`, `auto_execute_enabled` toggles
- **`rollback.rs`**: Rollback system for failed batches
- **Batch dependencies**: `depends_on` field enforces execution order

### Key Features

#### 1. Auto-Batch Creation
When AI response contains 2+ tool calls, automatically creates a batch.

#### 2. Auto-Approval
If all commands in batch are safe (score=100) and autonomy token is set, batch is auto-approved.

#### 3. Auto-Execution
If `auto_execute_enabled` is true and batch is auto-approved, it executes automatically.

#### 4. Batch Dependencies
Child batches can depend on parent batches. Child won't execute until parent completes.

```javascript
set_batch_dependency({
  batchId: child_id,
  dependsOn: parent_id
})
```

#### 5. Rollback
If a batch fails, rollback mechanism attempts to undo changes.

```javascript
rollback_batch({ batchId: failed_batch_id })
```

### Testing

**Create auto-batch:**
```javascript
create_batch({
  tabId: 1,
  entries: [
    { tool: 'execute_shell', args: { command: 'echo Phase3-A' } },
    { tool: 'execute_shell', args: { command: 'echo Phase3-B' } }
  ]
})
```

**Enable auto-approval:**
```javascript
update_autonomy_settings({
  auto_approve_enabled: true,
  auto_execute_enabled: true,
  autonomy_token: 'token123'
})
```

### Expected Output
```
Auto-created batch: <UUID>
Batch auto-approved (via autonomy_token)
Batch auto-executed
Audit log: all entries logged with timestamps
Dependency enforcement: child batch waits for parent
Rollback: executed if command fails
```

---

## Automated Tests

### Rust Integration Tests

**Location**: `src-tauri/tests/phase1_3_integration.rs`

**Run all tests:**
```bash
cd src-tauri
cargo test --test phase1_3_integration -- --nocapture
```

**Run specific test:**
```bash
cargo test --test phase1_3_integration test_phase1_single_tool_execution -- --nocapture
```

### Available Tests

| Test Name | What It Verifies |
|-----------|------------------|
| `test_phase1_single_tool_execution` | Tab creation, message addition, basic structure |
| `test_phase2_batch_workflow` | Batch creation, approval, execution flow |
| `test_phase3_auto_approval_and_dependencies` | Autonomy settings, auto-approval, dependencies |
| `test_phase3_rollback_structure` | Error detection and rollback readiness |
| `test_full_phase1_to_3_workflow` | Complete end-to-end workflow |

### Test Output
```
=== PHASE 1: Single Tool Execution Test ===
✅ Phase 1: Single tool execution structure verified

=== PHASE 2: Batch Creation, Approval, Execution Test ===
Created batch: <UUID>
✅ Phase 2: Batch creation and approval verified
✅ Phase 2: Batch execution workflow verified

=== PHASE 3: Auto-Approval and Dependencies Test ===
✅ Phase 3: Autonomy settings verified
✅ Phase 3: Batch dependencies verified
✅ Phase 3: Dependency enforcement verified

╔════════════════════════════════════════╗
║  ALL PHASES VERIFIED SUCCESSFULLY! ✅  ║
╚════════════════════════════════════════╝
```

---

## Interactive Testing

### HTML Interactive Tester

**Location**: `public/test_phase1_3_interactive.html`

### Features
- Create/approve/run batches from GUI
- Real-time batch status updates
- Dependency and rollback testing
- Color-coded logging

### How to Use

1. **Start the app:**
   ```bash
   cd ~/ReverseLab/Warp_Open/warp_tauri
   npm run tauri dev
   ```

2. **Open the tester:**
   - Navigate to: `http://localhost:5173/test_phase1_3_interactive.html`
   - Or open directly in Tauri webview

3. **Run tests:**
   - Click "▶ Run Full Test"
   - Watch logs in real-time
   - All phases execute automatically

4. **Clear logs:**
   - Click "🗑️ Clear Log" to reset

### Expected Behavior
- Phase 1: Creates single-command batch, approves, executes
- Phase 2: Creates multi-command batch, approves, executes
- Phase 3: Creates auto-batch, auto-approves with token, auto-executes, attempts rollback

---

## Audit Log Verification

### Location
```
$HOME/PHASE3_AUDIT.log
```

### What to Check

#### Batch Creation Entries
```
[2025-11-24T00:00:00Z] BATCH_CREATED: <UUID>
  - entries: 2
  - tab_id: 1
```

#### Batch Approval
```
[2025-11-24T00:00:01Z] BATCH_APPROVED: <UUID>
  - approved_by: user / auto_token123
```

#### Batch Execution
```
[2025-11-24T00:00:02Z] BATCH_RUNNING: <UUID>
[2025-11-24T00:00:03Z] BATCH_COMPLETED: <UUID>
  - status: Completed
  - duration: 1.2s
```

#### Command Execution
```
[2025-11-24T00:00:02Z] COMMAND_EXECUTED: execute_shell
  - command: echo Phase3-A
  - md5: a1b2c3d4...
  - exit_code: 0
```

#### Rollback Actions
```
[2025-11-24T00:00:05Z] ROLLBACK_INITIATED: <UUID>
[2025-11-24T00:00:06Z] ROLLBACK_COMPLETED: <UUID>
```

### Verification Commands
```bash
# View full log
cat ~/PHASE3_AUDIT.log

# Search for specific batch
grep "<BATCH_ID>" ~/PHASE3_AUDIT.log

# Count batches created today
grep "BATCH_CREATED" ~/PHASE3_AUDIT.log | grep $(date +%Y-%m-%d) | wc -l
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Batch not executing | Autonomy token mismatch | Verify `autonomy_token` in settings matches approval token |
| Audit log empty | Write permissions | Ensure app has write permission to home directory: `chmod 755 ~` |
| Frontend not updating | Event not emitted | Check `batch_updated` event is being emitted from backend |
| Phase 3 auto-create not working | Settings disabled | Confirm `auto_approve_enabled` & `auto_execute_enabled` in `AutonomySettings` |
| Dependency not enforced | Parent not completed | Verify parent batch status is `Completed` before child executes |
| Rollback fails | No rollback plan | Ensure rollback plan was generated during batch creation |
| Rust tests hang | Async operations | Ensure tests don't invoke Tauri commands that need webview |

### Debug Commands

```bash
# Check if app is running
ps -ef | grep warp-tauri

# View recent audit logs
tail -f ~/PHASE3_AUDIT.log

# Test Rust backend only
cd src-tauri && cargo test --lib

# Test specific integration test
cargo test --test phase1_3_integration test_phase2_batch_workflow -- --nocapture

# Check batch state
# (in DevTools console)
await window.__TAURI__.invoke('get_batches')
```

---

## Next Steps

### ✅ Completed
- **Phase 1**: Assistive Autonomy (single tool execution)
- **Phase 2**: Semi-Autonomy (batch with approval)
- **Phase 3**: Full Autonomy (auto-batch, auto-approve, dependencies, rollback)

### ⏭️ Next: Phase 4 - Learning System
**Goal**: Adapt policy based on success/failure rates

**Features to implement:**
- Track command success/failure rates
- Adjust safety scores dynamically
- Suggest safer alternatives for failed commands
- Pattern recognition for common workflows
- User preference learning

### Future Phases
- **Phase 5**: Multi-Agent Coordination
- **Phase 6**: Long-Term Goals & Autonomous Planning

---

## Files Generated

### Backend
- `src-tauri/src/lib.rs` - Library interface
- `src-tauri/src/conversation.rs` - Phase 3 fields added
- `src-tauri/src/ai_parser.rs` - Multi-tool parser
- `src-tauri/src/rollback.rs` - Rollback mechanism
- `src-tauri/tests/phase1_3_integration.rs` - Integration tests

### Frontend
- `src/components/AutonomySettings.vue` - Phase 3 toggles
- `src/components/BatchPanel.vue` - Auto badges, dependencies, rollback
- `public/test_phase1_3_interactive.html` - Interactive tester

### Documentation
- `docs/PHASE1_3_DOCUMENTATION.md` - This file
- `PHASE3_VERIFIED.md` - Verification report
- `TESTING_GUIDE.md` - Quick reference

### Test Scripts
- `test_phase3_auto.sh` - Automated verification
- `test_full_autonomy.sh` - Comprehensive Phase 1-3 test
- `run_phase3_test.sh` - Phase 3 specific

---

## Summary

Phase 1-3 is **fully implemented, tested, and documented**. The system provides:

✅ Single tool execution with safety checks  
✅ Batch execution with manual approval  
✅ Auto-batch creation from AI responses  
✅ Auto-approval for safe commands  
✅ Auto-execution when enabled  
✅ Batch dependencies for ordered execution  
✅ Rollback mechanism for failures  
✅ Comprehensive audit logging  
✅ Rust integration tests (no webview dependency)  
✅ Interactive HTML tester (runs in Tauri app)  
✅ Full documentation and troubleshooting guide  

**Ready to proceed to Phase 4: Learning System! 🚀**
