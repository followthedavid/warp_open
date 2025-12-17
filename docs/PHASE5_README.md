# Phase 5: Adaptive Policy Learning & Multi-Agent Coordination

## Overview

Phase 5 extends the Warp terminal with adaptive policy learning and multi-agent coordination capabilities. It builds on Phase 4's telemetry infrastructure to enable human-in-the-loop policy evolution and coordinated multi-agent workflows.

**Status**: ✅ Core Infrastructure Complete (4/10 tasks)

## Architecture

### Components

1. **PolicyStore** (`src-tauri/src/policy_store.rs`)
   - SQLite-backed versioned policy rule storage
   - Atomic apply/rollback with deterministic state tracking
   - Suggestion workflow (propose → review → apply/reject)
   - Tables: `policy_rules`, `policy_versions`, `policy_suggestions`

2. **AgentCoordinator** (`src-tauri/src/agents.rs`)
   - Thread-safe multi-agent state management
   - Agent registration, status updates, coordination
   - Supports idle/running/blocked states

3. **Suggestion Engine** (`phase4_trainer/phase5_suggest.py`)
   - Analyzes RandomForest feature importance from Phase 4 model
   - Proposes deny rules based on high-importance patterns
   - Outputs JSON policy diffs with confidence scores

4. **Tauri Commands** (`src-tauri/src/commands.rs`)
   - 11 new Phase 5 commands (6 policy + 5 agent)
   - Integrated into main.rs with proper state management

## Usage

### Policy Management Workflow

1. **Train Model** (Phase 4)
```bash
python3 -m phase4_trainer.train_policy \
  --csv ~/.warp_open/telemetry_export.csv \
  --out ./policy_model/policy_model.pkl
```

2. **Generate Suggestions**
```bash
python3 -m phase4_trainer.phase5_suggest \
  --csv ~/.warp_open/telemetry_export.csv \
  --model ./policy_model/policy_model.pkl \
  --out /tmp/policy_suggestions.json
```

3. **Review & Apply** (via PolicyReviewer UI)
   - View suggested policy diffs with confidence scores
   - Manually approve or reject each suggestion
   - Apply requires typing "APPLY" confirmation token
   - All changes versioned with rollback capability

### Tauri API

#### Policy Commands

```javascript
// List current policy rules
await invoke('policy_list_rules')

// Propose a new policy diff
await invoke('policy_propose_diff', {
  proposed_by: 'trainer_v1',
  diff_json: JSON.stringify({
    add: [{ pattern: '\\brm\\b', effect: 'deny', score: 0.95 }],
    remove: [],
    meta: { ... }
  })
})

// List pending suggestions
await invoke('policy_list_suggestions')

// Apply suggestion (requires confirmation)
await invoke('policy_apply_suggestion', {
  suggestion_id: 'uuid',
  author: 'admin',
  comment: 'Approved based on review',
  token: 'APPLY'  // Must type exactly "APPLY"
})

// Rollback to previous version
await invoke('policy_rollback', { version: 'version-uuid' })

// Reject suggestion
await invoke('policy_reject_suggestion', {
  suggestion_id: 'uuid',
  author: 'admin'
})

// Generate suggestions (runs Python script)
await invoke('phase5_generate_suggestions', {
  csv_path: null,  // Uses default
  model_path: null // Uses default
})
```

#### Agent Coordination Commands

```javascript
// Register new agent
const agentId = await invoke('agent_register', { name: 'Agent1' })

// Update agent status
await invoke('agent_update', {
  agent_id: agentId,
  action: 'processing_batch_3',
  score: 95
})

// Set agent status directly
await invoke('agent_set_status', {
  agent_id: agentId,
  status: 'blocked'
})

// List all agents
const agents = await invoke('agent_list')

// Unregister agent
await invoke('agent_unregister', { agent_id: agentId })
```

## Security Principles

### Hard Constraints

1. **Never Auto-Apply**: Model suggestions are NEVER automatically applied
2. **Human Approval Required**: All policy changes require explicit human review
3. **Confirmation Token**: Apply commands require typing "APPLY" exactly
4. **Audit Trail**: Every change logged with author, timestamp, comment
5. **Deterministic Rollback**: Exact state restoration using stored add_ids
6. **Local-First**: No external uploads, all processing local

### Policy Diff Format

```json
{
  "add": [
    {
      "pattern": "\\bcurl\\b.*\\|.*sh",
      "effect": "deny",
      "score": 0.98,
      "reason": "Feature importance: 0.9800"
    }
  ],
  "remove": ["rule-id-to-remove"],
  "meta": {
    "proposed_by": "trainer_v1",
    "model_version": "v1",
    "generated_at": "2024-01-15T10:30:00Z"
  }
}
```

## Database Schema

### policy_rules
- `id` TEXT PRIMARY KEY
- `pattern` TEXT NOT NULL (regex pattern)
- `effect` TEXT NOT NULL (allow/deny)
- `added_by` TEXT (author)
- `confidence` REAL (model confidence score)
- `ts` TEXT NOT NULL (ISO8601 timestamp)

### policy_versions
- `version` TEXT PRIMARY KEY (UUID)
- `ts` TEXT NOT NULL
- `author` TEXT NOT NULL
- `comment` TEXT
- `diff` TEXT NOT NULL (JSON policy diff)
- `add_ids` TEXT NOT NULL (JSON array of added rule IDs for rollback)

### policy_suggestions
- `id` TEXT PRIMARY KEY (UUID)
- `proposed_by` TEXT NOT NULL
- `proposed_at` TEXT NOT NULL
- `diff_json` TEXT NOT NULL
- `status` TEXT NOT NULL (pending/applied/rejected)
- `reviewed_by` TEXT
- `reviewed_at` TEXT

## Testing

### Unit Tests

```bash
# Test policy store and agents
cargo test --lib -- policy_store agents --nocapture
```

**Expected Output**:
- ✅ `test_policy_store_init` - Database initialization
- ✅ `test_policy_diff_workflow` - Full propose/apply/rollback cycle
- ✅ `test_agent_registration` - Agent registration and state
- ✅ `test_agent_update` - Agent status updates

### Integration Test (Manual)

1. Start app: `npm run tauri dev`
2. Open PolicyReviewer UI
3. Execute some commands to generate telemetry
4. Export CSV
5. Run trainer (Phase 4)
6. Generate suggestions (Phase 5)
7. Review and approve/reject suggestions
8. Verify policy rules updated
9. Test rollback

## Implementation Status

### ✅ Completed (4/10)
1. PolicyStore module with versioning (301 lines, 2 tests passing)
2. Policy Tauri commands (6 commands exposed)
3. Python suggestion engine (131 lines)
4. Multi-agent coordination module (120 lines, 2 tests passing)

### 🚧 Remaining (6/10)
5. PolicyReviewer UI Phase 5 enhancements
6. Phase 5 integration tests (Rust)
7. Interactive HTML tester
8. Phase 5 CI workflow
9. Combined Phase 1-5 verification script
10. Full end-to-end documentation

## File Manifest

### Rust
- `src-tauri/src/policy_store.rs` (304 lines) - Core policy storage
- `src-tauri/src/agents.rs` (120 lines) - Multi-agent coordination
- `src-tauri/src/commands.rs` (+184 lines) - Phase 5 commands
- `src-tauri/src/main.rs` (+16 lines) - Store initialization
- `src-tauri/src/lib.rs` (+2 lines) - Module exports

### Python
- `phase4_trainer/phase5_suggest.py` (131 lines) - Suggestion generator

### Documentation
- `docs/PHASE5_README.md` (this file)
- `PHASE5_IMPLEMENTATION_GUIDE.md` (339 lines) - Detailed guide

### Total New Code
- **Rust**: ~620 lines
- **Python**: ~131 lines
- **Documentation**: ~470 lines
- **Total**: ~1,221 lines

## Next Steps

1. **Update PolicyReviewer UI**
   - Add policy diff preview panel
   - Show confidence scores and model metadata
   - Implement approval workflow with confirmation
   - Add multi-agent dashboard

2. **Create Integration Tests**
   - Test full policy lifecycle
   - Test agent coordination
   - Test rollback scenarios

3. **Build Interactive Tester**
   - HTML page for manual verification
   - Visual diff display
   - Agent status visualization

4. **Add CI Pipeline**
   - Run all Phase 5 tests
   - Lint policy diff format
   - Smoke test trainer

5. **Combined Phase 1-5 Script**
   - Unified verification workflow
   - End-to-end testing
   - Documentation integration

## References

- Phase 4 README: `docs/PHASE4_README.md`
- Implementation Guide: `PHASE5_IMPLEMENTATION_GUIDE.md`
- Phase 4 Trainer: `phase4_trainer/train_policy.py`
- Telemetry Module: `src-tauri/src/telemetry.rs`

---

**Last Updated**: 2024-11-24  
**Status**: Core infrastructure complete, UI and testing in progress
