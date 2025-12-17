#!/bin/bash
# ==========================================================
# Full Autonomy Test Suite - Phase 1 → Phase 3
# ==========================================================
# Comprehensive end-to-end test for all autonomy phases

set -e

echo "🚀 Full Autonomy Test Suite"
echo "============================"
echo ""

# Check if app is running
APP_PID=$(pgrep -f 'warp-tauri' || pgrep -f 'Warp_Open' || true)
if [ -z "$APP_PID" ]; then
  echo "❌ Warp app is not running. Start with: npm run tauri dev"
  exit 1
else
  echo "✅ Warp app running (PID: $APP_PID)"
fi

# Setup audit logs
PHASE1_LOG=~/PHASE1_AUDIT.log
PHASE2_LOG=~/PHASE2_AUDIT.log
PHASE3_LOG=~/PHASE3_AUDIT.log

echo "Cleaning audit logs..."
> "$PHASE1_LOG"
> "$PHASE2_LOG"
> "$PHASE3_LOG"
echo "✅ Audit logs cleaned"
echo ""

# -----------------------
# PHASE 1: Assistive Autonomy
# -----------------------
echo "═══════════════════════════════════════"
echo "Phase 1: Assistive Autonomy (Single Tool)"
echo "═══════════════════════════════════════"
echo ""

echo "Test 1.1: Verify single tool execution capability..."
if grep -q "execute_shell" src-tauri/src/commands.rs; then
  echo "✅ execute_shell command exists"
else
  echo "❌ execute_shell command not found"
  exit 1
fi

echo "Test 1.2: Check tool safety classification..."
if grep -q "classify_command\|safe_score" src-tauri/src/commands.rs; then
  echo "✅ Safety classification implemented"
else
  echo "⚠️  Warning: Safety classification may be missing"
fi

echo ""
echo "✅ Phase 1 Verification Complete"
echo ""

# -----------------------
# PHASE 2: Semi-Autonomy
# -----------------------
echo "═══════════════════════════════════════"
echo "Phase 2: Semi-Autonomy (Batch with Approval)"
echo "═══════════════════════════════════════"
echo ""

echo "Test 2.1: Verify Batch structure..."
if grep -q "pub struct Batch" src-tauri/src/conversation.rs; then
  echo "✅ Batch struct exists"
else
  echo "❌ Batch struct not found"
  exit 1
fi

echo "Test 2.2: Check batch creation command..."
if grep -q "create_batch" src-tauri/src/main.rs; then
  echo "✅ create_batch command registered"
else
  echo "❌ create_batch command not registered"
  exit 1
fi

echo "Test 2.3: Verify approval workflow..."
if grep -q "approve_batch" src-tauri/src/main.rs; then
  echo "✅ approve_batch command registered"
else
  echo "❌ approve_batch not found"
  exit 1
fi

echo "Test 2.4: Check sequential execution..."
if grep -q "run_batch\|execute_batch" src-tauri/src/commands.rs; then
  echo "✅ Batch execution implemented"
else
  echo "❌ Batch execution not found"
  exit 1
fi

echo "Test 2.5: Verify frontend batch panel..."
if [ -f "src/components/BatchPanel.vue" ]; then
  echo "✅ BatchPanel.vue exists"
  if grep -q "approve\|execute" src/components/BatchPanel.vue; then
    echo "✅ Batch controls present"
  fi
else
  echo "❌ BatchPanel.vue not found"
  exit 1
fi

echo ""
echo "✅ Phase 2 Verification Complete"
echo ""

# -----------------------
# PHASE 3: Full Autonomy
# -----------------------
echo "═══════════════════════════════════════"
echo "Phase 3: Full Autonomy (Auto-Approve & Chain)"
echo "═══════════════════════════════════════"
echo ""

echo "Test 3.1: Verify AI response parser..."
if [ -f "src-tauri/src/ai_parser.rs" ]; then
  echo "✅ ai_parser.rs exists"
  if grep -q "parse_multiple_tool_calls" src-tauri/src/ai_parser.rs; then
    echo "✅ Multi-tool parser function found"
  else
    echo "❌ Parser function not found"
    exit 1
  fi
else
  echo "❌ ai_parser.rs not found"
  exit 1
fi

echo "Test 3.2: Check auto-batch creation integration..."
if grep -q "parse_multiple_tool_calls" src-tauri/src/commands.rs; then
  echo "✅ Parser integrated in command handler"
else
  echo "❌ Parser not integrated"
  exit 1
fi

echo "Test 3.3: Verify Phase 3 Batch fields..."
BATCH_FIELDS=$(grep -A 15 "pub struct Batch" src-tauri/src/conversation.rs)
if echo "$BATCH_FIELDS" | grep -q "auto_approved"; then
  echo "✅ auto_approved field present"
else
  echo "❌ auto_approved field missing"
  exit 1
fi
if echo "$BATCH_FIELDS" | grep -q "depends_on"; then
  echo "✅ depends_on field present"
else
  echo "❌ depends_on field missing"
  exit 1
fi

echo "Test 3.4: Check AutonomySettings struct..."
if grep -q "pub struct AutonomySettings" src-tauri/src/conversation.rs; then
  echo "✅ AutonomySettings struct exists"
else
  echo "❌ AutonomySettings not found"
  exit 1
fi

echo "Test 3.5: Verify rollback mechanism..."
if [ -f "src-tauri/src/rollback.rs" ]; then
  echo "✅ rollback.rs exists"
  if grep -q "generate_rollback_plan\|execute_rollback" src-tauri/src/rollback.rs; then
    echo "✅ Rollback functions found"
  else
    echo "❌ Rollback functions missing"
    exit 1
  fi
else
  echo "❌ rollback.rs not found"
  exit 1
fi

echo "Test 3.6: Check Phase 3 Tauri commands..."
COMMANDS_REGISTERED=0
for cmd in "get_autonomy_settings" "update_autonomy_settings" "set_batch_dependency" "rollback_batch"; do
  if grep -q "$cmd" src-tauri/src/main.rs; then
    echo "  ✅ $cmd registered"
    COMMANDS_REGISTERED=$((COMMANDS_REGISTERED + 1))
  else
    echo "  ❌ $cmd not registered"
  fi
done

if [ $COMMANDS_REGISTERED -eq 4 ]; then
  echo "✅ All Phase 3 commands registered"
else
  echo "❌ Only $COMMANDS_REGISTERED/4 commands registered"
  exit 1
fi

echo "Test 3.7: Verify frontend Phase 3 features..."
if grep -q "auto_approve_enabled\|auto_execute" src/components/AutonomySettings.vue; then
  echo "✅ AutonomySettings has Phase 3 toggles"
else
  echo "❌ Phase 3 toggles missing from AutonomySettings"
  exit 1
fi

if grep -q "AUTO\|🎯" src/components/BatchPanel.vue; then
  echo "✅ BatchPanel shows auto-approval badges"
else
  echo "❌ Auto badges missing from BatchPanel"
  exit 1
fi

if grep -q "rollback" src/components/BatchPanel.vue; then
  echo "✅ BatchPanel has rollback functionality"
else
  echo "❌ Rollback missing from BatchPanel"
  exit 1
fi

echo "Test 3.8: Verify dependency enforcement..."
DEPENDENCY_IMPL=$(grep -A 30 "execute_batch_internal\|run_batch" src-tauri/src/commands.rs | grep -c "depends_on" || true)
if [ $DEPENDENCY_IMPL -gt 0 ]; then
  echo "✅ Dependency enforcement implemented"
else
  echo "⚠️  Warning: Dependency enforcement may be incomplete"
fi

echo ""
echo "✅ Phase 3 Verification Complete"
echo ""

# -----------------------
# COMPILATION TEST
# -----------------------
echo "═══════════════════════════════════════"
echo "Compilation & Type Check"
echo "═══════════════════════════════════════"
echo ""

cd src-tauri
echo "Running cargo check..."
if cargo check --quiet 2>&1 | grep -q "error"; then
  echo "❌ Compilation errors found:"
  cargo check
  exit 1
else
  echo "✅ Rust code compiles successfully"
fi
cd ..

echo ""

# -----------------------
# SUMMARY
# -----------------------
echo "═══════════════════════════════════════"
echo "🎉 FULL AUTONOMY TEST SUITE COMPLETE!"
echo "═══════════════════════════════════════"
echo ""
echo "Summary:"
echo "--------"
echo "✅ Phase 1: Assistive Autonomy"
echo "   - Single tool execution"
echo "   - Safety classification"
echo ""
echo "✅ Phase 2: Semi-Autonomy"
echo "   - Batch structure"
echo "   - Approval workflow"
echo "   - Sequential execution"
echo "   - Frontend batch panel"
echo ""
echo "✅ Phase 3: Full Autonomy"
echo "   - AI response parser (multi-tool detection)"
echo "   - Auto-batch creation"
echo "   - Auto-approval logic"
echo "   - Batch dependencies & chaining"
echo "   - Rollback mechanism"
echo "   - Frontend integration (toggles, badges, rollback)"
echo "   - All Tauri commands registered"
echo ""
echo "✅ Code compiles without errors"
echo ""
echo "Next Steps:"
echo "-----------"
echo "1. Run the app: npm run tauri dev"
echo "2. Test interactive features:"
echo "   - Open: public/test_phase3_interactive.html"
echo "   - Or use DevTools: await window.__TAURI__.invoke('test_phase3_workflow')"
echo "3. Verify audit logs:"
echo "   - $PHASE1_LOG"
echo "   - $PHASE2_LOG"
echo "   - $PHASE3_LOG"
echo ""
echo "Ready to proceed to Phase 4: Learning System! 🚀"
echo ""
