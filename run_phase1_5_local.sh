#!/usr/bin/env bash
# run_phase1_5_local.sh
# Combined Phase 1-5 Local Verification Script
# Tests all Warp phases end-to-end

set -e

echo "========================================"
echo "🚀 Warp Phase 1-5 Combined Verification"
echo "========================================"
echo ""

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_step() {
    echo -e "${YELLOW}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((PASSED++))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    ((FAILED++))
}

# ========================================
# Phase 1: Core PTY & Basic Commands
# ========================================
print_header "Phase 1: Core PTY & Basic Commands"

print_step "Building Rust library..."
cd src-tauri
if cargo build --lib 2>&1 | tail -5; then
    print_success "Rust library compiles"
else
    print_error "Rust library failed to compile"
fi

print_step "Running PTY unit tests..."
if cargo test --lib --test pty -- --nocapture 2>&1 | grep -q "test result: ok"; then
    print_success "PTY tests pass"
else
    print_error "PTY tests failed"
fi

# ========================================
# Phase 2: Policy Engine
# ========================================
print_header "Phase 2: Policy Engine"

print_step "Testing command classification..."
if cargo test --lib -- test_command_classification --nocapture 2>&1 | grep -q "test result: ok"; then
    print_success "Command classification works"
else
    print_error "Command classification failed"
fi

print_step "Verifying deny patterns..."
if grep -q "DENY_PATTERNS" src/commands.rs; then
    print_success "Deny patterns defined"
else
    print_error "Deny patterns not found"
fi

# ========================================
# Phase 3: Batch Operations & Autonomy
# ========================================
print_header "Phase 3: Batch Operations & Autonomy"

print_step "Testing conversation state..."
if cargo test --lib conversation -- --nocapture 2>&1 | grep -q "test result: ok"; then
    print_success "Conversation state tests pass"
else
    print_error "Conversation state tests failed"
fi

print_step "Testing rollback functionality..."
if cargo test --lib rollback -- --nocapture 2>&1 | grep -q "test result: ok"; then
    print_success "Rollback tests pass"
else
    print_error "Rollback tests failed"
fi

# ========================================
# Phase 4: Telemetry & Learning
# ========================================
print_header "Phase 4: Telemetry & Learning System"

print_step "Testing telemetry store..."
if cargo test --lib telemetry -- --nocapture 2>&1 | grep -q "test result: ok"; then
    print_success "Telemetry tests pass"
else
    print_error "Telemetry tests failed"
fi

print_step "Checking Python trainer..."
cd ../phase4_trainer
if [ -f "train_policy.py" ] && [ -f "requirements.txt" ]; then
    print_success "Phase 4 trainer files present"
else
    print_error "Phase 4 trainer files missing"
fi

print_step "Verifying Python dependencies..."
if python3 -c "import pandas, numpy, sklearn, joblib" 2>/dev/null; then
    print_success "Python dependencies available"
else
    print_error "Python dependencies missing (run: pip install -r requirements.txt)"
fi

# ========================================
# Phase 5: Policy Learning & Multi-Agent
# ========================================
print_header "Phase 5: Adaptive Policy Learning & Multi-Agent Coordination"

cd ../src-tauri

print_step "Testing PolicyStore module..."
if cargo test --lib policy_store -- --nocapture 2>&1 | grep -q "test result: ok"; then
    print_success "PolicyStore tests pass"
else
    print_error "PolicyStore tests failed"
fi

print_step "Testing AgentCoordinator module..."
if cargo test --lib agents -- --nocapture 2>&1 | grep -q "test result: ok"; then
    print_success "AgentCoordinator tests pass"
else
    print_error "AgentCoordinator tests failed"
fi

print_step "Running Phase 5 integration tests..."
if cargo test --test phase5_integration -- --nocapture 2>&1 | grep -q "test result: ok"; then
    print_success "Phase 5 integration tests pass"
else
    print_error "Phase 5 integration tests failed"
fi

print_step "Checking Phase 5 Python suggestion generator..."
cd ../phase4_trainer
if [ -f "phase5_suggest.py" ]; then
    print_success "phase5_suggest.py present"
else
    print_error "phase5_suggest.py missing"
fi

print_step "Verifying suggestion generator imports..."
if python3 -c "from phase5_suggest import suggest_policy_diff" 2>/dev/null; then
    print_success "Suggestion generator imports OK"
else
    print_error "Suggestion generator import failed"
fi

# ========================================
# Security Checks
# ========================================
print_header "Security & Safety Checks"

cd ../src-tauri

print_step "Verifying no auto-apply in policy code..."
if grep -r "auto.*apply" src/policy_store.rs src/commands.rs 2>/dev/null; then
    print_error "Found potential auto-apply code (SECURITY RISK)"
else
    print_success "No auto-apply patterns found"
fi

print_step "Verifying APPLY token check..."
if grep -q 'token != "APPLY"' src/commands.rs; then
    print_success "APPLY token verification present"
else
    print_error "APPLY token check missing (SECURITY RISK)"
fi

print_step "Checking for hard-coded secrets..."
if grep -ri "api_key\|password\|secret" src/*.rs 2>/dev/null | grep -v "safety_score\|safety_label\|// " | grep -q .; then
    print_error "Potential hard-coded secrets found"
else
    print_success "No hard-coded secrets detected"
fi

# ========================================
# Documentation Check
# ========================================
print_header "Documentation Verification"

cd ..

print_step "Checking Phase 4 documentation..."
if [ -f "docs/PHASE4_README.md" ]; then
    print_success "Phase 4 README present"
else
    print_error "Phase 4 README missing"
fi

print_step "Checking Phase 5 documentation..."
if [ -f "docs/PHASE5_README.md" ]; then
    print_success "Phase 5 README present"
else
    print_error "Phase 5 README missing"
fi

print_step "Checking implementation guides..."
if [ -f "PHASE5_IMPLEMENTATION_GUIDE.md" ]; then
    print_success "Phase 5 implementation guide present"
else
    print_error "Phase 5 implementation guide missing"
fi

# ========================================
# File Structure Check
# ========================================
print_header "File Structure Verification"

print_step "Checking critical Phase 5 files..."
CRITICAL_FILES=(
    "src-tauri/src/policy_store.rs"
    "src-tauri/src/agents.rs"
    "src-tauri/tests/phase5_integration.rs"
    "phase4_trainer/phase5_suggest.py"
    "test_phase5_multi_agent.html"
    ".github/workflows/phase5.yml"
)

for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        print_success "$file exists"
    else
        print_error "$file missing"
    fi
done

# ========================================
# Interactive Tester Check
# ========================================
print_header "Interactive Testing Tools"

print_step "Checking HTML tester..."
if [ -f "test_phase5_multi_agent.html" ]; then
    LINES=$(wc -l < test_phase5_multi_agent.html)
    print_success "HTML tester present ($LINES lines)"
else
    print_error "HTML tester missing"
fi

# ========================================
# Summary
# ========================================
print_header "Test Summary"

TOTAL=$((PASSED + FAILED))
PASS_RATE=$((PASSED * 100 / TOTAL))

echo ""
echo "Total Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Pass Rate: ${PASS_RATE}%"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}========================================"
    echo "✅ ALL PHASE 1-5 CHECKS PASSED!"
    echo "========================================${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Run the app: npm run tauri dev"
    echo "2. Open test_phase5_multi_agent.html in browser"
    echo "3. Test policy management and agent coordination"
    exit 0
else
    echo -e "${RED}========================================"
    echo "❌ SOME CHECKS FAILED"
    echo "========================================${NC}"
    echo ""
    echo "Review failed tests above and fix issues."
    exit 1
fi
