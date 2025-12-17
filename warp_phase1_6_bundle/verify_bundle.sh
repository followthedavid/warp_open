#!/usr/bin/env bash
# verify_bundle.sh
# Automated verification script for Warp Phase 1-6 Bundle

set -e

BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BUNDLE_DIR"

echo "╔════════════════════════════════════════╗"
echo "║   Warp Phase 1-6 Bundle Verification  ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

# Test function
test_check() {
    local name="$1"
    local command="$2"
    
    echo -n "Testing: $name... "
    if eval "$command" &>/dev/null; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((pass_count++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((fail_count++))
        return 1
    fi
}

echo "🔍 File Structure Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "Dashboard directory exists" "[[ -d batch6_dashboard ]]"
test_check "index.html exists" "[[ -f batch6_dashboard/index.html ]]"
test_check "style.css exists" "[[ -f batch6_dashboard/style.css ]]"
test_check "timeline.js exists" "[[ -f batch6_dashboard/timeline.js ]]"
test_check "Database generator exists" "[[ -f generate_phase1_6_db.py ]]"
test_check "Test runner exists" "[[ -f run_phase1_6_auto_live.sh ]]"
test_check "README exists" "[[ -f README.md ]]"
test_check "LICENSE exists" "[[ -f LICENSE ]]"
test_check "QUICKSTART exists" "[[ -f QUICKSTART.md ]]"

echo ""
echo "🔐 Permission Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "Database generator is executable" "[[ -x generate_phase1_6_db.py ]]"
test_check "Test runner is executable" "[[ -x run_phase1_6_auto_live.sh ]]"

echo ""
echo "💾 Database Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ -f phase1_6_test.db ]]; then
    test_check "Database file exists" "true"
    test_check "Database is valid SQLite" "sqlite3 phase1_6_test.db 'SELECT 1;'"
    test_check "Batches table exists" "sqlite3 phase1_6_test.db 'SELECT * FROM batches LIMIT 1;'"
    test_check "Agents table exists" "sqlite3 phase1_6_test.db 'SELECT * FROM agents LIMIT 1;'"
    test_check "Plans table exists" "sqlite3 phase1_6_test.db 'SELECT * FROM plans LIMIT 1;'"
    test_check "Telemetry table exists" "sqlite3 phase1_6_test.db 'SELECT * FROM telemetry LIMIT 1;'"
    
    # Count records
    batches=$(sqlite3 phase1_6_test.db "SELECT COUNT(*) FROM batches;")
    agents=$(sqlite3 phase1_6_test.db "SELECT COUNT(*) FROM agents;")
    plans=$(sqlite3 phase1_6_test.db "SELECT COUNT(*) FROM plans;")
    telemetry=$(sqlite3 phase1_6_test.db "SELECT COUNT(*) FROM telemetry;")
    
    test_check "Database has batches ($batches)" "[[ $batches -gt 0 ]]"
    test_check "Database has agents ($agents)" "[[ $agents -gt 0 ]]"
    test_check "Database has plans ($plans)" "[[ $plans -gt 0 ]]"
    test_check "Database has telemetry ($telemetry)" "[[ $telemetry -gt 0 ]]"
else
    echo -e "${YELLOW}⚠ Database not found - generating...${NC}"
    python3 generate_phase1_6_db.py
    test_check "Database generated successfully" "[[ -f phase1_6_test.db ]]"
fi

echo ""
echo "📝 Content Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "index.html contains Timeline import" "grep -q 'Timeline' batch6_dashboard/index.html"
test_check "style.css contains theme colors" "grep -q '#0f0' batch6_dashboard/style.css"
test_check "timeline.js exports Timeline class" "grep -q 'export class Timeline' batch6_dashboard/timeline.js"
test_check "README has quick start section" "grep -q 'Quick Start' README.md"
test_check "Database generator has shebang" "head -1 generate_phase1_6_db.py | grep -q '#!/usr/bin/env python3'"

echo ""
echo "🔧 Python Environment Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_check "Python3 is available" "command -v python3"
test_check "SQLite3 is available" "command -v sqlite3"

if command -v python3 &>/dev/null; then
    python_version=$(python3 --version | awk '{print $2}')
    echo "  → Python version: $python_version"
fi

echo ""
echo "╔════════════════════════════════════════╗"
echo "║           Verification Summary         ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo -e "Tests passed: ${GREEN}$pass_count${NC}"
echo -e "Tests failed: ${RED}$fail_count${NC}"
echo ""

if [[ $fail_count -eq 0 ]]; then
    echo -e "${GREEN}✅ All tests passed! Bundle is ready for use.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run: ./run_phase1_6_auto_live.sh"
    echo "  2. Or open: batch6_dashboard/index.html"
    echo "  3. Read: QUICKSTART.md for detailed instructions"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Please review the output above.${NC}"
    exit 1
fi
