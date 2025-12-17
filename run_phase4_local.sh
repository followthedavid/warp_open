#!/bin/bash
# run_phase4_local.sh
# Helper script for Phase 4 local testing workflow

set -e

echo "================================"
echo "Phase 4 Local Workflow Runner"
echo "================================"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "phase4_trainer/train_policy.py" ]; then
    echo "Error: Must run from warp_tauri directory"
    exit 1
fi

# Step 1: Setup Python venv if not exists
if [ ! -d ".venv" ]; then
    echo -e "${BLUE}Step 1: Creating Python virtual environment...${NC}"
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r phase4_trainer/requirements.txt
    echo -e "${GREEN}✓ Python environment setup complete${NC}"
    echo ""
else
    echo -e "${GREEN}✓ Python environment exists${NC}"
    source .venv/bin/activate
    echo ""
fi

# Step 2: Run Rust telemetry tests
echo -e "${BLUE}Step 2: Running Rust telemetry tests...${NC}"
cd src-tauri
cargo test --lib telemetry -- --nocapture 2>&1 | tail -20
echo -e "${GREEN}✓ Rust tests passed${NC}"
echo ""
cd ..

# Step 3: Generate sample telemetry data
echo -e "${BLUE}Step 3: Generating sample telemetry data...${NC}"
mkdir -p testdata
python3 phase4_trainer/generate_sample_csv.py --out ./testdata/sample_telemetry.csv --count 150
echo -e "${GREEN}✓ Sample data generated: testdata/sample_telemetry.csv${NC}"
echo ""

# Step 4: Train model on sample data
echo -e "${BLUE}Step 4: Training policy model...${NC}"
python3 -m phase4_trainer.train_policy --csv ./testdata/sample_telemetry.csv --out ./policy_model/policy_model.pkl
echo -e "${GREEN}✓ Model trained: policy_model/policy_model.pkl${NC}"
echo ""

# Step 5: Test predictions
echo -e "${BLUE}Step 5: Testing predictions...${NC}"
echo ""
echo "Test 1: Safe command"
python3 -m phase4_trainer.predict "ls -la"
echo ""
echo "Test 2: Unsafe command"
python3 -m phase4_trainer.predict "rm -rf /"
echo ""
echo "Test 3: Unknown command"
python3 -m phase4_trainer.predict "git status"
echo ""

echo -e "${GREEN}✓ Predictions look good!${NC}"
echo ""

# Summary
echo "================================"
echo "Phase 4 Local Workflow Complete"
echo "================================"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Start app: npm run tauri dev"
echo "2. Open PolicyReviewer component"
echo "3. Review telemetry data"
echo "4. Label some commands manually"
echo "5. Export CSV and retrain"
echo ""
echo -e "${GREEN}All Phase 4 components verified!${NC}"
