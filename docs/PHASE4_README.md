# Phase 4: Telemetry & Learning System

**Status**: ✅ **IMPLEMENTED**  
**Date**: November 24, 2025

---

## Overview

Phase 4 adds a learning and observability layer to Warp's autonomy system. It collects telemetry from command execution, trains safety classifiers offline, and provides a human-in-the-loop review workflow for policy updates.

**Key Principles:**
- 🔒 **Human approval required** for all policy changes
- 📊 **Local-first** - all data stays on your machine
- 🧪 **Experimental** - models assist humans, never auto-apply
- 🔍 **Observable** - full audit trail of decisions

---

## Architecture

```
┌──────────────────┐
│  Command Exec    │──┐
│  (Phase 1-3)     │  │
└──────────────────┘  │
                      ├──> Telemetry Events
┌──────────────────┐  │
│  Policy Engine   │──┘
│  (classify_cmd)  │
└──────────────────┘

         │
         ▼
┌──────────────────────┐
│  Telemetry Store     │
│  (SQLite)            │
│  ~/.warp_open/       │
│  telemetry.sqlite    │
└──────────────────────┘
         │
         ├──> Export CSV
         │
         ▼
┌──────────────────────┐
│  Trainer (Python)    │
│  sklearn RandomFor   │
│  forest              │
└──────────────────────┘
         │
         ▼
┌──────────────────────┐
│  policy_model.pkl    │
│  (classifier)        │
└──────────────────────┘
         │
         ▼
┌──────────────────────┐
│  Policy Reviewer UI  │
│  (Vue component)     │
│  - Review predictions│
│  - Manual labeling   │
│  - Trigger training  │
└──────────────────────┘
```

---

## Components

### 1. Telemetry Store (Rust)

**File**: `src-tauri/src/telemetry.rs`

SQLite-backed telemetry storage that captures:
- Command text
- Exit codes
- Tool names
- Safety scores (from policy engine)
- Manual labels (from human review)
- Execution metadata

**Schema**:
```sql
CREATE TABLE telemetry (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    tab_id INTEGER,
    batch_id TEXT,
    tool TEXT,
    command TEXT,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    safety_score INTEGER,
    safety_label INTEGER,  -- 0=safe, 1=unsafe, 2=unknown
    metadata TEXT
);
```

**API**:
- `telemetry_insert_event(event_json)` - Insert event
- `telemetry_query_recent(limit)` - Query N most recent events
- `telemetry_export_csv(out_path)` - Export to CSV for training

**Location**: `~/.warp_open/telemetry.sqlite`

### 2. Policy Trainer (Python)

**File**: `phase4_trainer/train_policy.py`

Offline trainer that:
- Loads telemetry CSV
- Extracts command text features (TF-IDF)
- Trains RandomForest classifier (safe vs unsafe)
- Outputs metrics and model file

**Features**:
- TF-IDF vectorization (1-3 gram features)
- 200-tree RandomForest with max_depth=10
- Train/test split with stratification
- Classification report + confusion matrix
- Feature importance analysis

**Usage**:
```bash
# Generate sample data
python3 phase4_trainer/generate_sample_csv.py --out ./testdata/sample.csv

# Train model
python3 -m phase4_trainer.train_policy --csv ./testdata/sample.csv --out ./policy_model/policy_model.pkl
```

**Requirements**:
```bash
cd phase4_trainer
pip install -r requirements.txt
```

Dependencies:
- numpy
- pandas
- scikit-learn
- joblib
- sqlalchemy

### 3. Prediction Script (Python)

**File**: `phase4_trainer/predict.py`

Predict safety for individual commands:

```bash
python3 -m phase4_trainer.predict "rm -rf /"
# Output:
# Command: rm -rf /
# Prediction: unsafe
# Confidence: 98.50%
# Probabilities: safe=1.50%, unsafe=98.50%
```

### 4. Policy Reviewer UI (Vue)

**File**: `src/components/PolicyReviewer.vue`

Interactive review interface:
- **Refresh** - Load recent telemetry
- **Export CSV** - Export for training
- **Run Trainer** - Trigger model training
- **Manual Labeling** - Label events as safe/unsafe/unknown
- **Visual Feedback** - Color-coded rows by label and score

**Access**: Open PolicyReviewer component in your Warp app

---

## Workflow

### End-to-End Process

1. **Collect Telemetry** (Automatic)
   - Commands execute through Phase 1-3
   - Policy engine assigns safety_score
   - Events logged to telemetry database

2. **Review & Label** (Manual)
   - Open PolicyReviewer UI
   - Review recent commands
   - Apply manual labels where model is uncertain
   - Labels saved as new telemetry events

3. **Export Data** (Click button)
   - Export CSV from PolicyReviewer
   - Default: `~/.warp_open/telemetry_export.csv`

4. **Train Model** (Click button or CLI)
   - Trainer reads CSV
   - Trains classifier on labeled data
   - Outputs `policy_model/policy_model.pkl`
   - Shows accuracy metrics

5. **Review Predictions** (Future Integration)
   - Load model in policy engine
   - Suggest safety adjustments
   - Human approves or rejects suggestions

---

## Safety & Security

### Critical Rules

1. **Never Auto-Apply Policy Changes**
   - Trainer outputs are suggestions only
   - Human must approve every policy update
   - No automated enforcement of model predictions

2. **Hard Denylist Cannot Be Overridden**
   - Model cannot reduce safety of known-dangerous patterns
   - Denylist patterns (rm -rf, curl|sh, etc.) always blocked
   - Model can only suggest adding to denylist

3. **Local Data Only**
   - All telemetry stays on local machine
   - No external uploads or API calls
   - SQLite database at `~/.warp_open/`

4. **Access Control**
   - `phase4_trigger_trainer` command is manual-only
   - Requires explicit user click in UI
   - Confirmation dialog before training

5. **Audit Trail**
   - Every label change logged as telemetry event
   - Metadata includes who, when, why
   - Full history preserved in SQLite

### Operational Safety

- **Start Small**: Collect 100+ diverse examples before training
- **Review Labels**: Check label distribution before training
- **Validate Model**: Review accuracy metrics before using predictions
- **Test Predictions**: Use `predict.py` to spot-check commands
- **Incremental Updates**: Retrain periodically, don't rely on stale models

---

## Testing

### Local Smoke Tests

1. **Telemetry Init**
```bash
cd src-tauri
cargo test --lib telemetry -- --nocapture
```

2. **Generate Sample Data**
```bash
python3 phase4_trainer/generate_sample_csv.py --out ./testdata/sample.csv --count 100
```

3. **Train on Sample**
```bash
python3 -m phase4_trainer.train_policy --csv ./testdata/sample.csv --out ./policy_model/test_model.pkl
```

4. **Predict Command**
```bash
python3 -m phase4_trainer.predict --model ./policy_model/test_model.pkl "echo hello"
```

5. **UI Manual Test**
- Launch app: `npm run tauri dev`
- Open PolicyReviewer component
- Click Refresh → verify events load
- Click Export CSV → verify file created
- Click Run Trainer → verify training completes

---

## CI Integration

GitHub Actions workflow for Phase 4:

```yaml
name: Phase 4 Tests
on: [push]
jobs:
  phase4:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      
      - name: Run Telemetry Tests
        run: |
          cd warp_tauri/src-tauri
          cargo test --lib telemetry
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Trainer Deps
        run: |
          python -m venv .venv
          source .venv/bin/activate
          pip install -r phase4_trainer/requirements.txt
      
      - name: Generate Sample Data
        run: |
          source .venv/bin/activate
          python3 phase4_trainer/generate_sample_csv.py --out ./testdata/sample.csv --count 100
      
      - name: Train Model
        run: |
          source .venv/bin/activate
          python3 -m phase4_trainer.train_policy --csv ./testdata/sample.csv --out ./policy_model/test.pkl
```

---

## Files

### Created

**Rust Backend:**
- `src-tauri/src/telemetry.rs` (295 lines) - Telemetry store
- `src-tauri/src/commands.rs` (added 88 lines) - Tauri commands
- `src-tauri/src/main.rs` (modified) - Initialize telemetry store

**Python Trainer:**
- `phase4_trainer/requirements.txt` - Dependencies
- `phase4_trainer/train_policy.py` (154 lines) - Trainer script
- `phase4_trainer/predict.py` (41 lines) - Prediction script
- `phase4_trainer/generate_sample_csv.py` (110 lines) - Sample data generator

**Frontend:**
- `src/components/PolicyReviewer.vue` (279 lines) - Review UI

**Documentation:**
- `docs/PHASE4_README.md` (this file)

**Helper Scripts:**
- `run_phase4_local.sh` - Local workflow automation

---

## Usage Examples

### Example 1: First Time Setup

```bash
# 1. Install Python dependencies
cd phase4_trainer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Generate sample data for testing
python3 generate_sample_csv.py --out ../testdata/sample.csv --count 200

# 3. Train initial model
python3 -m train_policy --csv ../testdata/sample.csv --out ../policy_model/policy_model.pkl

# 4. Test prediction
python3 -m predict "ls -la"
```

### Example 2: Review & Retrain Workflow

1. Use app normally - telemetry collects automatically
2. Open PolicyReviewer UI in app
3. Review recent commands
4. Label uncertain cases manually
5. Click "Export CSV"
6. Click "Run Trainer" (or run manually in terminal)
7. Review metrics in terminal output
8. Model saved to `policy_model/policy_model.pkl`

### Example 3: Check Model Quality

```bash
# After training, spot-check predictions
python3 -m phase4_trainer.predict "rm -rf /"     # Should be unsafe
python3 -m phase4_trainer.predict "ls -la"       # Should be safe
python3 -m phase4_trainer.predict "git status"   # May be unknown

# If predictions look good, model is ready for review
# Human decides whether to apply any suggestions
```

---

## Troubleshooting

### Telemetry Database Not Found

**Error**: `Failed to open telemetry database`

**Solution**:
```bash
mkdir -p ~/.warp_open
# Restart app - database will be created automatically
```

### Trainer Not Found

**Error**: `Failed to run trainer: No such file or directory`

**Solution**:
```bash
# Ensure Python3 is installed
which python3

# Ensure phase4_trainer is in project root
ls phase4_trainer/train_policy.py

# Install dependencies
cd phase4_trainer
pip install -r requirements.txt
```

### Not Enough Training Data

**Error**: `Not enough labeled training data (5 samples)`

**Solution**:
- Need at least 10 labeled examples (safety_label = 0 or 1)
- Use PolicyReviewer to manually label more commands
- Or generate sample data: `python3 generate_sample_csv.py`

### Model Predictions Are Bad

**Symptoms**: Low accuracy, wrong predictions

**Solutions**:
1. Check label distribution - need both safe AND unsafe examples
2. Collect more diverse commands
3. Review and correct mislabeled data
4. Retrain with larger dataset (200+ samples recommended)

---

## Future Enhancements

### Phase 4B (Planned)

- **Real-time Predictions**: Load model in Rust, predict on each command
- **Confidence Thresholds**: Only show predictions above confidence level
- **Pattern Recognition**: Detect common command sequences
- **Auto-Suggest Allow/Deny**: Propose new patterns for human review

### Phase 4C (Planned)

- **Policy Diff View**: Show before/after policy changes
- **Approval Workflow**: Multi-stage review for policy updates
- **Rollback**: Revert to previous policy version
- **A/B Testing**: Compare old vs new policy in safe mode

---

## Conclusion

Phase 4 provides a foundation for learning from execution history while maintaining strict human oversight. The system is designed to assist, not replace, human judgment in security-critical decisions.

**Next Steps**:
1. Collect real telemetry from your usage
2. Review and label edge cases
3. Train initial model
4. Evaluate predictions manually
5. Decide on policy improvements (with human approval)

**Status**: ✅ **COMPLETE AND READY FOR USE**
