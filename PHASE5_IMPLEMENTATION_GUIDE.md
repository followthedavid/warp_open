# Phase 5 Implementation Guide

**Status**: PolicyStore Complete + Remaining Components Ready

---

## Completed ✅

### PolicyStore Module (301 lines)
- **File**: `src-tauri/src/policy_store.rs`
- **Features**:
  - SQLite-backed versioned policy rules
  - Propose/apply/rollback policy diffs
  - Suggestion tracking and approval workflow
  - Atomic transactions with add_ids tracking
  - 2 unit tests (both passing)

---

## Remaining Components (Ready to Paste)

### 1. Expose policy_store in lib.rs

```rust
// Add to src-tauri/src/lib.rs
pub mod policy_store;
```

### 2. Initialize PolicyStore in main.rs

```rust
// Add to src-tauri/src/main.rs after telemetry_store init
let policy_store = PolicyStore::open(std::path::PathBuf::from(format!("{}/policy.sqlite", warp_dir)))
    .expect("Failed to open policy database");
```

### 3. Add Policy Tauri Commands

```rust
// Add to src-tauri/src/commands.rs

use crate::policy_store::{PolicyStore, PolicyRule};

#[tauri::command]
pub fn policy_list_rules(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
) -> Result<Vec<PolicyRule>, String> {
    policy.lock().unwrap()
        .list_rules()
        .map_err(|e| format!("Failed to list rules: {}", e))
}

#[tauri::command]
pub fn policy_propose_diff(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
    proposed_by: String,
    diff_json: String,
) -> Result<String, String> {
    policy.lock().unwrap()
        .propose_diff(&proposed_by, &diff_json)
        .map_err(|e| format!("Failed to propose diff: {}", e))
}

#[tauri::command]
pub fn policy_list_suggestions(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
) -> Result<Vec<serde_json::Value>, String> {
    policy.lock().unwrap()
        .list_suggestions()
        .map_err(|e| format!("Failed to list suggestions: {}", e))
}

#[tauri::command]
pub fn policy_apply_suggestion(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
    suggestion_id: String,
    author: String,
    comment: String,
    token: String, // Confirmation token
) -> Result<String, String> {
    // Security: verify token matches expected confirmation
    if token != "APPLY" {
        return Err("Invalid confirmation token. Type APPLY to confirm.".to_string());
    }
    
    policy.lock().unwrap()
        .apply_diff(&suggestion_id, &author, &comment)
        .map_err(|e| format!("Failed to apply suggestion: {}", e))
}

#[tauri::command]
pub fn policy_rollback(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
    version: String,
) -> Result<(), String> {
    policy.lock().unwrap()
        .rollback_version(&version)
        .map_err(|e| format!("Failed to rollback: {}", e))
}

#[tauri::command]
pub fn policy_reject_suggestion(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
    suggestion_id: String,
    author: String,
) -> Result<(), String> {
    policy.lock().unwrap()
        .reject_suggestion(&suggestion_id, &author)
        .map_err(|e| format!("Failed to reject: {}", e))
}
```

### 4. Register Commands in main.rs

```rust
.invoke_handler(tauri::generate_handler![
    // ... existing commands
    policy_list_rules,
    policy_propose_diff,
    policy_list_suggestions,
    policy_apply_suggestion,
    policy_rollback,
    policy_reject_suggestion,
])
```

### 5. Python Suggestion Script

**File**: `phase4_trainer/phase5_suggest.py`

```python
#!/usr/bin/env python3
# phase4_trainer/phase5_suggest.py
import argparse
import pandas as pd
import numpy as np
import joblib
import json
import re
from sklearn.feature_extraction.text import TfidfVectorizer

def suggest_policy_diff(csv_path: str, model_path: str, out_json: str, top_n: int = 20):
    """Generate policy diff suggestions from trained model"""
    
    # Load data and model
    df = pd.read_csv(csv_path)
    model = joblib.load(model_path)
    
    # Extract feature importance from pipeline
    vect = model.named_steps['tfidf']
    clf = model.named_steps['clf']
    feature_names = vect.get_feature_names_out()
    importances = clf.feature_importances_
    
    # Get top features that predict unsafe
    top_features = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:top_n]
    
    suggestions = []
    for term, score in top_features:
        # Create safe regex pattern (escape special chars)
        pattern = r'\b' + re.escape(term) + r'\b'
        suggestions.append({
            'pattern': pattern,
            'effect': 'deny',
            'score': float(score)
        })
    
    # Generate policy diff
    policy_diff = {
        'add': suggestions,
        'remove': [],
        'meta': {
            'proposed_by': 'trainer_v1',
            'model_version': 'v1',
            'generated_at': pd.Timestamp.now().isoformat()
        }
    }
    
    with open(out_json, 'w') as f:
        json.dump(policy_diff, f, indent=2)
    
    print(f"Generated {len(suggestions)} policy suggestions")
    print(f"Saved to: {out_json}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate policy diff suggestions")
    parser.add_argument('--csv', required=True, help="Telemetry CSV")
    parser.add_argument('--model', required=True, help="Trained model .pkl file")
    parser.add_argument('--out', required=True, help="Output JSON file")
    parser.add_argument('--top-n', type=int, default=20, help="Number of suggestions")
    args = parser.parse_args()
    
    suggest_policy_diff(args.csv, args.model, args.out, args.top_n)
```

### 6. Multi-Agent Coordination Module

**File**: `src-tauri/src/agents.rs`

```rust
// src-tauri/src/agents.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentState {
    pub id: String,
    pub name: String,
    pub status: String, // idle, running, blocked
    pub last_action: Option<String>,
    pub last_score: Option<i32>,
}

#[derive(Clone)]
pub struct AgentCoordinator {
    pub agents: Arc<Mutex<HashMap<String, AgentState>>>,
}

impl AgentCoordinator {
    pub fn new() -> Self {
        AgentCoordinator {
            agents: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_agent(&self, name: Option<String>) -> String {
        let id = Uuid::new_v4().to_string();
        let agent_name = name.unwrap_or_else(|| format!("Agent_{}", &id[..8]));
        
        let agent = AgentState {
            id: id.clone(),
            name: agent_name,
            status: "idle".to_string(),
            last_action: None,
            last_score: None,
        };
        
        self.agents.lock().unwrap().insert(id.clone(), agent);
        eprintln!("[AGENTS] Registered agent: {}", id);
        id
    }

    pub fn update_agent(&self, agent_id: &str, action: String, score: i32) -> anyhow::Result<()> {
        let mut agents = self.agents.lock().unwrap();
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.last_action = Some(action);
            agent.last_score = Some(score);
            agent.status = "running".to_string();
            Ok(())
        } else {
            anyhow::bail!("Agent not found")
        }
    }

    pub fn get_agents(&self) -> Vec<AgentState> {
        self.agents.lock().unwrap().values().cloned().collect()
    }
}
```

### 7. Agent Tauri Commands

```rust
// Add to commands.rs
use crate::agents::{AgentCoordinator, AgentState};

#[tauri::command]
pub fn agent_register(
    coordinator: State<'_, AgentCoordinator>,
    name: Option<String>,
) -> String {
    coordinator.register_agent(name)
}

#[tauri::command]
pub fn agent_update(
    coordinator: State<'_, AgentCoordinator>,
    agent_id: String,
    action: String,
    score: i32,
) -> Result<(), String> {
    coordinator.update_agent(&agent_id, action, score)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_list(
    coordinator: State<'_, AgentCoordinator>,
) -> Vec<AgentState> {
    coordinator.get_agents()
}
```

---

## Testing

### Run Policy Store Tests
```bash
cd src-tauri
cargo test --lib policy_store -- --nocapture
```

### Generate Policy Suggestions
```bash
source .venv/bin/activate
python3 -m phase4_trainer.phase5_suggest \
    --csv ~/.warp_open/telemetry_export.csv \
    --model ./policy_model/policy_model.pkl \
    --out /tmp/policy_suggestions.json
```

---

## Security Principles

1. **Human Approval Required**: All policy changes require explicit approval
2. **Confirmation Token**: Apply commands require typing "APPLY"
3. **Audit Trail**: Every change logged with author, timestamp, version
4. **Rollback Support**: Deterministic rollback using stored add_ids
5. **No Auto-Apply**: Trainer suggestions never auto-applied

---

## Next Steps

1. Add remaining modules to `src-tauri/src/lib.rs`
2. Initialize stores in `main.rs`
3. Register all Tauri commands
4. Create Phase 5 tests
5. Build PolicyReviewer UI enhancements
6. Create documentation
7. Add CI workflow

---

**Status**: Core infrastructure complete, integration components ready to paste
