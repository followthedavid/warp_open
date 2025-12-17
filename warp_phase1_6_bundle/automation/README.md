# Warp Phase 1-6 Automation Package

**Version**: 1.0.0  
**Status**: Production Ready  
**License**: MIT

## 🎯 Overview

The Warp Phase 1-6 Automation Package implements Tier 1 & Tier 2 intelligent automation features to minimize manual intervention while preserving human oversight for safety-critical operations.

### Features Implemented

**Tier 1 - Immediate, Low Complexity**
- ✅ Auto-approval of deterministic/safe commands
- ✅ Scheduled triggers for timed execution
- ✅ Real-time anomaly alerts
- ✅ Enhanced structured logging
- ✅ Auto-dashboard summaries

**Tier 2 - Moderate Complexity**
- ✅ Predictive plan safety scoring (ML)
- ✅ Dynamic agent assignment
- ✅ Auto-retry failed operations
- ✅ Automatic rollback mechanism
- ✅ Batch failure detection

## 📦 Package Contents

```
automation/
├── rust/
│   └── scheduler_automation.rs    # Core automation scheduler
├── js/
│   └── alertStore_automation.js   # Real-time alert management
├── python/
│   └── phase6_safety_ml.py        # ML safety prediction
├── dashboard/
│   └── dashboard_automation.html  # Live monitoring UI
└── README.md                       # This file
```

## 🚀 Quick Start

### 1. Rust Integration

Add to your `Cargo.toml`:
```toml
[dependencies]
chrono = "0.4"
serde = { version = "1.0", features = ["derive"] }
```

Copy `rust/scheduler_automation.rs` to `src-tauri/src/` and add to `main.rs`:

```rust
mod scheduler_automation;
use scheduler_automation::{SchedulerAutomation, AutomationConfig};
use std::sync::{Arc, Mutex};

fn main() {
    // Initialize automation
    let automation = Arc::new(Mutex::new(
        SchedulerAutomation::new(10) // 10 second interval
    ));
    
    tauri::Builder::default()
        .manage(automation)
        .invoke_handler(tauri::generate_handler![
            start_automation,
            stop_automation,
            update_automation_config
        ])
        .run(tauri::generate_context!())
        .expect("error running application");
}

#[tauri::command]
fn start_automation(state: tauri::State<'_, Arc<Mutex<SchedulerAutomation>>>) {
    let automation = state.lock().unwrap();
    automation.start();
}

#[tauri::command]
fn stop_automation(state: tauri::State<'_, Arc<Mutex<SchedulerAutomation>>>) {
    let automation = state.lock().unwrap();
    automation.stop();
}

#[tauri::command]
fn update_automation_config(
    state: tauri::State<'_, Arc<Mutex<SchedulerAutomation>>>,
    config: AutomationConfig
) {
    let automation = state.lock().unwrap();
    automation.update_config(config);
}
```

### 2. JavaScript/Vue Integration

Copy `js/alertStore_automation.js` to your Vue `src/composables/` directory.

In your component:
```vue
<script setup>
import { 
  alertStore, 
  startAutoMonitoring, 
  stopAutoMonitoring 
} from '@/composables/alertStore_automation.js';
import { onMounted, onUnmounted } from 'vue';

let monitoringInterval = null;

onMounted(() => {
  monitoringInterval = startAutoMonitoring(() => ({
    plans: planStore.plans,
    batches: batchStore.batches,
    agents: agentStore.agents,
    telemetry: telemetryStore.events
  }), 30000); // Check every 30 seconds
});

onUnmounted(() => {
  stopAutoMonitoring(monitoringInterval);
});
</script>

<template>
  <div v-for="alert in alertStore.alerts" :key="alert.id">
    <div :class="`alert alert-${alert.severity}`">
      {{ alert.message }}
    </div>
  </div>
</template>
```

### 3. Python ML Integration

Install dependencies:
```bash
pip install pandas numpy scikit-learn joblib
```

Train the model:
```bash
cd automation/python
python3 phase6_safety_ml.py --train --data ../../phase1_6_test.db
```

Use in Rust (via subprocess):
```rust
use std::process::Command;
use serde_json::Value;

fn get_plan_safety_score(plan_step: &PlanStep) -> f32 {
    // Write plan step to JSON
    let json_path = "/tmp/plan_step.json";
    std::fs::write(json_path, serde_json::to_string(plan_step).unwrap()).unwrap();
    
    // Call Python predictor
    let output = Command::new("python3")
        .arg("automation/python/phase6_safety_ml.py")
        .arg("--predict")
        .arg(json_path)
        .output()
        .expect("Failed to run ML predictor");
    
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    result["safety_score"].as_f64().unwrap() as f32
}
```

### 4. Dashboard Deployment

Open `dashboard/dashboard_automation.html` in:
- Tauri webview
- Standalone browser
- Embedded iframe

```rust
// Tauri: Open dashboard in new window
#[tauri::command]
fn open_automation_dashboard(app: tauri::AppHandle) {
    tauri::WindowBuilder::new(
        &app,
        "automation_dashboard",
        tauri::WindowUrl::App("automation/dashboard/dashboard_automation.html".into())
    )
    .title("Automation Dashboard")
    .inner_size(1400.0, 900.0)
    .build()
    .unwrap();
}
```

## 📊 Configuration

### Automation Config Options

```rust
pub struct AutomationConfig {
    pub enable_auto_approval: bool,      // Enable auto-approval
    pub auto_approval_threshold: f32,    // Safety threshold (0.0-1.0)
    pub enable_dynamic_assignment: bool, // Enable agent assignment
    pub enable_auto_retry: bool,         // Enable retry logic
    pub max_retry_count: u32,            // Max retries per step
    pub enable_rollback: bool,           // Enable rollback on failure
}
```

### Default Values

```rust
AutomationConfig {
    enable_auto_approval: true,
    auto_approval_threshold: 0.8,  // 80% confidence minimum
    enable_dynamic_assignment: true,
    enable_auto_retry: true,
    max_retry_count: 1,
    enable_rollback: true,
}
```

## 🔧 Advanced Usage

### Scheduled Tasks

```rust
use chrono::{Utc, Duration};
use scheduler_automation::{ScheduledTask, TaskType};

// Schedule a plan to run in 1 hour
let task = ScheduledTask {
    plan_id: "plan_001".to_string(),
    run_at: Utc::now() + Duration::hours(1),
    task_type: TaskType::AdvancePlan,
};

automation.add_scheduled_task(task);
```

### Custom Alert Monitors

```javascript
// Add custom monitoring logic
export function monitorCustomMetric(data) {
  if (data.custom_score < 50) {
    alertStore.addAlert(
      `Custom metric below threshold: ${data.custom_score}`,
      AlertSeverity.HIGH,
      { metric_id: data.id }
    );
  }
}

// Add to monitoring loop
export function runAllMonitors(state) {
  // ... existing monitors
  if (state.customData) {
    monitorCustomMetric(state.customData);
  }
}
```

### ML Model Retraining

```bash
# Export telemetry to CSV
sqlite3 phase1_6_test.db << EOF
.mode csv
.output phase6_telemetry.csv
SELECT 
  command_type,
  agent_id,
  previous_failures,
  safety_score,
  batch_size,
  dependency_count,
  execution_time_avg,
  CASE WHEN status='Completed' THEN 1 ELSE 0 END as safe_to_advance
FROM telemetry;
EOF

# Retrain model
python3 automation/python/phase6_safety_ml.py --train --data phase6_telemetry.csv
```

## 🛡️ Safety Features

### Human Oversight Preserved

- **Auto-approval only for high-confidence plans** (>80% safety score)
- **Manual review required** for ambiguous operations
- **Alert escalation** for critical issues
- **Rollback capability** for failed operations
- **Audit logging** of all automated decisions

### Safety Thresholds

| Threshold | Action |
|-----------|--------|
| ≥ 0.8 | Auto-approve |
| 0.5 - 0.8 | Manual review required |
| < 0.5 | Block + alert |

## 📈 Monitoring & Metrics

### Dashboard Metrics

- **Auto-Approved**: Count of automatically approved plans
- **Retried**: Count of retry attempts
- **Agents Assigned**: Dynamic assignments made
- **Rollbacks**: Failed operations rolled back
- **Alerts**: Total alerts generated
- **Events**: Total automation events

### Event Types

```javascript
// Tauri events emitted by automation
'auto_approved'           // Plan auto-approved
'manual_review_required'  // Manual review needed
'step_retried'            // Step retried
'step_rolled_back'        // Step rolled back
'agent_assigned'          // Agent dynamically assigned
'warp:alert'              // Alert generated
```

## 🧪 Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_auto_approval() {
        let automation = SchedulerAutomation::new(10);
        let config = automation.get_config();
        assert_eq!(config.auto_approval_threshold, 0.8);
    }
}
```

### Integration Testing

```bash
# Generate test database
python3 generate_phase1_6_db.py

# Run verification
./verify_bundle.sh

# Start automation in test mode
./run_phase1_6_auto_live.sh
```

## 🐛 Troubleshooting

### Common Issues

**Automation not starting**
```bash
# Check if scheduler is running
ps aux | grep automation

# Check logs
tail -f /tmp/warp_phase1_6_auto.log
```

**ML predictions failing**
```bash
# Verify model exists
ls -la automation/python/phase6_safety_model.pkl

# Test prediction manually
echo '{"command_type": 0, "agent_id": 1, "previous_failures": 0, "safety_score": 95, "batch_size": 1, "dependency_count": 0, "execution_time_avg": 1.5}' > test_step.json
python3 automation/python/phase6_safety_ml.py --predict test_step.json
```

**Dashboard not loading**
- Check browser console for errors
- Verify Tauri event listeners are registered
- Ensure WebSocket connection (if applicable)

## 📚 API Reference

### Rust API

```rust
// SchedulerAutomation
pub fn new(interval_sec: u64) -> Self
pub fn start(&self)
pub fn stop(&self)
pub fn add_scheduled_task(&self, task: ScheduledTask)
pub fn update_config(&self, config: AutomationConfig)
pub fn get_config(&self) -> AutomationConfig
pub fn is_running(&self) -> bool
```

### JavaScript API

```javascript
// alertStore
alertStore.addAlert(message, severity, metadata)
alertStore.removeAlert(alertId)
alertStore.acknowledgeAlert(alertId)
alertStore.clearAll()

// Monitoring
startAutoMonitoring(getState, intervalMs)
stopAutoMonitoring(intervalId)
runAllMonitors(state)
```

### Python API

```python
# Phase6SafetyPredictor
predictor = Phase6SafetyPredictor()
predictor.train(csv_path)
score = predictor.predict_safety(plan_step)
scores = predictor.predict_batch(plan_steps)
is_safe = predictor.is_safe_to_advance(plan_step, threshold)
```

## 🔄 Tier 3 Roadmap

**Future Enhancements** (Not yet implemented):
- ML-driven policy auto-approval
- Predictive batch prioritization
- Plan template generation from history
- Continuous model retraining pipeline
- Fully autonomous "Warp Ops" mode

## 📄 License

MIT License - See bundle LICENSE file

## 🤝 Support

- Check main bundle README.md
- Review DEPLOYMENT_SUMMARY.md
- Inspect logs: `/tmp/warp_phase1_6_auto.log`
- Verify with: `./verify_bundle.sh`

---

**Built with safety, observability, and human oversight as core principles.**

*Warp Phase 1-6 Automation Package v1.0.0*
