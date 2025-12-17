// Tauri Integration Commands for Warp Phase 1-6 Automation
//
// This file demonstrates how to integrate the scheduler_automation.rs module
// into a Tauri application with complete IPC commands, state management,
// and event emission.
//
// Usage:
// 1. Copy this file to your src-tauri/src/ directory
// 2. Copy scheduler_automation.rs to the same directory
// 3. Add the commands to your main.rs as shown below
// 4. Update Cargo.toml with required dependencies

use scheduler_automation::{SchedulerAutomation, AutomationConfig, ScheduledTask, TaskType};
use std::sync::{Arc, Mutex};
use tauri::{Manager, State};
use serde::{Serialize, Deserialize};

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

/// Application state holding the automation scheduler
pub struct AutomationState {
    pub scheduler: Arc<Mutex<SchedulerAutomation>>,
}

impl AutomationState {
    pub fn new(interval_sec: u64) -> Self {
        Self {
            scheduler: Arc::new(Mutex::new(SchedulerAutomation::new(interval_sec))),
        }
    }
}

// ============================================================================
// TAURI COMMANDS
// ============================================================================

/// Start the automation scheduler
#[tauri::command]
pub fn start_automation(
    state: State<'_, AutomationState>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let scheduler = state.scheduler.lock()
        .map_err(|e| format!("Failed to lock scheduler: {}", e))?;
    
    scheduler.start();
    
    // Emit event to frontend
    app.emit_all("automation_started", ()).ok();
    
    Ok("Automation scheduler started successfully".to_string())
}

/// Stop the automation scheduler
#[tauri::command]
pub fn stop_automation(
    state: State<'_, AutomationState>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let scheduler = state.scheduler.lock()
        .map_err(|e| format!("Failed to lock scheduler: {}", e))?;
    
    scheduler.stop();
    
    // Emit event to frontend
    app.emit_all("automation_stopped", ()).ok();
    
    Ok("Automation scheduler stopped successfully".to_string())
}

/// Get current automation configuration
#[tauri::command]
pub fn get_automation_config(
    state: State<'_, AutomationState>,
) -> Result<AutomationConfig, String> {
    let scheduler = state.scheduler.lock()
        .map_err(|e| format!("Failed to lock scheduler: {}", e))?;
    
    Ok(scheduler.get_config())
}

/// Update automation configuration
#[tauri::command]
pub fn update_automation_config(
    state: State<'_, AutomationState>,
    config: AutomationConfig,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let scheduler = state.scheduler.lock()
        .map_err(|e| format!("Failed to lock scheduler: {}", e))?;
    
    scheduler.update_config(config.clone());
    
    // Emit event with new config
    app.emit_all("automation_config_updated", &config).ok();
    
    Ok("Configuration updated successfully".to_string())
}

/// Check if automation is currently running
#[tauri::command]
pub fn is_automation_running(
    state: State<'_, AutomationState>,
) -> Result<bool, String> {
    let scheduler = state.scheduler.lock()
        .map_err(|e| format!("Failed to lock scheduler: {}", e))?;
    
    Ok(scheduler.is_running())
}

/// Add a scheduled task to the automation queue
#[tauri::command]
pub fn add_scheduled_task(
    state: State<'_, AutomationState>,
    task: ScheduledTask,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let scheduler = state.scheduler.lock()
        .map_err(|e| format!("Failed to lock scheduler: {}", e))?;
    
    scheduler.add_scheduled_task(task.clone());
    
    // Emit event
    app.emit_all("scheduled_task_added", &task).ok();
    
    Ok(format!("Task scheduled for plan: {}", task.plan_id))
}

/// Get automation statistics (for dashboard)
#[derive(Serialize, Deserialize, Clone)]
pub struct AutomationStats {
    pub is_running: bool,
    pub auto_approved_count: u32,
    pub manual_review_count: u32,
    pub retry_count: u32,
    pub rollback_count: u32,
    pub agent_assignment_count: u32,
    pub scheduled_task_count: u32,
}

#[tauri::command]
pub fn get_automation_stats(
    state: State<'_, AutomationState>,
) -> Result<AutomationStats, String> {
    let scheduler = state.scheduler.lock()
        .map_err(|e| format!("Failed to lock scheduler: {}", e))?;
    
    // Note: You'll need to add these methods to SchedulerAutomation
    // or track stats separately in your application
    Ok(AutomationStats {
        is_running: scheduler.is_running(),
        auto_approved_count: 0,  // TODO: Track in scheduler
        manual_review_count: 0,  // TODO: Track in scheduler
        retry_count: 0,          // TODO: Track in scheduler
        rollback_count: 0,       // TODO: Track in scheduler
        agent_assignment_count: 0, // TODO: Track in scheduler
        scheduled_task_count: 0,   // TODO: Track in scheduler
    })
}

// ============================================================================
// MAIN.RS INTEGRATION EXAMPLE
// ============================================================================

/*
Add to your main.rs:

use tauri::Manager;
mod scheduler_automation;
mod tauri_commands_example;

fn main() {
    // Initialize automation state
    let automation_state = tauri_commands_example::AutomationState::new(10);
    
    tauri::Builder::default()
        .manage(automation_state)
        .invoke_handler(tauri::generate_handler![
            tauri_commands_example::start_automation,
            tauri_commands_example::stop_automation,
            tauri_commands_example::get_automation_config,
            tauri_commands_example::update_automation_config,
            tauri_commands_example::is_automation_running,
            tauri_commands_example::add_scheduled_task,
            tauri_commands_example::get_automation_stats,
        ])
        .setup(|app| {
            // Optional: Auto-start automation on app launch
            // let state = app.state::<tauri_commands_example::AutomationState>();
            // let scheduler = state.scheduler.lock().unwrap();
            // scheduler.start();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
*/

// ============================================================================
// FRONTEND INTEGRATION EXAMPLES (JavaScript/TypeScript)
// ============================================================================

/*
// Import Tauri invoke function
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';

// Start automation
async function startAutomation() {
  try {
    const result = await invoke('start_automation');
    console.log(result);
  } catch (error) {
    console.error('Failed to start automation:', error);
  }
}

// Stop automation
async function stopAutomation() {
  try {
    const result = await invoke('stop_automation');
    console.log(result);
  } catch (error) {
    console.error('Failed to stop automation:', error);
  }
}

// Get current config
async function getConfig() {
  try {
    const config = await invoke('get_automation_config');
    console.log('Current config:', config);
    return config;
  } catch (error) {
    console.error('Failed to get config:', error);
  }
}

// Update config
async function updateConfig(newConfig) {
  try {
    const result = await invoke('update_automation_config', { config: newConfig });
    console.log(result);
  } catch (error) {
    console.error('Failed to update config:', error);
  }
}

// Check if running
async function isRunning() {
  try {
    const running = await invoke('is_automation_running');
    console.log('Automation running:', running);
    return running;
  } catch (error) {
    console.error('Failed to check status:', error);
  }
}

// Add scheduled task
async function scheduleTask(planId, runAtTimestamp, taskType) {
  try {
    const task = {
      plan_id: planId,
      run_at: runAtTimestamp, // ISO 8601 timestamp
      task_type: taskType,    // 'AdvancePlan', 'ExecuteBatch', or 'RetryStep'
    };
    const result = await invoke('add_scheduled_task', { task });
    console.log(result);
  } catch (error) {
    console.error('Failed to schedule task:', error);
  }
}

// Get statistics
async function getStats() {
  try {
    const stats = await invoke('get_automation_stats');
    console.log('Automation stats:', stats);
    return stats;
  } catch (error) {
    console.error('Failed to get stats:', error);
  }
}

// Listen to automation events
async function setupEventListeners() {
  // Listen for automation start
  await listen('automation_started', (event) => {
    console.log('Automation started');
  });
  
  // Listen for automation stop
  await listen('automation_stopped', (event) => {
    console.log('Automation stopped');
  });
  
  // Listen for config updates
  await listen('automation_config_updated', (event) => {
    console.log('Config updated:', event.payload);
  });
  
  // Listen for scheduled task additions
  await listen('scheduled_task_added', (event) => {
    console.log('Task scheduled:', event.payload);
  });
  
  // Listen for auto-approval events (emitted by scheduler)
  await listen('auto_approved', (event) => {
    console.log('Plan auto-approved:', event.payload);
  });
  
  // Listen for manual review events
  await listen('manual_review_required', (event) => {
    console.log('Manual review required:', event.payload);
  });
  
  // Listen for retry events
  await listen('step_retried', (event) => {
    console.log('Step retried:', event.payload);
  });
  
  // Listen for rollback events
  await listen('step_rolled_back', (event) => {
    console.log('Step rolled back:', event.payload);
  });
  
  // Listen for agent assignment events
  await listen('agent_assigned', (event) => {
    console.log('Agent assigned:', event.payload);
  });
}

// Example Vue component usage
export default {
  data() {
    return {
      isRunning: false,
      config: null,
      stats: null,
    };
  },
  async mounted() {
    await setupEventListeners();
    await this.refreshStatus();
    
    // Refresh stats every 5 seconds
    setInterval(() => this.refreshStatus(), 5000);
  },
  methods: {
    async refreshStatus() {
      this.isRunning = await isRunning();
      this.config = await getConfig();
      this.stats = await getStats();
    },
    async toggleAutomation() {
      if (this.isRunning) {
        await stopAutomation();
      } else {
        await startAutomation();
      }
      await this.refreshStatus();
    },
    async updateThreshold(newThreshold) {
      const newConfig = {
        ...this.config,
        auto_approval_threshold: newThreshold,
      };
      await updateConfig(newConfig);
      await this.refreshStatus();
    },
  },
};
*/
