// src-tauri/src/test_runner.rs
// Synchronous in-process executor for test purposes only
// Does not interact with Tauri runtime or async webview layer

use crate::conversation::{ConversationState, BatchStatus};
use serde::Serialize;
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Clone)]
pub struct TestEntryResult {
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Debug, Serialize)]
pub struct TestBatchResult {
    pub batch_id: String,
    pub entry_results: Vec<TestEntryResult>,
    pub success: bool,
}

/// Execute a shell command synchronously and return result
fn execute_shell_direct(cmd: &str) -> TestEntryResult {
    eprintln!("[TEST_RUNNER] Executing: {}", cmd);
    
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();
    
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let exit_code = out.status.code().unwrap_or(-1);
            
            eprintln!("[TEST_RUNNER] Exit code: {}", exit_code);
            
            TestEntryResult {
                command: cmd.to_string(),
                stdout,
                stderr,
                exit_code,
            }
        }
        Err(e) => {
            eprintln!("[TEST_RUNNER] Execution error: {}", e);
            TestEntryResult {
                command: cmd.to_string(),
                stdout: String::new(),
                stderr: format!("Execution error: {}", e),
                exit_code: -1,
            }
        }
    }
}

/// Run a batch synchronously in-process for testing
/// This bypasses all async/webview layers and executes immediately
pub fn run_phase3_batch_inproc(
    state: Arc<Mutex<ConversationState>>,
    batch_id: &str,
) -> TestBatchResult {
    eprintln!("[TEST_RUNNER] Running batch {} in-process", batch_id);
    
    let mut entry_results = vec![];
    
    // Get batch and execute each entry
    {
        let mut state_guard = state.lock().unwrap();
        
        let batch = match state_guard.get_batch(batch_id) {
            Some(b) => b.clone(),
            None => {
                eprintln!("[TEST_RUNNER] Batch {} not found", batch_id);
                return TestBatchResult {
                    batch_id: batch_id.to_string(),
                    entry_results: vec![],
                    success: false,
                };
            }
        };
        
        eprintln!("[TEST_RUNNER] Batch status: {:?}", batch.status);
        eprintln!("[TEST_RUNNER] Batch has {} entries", batch.entries.len());
        
        // Update status to Running
        state_guard.update_batch_status(batch_id, BatchStatus::Running);
        
        // Execute each entry
        for entry in batch.entries.iter() {
            // Extract command from args
            let command = if let Some(cmd) = entry.args.get("command") {
                cmd.as_str().unwrap_or("").to_string()
            } else {
                eprintln!("[TEST_RUNNER] Entry has no command");
                continue;
            };
            
            let result = execute_shell_direct(&command);
            entry_results.push(result);
        }
        
        // Update status to Completed
        state_guard.update_batch_status(batch_id, BatchStatus::Completed);
        eprintln!("[TEST_RUNNER] Batch completed successfully");
    }
    
    TestBatchResult {
        batch_id: batch_id.to_string(),
        entry_results,
        success: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::BatchEntry;
    
    #[test]
    fn test_execute_shell_direct() {
        let result = execute_shell_direct("echo 'test output'");
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("test output"));
    }
    
    #[test]
    fn test_run_batch_inproc() {
        let state = Arc::new(Mutex::new(ConversationState::new()));
        
        let batch_id = {
            let s = state.lock().unwrap();
            let tab_id = s.create_tab("Test".to_string());
            
            let entries = vec![BatchEntry {
                id: uuid::Uuid::new_v4().to_string(),
                origin_message_id: None,
                tool: "execute_shell".to_string(),
                args: serde_json::json!({"command": "echo 'inproc test'"}),
                created_at: chrono::Utc::now().to_rfc3339(),
                status: BatchStatus::Pending,
                result: None,
                safe_score: 100,
                requires_manual: false,
            }];
            
            let batch = s.create_batch(tab_id, entries);
            batch.id
        };
        
        let result = run_phase3_batch_inproc(state.clone(), &batch_id);
        
        assert!(result.success);
        assert_eq!(result.entry_results.len(), 1);
        assert!(result.entry_results[0].stdout.contains("inproc test"));
        
        // Verify batch status was updated
        let s = state.lock().unwrap();
        let batch = s.get_batch(&batch_id).unwrap();
        assert_eq!(batch.status, BatchStatus::Completed);
    }
}
