// Phase 3: Rollback mechanism for failed batches
use serde::{Deserialize, Serialize};
use crate::conversation::{Batch, BatchStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackAction {
    pub entry_id: String,
    pub tool: String,
    pub undo_operation: UndoOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UndoOperation {
    DeleteFile { path: String },
    RestoreFile { path: String, original_content: String },
    None, // For read-only operations
}

/// Generate rollback plan for a batch
pub fn generate_rollback_plan(batch: &Batch) -> Vec<RollbackAction> {
    let mut actions = Vec::new();
    
    for entry in &batch.entries {
        if entry.status != BatchStatus::Completed {
            continue; // Only rollback completed entries
        }
        
        let undo_op = match entry.tool.as_str() {
            "write_file" => {
                // For write operations, we need to capture the original state
                // In real implementation, would need to read file before write
                if let Some(path) = entry.args.get("path").and_then(|p| p.as_str()) {
                    UndoOperation::DeleteFile {
                        path: path.to_string(),
                    }
                } else {
                    UndoOperation::None
                }
            }
            "execute_shell" => {
                // Shell commands are generally not reversible
                UndoOperation::None
            }
            "read_file" => {
                // Read operations don't need rollback
                UndoOperation::None
            }
            _ => UndoOperation::None,
        };
        
        actions.push(RollbackAction {
            entry_id: entry.id.clone(),
            tool: entry.tool.clone(),
            undo_operation: undo_op,
        });
    }
    
    actions
}

/// Execute rollback actions
pub async fn execute_rollback(actions: Vec<RollbackAction>) -> Result<String, String> {
    let mut results = Vec::new();
    
    for action in actions {
        match &action.undo_operation {
            UndoOperation::DeleteFile { path } => {
                let expanded = shellexpand::tilde(path).to_string();
                match std::fs::remove_file(&expanded) {
                    Ok(_) => {
                        results.push(format!("[{}] Deleted: {}", action.entry_id, path));
                        eprintln!("[ROLLBACK] Deleted file: {}", path);
                    }
                    Err(e) => {
                        results.push(format!("[{}] Failed to delete {}: {}", action.entry_id, path, e));
                        eprintln!("[ROLLBACK] Failed to delete {}: {}", path, e);
                    }
                }
            }
            UndoOperation::RestoreFile { path, original_content } => {
                let expanded = shellexpand::tilde(path).to_string();
                match std::fs::write(&expanded, original_content) {
                    Ok(_) => {
                        results.push(format!("[{}] Restored: {}", action.entry_id, path));
                        eprintln!("[ROLLBACK] Restored file: {}", path);
                    }
                    Err(e) => {
                        results.push(format!("[{}] Failed to restore {}: {}", action.entry_id, path, e));
                        eprintln!("[ROLLBACK] Failed to restore {}: {}", path, e);
                    }
                }
            }
            UndoOperation::None => {
                results.push(format!("[{}] No rollback needed for {}", action.entry_id, action.tool));
            }
        }
    }
    
    Ok(results.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::BatchEntry;
    use serde_json::json;
    
    #[test]
    fn test_rollback_plan_generation() {
        let entry = BatchEntry {
            id: "test-1".to_string(),
            origin_message_id: None,
            tool: "write_file".to_string(),
            args: json!({ "path": "/tmp/test.txt", "content": "test" }),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            status: BatchStatus::Completed,
            result: Some("success".to_string()),
            safe_score: 100,
            requires_manual: false,
        };
        
        let batch = Batch {
            id: "batch-1".to_string(),
            entries: vec![entry],
            creator_tab: 1,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            status: BatchStatus::Completed,
            approved_by: None,
            auto_approved: false,
            depends_on: None,
        };
        
        let plan = generate_rollback_plan(&batch);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].tool, "write_file");
        
        match &plan[0].undo_operation {
            UndoOperation::DeleteFile { path } => {
                assert_eq!(path, "/tmp/test.txt");
            }
            _ => panic!("Expected DeleteFile operation"),
        }
    }
}
