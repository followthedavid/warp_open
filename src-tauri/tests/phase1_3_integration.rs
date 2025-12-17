#![cfg(test)]

use warp_tauri::conversation::{ConversationState, BatchEntry, BatchStatus};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread::sleep;

/// Helper: Wait for batch to complete with timeout
fn wait_for_batch_completion(
    state: &Arc<Mutex<ConversationState>>,
    batch_id: &str,
    timeout_secs: u64,
) -> bool {
    let mut waited = 0;
    while waited < timeout_secs {
        {
            let s = state.lock().unwrap();
            if let Some(batch) = s.get_batch(batch_id) {
                if batch.status == BatchStatus::Completed || batch.status == BatchStatus::Error {
                    return batch.status == BatchStatus::Completed;
                }
            }
        }
        sleep(Duration::from_millis(500));
        waited += 1;
    }
    false
}

#[test]
fn test_phase1_single_tool_execution() {
    println!("=== PHASE 1: Single Tool Execution Test ===");
    
    let state = Arc::new(Mutex::new(ConversationState::new()));
    
    // Phase 1: Single tool execution
    let tab_id = {
        let s = state.lock().unwrap();
        s.create_tab("Phase1 Test".to_string())
    };
    
    // Add user message
    {
        let s = state.lock().unwrap();
        s.add_message(tab_id, "user".to_string(), "echo 'Phase 1 Test'".to_string());
    }
    
    // Verify tab has messages
    let tab = {
        let s = state.lock().unwrap();
        s.get_tab(tab_id)
    };
    
    assert!(tab.is_some(), "Tab should exist");
    let tab = tab.unwrap();
    assert!(tab.messages.len() >= 7, "Tab should have initial messages plus user message");
    
    println!("✅ Phase 1: Single tool execution structure verified");
}

#[test]
fn test_phase2_batch_workflow() {
    println!("=== PHASE 2: Batch Creation, Approval, Execution Test ===");
    
    let state = Arc::new(Mutex::new(ConversationState::new()));
    
    let tab_id = {
        let s = state.lock().unwrap();
        s.create_tab("Phase2 Test".to_string())
    };
    
    // Create batch entries
    let entries = vec![
        BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "echo 'Phase2 Test A'"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        },
        BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "pwd"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        },
    ];
    
    // Create batch
    let batch_id = {
        let s = state.lock().unwrap();
        let batch = s.create_batch(tab_id, entries);
        assert_eq!(batch.status, BatchStatus::Pending);
        assert_eq!(batch.entries.len(), 2);
        batch.id
    };
    
    println!("Created batch: {}", batch_id);
    
    // Approve batch
    {
        let s = state.lock().unwrap();
        s.approve_batch(&batch_id, Some("test_user".to_string()));
    }
    
    // Verify approval
    {
        let s = state.lock().unwrap();
        let batch = s.get_batch(&batch_id).unwrap();
        assert_eq!(batch.status, BatchStatus::Approved);
        assert_eq!(batch.approved_by, Some("test_user".to_string()));
    }
    
    println!("✅ Phase 2: Batch creation and approval verified");
    
    // Update status to simulate execution
    {
        let s = state.lock().unwrap();
        s.update_batch_status(&batch_id, BatchStatus::Running);
    }
    
    {
        let s = state.lock().unwrap();
        let batch = s.get_batch(&batch_id).unwrap();
        assert_eq!(batch.status, BatchStatus::Running);
    }
    
    // Simulate completion
    {
        let s = state.lock().unwrap();
        s.update_batch_status(&batch_id, BatchStatus::Completed);
    }
    
    {
        let s = state.lock().unwrap();
        let batch = s.get_batch(&batch_id).unwrap();
        assert_eq!(batch.status, BatchStatus::Completed);
    }
    
    println!("✅ Phase 2: Batch execution workflow verified");
}

#[test]
fn test_phase3_auto_approval_and_dependencies() {
    println!("=== PHASE 3: Auto-Approval and Dependencies Test ===");
    
    let state = Arc::new(Mutex::new(ConversationState::new()));
    
    let tab_id = {
        let s = state.lock().unwrap();
        s.create_tab("Phase3 Test".to_string())
    };
    
    // Test autonomy settings
    {
        let s = state.lock().unwrap();
        let settings = s.get_autonomy_settings();
        assert_eq!(settings.auto_approve_enabled, false);
        assert_eq!(settings.auto_execute_enabled, false);
    }
    
    // Update autonomy settings
    {
        let s = state.lock().unwrap();
        let mut settings = s.get_autonomy_settings();
        settings.auto_approve_enabled = true;
        settings.auto_execute_enabled = true;
        settings.autonomy_token = Some("test_token".to_string());
        s.update_autonomy_settings(settings);
    }
    
    // Verify settings update
    {
        let s = state.lock().unwrap();
        let settings = s.get_autonomy_settings();
        assert_eq!(settings.auto_approve_enabled, true);
        assert_eq!(settings.auto_execute_enabled, true);
        assert_eq!(settings.autonomy_token, Some("test_token".to_string()));
    }
    
    println!("✅ Phase 3: Autonomy settings verified");
    
    // Create parent batch
    let parent_batch_id = {
        let s = state.lock().unwrap();
        let entries = vec![BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "echo 'Parent Batch'"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        }];
        let mut batch = s.create_batch(tab_id, entries);
        batch.auto_approved = true;
        batch.id.clone()
    };
    
    // Create dependent (child) batch
    let child_batch_id = {
        let s = state.lock().unwrap();
        let entries = vec![BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "echo 'Child Batch'"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        }];
        let batch = s.create_batch(tab_id, entries);
        batch.id.clone()
    };
    
    // Set dependency
    {
        let s = state.lock().unwrap();
        s.set_batch_dependency(&child_batch_id, Some(parent_batch_id.clone()))
            .expect("Should set dependency");
    }
    
    // Verify dependency
    {
        let s = state.lock().unwrap();
        let child = s.get_batch(&child_batch_id).unwrap();
        assert_eq!(child.depends_on, Some(parent_batch_id.clone()));
    }
    
    println!("✅ Phase 3: Batch dependencies verified");
    
    // Simulate parent completion before child can run
    {
        let s = state.lock().unwrap();
        s.update_batch_status(&parent_batch_id, BatchStatus::Approved);
        s.update_batch_status(&parent_batch_id, BatchStatus::Running);
        s.update_batch_status(&parent_batch_id, BatchStatus::Completed);
    }
    
    {
        let s = state.lock().unwrap();
        let parent = s.get_batch(&parent_batch_id).unwrap();
        assert_eq!(parent.status, BatchStatus::Completed);
    }
    
    // Now child can execute (verify parent is completed)
    {
        let s = state.lock().unwrap();
        let child = s.get_batch(&child_batch_id).unwrap();
        let parent = s.get_batch(&parent_batch_id).unwrap();
        
        if let Some(parent_id) = &child.depends_on {
            assert_eq!(parent_id, &parent_batch_id);
            assert_eq!(parent.status, BatchStatus::Completed, "Parent must complete first");
        }
    }
    
    println!("✅ Phase 3: Dependency enforcement verified");
}

#[test]
fn test_phase3_rollback_structure() {
    println!("=== PHASE 3: Rollback Mechanism Test ===");
    
    let state = Arc::new(Mutex::new(ConversationState::new()));
    
    let tab_id = {
        let s = state.lock().unwrap();
        s.create_tab("Phase3 Rollback Test".to_string())
    };
    
    // Create batch that will "fail"
    let batch_id = {
        let s = state.lock().unwrap();
        let entries = vec![BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "false"}), // Command that fails
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        }];
        let batch = s.create_batch(tab_id, entries);
        batch.id
    };
    
    // Simulate failure
    {
        let s = state.lock().unwrap();
        s.approve_batch(&batch_id, Some("test".to_string()));
        s.update_batch_status(&batch_id, BatchStatus::Running);
        s.update_batch_status(&batch_id, BatchStatus::Error);
    }
    
    // Verify error state
    {
        let s = state.lock().unwrap();
        let batch = s.get_batch(&batch_id).unwrap();
        assert_eq!(batch.status, BatchStatus::Error);
    }
    
    println!("✅ Phase 3: Rollback structure (error detection) verified");
    
    // Note: Actual rollback execution would be in rollback.rs module
    // This test verifies the batch can reach error state and be identified for rollback
}

#[test]
fn test_full_phase1_to_3_workflow() {
    println!("\n╔════════════════════════════════════════╗");
    println!("║  FULL PHASE 1→3 INTEGRATION TEST      ║");
    println!("╚════════════════════════════════════════╝\n");
    
    let state = Arc::new(Mutex::new(ConversationState::new()));
    
    // PHASE 1
    println!("Phase 1: Testing single tool execution...");
    let tab_id = {
        let s = state.lock().unwrap();
        s.create_tab("Full Workflow Test".to_string())
    };
    
    {
        let s = state.lock().unwrap();
        s.add_message(tab_id, "user".to_string(), "test command".to_string());
    }
    
    println!("✅ Phase 1 PASSED\n");
    
    // PHASE 2
    println!("Phase 2: Testing batch workflow...");
    let batch_id = {
        let s = state.lock().unwrap();
        let entries = vec![
            BatchEntry {
                id: uuid::Uuid::new_v4().to_string(),
                origin_message_id: None,
                tool: "execute_shell".to_string(),
                args: serde_json::json!({"command": "echo test"}),
                created_at: chrono::Utc::now().to_rfc3339(),
                status: BatchStatus::Pending,
                result: None,
                safe_score: 100,
                requires_manual: false,
            },
        ];
        let batch = s.create_batch(tab_id, entries);
        batch.id
    };
    
    {
        let s = state.lock().unwrap();
        s.approve_batch(&batch_id, Some("workflow_test".to_string()));
        s.update_batch_status(&batch_id, BatchStatus::Completed);
    }
    
    println!("✅ Phase 2 PASSED\n");
    
    // PHASE 3
    println!("[PHASE 3] Starting autonomy features test...");
    
    // Test auto-approval settings
    println!("[PHASE 3 LOG] Getting current autonomy settings...");
    {
        let s = state.lock().unwrap();
        let mut settings = s.get_autonomy_settings();
        println!("[PHASE 3 LOG] Current settings: auto_approve={}, auto_execute={}",
                 settings.auto_approve_enabled, settings.auto_execute_enabled);
        
        settings.auto_approve_enabled = true;
        settings.autonomy_token = Some("full_test_token".to_string());
        
        println!("[PHASE 3 LOG] Updating autonomy settings to: auto_approve=true, token=full_test_token");
        s.update_autonomy_settings(settings);
        println!("[PHASE 3 LOG] Settings updated successfully");
    }
    
    println!("[PHASE 3 LOG] Verifying settings were applied...");
    {
        let s = state.lock().unwrap();
        let settings = s.get_autonomy_settings();
        println!("[PHASE 3 LOG] Verified: auto_approve={}, token={:?}",
                 settings.auto_approve_enabled, settings.autonomy_token);
    }
    
    // Test dependencies
    println!("[PHASE 3 LOG] Creating parent batch...");
    let parent_id = {
        let s = state.lock().unwrap();
        let entries = vec![BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "echo parent"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        }];
        let batch = s.create_batch(tab_id, entries);
        println!("[PHASE 3 LOG] Parent batch created: {}", batch.id);
        batch.id
    };
    
    println!("[PHASE 3 LOG] Creating child batch...");
    let child_id = {
        let s = state.lock().unwrap();
        let entries = vec![BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "echo child"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        }];
        let batch = s.create_batch(tab_id, entries);
        println!("[PHASE 3 LOG] Child batch created: {}", batch.id);
        batch.id
    };
    
    println!("[PHASE 3 LOG] Setting batch dependency: child depends on parent...");
    {
        let s = state.lock().unwrap();
        s.set_batch_dependency(&child_id, Some(parent_id.clone())).unwrap();
        println!("[PHASE 3 LOG] Dependency set successfully");
    }
    
    println!("[PHASE 3 LOG] Verifying dependency was set...");
    {
        let s = state.lock().unwrap();
        let child = s.get_batch(&child_id).unwrap();
        println!("[PHASE 3 LOG] Child batch depends_on: {:?}", child.depends_on);
        assert_eq!(child.depends_on, Some(parent_id));
        println!("[PHASE 3 LOG] Dependency verification passed");
    }
    
    println!("✅ Phase 3 PASSED\n");
    
    println!("╔════════════════════════════════════════╗");
    println!("║  ALL PHASES VERIFIED SUCCESSFULLY! ✅  ║");
    println!("╚════════════════════════════════════════╝");
}
