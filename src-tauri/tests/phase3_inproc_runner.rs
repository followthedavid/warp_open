#![cfg(test)]

use warp_tauri::{create_test_state, test_runner::run_phase3_batch_inproc};
use warp_tauri::conversation::{BatchEntry, BatchStatus, AutonomySettings};

#[test]
fn test_phase3_inproc_runner() {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║  PHASE 3 — IN-PROC EXECUTION TEST     ║");
    println!("╚═══════════════════════════════════════╝\n");

    let state = create_test_state();
    
    let (tab_id, batch_id) = {
        let mut s = state.lock().unwrap();
        
        // Enable autonomy settings
        let settings = AutonomySettings {
            autonomy_token: Some("test_token".to_string()),
            auto_approve_enabled: true,
            auto_execute_enabled: true,
        };
        s.update_autonomy_settings(settings);
        println!("[TEST] ✅ Autonomy settings enabled");
        
        // Create tab
        let tab_id = s.create_tab("Phase3 InProc Test".to_string());
        println!("[TEST] ✅ Created tab: {}", tab_id);
        
        // Create batch with multiple commands
        let entries = vec![
            BatchEntry {
                id: uuid::Uuid::new_v4().to_string(),
                origin_message_id: None,
                tool: "execute_shell".to_string(),
                args: serde_json::json!({"command": "echo 'Phase3 InProc Test A'"}),
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
                args: serde_json::json!({"command": "echo 'Phase3 InProc Test B'"}),
                created_at: chrono::Utc::now().to_rfc3339(),
                status: BatchStatus::Pending,
                result: None,
                safe_score: 100,
                requires_manual: false,
            },
        ];
        
        let batch = s.create_batch(tab_id, entries);
        let batch_id = batch.id.clone();
        
        println!("[TEST] ✅ Created batch: {}", batch_id);
        println!("[TEST]    Entries: {}", batch.entries.len());
        println!("[TEST]    Status: {:?}", batch.status);
        
        // Approve batch (simulating auto-approval)
        s.approve_batch(&batch_id, Some("auto_test_token".to_string()));
        println!("[TEST] ✅ Batch auto-approved");
        
        (tab_id, batch_id)
    };
    
    // Execute batch synchronously using in-process runner
    println!("\n[TEST] 🚀 Executing batch in-process...");
    let result = run_phase3_batch_inproc(state.clone(), &batch_id);
    
    println!("\n[TEST] 📊 Execution Results:");
    println!("[TEST]    Success: {}", result.success);
    println!("[TEST]    Batch ID: {}", result.batch_id);
    println!("[TEST]    Entries executed: {}", result.entry_results.len());
    
    for (i, entry_result) in result.entry_results.iter().enumerate() {
        println!("\n[TEST]    Entry {}:", i + 1);
        println!("[TEST]      Command: {}", entry_result.command);
        println!("[TEST]      Exit code: {}", entry_result.exit_code);
        println!("[TEST]      Stdout: {}", entry_result.stdout.trim());
        if !entry_result.stderr.is_empty() {
            println!("[TEST]      Stderr: {}", entry_result.stderr.trim());
        }
    }
    
    // Verify execution succeeded
    assert!(result.success, "Batch execution must succeed");
    assert_eq!(result.entry_results.len(), 2, "Should execute 2 entries");
    
    // Verify outputs
    assert!(
        result.entry_results[0].stdout.contains("Phase3 InProc Test A"),
        "First command output should contain expected text"
    );
    assert_eq!(result.entry_results[0].exit_code, 0, "First command should succeed");
    
    assert!(
        result.entry_results[1].stdout.contains("Phase3 InProc Test B"),
        "Second command output should contain expected text"
    );
    assert_eq!(result.entry_results[1].exit_code, 0, "Second command should succeed");
    
    // Verify batch status was updated to Completed
    {
        let s = state.lock().unwrap();
        let batch = s.get_batch(&batch_id).unwrap();
        assert_eq!(
            batch.status,
            BatchStatus::Completed,
            "Batch status must be Completed after execution"
        );
        println!("\n[TEST] ✅ Batch status verified: {:?}", batch.status);
    }
    
    println!("\n╔═══════════════════════════════════════╗");
    println!("║  ✅ PHASE 3 IN-PROC TEST PASSED! ✅   ║");
    println!("╚═══════════════════════════════════════╝\n");
}

#[test]
fn test_phase3_batch_dependencies() {
    println!("\n╔═══════════════════════════════════════╗");
    println!("║  PHASE 3 — DEPENDENCY TEST            ║");
    println!("╚═══════════════════════════════════════╝\n");

    let state = create_test_state();
    
    let (parent_id, child_id) = {
        let mut s = state.lock().unwrap();
        
        let tab_id = s.create_tab("Dependency Test".to_string());
        
        // Create parent batch
        let parent_entries = vec![BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "echo 'Parent batch'"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        }];
        
        let parent_batch = s.create_batch(tab_id, parent_entries);
        let parent_id = parent_batch.id.clone();
        println!("[TEST] ✅ Created parent batch: {}", parent_id);
        
        // Create child batch
        let child_entries = vec![BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: serde_json::json!({"command": "echo 'Child batch'"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 100,
            requires_manual: false,
        }];
        
        let child_batch = s.create_batch(tab_id, child_entries);
        let child_id = child_batch.id.clone();
        println!("[TEST] ✅ Created child batch: {}", child_id);
        
        // Set dependency
        s.set_batch_dependency(&child_id, Some(parent_id.clone())).unwrap();
        println!("[TEST] ✅ Set dependency: child depends on parent");
        
        (parent_id, child_id)
    };
    
    // Verify dependency was set
    {
        let s = state.lock().unwrap();
        let child = s.get_batch(&child_id).unwrap();
        assert_eq!(
            child.depends_on,
            Some(parent_id.clone()),
            "Child batch should depend on parent"
        );
        println!("[TEST] ✅ Dependency verified: child.depends_on = {:?}", child.depends_on);
    }
    
    // Execute parent first
    {
        let mut s = state.lock().unwrap();
        s.approve_batch(&parent_id, Some("test".to_string()));
    }
    
    let parent_result = run_phase3_batch_inproc(state.clone(), &parent_id);
    assert!(parent_result.success, "Parent batch must execute successfully");
    println!("[TEST] ✅ Parent batch executed successfully");
    
    // Now child can execute (parent is completed)
    {
        let s = state.lock().unwrap();
        let parent = s.get_batch(&parent_id).unwrap();
        assert_eq!(parent.status, BatchStatus::Completed, "Parent must be completed");
        
        let child = s.get_batch(&child_id).unwrap();
        if let Some(dep_id) = &child.depends_on {
            let parent_batch = s.get_batch(dep_id).unwrap();
            assert_eq!(
                parent_batch.status,
                BatchStatus::Completed,
                "Dependency must be completed before child executes"
            );
        }
    }
    
    println!("\n╔═══════════════════════════════════════╗");
    println!("║  ✅ DEPENDENCY TEST PASSED! ✅        ║");
    println!("╚═══════════════════════════════════════╝\n");
}
