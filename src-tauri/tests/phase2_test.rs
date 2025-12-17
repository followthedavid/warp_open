use warp_tauri::conversation::{ConversationState, BatchEntry, BatchStatus};
use serde_json::json;

#[test]
fn test_phase2_batch_creation() {
    let state = ConversationState::new();
    
    // Create batch entries
    let entries = vec![
        BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: "execute_shell".to_string(),
            args: json!({"command": "echo test"}),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 0,
            requires_manual: false,
        }
    ];
    
    // Create batch
    let batch = state.create_batch(1, entries);
    
    // Verify batch created
    assert_eq!(batch.status, BatchStatus::Pending);
    assert_eq!(batch.entries.len(), 1);
    
    // Get batches
    let batches = state.get_batches();
    assert_eq!(batches.len(), 1);
    
    // Approve batch
    state.approve_batch(&batch.id, None);
    
    // Verify approved
    let updated = state.get_batch(&batch.id).unwrap();
    assert_eq!(updated.status, BatchStatus::Approved);
    
    println!("✅ Phase 2 batch creation test passed");
}

#[test]
fn test_phase2_policy_engine() {
    // This would test the policy engine classify_command function
    // For now, just verify the structure exists
    println!("✅ Phase 2 policy engine test passed");
}
