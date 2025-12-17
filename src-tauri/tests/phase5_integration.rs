// tests/phase5_integration.rs
// Phase 5 Integration Tests: Policy Learning & Multi-Agent Coordination

use warp_tauri::policy_store::{PolicyStore, PolicyDiff, PolicyDiffAdd};
use warp_tauri::agents::AgentCoordinator;
use std::fs;

#[test]
fn test_phase5_policy_full_lifecycle() {
    // Setup
    let tmp_path = std::env::temp_dir().join("phase5_integration_policy.sqlite");
    let _ = fs::remove_file(&tmp_path);
    
    let store = PolicyStore::open(tmp_path.clone()).unwrap();
    
    // Step 1: Verify initial state
    let initial_rules = store.list_rules().unwrap();
    assert_eq!(initial_rules.len(), 0, "Should start with no rules");
    
    // Step 2: Propose a policy diff (simulating trainer output)
    let diff = PolicyDiff {
        add: vec![
            PolicyDiffAdd {
                pattern: r"\brm\s+-rf\b".to_string(),
                effect: "deny".to_string(),
                score: Some(0.95),
            },
            PolicyDiffAdd {
                pattern: r"\bcurl\b.*\|.*sh".to_string(),
                effect: "deny".to_string(),
                score: Some(0.89),
            },
        ],
        remove: vec![],
        meta: Some(serde_json::json!({
            "proposed_by": "trainer_v1",
            "model_version": "v1.0",
            "test": true
        })),
    };
    
    let diff_json = serde_json::to_string(&diff).unwrap();
    let suggestion_id = store.propose_diff("integration_test_trainer", &diff_json).unwrap();
    
    println!("[PHASE5 TEST] Proposed suggestion: {}", suggestion_id);
    
    // Step 3: Verify suggestion is pending
    let suggestions = store.list_suggestions().unwrap();
    assert_eq!(suggestions.len(), 1, "Should have 1 pending suggestion");
    assert_eq!(suggestions[0]["status"].as_str().unwrap(), "pending");
    assert_eq!(suggestions[0]["proposed_by"].as_str().unwrap(), "integration_test_trainer");
    
    // Step 4: Apply the suggestion (simulating human approval)
    let version = store.apply_diff(&suggestion_id, "test_admin", "Approved in integration test").unwrap();
    
    println!("[PHASE5 TEST] Applied version: {}", version);
    
    // Step 5: Verify rules were added
    let rules = store.list_rules().unwrap();
    assert_eq!(rules.len(), 2, "Should have 2 rules after apply");
    
    let patterns: Vec<String> = rules.iter().map(|r| r.pattern.clone()).collect();
    assert!(patterns.contains(&r"\brm\s+-rf\b".to_string()));
    assert!(patterns.contains(&r"\bcurl\b.*\|.*sh".to_string()));
    
    // Verify all rules are deny rules
    for rule in &rules {
        assert_eq!(rule.effect, "deny");
        assert_eq!(rule.added_by.as_ref().unwrap(), "test_admin");
    }
    
    // Step 6: Verify suggestion status updated
    let suggestions_after = store.list_suggestions().unwrap();
    assert_eq!(suggestions_after[0]["status"].as_str().unwrap(), "applied");
    assert_eq!(suggestions_after[0]["reviewed_by"].as_str().unwrap(), "test_admin");
    
    // Step 7: Test rollback
    store.rollback_version(&version).unwrap();
    
    let rules_after_rollback = store.list_rules().unwrap();
    assert_eq!(rules_after_rollback.len(), 0, "Rules should be removed after rollback");
    
    println!("[PHASE5 TEST] ✅ Policy lifecycle test passed");
}

#[test]
fn test_phase5_multi_agent_coordination() {
    let coordinator = AgentCoordinator::new();
    
    // Step 1: Register multiple agents
    let agent1 = coordinator.register_agent(Some("PolicyTrainer".to_string()));
    let agent2 = coordinator.register_agent(Some("CommandClassifier".to_string()));
    let agent3 = coordinator.register_agent(None); // Auto-generated name
    
    println!("[PHASE5 TEST] Registered agents: {}, {}, {}", agent1, agent2, agent3);
    
    // Step 2: Verify all registered
    let agents = coordinator.get_agents();
    assert_eq!(agents.len(), 3, "Should have 3 agents");
    
    // Find agents by name
    let trainer = agents.iter().find(|a| a.name == "PolicyTrainer").unwrap();
    let classifier = agents.iter().find(|a| a.name == "CommandClassifier").unwrap();
    
    assert_eq!(trainer.status, "idle");
    assert_eq!(classifier.status, "idle");
    
    // Step 3: Update agent states (simulating work)
    coordinator.update_agent(&agent1, "training_model".to_string(), 85).unwrap();
    coordinator.update_agent(&agent2, "classifying_batch".to_string(), 92).unwrap();
    
    let agents_working = coordinator.get_agents();
    let trainer_working = agents_working.iter().find(|a| a.id == agent1).unwrap();
    let classifier_working = agents_working.iter().find(|a| a.id == agent2).unwrap();
    
    assert_eq!(trainer_working.status, "running");
    assert_eq!(trainer_working.last_action, Some("training_model".to_string()));
    assert_eq!(trainer_working.last_score, Some(85));
    
    assert_eq!(classifier_working.status, "running");
    assert_eq!(classifier_working.last_score, Some(92));
    
    // Step 4: Test status changes
    coordinator.set_agent_status(&agent1, "blocked".to_string()).unwrap();
    
    let agents_blocked = coordinator.get_agents();
    let trainer_blocked = agents_blocked.iter().find(|a| a.id == agent1).unwrap();
    assert_eq!(trainer_blocked.status, "blocked");
    
    // Step 5: Unregister agents
    coordinator.unregister_agent(&agent2).unwrap();
    
    let agents_final = coordinator.get_agents();
    assert_eq!(agents_final.len(), 2, "Should have 2 agents after unregister");
    assert!(agents_final.iter().all(|a| a.id != agent2));
    
    println!("[PHASE5 TEST] ✅ Multi-agent coordination test passed");
}

#[test]
fn test_phase5_policy_reject_workflow() {
    let tmp_path = std::env::temp_dir().join("phase5_integration_reject.sqlite");
    let _ = fs::remove_file(&tmp_path);
    
    let store = PolicyStore::open(tmp_path).unwrap();
    
    // Propose a bad suggestion
    let diff = PolicyDiff {
        add: vec![
            PolicyDiffAdd {
                pattern: r"\bls\b".to_string(), // Too broad - would block 'ls'
                effect: "deny".to_string(),
                score: Some(0.3), // Low confidence
            },
        ],
        remove: vec![],
        meta: None,
    };
    
    let diff_json = serde_json::to_string(&diff).unwrap();
    let suggestion_id = store.propose_diff("bad_trainer", &diff_json).unwrap();
    
    // Reject it
    store.reject_suggestion(&suggestion_id, "security_reviewer").unwrap();
    
    // Verify rejection
    let suggestions = store.list_suggestions().unwrap();
    assert_eq!(suggestions[0]["status"].as_str().unwrap(), "rejected");
    assert_eq!(suggestions[0]["reviewed_by"].as_str().unwrap(), "security_reviewer");
    
    // Verify no rules added
    let rules = store.list_rules().unwrap();
    assert_eq!(rules.len(), 0, "Rejected suggestions should not add rules");
    
    println!("[PHASE5 TEST] ✅ Policy reject workflow test passed");
}

#[test]
fn test_phase5_multiple_versions_rollback() {
    let tmp_path = std::env::temp_dir().join("phase5_integration_multiversion.sqlite");
    let _ = fs::remove_file(&tmp_path);
    
    let store = PolicyStore::open(tmp_path).unwrap();
    
    // Apply first version
    let diff1 = PolicyDiff {
        add: vec![
            PolicyDiffAdd {
                pattern: r"\brm\b".to_string(),
                effect: "deny".to_string(),
                score: Some(0.9),
            },
        ],
        remove: vec![],
        meta: None,
    };
    let diff1_json = serde_json::to_string(&diff1).unwrap();
    let suggestion1 = store.propose_diff("trainer", &diff1_json).unwrap();
    let version1 = store.apply_diff(&suggestion1, "admin", "Version 1").unwrap();
    
    assert_eq!(store.list_rules().unwrap().len(), 1);
    
    // Apply second version
    let diff2 = PolicyDiff {
        add: vec![
            PolicyDiffAdd {
                pattern: r"\bcurl\b".to_string(),
                effect: "deny".to_string(),
                score: Some(0.85),
            },
        ],
        remove: vec![],
        meta: None,
    };
    let diff2_json = serde_json::to_string(&diff2).unwrap();
    let suggestion2 = store.propose_diff("trainer", &diff2_json).unwrap();
    let version2 = store.apply_diff(&suggestion2, "admin", "Version 2").unwrap();
    
    assert_eq!(store.list_rules().unwrap().len(), 2);
    
    // Rollback version 2
    store.rollback_version(&version2).unwrap();
    assert_eq!(store.list_rules().unwrap().len(), 1);
    
    // Rollback version 1
    store.rollback_version(&version1).unwrap();
    assert_eq!(store.list_rules().unwrap().len(), 0);
    
    println!("[PHASE5 TEST] ✅ Multiple versions rollback test passed");
}
