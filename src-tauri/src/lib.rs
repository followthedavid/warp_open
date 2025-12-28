// Library interface for Warp Tauri
// Exposes modules for integration testing

pub mod conversation;
pub mod commands;
pub mod ai_parser;
pub mod rollback;
pub mod test_bridge;
pub mod test_runner;
pub mod telemetry;
pub mod policy_store;
pub mod agents;
pub mod plan_store;
pub mod monitoring;
pub mod scheduler;
pub mod phase1_6_tests;
pub mod ollama;
pub mod ssh_session;
pub mod scaffolding;

use conversation::ConversationState;
use std::sync::{Arc, Mutex};

/// Create a test state for integration tests
pub fn create_test_state() -> Arc<Mutex<ConversationState>> {
    Arc::new(Mutex::new(ConversationState::new()))
}
