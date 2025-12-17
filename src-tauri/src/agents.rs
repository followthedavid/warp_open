// src-tauri/src/agents.rs
// Phase 5: Multi-Agent Coordination Module

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Represents the state of a single AI agent in the coordination system
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentState {
    pub id: String,
    pub name: String,
    pub status: String, // idle, running, blocked
    pub last_action: Option<String>,
    pub last_score: Option<i32>,
}

/// Coordinates multiple agents operating in parallel
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

    /// Register a new agent in the coordination system
    pub fn register_agent(&self, name: Option<String>) -> String {
        let id = Uuid::new_v4().to_string();
        let agent_name = name.unwrap_or_else(|| format!("Agent_{}", &id[..8]));
        
        let agent = AgentState {
            id: id.clone(),
            name: agent_name.clone(),
            status: "idle".to_string(),
            last_action: None,
            last_score: None,
        };
        
        self.agents.lock().unwrap().insert(id.clone(), agent);
        eprintln!("[AGENTS] Registered agent: {} ({})", agent_name, id);
        id
    }

    /// Update an agent's status and last action
    pub fn update_agent(&self, agent_id: &str, action: String, score: i32) -> anyhow::Result<()> {
        let mut agents = self.agents.lock().unwrap();
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.last_action = Some(action.clone());
            agent.last_score = Some(score);
            agent.status = "running".to_string();
            eprintln!("[AGENTS] Updated agent {}: action={}, score={}", agent_id, action, score);
            Ok(())
        } else {
            anyhow::bail!("Agent {} not found", agent_id)
        }
    }

    /// Set agent status directly
    pub fn set_agent_status(&self, agent_id: &str, status: String) -> anyhow::Result<()> {
        let mut agents = self.agents.lock().unwrap();
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.status = status.clone();
            eprintln!("[AGENTS] Agent {} status changed to: {}", agent_id, status);
            Ok(())
        } else {
            anyhow::bail!("Agent {} not found", agent_id)
        }
    }

    /// Get all registered agents
    pub fn get_agents(&self) -> Vec<AgentState> {
        self.agents.lock().unwrap().values().cloned().collect()
    }

    /// Remove an agent from the coordination system
    pub fn unregister_agent(&self, agent_id: &str) -> anyhow::Result<()> {
        let mut agents = self.agents.lock().unwrap();
        if agents.remove(agent_id).is_some() {
            eprintln!("[AGENTS] Unregistered agent: {}", agent_id);
            Ok(())
        } else {
            anyhow::bail!("Agent {} not found", agent_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_registration() {
        let coordinator = AgentCoordinator::new();
        let id = coordinator.register_agent(Some("TestAgent".to_string()));
        
        let agents = coordinator.get_agents();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "TestAgent");
        assert_eq!(agents[0].status, "idle");
    }

    #[test]
    fn test_agent_update() {
        let coordinator = AgentCoordinator::new();
        let id = coordinator.register_agent(None);
        
        coordinator.update_agent(&id, "test_action".to_string(), 95).unwrap();
        
        let agents = coordinator.get_agents();
        assert_eq!(agents[0].status, "running");
        assert_eq!(agents[0].last_action, Some("test_action".to_string()));
        assert_eq!(agents[0].last_score, Some(95));
    }
}
