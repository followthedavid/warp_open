// src-tauri/src/monitoring.rs
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PhaseEvent {
    pub phase: String,
    pub message: String,
    pub status: String, // "running", "success", "failure"
    pub timestamp: String,
    pub batch_id: Option<String>,
    pub agent_id: Option<String>,
    pub policy_suggestion: Option<String>,
    pub suggestion_confidence: Option<f32>,
}

#[derive(Clone)]
pub struct MonitoringState {
    pub events: Arc<Mutex<HashMap<String, Vec<PhaseEvent>>>>,
}

impl MonitoringState {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_event(&self, app: &AppHandle, event: PhaseEvent) {
        let mut map = self.events.lock().unwrap();
        map.entry(event.phase.clone()).or_default().push(event.clone());
        
        // Keep only last 100 events per phase to prevent memory growth
        if let Some(events) = map.get_mut(&event.phase) {
            if events.len() > 100 {
                events.drain(0..(events.len() - 100));
            }
        }
        
        // Push live update to frontend
        let _ = app.emit_all("monitor_update", serde_json::to_value(&*map).unwrap());
    }

    pub fn get_events(&self) -> HashMap<String, Vec<PhaseEvent>> {
        self.events.lock().unwrap().clone()
    }

    pub fn clear_phase(&self, phase: &str) {
        let mut map = self.events.lock().unwrap();
        map.remove(phase);
    }

    pub fn clear_all(&self) {
        let mut map = self.events.lock().unwrap();
        map.clear();
    }
}

// Helper to create timestamp
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

// Helper function to log phase events
pub fn log_phase_event(monitor: &MonitoringState, app: &AppHandle, phase: &str, message: &str, status: &str) {
    monitor.add_event(app, PhaseEvent {
        phase: phase.to_string(),
        message: message.to_string(),
        status: status.to_string(),
        timestamp: now_iso(),
        batch_id: None,
        agent_id: None,
        policy_suggestion: None,
        suggestion_confidence: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitoring_state() {
        let state = MonitoringState::new();
        
        // Create mock app handle - in real tests this would be a proper Tauri app
        // For now we'll just test the state management without emitting
        let event1 = PhaseEvent {
            phase: "phase1".to_string(),
            message: "Test event 1".to_string(),
            status: "success".to_string(),
            timestamp: now_iso(),
            batch_id: Some("batch123".to_string()),
            agent_id: None,
            policy_suggestion: None,
            suggestion_confidence: None,
        };
        
        let event2 = PhaseEvent {
            phase: "phase2".to_string(),
            message: "Test event 2".to_string(),
            status: "failure".to_string(),
            timestamp: now_iso(),
            batch_id: None,
            agent_id: Some("agent1".to_string()),
            policy_suggestion: None,
            suggestion_confidence: None,
        };
        
        // Manually add to state without app handle
        {
            let mut map = state.events.lock().unwrap();
            map.entry(event1.phase.clone()).or_default().push(event1.clone());
            map.entry(event2.phase.clone()).or_default().push(event2.clone());
        }
        
        let events = state.get_events();
        assert_eq!(events.len(), 2);
        assert!(events.contains_key("phase1"));
        assert!(events.contains_key("phase2"));
        
        // Test clear
        state.clear_phase("phase1");
        let events = state.get_events();
        assert_eq!(events.len(), 1);
        assert!(!events.contains_key("phase1"));
        
        state.clear_all();
        let events = state.get_events();
        assert_eq!(events.len(), 0);
    }
}
