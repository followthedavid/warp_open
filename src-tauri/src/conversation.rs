use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: u64,
    pub role: String, // "user", "ai", "system"
    pub content: String,
    pub timestamp: u64,
}

// PHASE 2: Semi-Autonomy Batch Structures
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum BatchStatus {
    Pending,
    Approved,
    Running,
    Completed,
    Rejected,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEntry {
    pub id: String,
    pub origin_message_id: Option<u64>,
    pub tool: String,
    pub args: serde_json::Value,
    pub created_at: String,
    pub status: BatchStatus,
    pub result: Option<String>,
    pub safe_score: u8,
    pub requires_manual: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Batch {
    pub id: String,
    pub entries: Vec<BatchEntry>,
    pub creator_tab: u64,
    pub created_at: String,
    pub status: BatchStatus,
    pub approved_by: Option<String>,
    // Phase 3 fields
    pub auto_approved: bool,
    pub depends_on: Option<String>, // Parent batch ID for chaining
}

// Phase 3: Autonomy Settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomySettings {
    pub autonomy_token: Option<String>,
    pub auto_approve_enabled: bool,
    pub auto_execute_enabled: bool,
}

impl Default for AutonomySettings {
    fn default() -> Self {
        Self {
            autonomy_token: None,
            auto_approve_enabled: false,
            auto_execute_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tab {
    pub id: u64,
    pub name: String,
    pub messages: Vec<Message>,
    pub is_thinking: bool,
}

#[derive(Debug, Clone)]
pub struct ConversationState {
    tabs: Arc<Mutex<HashMap<u64, Tab>>>,
    active_tab_id: Arc<Mutex<Option<u64>>>,
    next_message_id: Arc<Mutex<u64>>,
    batches: Arc<Mutex<Vec<Batch>>>,
    autonomy_settings: Arc<Mutex<AutonomySettings>>,
}

impl ConversationState {
    pub fn new() -> Self {
        let state = Self {
            tabs: Arc::new(Mutex::new(HashMap::new())),
            active_tab_id: Arc::new(Mutex::new(None)),
            next_message_id: Arc::new(Mutex::new(1)),
            batches: Arc::new(Mutex::new(Vec::new())),
            autonomy_settings: Arc::new(Mutex::new(AutonomySettings::default())),
        };
        
        // Create initial tab
        state.create_tab("AI Assistant".to_string());
        
        state
    }
    
    pub fn create_tab(&self, name: String) -> u64 {
        let tab_id = chrono::Utc::now().timestamp_millis() as u64;
        
        let system_prompt = "You are a function-calling AI. You MUST use tools to answer questions. NEVER make up answers.\n\nWhen user asks a question that requires data, you MUST respond with ONLY a JSON tool call. NO other text.\n\nAVAILABLE TOOLS:\n1. execute_shell - Run shell commands\n   {\"tool\":\"execute_shell\",\"args\":{\"command\":\"ls ~/\"}}\n\n2. read_file - Read file contents\n   {\"tool\":\"read_file\",\"args\":{\"path\":\"~/.zshrc\"}}\n\n3. write_file - Create or overwrite a file\n   {\"tool\":\"write_file\",\"args\":{\"path\":\"~/test.txt\",\"content\":\"test\"}}\n\n4. edit_file - Make surgical edits to a file (find and replace)\n   {\"tool\":\"edit_file\",\"args\":{\"path\":\"~/file.txt\",\"old_string\":\"old text\",\"new_string\":\"new text\"}}\n   Optional: \"replace_all\":true to replace all occurrences\n\n5. web_fetch - Fetch content from a URL\n   {\"tool\":\"web_fetch\",\"args\":{\"url\":\"https://example.com\"}}\n\nRULES:\n1. If you need data, call a tool (output ONLY JSON, nothing else)\n2. After seeing [Tool Result], explain it in natural language\n3. Use double quotes only\n4. Use ~ for home directory\n5. PREFER edit_file over write_file when making changes to existing files";
        
        let greeting = "Hello! I'm ready to help. Ask me to read files, run commands, or write files.\n\nWhat would you like me to do?";
        
        let tab = Tab {
            id: tab_id,
            name: name.clone(),
            messages: vec![
                Message {
                    id: self.next_msg_id(),
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                },
                // Few-shot examples to teach tool calling
                Message {
                    id: self.next_msg_id(),
                    role: "user".to_string(),
                    content: "What files are in my home directory?".to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                },
                Message {
                    id: self.next_msg_id(),
                    role: "ai".to_string(),
                    content: "{\"tool\":\"execute_shell\",\"args\":{\"command\":\"ls ~/\"}}".to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                },
                Message {
                    id: self.next_msg_id(),
                    role: "user".to_string(),
                    content: "[Tool Result]\nDesktop\nDocuments\nDownloads".to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                },
                Message {
                    id: self.next_msg_id(),
                    role: "ai".to_string(),
                    content: "I found 3 directories in your home: Desktop, Documents, and Downloads.".to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                },
                Message {
                    id: self.next_msg_id(),
                    role: "ai".to_string(),
                    content: greeting.to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                },
            ],
            is_thinking: false,
        };
        
        self.tabs.lock().unwrap().insert(tab_id, tab);
        *self.active_tab_id.lock().unwrap() = Some(tab_id);
        
        eprintln!("[conversation] Created tab {} with ID {}", name, tab_id);
        tab_id
    }
    
    fn next_msg_id(&self) -> u64 {
        let mut id = self.next_message_id.lock().unwrap();
        let current = *id;
        *id += 1;
        current
    }
    
    pub fn get_tabs(&self) -> Vec<Tab> {
        self.tabs.lock().unwrap().values().cloned().collect()
    }
    
    pub fn get_tab(&self, tab_id: u64) -> Option<Tab> {
        self.tabs.lock().unwrap().get(&tab_id).cloned()
    }
    
    pub fn get_active_tab_id(&self) -> Option<u64> {
        *self.active_tab_id.lock().unwrap()
    }
    
    pub fn add_message(&self, tab_id: u64, role: String, content: String) -> Option<u64> {
        let msg_id = self.next_msg_id();
        let message = Message {
            id: msg_id,
            role,
            content,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        let mut tabs = self.tabs.lock().unwrap();
        if let Some(tab) = tabs.get_mut(&tab_id) {
            tab.messages.push(message);
            eprintln!("[conversation] Added message {} to tab {}", msg_id, tab_id);
            Some(msg_id)
        } else {
            None
        }
    }
    
    pub fn set_thinking(&self, tab_id: u64, thinking: bool) {
        let mut tabs = self.tabs.lock().unwrap();
        if let Some(tab) = tabs.get_mut(&tab_id) {
            tab.is_thinking = thinking;
            eprintln!("[conversation] ⏱️ set_thinking({}, {}) called", tab_id, thinking);
        }
    }
    
    // Count recent tool calls (to prevent infinite chains)
    pub fn count_recent_tool_calls(&self, tab_id: u64) -> usize {
        if let Some(tab) = self.get_tab(tab_id) {
            // Count tool calls since the last user message
            let mut count = 0;
            for msg in tab.messages.iter().rev() {
                if msg.role == "user" && !msg.content.starts_with("[Tool") {
                    // Hit a real user message, stop counting
                    break;
                }
                if msg.role == "ai" && msg.content.trim().starts_with('{') && msg.content.contains("\"tool\"") {
                    count += 1;
                }
            }
            count
        } else {
            0
        }
    }
    
    // PHASE 2: Batch Management Methods
    pub fn create_batch(&self, tab_id: u64, entries: Vec<BatchEntry>) -> Batch {
        let batch = Batch {
            id: Uuid::new_v4().to_string(),
            entries,
            creator_tab: tab_id,
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            approved_by: None,
            auto_approved: false,
            depends_on: None,
        };
        self.batches.lock().unwrap().push(batch.clone());
        eprintln!("[PHASE 2] Created batch {} with {} entries", batch.id, batch.entries.len());
        batch
    }
    
    pub fn get_batches(&self) -> Vec<Batch> {
        self.batches.lock().unwrap().clone()
    }
    
    pub fn get_batch(&self, batch_id: &str) -> Option<Batch> {
        self.batches.lock().unwrap()
            .iter()
            .find(|b| b.id == batch_id)
            .cloned()
    }
    
    pub fn update_batch_status(&self, batch_id: &str, status: BatchStatus) {
        let mut batches = self.batches.lock().unwrap();
        if let Some(batch) = batches.iter_mut().find(|b| b.id == batch_id) {
            batch.status = status;
            eprintln!("[PHASE 2] Updated batch {} status to {:?}", batch_id, batch.status);
        }
    }
    
    pub fn approve_batch(&self, batch_id: &str, approved_by: Option<String>) {
        let mut batches = self.batches.lock().unwrap();
        if let Some(batch) = batches.iter_mut().find(|b| b.id == batch_id) {
            batch.status = BatchStatus::Approved;
            batch.approved_by = approved_by;
            eprintln!("[PHASE 2] Approved batch {}", batch_id);
        }
    }

    // PHASE 3: Dependency management
    pub fn set_batch_dependency(&self, batch_id: &str, depends_on: Option<String>) -> Result<(), String> {
        let mut batches = self.batches.lock().unwrap();
        let Some(batch) = batches.iter_mut().find(|b| b.id == batch_id) else {
            return Err(format!("Batch {} not found", batch_id));
        };
        batch.depends_on = depends_on;
        eprintln!("[PHASE 3] Updated dependency for batch {} -> {:?}", batch_id, batch.depends_on);
        Ok(())
    }
    
    // PHASE 3: Autonomy Settings Methods
    pub fn get_autonomy_settings(&self) -> AutonomySettings {
        self.autonomy_settings.lock().unwrap().clone()
    }
    
    pub fn update_autonomy_settings(&self, settings: AutonomySettings) {
        let auto_approve = settings.auto_approve_enabled;
        let auto_execute = settings.auto_execute_enabled;
        *self.autonomy_settings.lock().unwrap() = settings;
        eprintln!("[PHASE 3] Updated autonomy settings: auto_approve={}, auto_execute={}", 
            auto_approve, auto_execute
        );
    }

    pub fn get_messages_for_ai(&self, tab_id: u64) -> Vec<serde_json::Value> {
        if let Some(tab) = self.get_tab(tab_id) {
            tab.messages
                .iter()
                .enumerate()
                .filter(|(idx, m)| {
                    // Keep first 10 messages (system prompt + few-shot examples)
                    if *idx < 10 {
                        return true;
                    }
                    // After that, skip tool call JSON messages, keep everything else
                    if m.role == "ai" {
                        let trimmed = m.content.trim();
                        let is_tool_json = trimmed.starts_with('{') && trimmed.contains("\"tool\"");
                        !is_tool_json
                    } else {
                        true
                    }
                })
                .map(|(_, m)| {
                    serde_json::json!({
                        "role": if m.role == "ai" { "assistant" } else { &m.role },
                        "content": m.content
                    })
                })
                .collect()
        } else {
            vec![]
        }
    }
}
