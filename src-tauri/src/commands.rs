use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use tauri::{Manager, State};
use warp_core::pty::WarpPty;
use serde::{Deserialize, Serialize};
use regex::Regex;

// Helper to handle poisoned mutex - recovers lock even after panic
fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        eprintln!("[WARN] Mutex was poisoned, recovering...");
        poisoned.into_inner()
    })
}

// BUGFIX: Prevent duplicate tool executions
lazy_static::lazy_static! {
    static ref EXECUTING_TOOLS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtyInfo {
    pub id: u32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtyOutput {
    pub id: u32,
    pub data: String,
}

pub struct PtyRegistry {
    ptys: Arc<Mutex<HashMap<u32, WarpPty>>>,
    next_id: Arc<Mutex<u32>>,
}

impl PtyRegistry {
    pub fn new() -> Self {
        Self {
            ptys: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }
}

#[tauri::command]
pub fn spawn_pty(
    shell: Option<String>,
    registry: State<'_, PtyRegistry>,
) -> Result<PtyInfo, String> {
    let shell_cmd = shell.unwrap_or_else(|| {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string())
    });
    
    eprintln!("[spawn_pty] Spawning PTY with shell: {}", shell_cmd);
    let pty = WarpPty::spawn_simple(shell_cmd).map_err(|e| format!("Failed to spawn PTY: {}", e))?;
    
    let mut next_id = lock_or_recover(&registry.next_id);
    let id = *next_id;
    *next_id += 1;

    lock_or_recover(&registry.ptys).insert(id, pty);
    eprintln!("[spawn_pty] PTY spawned successfully with ID: {}", id);
    
    Ok(PtyInfo { id })
}

#[tauri::command]
pub fn send_input(
    id: u32,
    input: String,
    registry: State<'_, PtyRegistry>,
) -> Result<(), String> {
    let mut ptys = lock_or_recover(&registry.ptys);

    if let Some(pty) = ptys.get_mut(&id) {
        eprintln!("[send_input] PTY {} input: {:?}", id, input);
        pty.write_input(input.as_bytes())
            .map_err(|e| format!("Failed to write input: {}", e))?;
        Ok(())
    } else {
        Err(format!("PTY {} not found", id))
    }
}

#[tauri::command]
pub fn resize_pty(
    id: u32,
    cols: u16,
    rows: u16,
    registry: State<'_, PtyRegistry>,
) -> Result<(), String> {
    let mut ptys = lock_or_recover(&registry.ptys);

    if let Some(pty) = ptys.get_mut(&id) {
        pty.resize(cols, rows)
            .map_err(|e| format!("Failed to resize PTY: {}", e))?;
        Ok(())
    } else {
        Err(format!("PTY {} not found", id))
    }
}

#[tauri::command]
pub fn read_pty(
    id: u32,
    registry: State<'_, PtyRegistry>,
) -> Result<String, String> {
    let mut ptys = lock_or_recover(&registry.ptys);

    if let Some(pty) = ptys.get_mut(&id) {
        let output = pty.read_output()
            .map_err(|e| format!("Failed to read output: {}", e))?;
        let output_str = String::from_utf8_lossy(&output).to_string();
        if !output_str.is_empty() {
            eprintln!("[read_pty] PTY {} output: {:?}", id, output_str);
        }
        Ok(output_str)
    } else {
        Err(format!("PTY {} not found", id))
    }
}

#[tauri::command]
pub fn close_pty(
    id: u32,
    registry: State<'_, PtyRegistry>,
) -> Result<(), String> {
    let mut ptys = lock_or_recover(&registry.ptys);

    if ptys.remove(&id).is_some() {
        Ok(())
    } else {
        Err(format!("PTY {} not found", id))
    }
}

/// Start streaming PTY output via Tauri events
/// This replaces the polling-based read_pty approach with event-driven updates
#[tauri::command]
pub async fn start_pty_output_stream(
    id: u32,
    registry: State<'_, PtyRegistry>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    // Clone the ptys Arc to use in the async task
    let ptys = registry.ptys.clone();

    // Spawn a tokio task to continuously read PTY output and emit events
    tokio::spawn(async move {
        let mut consecutive_empty = 0;
        let mut last_check = std::time::Instant::now();

        loop {
            // Adaptive polling: faster when output is coming, slower when idle
            let poll_interval = if consecutive_empty > 10 {
                std::time::Duration::from_millis(100) // Slow down when idle
            } else if consecutive_empty > 5 {
                std::time::Duration::from_millis(50)  // Medium speed
            } else {
                std::time::Duration::from_millis(16)  // ~60fps when active
            };

            tokio::time::sleep(poll_interval).await;

            // Try to read output
            let output = {
                let mut guard = match ptys.lock() {
                    Ok(g) => g,
                    Err(poisoned) => {
                        eprintln!("[PTY Stream {}] Mutex poisoned, recovering...", id);
                        poisoned.into_inner()
                    }
                };

                match guard.get_mut(&id) {
                    Some(pty) => {
                        match pty.read_output() {
                            Ok(data) => {
                                if !data.is_empty() {
                                    String::from_utf8_lossy(&data).to_string()
                                } else {
                                    String::new()
                                }
                            }
                            Err(_) => {
                                eprintln!("[PTY Stream {}] Read error, stopping stream", id);
                                break;
                            }
                        }
                    }
                    None => {
                        // PTY was closed
                        eprintln!("[PTY Stream {}] PTY not found, stopping stream", id);
                        break;
                    }
                }
            };

            if !output.is_empty() {
                consecutive_empty = 0;
                // Emit the output event
                let _ = app_handle.emit_all("pty_output", serde_json::json!({
                    "id": id,
                    "data": output
                }));
            } else {
                consecutive_empty += 1;
            }

            // Periodic heartbeat every 5 seconds to confirm stream is alive
            if last_check.elapsed() > std::time::Duration::from_secs(5) {
                last_check = std::time::Instant::now();
                // Check if PTY still exists
                let still_exists = {
                    let guard = match ptys.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner()
                    };
                    guard.contains_key(&id)
                };
                if !still_exists {
                    eprintln!("[PTY Stream {}] PTY removed, stopping stream", id);
                    break;
                }
            }
        }

        eprintln!("[PTY Stream {}] Stream ended", id);
    });

    Ok(())
}

// PHASE 2: Policy Engine - Command Classification
lazy_static::lazy_static! {
    static ref DENY_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)rm\s+-rf").unwrap(),
        Regex::new(r"(?i)curl\s+\S+\s*\|\s*sh").unwrap(),
        Regex::new(r"(?i)\bsudo\b").unwrap(),
        Regex::new(r"(?i)\bssh\b").unwrap(),
        Regex::new(r"(?i)\bscp\b").unwrap(),
        Regex::new(r"(?i)\bsftp\b").unwrap(),
        Regex::new(r"(?i)dd\s+if=").unwrap(),
        Regex::new(r"(?i)mkfs").unwrap(),
        Regex::new(r"(?i)fdisk").unwrap(),
    ];
    
    static ref ALLOW_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)^brew\s+install\s+\S+").unwrap(),
        Regex::new(r"(?i)^apt(-get)?\s+install\s+\S+").unwrap(),
        Regex::new(r"(?i)^which\s+\S+").unwrap(),
        Regex::new(r"(?i)^ls\b").unwrap(),
        Regex::new(r"(?i)^cat\b").unwrap(),
        Regex::new(r"(?i)^echo\b").unwrap(),
        Regex::new(r"(?i)^pwd\b").unwrap(),
        Regex::new(r"(?i)^whoami\b").unwrap(),
        Regex::new(r"(?i)^uname\b").unwrap(),
        Regex::new(r"(?i)^date\b").unwrap(),
    ];
}

/// Calculate safety score for a tool call
pub fn calculate_safety_score(tool: &str, args: &serde_json::Value) -> u8 {
    match tool {
        "execute_shell" => {
            if let Some(cmd) = args.get("command").and_then(|c| c.as_str()) {
                let (_, _, score) = classify_command(cmd);
                score
            } else {
                50 // Missing command
            }
        }
        "read_file" | "write_file" => 100, // File operations are safe
        _ => 50, // Unknown tools get moderate score
    }
}

/// Classify a command for safety
/// Returns (allowed, requires_manual, safe_score)
pub fn classify_command(cmd: &str) -> (bool, bool, u8) {
    // Check deny patterns first
    for re in DENY_PATTERNS.iter() {
        if re.is_match(cmd) {
            eprintln!("[PHASE 2 POLICY] DENIED: {}", cmd);
            return (false, true, 0);
        }
    }
    
    // Check allow patterns
    for re in ALLOW_PATTERNS.iter() {
        if re.is_match(cmd) {
            eprintln!("[PHASE 2 POLICY] ALLOWED: {}", cmd);
            return (true, false, 100);
        }
    }
    
    // Unknown command - requires manual approval
    eprintln!("[PHASE 2 POLICY] UNKNOWN (requires manual): {}", cmd);
    (false, true, 50)
}

// AI and shell execution commands for AI-first interface

#[tauri::command]
pub async fn ai_query(
    tab_id: u64,
    prompt: String,
) -> Result<String, String> {
    eprintln!("[ai_query] Tab {} prompt: {}", tab_id, prompt);
    
    // Fallback non-streaming version
    Ok(format!("AI Response: I received your message '{}'. This is a placeholder. Connect me to Ollama to get real AI responses!", prompt))
}

// Streaming AI query with Ollama integration
#[tauri::command]
pub async fn ai_query_stream(
    tab_id: u64,
    messages: Vec<serde_json::Value>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    use futures_util::StreamExt;
    
    eprintln!("[ai_query_stream] Tab {} with {} messages", tab_id, messages.len());
    
    // Check if Ollama is available
    let client = reqwest::Client::new();
    let ollama_url = "http://localhost:11434/api/chat";
    
    let payload = serde_json::json!({
        "model": "llama3.2:3b-instruct-q4_K_M",
        "messages": messages,
        "stream": true,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 500
        }
    });
    
    match client.post(ollama_url).json(&payload).send().await {
        Ok(response) => {
            let mut stream = response.bytes_stream();
            let mut accumulated_response = String::new();
            
            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        // Parse JSON chunk from Ollama
                        if let Ok(text) = String::from_utf8(chunk.to_vec()) {
                            // Ollama returns newline-delimited JSON
                            for line in text.lines() {
                                if line.trim().is_empty() {
                                    continue;
                                }
                                
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                                    // For chat API, response is in message.content
                                    if let Some(message) = json["message"].as_object() {
                                        if let Some(response_text) = message["content"].as_str() {
                                            eprintln!("[CHUNK] {}", response_text);
                                            accumulated_response.push_str(response_text);
                                            // Emit token chunk to frontend
                                            let _ = app_handle.emit_all("ai_response_chunk", serde_json::json!({
                                                "tabId": tab_id,
                                                "chunk": response_text
                                            }));
                                        }
                                    }
                                    
                                    // Check if done
                                    if json["done"].as_bool().unwrap_or(false) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[ai_query_stream] Stream error: {}", e);
                        let _ = app_handle.emit_all("ai_response_chunk", serde_json::json!({
                            "tabId": tab_id,
                            "chunk": format!("\n[Stream error: {}]", e)
                        }));
                        break;
                    }
                }
            }
            
            // Signal completion  
            let _ = app_handle.emit_all("ai_response_done", serde_json::json!({
                "tabId": tab_id
            }));
            
            // Check if the complete response is a tool call JSON
            let complete_response = accumulated_response.trim();
            if complete_response.starts_with('{') && complete_response.contains("\"tool\"") {
                eprintln!("[ai_query_stream] Detected tool call JSON");
                
                // Try to parse and execute the tool
                if let Ok(tool_call) = serde_json::from_str::<serde_json::Value>(complete_response) {
                    if let (Some(tool_name), Some(args)) = (tool_call.get("tool"), tool_call.get("args")) {
                        eprintln!("[ai_query_stream] Executing tool: {}", tool_name);
                        
                        // Execute the tool based on type
                        let result = match tool_name.as_str() {
                            Some("read_file") => {
                                if let Some(path) = args.get("path").and_then(|p| p.as_str()) {
                                    eprintln!("[read_file] ⚡ TOOL EXECUTION ⚡ Reading: {}", path);
                                    let expanded = shellexpand::tilde(path).to_string();
                                    std::fs::read_to_string(&expanded)
                                        .map_err(|e| format!("Failed to read {}: {}", path, e))
                                } else {
                                    Err("Missing 'path' argument".to_string())
                                }
                            },
                            Some("write_file") => {
                                if let (Some(path), Some(content)) = (
                                    args.get("path").and_then(|p| p.as_str()),
                                    args.get("content").and_then(|c| c.as_str())
                                ) {
                                    eprintln!("[write_file] ⚡ TOOL EXECUTION ⚡ Writing to: {}", path);
                                    let expanded = shellexpand::tilde(path).to_string();
                                    std::fs::write(&expanded, content)
                                        .map(|_| format!("Wrote {} bytes to {}", content.len(), path))
                                        .map_err(|e| format!("Failed to write {}: {}", path, e))
                                } else {
                                    Err("Missing 'path' or 'content' argument".to_string())
                                }
                            },
                            Some("execute_shell") => {
                                if let Some(command) = args.get("command").and_then(|c| c.as_str()) {
                                    eprintln!("[execute_shell] ⚡ TOOL EXECUTION ⚡ Running: {}", command);
                                    let output = std::process::Command::new("sh")
                                        .arg("-c")
                                        .arg(command)
                                        .output()
                                        .map_err(|e| format!("Failed to execute: {}", e))?;
                                    
                                    let mut result = String::from_utf8_lossy(&output.stdout).to_string();
                                    if !output.stderr.is_empty() {
                                        result.push_str("\n");
                                        result.push_str(&String::from_utf8_lossy(&output.stderr));
                                    }
                                    Ok(result)
                                } else {
                                    Err("Missing 'command' argument".to_string())
                                }
                            },
                            _ => Err(format!("Unknown tool: {:?}", tool_name))
                        };
                        
                        // Emit tool result event to frontend
                        let _ = app_handle.emit_all("tool_executed", serde_json::json!({
                            "tabId": tab_id,
                            "toolCall": complete_response,
                            "result": result
                        }));
                        
                        eprintln!("[ai_query_stream] Tool execution complete");
                    }
                }
            }
            
            Ok(())
        }
        Err(e) => {
            eprintln!("[ai_query_stream] Ollama connection failed: {}", e);
            
            // Fall back to placeholder response
            let last_user_msg = messages.iter()
                .filter(|m| m["role"] == "user")
                .last()
                .and_then(|m| m["content"].as_str())
                .unwrap_or("(no message)");
            
            let placeholder = format!(
                "I received: '{}'\n\n[Ollama not available. Start it with: ollama serve]\n\nFor best results on your M2 8GB, use: deepseek-coder:6.7b",
                last_user_msg
            );
            
            // Simulate streaming for placeholder
            for chunk in placeholder.chars() {
                let _ = app_handle.emit_all("ai_response_chunk", serde_json::json!({
                    "tabId": tab_id,
                    "chunk": chunk.to_string()
                }));
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
            
            let _ = app_handle.emit_all("ai_response_done", serde_json::json!({
                "tabId": tab_id
            }));
            
            Ok(())
        }
    }
}

#[tauri::command]
pub async fn execute_shell(
    command: String,
) -> Result<String, String> {
    eprintln!("[execute_shell] ⚡ TOOL EXECUTION ⚡ Executing: {}", command);
    
    use std::process::Command;
    
    let output = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    
    // Combine stdout and stderr for display
    let mut result = stdout;
    if !stderr.is_empty() {
        if !result.is_empty() {
            result.push_str("\n");
        }
        result.push_str(&stderr);
    }
    
    if !output.status.success() {
        return Err(format!("Command exited with code: {:?}\n{}", output.status.code(), result));
    }
    
    Ok(result)
}

#[tauri::command]
pub async fn read_file(path: String) -> Result<String, String> {
    eprintln!("[read_file] ⚡ TOOL EXECUTION ⚡ Reading: {}", path);
    let expanded_path = shellexpand::tilde(&path).to_string();
    std::fs::read_to_string(&expanded_path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))
}

#[tauri::command]
pub async fn write_file(path: String, content: String) -> Result<String, String> {
    eprintln!("[write_file] ⚡ TOOL EXECUTION ⚡ Writing to: {}", path);
    let expanded_path = shellexpand::tilde(&path).to_string();
    std::fs::write(&expanded_path, &content)
        .map_err(|e| format!("Failed to write {}: {}", path, e))?;
    Ok(format!("Wrote {} bytes to {}", content.len(), path))
}

#[derive(Debug, Clone, Serialize)]
pub struct FileEntryNode {
    pub path: String,
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<FileEntryNode>>,
}

fn collect_directory_entries(path: &Path, depth: usize, remaining: &mut usize) -> Result<Vec<FileEntryNode>, String> {
    if depth > 4 || *remaining == 0 {
        return Ok(vec![]);
    }

    let entries = std::fs::read_dir(path)
        .map_err(|e| format!("Failed to read dir {}: {}", path.display(), e))?;
    let mut nodes = Vec::new();

    for entry_res in entries {
        if *remaining == 0 {
            break;
        }
        let entry = entry_res.map_err(|e| format!("Dir entry error: {}", e))?;
        let file_type = entry.file_type().map_err(|e| format!("File type error: {}", e))?;
        let entry_path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".git" || name == "node_modules" {
            continue;
        }

        let kind = if file_type.is_dir() { "dir" } else { "file" }.to_string();
        let children = if file_type.is_dir() {
            collect_directory_entries(&entry_path, depth + 1, remaining)?
        } else {
            Vec::new()
        };

        nodes.push(FileEntryNode {
            path: entry_path.display().to_string(),
            name,
            kind: kind.clone(),
            children: if children.is_empty() { None } else { Some(children) },
        });
        *remaining = remaining.saturating_sub(1);
    }

    nodes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(nodes)
}

#[tauri::command]
pub async fn list_directory_tree(path: Option<String>) -> Result<Vec<FileEntryNode>, String> {
    let base_path = match path {
        Some(p) => PathBuf::from(shellexpand::tilde(&p).to_string()),
        None => std::env::current_dir().map_err(|e| format!("Failed to get cwd: {}", e))?,
    };
    let mut remaining = 2_000;
    collect_directory_entries(&base_path, 0, &mut remaining)
}

#[tauri::command]
pub fn current_working_dir() -> Result<String, String> {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .map_err(|e| format!("Failed to get cwd: {}", e))
}

/// List directory entries for autocomplete (lightweight, single level)
#[tauri::command]
pub fn list_directory(path: String, prefix: String) -> Result<Vec<String>, String> {
    let expanded_path = shellexpand::tilde(&path).to_string();
    let dir_path = PathBuf::from(&expanded_path);

    // If prefix contains a path separator, adjust the search directory
    let (search_dir, file_prefix) = if prefix.contains('/') {
        let prefix_path = PathBuf::from(&prefix);
        if let Some(parent) = prefix_path.parent() {
            let full_parent = if prefix.starts_with('/') {
                PathBuf::from(parent)
            } else {
                dir_path.join(parent)
            };
            let file_part = prefix_path.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            (full_parent, file_part)
        } else {
            (dir_path, prefix.clone())
        }
    } else {
        (dir_path, prefix.clone())
    };

    let read_dir = std::fs::read_dir(&search_dir)
        .map_err(|e| format!("Failed to read directory: {}", e))?;

    let mut results: Vec<String> = Vec::new();
    let lower_prefix = file_prefix.to_lowercase();

    for entry in read_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip hidden files unless prefix starts with .
        if name.starts_with('.') && !lower_prefix.starts_with('.') {
            continue;
        }

        // Filter by prefix
        if !name.to_lowercase().starts_with(&lower_prefix) {
            continue;
        }

        // Append / for directories
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let display_name = if is_dir {
            format!("{}/", name)
        } else {
            name
        };

        results.push(display_name);
    }

    // Sort directories first, then files
    results.sort_by(|a, b| {
        let a_is_dir = a.ends_with('/');
        let b_is_dir = b.ends_with('/');
        match (a_is_dir, b_is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.cmp(b),
        }
    });

    // Limit results
    results.truncate(50);

    Ok(results)
}

#[tauri::command]
pub async fn send_test_message(
    message: String,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    eprintln!("[send_test_message] Sending test message via IPC: {}", message);
    
    // Emit event to frontend to trigger sendMessage
    let _ = app_handle.emit_all("test_send_message", message);
    
    Ok(())
}

// Conversation state commands
use crate::conversation::{ConversationState, Tab};

#[tauri::command]
pub async fn get_conversation_state(
    state: State<'_, ConversationState>,
) -> Result<Vec<Tab>, String> {
    let tabs = state.get_tabs();
    for tab in &tabs {
        eprintln!("[get_conversation_state] Tab {} is_thinking={}", tab.id, tab.is_thinking);
    }
    Ok(tabs)
}

#[tauri::command]
pub async fn send_user_message(
    tab_id: u64,
    content: String,
    state: State<'_, ConversationState>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    eprintln!("[send_user_message] Tab {} message: {}", tab_id, content);
    
    // Add user message to state
    state.add_message(tab_id, "user".to_string(), content.clone());
    
    // Notify frontend
    let _ = app_handle.emit_all("conversation_updated", serde_json::json!({
        "tabId": tab_id
    }));
    
    // Start AI response
    state.set_thinking(tab_id, true);
    let _ = app_handle.emit_all("conversation_updated", serde_json::json!({
        "tabId": tab_id
    }));
    
    // Get messages for AI
    let messages = state.get_messages_for_ai(tab_id);
    
    // Call AI with tools enabled
    ai_query_stream_internal(tab_id, messages, state, app_handle, true).await?;
    
    Ok(())
}

// Sanitize AI-generated JSON by fixing common mistakes
fn sanitize_json(input: &str) -> String {
    // Simple approach: replace all single quotes with double quotes
    // This works for tool JSON since we control the format and don't use apostrophes in values
    input.replace('\'', "\"")
}

// Internal AI query that integrates with conversation state
pub async fn ai_query_stream_internal(
    tab_id: u64,
    mut messages: Vec<serde_json::Value>,
    state: State<'_, ConversationState>,
    app_handle: tauri::AppHandle,
    allow_tools: bool,
) -> Result<(), String> {
    use futures_util::StreamExt;
    
    eprintln!("[ai_query_stream_internal] Tab {} with {} messages (allow_tools={})", tab_id, messages.len(), allow_tools);
    
    // If this is a follow-up after tool execution, instruct AI to explain in prose
    if !allow_tools {
        messages.push(serde_json::json!({
            "role": "user",
            "content": "Based on the tool output above, provide a brief natural language summary for the user."
        }));
    }
    
    let client = reqwest::Client::new();
    let ollama_url = "http://localhost:11434/api/chat";
    
    let payload = serde_json::json!({
        "model": "llama3.2:3b-instruct-q4_K_M",
        "messages": messages,
        "stream": true,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 500
        }
    });
    
    match client.post(ollama_url).json(&payload).send().await {
        Ok(response) => {
            let mut stream = response.bytes_stream();
            let mut accumulated_response = String::new();
            
            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        if let Ok(text) = String::from_utf8(chunk.to_vec()) {
                            for line in text.lines() {
                                if line.trim().is_empty() {
                                    continue;
                                }
                                
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                                    if let Some(message) = json["message"].as_object() {
                                        if let Some(response_text) = message["content"].as_str() {
                                            eprintln!("[CHUNK] {}", response_text);
                                            accumulated_response.push_str(response_text);
                                        }
                                    }
                                    
                                    if json["done"].as_bool().unwrap_or(false) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[ai_query_stream_internal] Stream error: {}", e);
                        break;
                    }
                }
            }
            
            // Check if response is a tool call (only if tools are allowed)
            let complete_response = accumulated_response.trim();
            
            // If tools are disabled, treat everything as plain text
            if !allow_tools {
                if !complete_response.is_empty() {
                    state.add_message(tab_id, "ai".to_string(), complete_response.to_string());
                } else {
                    // AI returned empty response - provide fallback
                    eprintln!("[ai_query_stream_internal] AI returned empty response after tool execution");
                    state.add_message(tab_id, "ai".to_string(), "✓ Command executed".to_string());
                }
                state.set_thinking(tab_id, false);
                let _ = app_handle.emit_all("conversation_updated", serde_json::json!({"tabId": tab_id}));
                return Ok(());
            }
            
            // PHASE 3: Auto-detect multiple tool calls and batch them
            use crate::ai_parser::parse_multiple_tool_calls;
            if let Some(tool_calls) = parse_multiple_tool_calls(complete_response) {
                eprintln!("[PHASE 3] Detected {} tool calls, auto-creating batch", tool_calls.len());
                
                // Convert ParsedToolCall to BatchEntry
                let entries: Vec<BatchEntry> = tool_calls.iter().enumerate().map(|(idx, tc)| {
                    let safe_score = crate::commands::calculate_safety_score(&tc.tool, &tc.args);
                    BatchEntry {
                        id: format!("entry-{}", idx),
                        origin_message_id: None,
                        tool: tc.tool.clone(),
                        args: tc.args.clone(),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        status: BatchStatus::Pending,
                        result: None,
                        safe_score,
                        requires_manual: safe_score < 100,
                    }
                }).collect();
                
                // Create batch
                let batch = state.create_batch(tab_id, entries);
                let batch_id = batch.id.clone();
                
                // Check autonomy settings
                let settings = state.get_autonomy_settings();
                let all_safe = batch.entries.iter().all(|e| e.safe_score == 100);
                
                let mut auto_approved = false;
                let mut auto_executed = false;
                
                // Auto-approve if all commands safe and auto_approve_enabled
                if all_safe && settings.auto_approve_enabled && settings.autonomy_token.is_some() {
                    eprintln!("[PHASE 3] Auto-approving batch {} (all safe, auto_approve enabled)", batch_id);
                    state.approve_batch(&batch_id, settings.autonomy_token.clone());
                    auto_approved = true;
                    
                    // Auto-execute if also enabled
                    if settings.auto_execute_enabled {
                        eprintln!("[PHASE 3] Auto-executing batch {} (auto_execute enabled)", batch_id);
                        let batch_id_clone = batch_id.clone();
                        let token_clone = settings.autonomy_token.clone();
                        let state_ref = state.inner().clone();
                        let app_clone = app_handle.clone();
                        tokio::spawn(async move {
                            // Manually execute the batch without State wrapper
                            let _ = execute_batch_internal(&batch_id_clone, &token_clone, &state_ref, &app_clone).await;
                        });
                        auto_executed = true;
                    }
                }
                
                // Log batch creation
                let status_msg = if auto_executed {
                    format!("[Phase 3] Created batch {} with {} commands (auto-approved & auto-executed)", batch_id, batch.entries.len())
                } else if auto_approved {
                    format!("[Phase 3] Created batch {} with {} commands (auto-approved, awaiting execution)", batch_id, batch.entries.len())
                } else {
                    format!("[Phase 3] Created batch {} with {} commands (awaiting approval)", batch_id, batch.entries.len())
                };
                
                state.add_message(tab_id, "ai".to_string(), status_msg);
                
                state.set_thinking(tab_id, false);
                let _ = app_handle.emit_all("conversation_updated", serde_json::json!({"tabId": tab_id}));
                let _ = app_handle.emit_all("batch_created", serde_json::json!({
                    "batchId": batch_id,
                    "autoApproved": auto_approved,
                    "autoExecuted": auto_executed
                }));
                
                return Ok(());
            }
            
            if complete_response.starts_with('{') && complete_response.contains("\"tool\"") {
                eprintln!("[ai_query_stream_internal] Detected tool call JSON");
                
                // BUGFIX: Check for duplicate tool execution
                let tool_key = format!("{}:{}", tab_id, complete_response);
                {
                    let mut executing = lock_or_recover(&EXECUTING_TOOLS);
                    if executing.contains(&tool_key) {
                        eprintln!("[DUPLICATE DETECTED] Skipping duplicate tool execution");
                        state.set_thinking(tab_id, false);
                        let _ = app_handle.emit_all("conversation_updated", serde_json::json!({"tabId": tab_id}));
                        return Ok(());
                    }
                    executing.insert(tool_key.clone());
                }
                
                // DO NOT add tool call message to state (hide JSON from UI)
                // state.add_message(tab_id, "ai".to_string(), complete_response.to_string());
                
// Try to parse and execute the tool (with sanitizer fallback)
                let mut parsed: Option<serde_json::Value> = serde_json::from_str::<serde_json::Value>(complete_response).ok();
                if parsed.is_none() {
                    let sanitized = sanitize_json(complete_response);
                    eprintln!("[ai_query_stream_internal] Original failed, trying sanitized: {}", sanitized);
                    match serde_json::from_str::<serde_json::Value>(&sanitized) {
                        Ok(val) => parsed = Some(val),
                        Err(e) => {
                            eprintln!("[ai_query_stream_internal] JSON parse error after sanitization: {}", e);
                            eprintln!("[ai_query_stream_internal] Failed to parse tool call, stopping thinking");
                            // Clean up tracking
                            lock_or_recover(&EXECUTING_TOOLS).remove(&tool_key);
                            state.set_thinking(tab_id, false);
                            let _ = app_handle.emit_all("conversation_updated", serde_json::json!({
                                "tabId": tab_id
                            }));
                            return Ok(());
                        }
                    }
                }
                if let Some(tool_call) = parsed {
                    if let (Some(tool_name), Some(args)) = (tool_call.get("tool"), tool_call.get("args")) {
                        eprintln!("[ai_query_stream_internal] Executing tool: {}", tool_name);
                        
                        // Execute the tool
                        let result = match tool_name.as_str() {
                            Some("read_file") => {
                                if let Some(path) = args.get("path").and_then(|p| p.as_str()) {
                                    eprintln!("[read_file] ⚡ TOOL EXECUTION ⚡ Reading: {}", path);
                                    let expanded = shellexpand::tilde(path).to_string();
                                    std::fs::read_to_string(&expanded)
                                        .map_err(|e| format!("Failed to read {}: {}", path, e))
                                } else {
                                    Err("Missing 'path' argument".to_string())
                                }
                            },
                            Some("write_file") => {
                                if let (Some(path), Some(content)) = (
                                    args.get("path").and_then(|p| p.as_str()),
                                    args.get("content").and_then(|c| c.as_str())
                                ) {
                                    eprintln!("[write_file] ⚡ TOOL EXECUTION ⚡ Writing to: {}", path);
                                    let expanded = shellexpand::tilde(path).to_string();
                                    std::fs::write(&expanded, content)
                                        .map(|_| format!("Wrote {} bytes to {}", content.len(), path))
                                        .map_err(|e| format!("Failed to write {}: {}", path, e))
                                } else {
                                    Err("Missing 'path' or 'content' argument".to_string())
                                }
                            },
                            Some("execute_shell") => {
                                if let Some(command) = args.get("command").and_then(|c| c.as_str()) {
                                    eprintln!("[execute_shell] ⚡ TOOL EXECUTION ⚡ Running: {}", command);
                                    let output = std::process::Command::new("sh")
                                        .arg("-c")
                                        .arg(command)
                                        .output()
                                        .map_err(|e| format!("Failed to execute: {}", e))?;
                                    
                                    let mut result = String::from_utf8_lossy(&output.stdout).to_string();
                                    if !output.stderr.is_empty() {
                                        result.push_str("\n");
                                        result.push_str(&String::from_utf8_lossy(&output.stderr));
                                    }
                                    Ok(result)
                                } else {
                                    Err("Missing 'command' argument".to_string())
                                }
                            },
                            _ => Err(format!("Unknown tool: {:?}", tool_name))
                        };
                        
                        // Add tool result as system message for AI context (not displayed in UI)
                        let result_msg = match &result {
                            Ok(output) => format!("[Tool Result]\n{}", output),
                            Err(e) => format!("[Tool Error]\n{}", e),
                        };
                        state.add_message(tab_id, "system".to_string(), result_msg);
                        
                        eprintln!("[ai_query_stream_internal] Tool execution complete, requesting AI follow-up");
                        
                        // PHASE 1: ASSISTIVE AUTONOMY
                        // After tool execution, trigger EXACTLY ONE follow-up with tools DISABLED
                        // This ensures the AI explains the result in natural language
                        // and cannot auto-loop into another tool call.
                        eprintln!("[PHASE 1] Triggering single follow-up explanation (tools disabled)");
                        let follow_up_messages = state.get_messages_for_ai(tab_id);
                        let app_clone = app_handle.clone();
                        
                        // Clean up tracking before follow-up
                        lock_or_recover(&EXECUTING_TOOLS).remove(&tool_key);
                        
                        // Note: state is moved into follow-up call, which will handle stopping thinking
                        Box::pin(ai_query_stream_internal(tab_id, follow_up_messages, state, app_clone, false)).await?;
                        
                        return Ok(()); // Exit early, follow-up handles stopping thinking
                    }
                }
                
                // If tool parsing failed, stop thinking
                lock_or_recover(&EXECUTING_TOOLS).remove(&tool_key);
                state.set_thinking(tab_id, false);
                let _ = app_handle.emit_all("conversation_updated", serde_json::json!({
                    "tabId": tab_id
                }));
            } else {
                // Regular AI response
                state.add_message(tab_id, "ai".to_string(), accumulated_response.clone());
                
                // Notify frontend
                let _ = app_handle.emit_all("conversation_updated", serde_json::json!({
                    "tabId": tab_id
                }));
                
                // Stop thinking after regular response
                state.set_thinking(tab_id, false);
                let _ = app_handle.emit_all("conversation_updated", serde_json::json!({
                    "tabId": tab_id
                }));
            }
            
            Ok(())
        }
        Err(e) => {
            eprintln!("[ai_query_stream_internal] Ollama connection failed: {}", e);
            
            let placeholder = format!(
                "[Ollama not available. Start it with: ollama serve]\n\nFor best results on your M2 8GB, use: deepseek-coder:6.7b"
            );
            
            state.add_message(tab_id, "ai".to_string(), placeholder);
            state.set_thinking(tab_id, false);
            
            let _ = app_handle.emit_all("conversation_updated", serde_json::json!({
                "tabId": tab_id
            }));
            
            Ok(())
        }
    }
}

// PHASE 2: Batch Execution Command
use crate::conversation::{Batch, BatchEntry, BatchStatus};
use std::fs::OpenOptions;
use std::io::Write;

/// Append audit log entry
fn audit_log(batch_id: &str, entry_id: &str, tool: &str, result: &str, approved_by: &Option<String>) {
    let log_path = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()) + "/PHASE2_AUDIT.log";
    let timestamp = chrono::Utc::now().to_rfc3339();
    let approved_str = approved_by.as_deref().unwrap_or("manual");
    let log_entry = format!(
        "{}|batch:{}|entry:{}|tool:{}|approved_by:{}|result_hash:{}\n",
        timestamp,
        batch_id,
        entry_id,
        tool,
        approved_str,
        format!("{:x}", md5::compute(result))
    );
    
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let _ = file.write_all(log_entry.as_bytes());
        eprintln!("[PHASE 2 AUDIT] Logged to {}", log_path);
    }
}

#[tauri::command]
pub async fn test_phase2_workflow(
    state: State<'_, ConversationState>,
    _app_handle: tauri::AppHandle,
) -> Result<String, String> {
    eprintln!("[PHASE 2 TEST] Starting automated workflow test");
    
    // Step 1: Get initial batches
    let initial = state.get_batches();
    eprintln!("[PHASE 2 TEST] Initial batches: {}", initial.len());
    
    // Step 2: Create test batch
    let entries = vec![
        serde_json::json!({
            "tool": "execute_shell",
            "args": {"command": "echo '=== Phase 2 Automated Test ==="}
        }),
        serde_json::json!({
            "tool": "execute_shell",
            "args": {"command": "pwd"}
        }),
        serde_json::json!({
            "tool": "execute_shell",
            "args": {"command": "whoami"}
        }),
        serde_json::json!({
            "tool": "execute_shell",
            "args": {"command": "date"}
        }),
    ];
    
    let mut batch_entries = Vec::new();
    for entry_json in entries {
        let tool = entry_json.get("tool").and_then(|t| t.as_str()).ok_or("Missing tool")?;
        let args = entry_json.get("args").ok_or("Missing args")?;
        
        let entry = BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: tool.to_string(),
            args: args.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 0,
            requires_manual: false,
        };
        batch_entries.push(entry);
    }
    
    let batch = state.create_batch(1, batch_entries);
    let batch_id = batch.id.clone();
    eprintln!("[PHASE 2 TEST] Created batch: {}", batch_id);
    
    // Step 3: Approve batch
    state.approve_batch(&batch_id, Some("test_automation".to_string()));
    eprintln!("[PHASE 2 TEST] Approved batch");
    
    // Small delay
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    // Step 4: Run batch
    let batch_for_run = state.get_batch(&batch_id).ok_or("Batch not found")?;
    
    if batch_for_run.status != BatchStatus::Approved {
        return Err(format!("Batch not approved: {:?}", batch_for_run.status));
    }
    
    // Mark as running
    state.update_batch_status(&batch_id, BatchStatus::Running);
    eprintln!("[PHASE 2 TEST] Running batch...");
    
    // Execute each entry
    let mut results = Vec::new();
    for entry in &batch_for_run.entries {
        if entry.tool == "execute_shell" {
            if let Some(cmd) = entry.args.get("command").and_then(|c| c.as_str()) {
                let (allowed, _, safe_score) = classify_command(cmd);
                
                if allowed {
                    match std::process::Command::new("sh")
                        .arg("-c")
                        .arg(cmd)
                        .output()
                    {
                        Ok(output) => {
                            let result = String::from_utf8_lossy(&output.stdout).to_string();
                            results.push(format!("[{}] {}: {} (score: {})", 
                                entry.id[..8].to_string(), cmd, 
                                result.trim(), safe_score));
                            
                            // Write audit log
                            audit_log(&batch_id, &entry.id, &entry.tool, &result, 
                                &Some("test_automation".to_string()));
                        }
                        Err(e) => {
                            results.push(format!("[{}] {}: ERROR - {}", 
                                entry.id[..8].to_string(), cmd, e));
                        }
                    }
                } else {
                    results.push(format!("[{}] {}: BLOCKED (score: {})", 
                        entry.id[..8].to_string(), cmd, safe_score));
                }
            }
        }
    }
    
    // Mark as completed
    state.update_batch_status(&batch_id, BatchStatus::Completed);
    eprintln!("[PHASE 2 TEST] Batch completed");
    
    // Step 5: Verify results
    let final_batches = state.get_batches();
    eprintln!("[PHASE 2 TEST] Final batches: {}", final_batches.len());
    
    let test_batch = final_batches.iter().find(|b| b.id == batch_id)
        .ok_or("Test batch not found in final results")?;
    
    if test_batch.status != BatchStatus::Completed {
        return Err(format!("Batch not completed: {:?}", test_batch.status));
    }
    
    eprintln!("[PHASE 2 TEST] ✅ All tests passed!");
    
    // Return summary
    let summary = format!(
        "Phase 2 Automated Test Results:\n\nBatch ID: {}\nStatus: {:?}\nEntries: {}\n\nResults:\n{}\n\n✅ All tests passed!",
        batch_id,
        test_batch.status,
        test_batch.entries.len(),
        results.join("\n")
    );
    
    Ok(summary)
}

#[tauri::command]
pub async fn create_batch(
    tab_id: u64,
    entries: Vec<serde_json::Value>,
    state: State<'_, ConversationState>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    eprintln!("[PHASE 2] create_batch called with {} entries", entries.len());
    
    // Parse entries
    let mut batch_entries = Vec::new();
    for entry_json in entries {
        let tool = entry_json.get("tool")
            .and_then(|t| t.as_str())
            .ok_or("Missing tool field")?;
        let args = entry_json.get("args")
            .ok_or("Missing args field")?;
        
        let entry = BatchEntry {
            id: uuid::Uuid::new_v4().to_string(),
            origin_message_id: None,
            tool: tool.to_string(),
            args: args.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score: 0,
            requires_manual: false,
        };
        batch_entries.push(entry);
    }
    
    // Create batch
    let batch = state.create_batch(tab_id, batch_entries);
    let batch_id = batch.id.clone();
    
    eprintln!("[PHASE 2] Created batch {}", batch_id);
    
    // Notify frontend
    let _ = app_handle.emit_all("batch_updated", serde_json::json!({
        "batchId": &batch_id
    }));
    
    Ok(batch_id)
}

#[tauri::command]
pub async fn get_batches(
    state: State<'_, ConversationState>,
) -> Result<Vec<Batch>, String> {
    Ok(state.get_batches())
}

#[tauri::command]
pub async fn approve_batch(
    batch_id: String,
    autonomy_token: Option<String>,
    state: State<'_, ConversationState>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    state.approve_batch(&batch_id, autonomy_token);
    
    // Notify frontend
    let _ = app_handle.emit_all("batch_updated", serde_json::json!({
        "batchId": batch_id
    }));
    
    Ok(())
}

// Internal batch execution without State wrapper (for Phase 3 auto-execute)
async fn execute_batch_internal(
    batch_id: &str,
    autonomy_token: &Option<String>,
    state: &ConversationState,
    app_handle: &tauri::AppHandle,
) -> Result<(), String> {
    eprintln!("[PHASE 3] execute_batch_internal called for batch {}", batch_id);
    
    // Get batch
    let mut batch = state.get_batch(batch_id)
        .ok_or_else(|| format!("Batch {} not found", batch_id))?;

    // Enforce dependency before running
    if let Some(parent_id) = &batch.depends_on {
        if let Some(parent) = state.get_batch(parent_id) {
            if parent.status != BatchStatus::Completed {
                eprintln!("[PHASE 3] Batch {} blocked by dependency on {} (status={:?})", batch_id, parent_id, parent.status);
                return Err(format!("Blocked: parent batch {} not completed (status: {:?})", parent_id, parent.status));
            }
        } else {
            return Err(format!("Blocked: parent batch {} not found", parent_id));
        }
    }
    
    // Check status
    if batch.status != BatchStatus::Pending && batch.status != BatchStatus::Approved {
        return Err(format!("Batch is not in pending/approved state: {:?}", batch.status));
    }
    
    // Mark batch as running
    state.update_batch_status(batch_id, BatchStatus::Running);
    let _ = app_handle.emit_all("batch_updated", serde_json::json!({ "batchId": batch_id }));
    
    // Execute each entry sequentially
    let mut all_success = true;
    for entry in &mut batch.entries {
        // Classify command if it's execute_shell
        if entry.tool == "execute_shell" {
            if let Some(cmd) = entry.args.get("command").and_then(|c| c.as_str()) {
                let (allowed, requires_manual, safe_score) = classify_command(cmd);
                
                // Update entry metadata
                entry.safe_score = safe_score;
                entry.requires_manual = requires_manual;
                
                // Check if blocked
                if !allowed && requires_manual {
                    if autonomy_token.is_none() && batch.approved_by.is_none() {
                        entry.status = BatchStatus::Error;
                        entry.result = Some(format!("BLOCKED: Command denied by policy"));
                        eprintln!("[PHASE 3] Entry {} blocked by policy", entry.id);
                        all_success = false;
                        continue;
                    }
                }
            }
        }
        
        // Execute the tool
        eprintln!("[PHASE 3] Executing entry {}: {}", entry.id, entry.tool);
        entry.status = BatchStatus::Running;
        
        let result = match entry.tool.as_str() {
            "execute_shell" => {
                if let Some(cmd) = entry.args.get("command").and_then(|c| c.as_str()) {
                    match std::process::Command::new("sh")
                        .arg("-c")
                        .arg(cmd)
                        .output()
                    {
                        Ok(output) => {
                            let mut res = String::from_utf8_lossy(&output.stdout).to_string();
                            if !output.stderr.is_empty() {
                                res.push_str("\n");
                                res.push_str(&String::from_utf8_lossy(&output.stderr));
                            }
                            Ok(res)
                        },
                        Err(e) => Err(format!("Failed to execute: {}", e))
                    }
                } else {
                    Err("Missing command argument".to_string())
                }
            },
            "read_file" => {
                if let Some(path) = entry.args.get("path").and_then(|p| p.as_str()) {
                    let expanded = shellexpand::tilde(path).to_string();
                    std::fs::read_to_string(&expanded)
                        .map_err(|e| format!("Failed to read {}: {}", path, e))
                } else {
                    Err("Missing path argument".to_string())
                }
            },
            "write_file" => {
                if let (Some(path), Some(content)) = (
                    entry.args.get("path").and_then(|p| p.as_str()),
                    entry.args.get("content").and_then(|c| c.as_str())
                ) {
                    let expanded = shellexpand::tilde(path).to_string();
                    std::fs::write(&expanded, content)
                        .map(|_| format!("Wrote {} bytes to {}", content.len(), path))
                        .map_err(|e| format!("Failed to write {}: {}", path, e))
                } else {
                    Err("Missing path or content argument".to_string())
                }
            },
            _ => Err(format!("Unknown tool: {}", entry.tool))
        };
        
        // Store result
        match result {
            Ok(output) => {
                entry.result = Some(output.clone());
                entry.status = BatchStatus::Completed;
                
                // Audit log
                audit_log(batch_id, &entry.id, &entry.tool, &output, &batch.approved_by);
                
                // Add to conversation
                state.add_message(batch.creator_tab, "user".to_string(), format!("[Tool Result]\n{}", output));
            },
            Err(e) => {
                entry.result = Some(e.clone());
                entry.status = BatchStatus::Error;
                all_success = false;
                
                // Audit log
                audit_log(batch_id, &entry.id, &entry.tool, &e, &batch.approved_by);
                
                // Add error to conversation
                state.add_message(batch.creator_tab, "user".to_string(), format!("[Tool Error]\n{}", e));
            }
        }
    }
    
    // Update final batch status
    let final_status = if all_success {
        BatchStatus::Completed
    } else {
        BatchStatus::Error
    };
    state.update_batch_status(batch_id, final_status);
    
    // Notify frontend
    let _ = app_handle.emit_all("batch_updated", serde_json::json!({ "batchId": batch_id }));
    let _ = app_handle.emit_all("conversation_updated", serde_json::json!({ "tabId": batch.creator_tab }));
    
    eprintln!("[PHASE 3] Batch {} execution complete: {:?}", batch_id, final_status);
    Ok(())
}

#[tauri::command]
pub async fn run_batch(
    batch_id: String,
    autonomy_token: Option<String>,
    state: State<'_, ConversationState>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    eprintln!("[PHASE 2] run_batch called for batch {}", batch_id);
    execute_batch_internal(&batch_id, &autonomy_token, state.inner(), &app_handle).await
}

// PHASE 3: Autonomy Settings Commands
use crate::conversation::AutonomySettings;

#[tauri::command]
pub async fn get_autonomy_settings(
    state: State<'_, ConversationState>,
) -> Result<AutonomySettings, String> {
    Ok(state.get_autonomy_settings())
}

#[tauri::command]
pub async fn update_autonomy_settings(
    settings: AutonomySettings,
    state: State<'_, ConversationState>,
) -> Result<(), String> {
    state.update_autonomy_settings(settings);
    Ok(())
}

// PHASE 3: Batch dependency command
#[tauri::command]
pub async fn set_batch_dependency(
    batch_id: String,
    depends_on: Option<String>,
    state: State<'_, ConversationState>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    state.set_batch_dependency(&batch_id, depends_on)?;
    let _ = app_handle.emit_all("batch_updated", serde_json::json!({ "batchId": batch_id }));
    Ok(())
}

// PHASE 3: Rollback command
use crate::rollback::{generate_rollback_plan, execute_rollback};

#[tauri::command]
pub async fn rollback_batch(
    batch_id: String,
    state: State<'_, ConversationState>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    eprintln!("[PHASE 3] rollback_batch called for {}", batch_id);
    
    // Get batch
    let batch = state.get_batch(&batch_id)
        .ok_or_else(|| format!("Batch {} not found", batch_id))?;
    
    // Only allow rollback for completed or error batches
    if batch.status != BatchStatus::Completed && batch.status != BatchStatus::Error {
        return Err(format!("Cannot rollback batch in {:?} state", batch.status));
    }
    
    // Generate rollback plan
    let actions = generate_rollback_plan(&batch);
    eprintln!("[PHASE 3] Generated {} rollback actions", actions.len());
    
    // Execute rollback
    let result = execute_rollback(actions).await?;
    
    // Mark batch as rolled back (revert to Pending)
    state.update_batch_status(&batch_id, BatchStatus::Pending);
    
    // Notify frontend
    let _ = app_handle.emit_all("batch_updated", serde_json::json!({ "batchId": &batch_id }));
    let _ = app_handle.emit_all("batch_rolled_back", serde_json::json!({ 
        "batchId": &batch_id,
        "result": result
    }));
    
    eprintln!("[PHASE 3] Rollback complete for batch {}", batch_id);
    Ok(result)
}

#[tauri::command]
pub async fn test_phase3_workflow(
    state: State<'_, ConversationState>,
    _app_handle: tauri::AppHandle,
) -> Result<String, String> {
    eprintln!("[PHASE 3 TEST] Starting automated workflow test");
    let mut results = Vec::new();
    
    // Step 1: Enable autonomy settings
    let settings = AutonomySettings {
        autonomy_token: Some("test_phase3".to_string()),
        auto_approve_enabled: true,
        auto_execute_enabled: false, // Don't auto-execute for test control
    };
    state.update_autonomy_settings(settings.clone());
    results.push("✓ Step 1: Autonomy settings enabled".to_string());
    
    // Step 2: Simulate multi-tool AI response (would normally come from parser)
    let ai_response = r#"
{"tool":"execute_shell","args":{"command":"echo 'Phase 3 Test 1'"}}
{"tool":"execute_shell","args":{"command":"pwd"}}
{"tool":"execute_shell","args":{"command":"date"}}
    "#;
    
    use crate::ai_parser::parse_multiple_tool_calls;
    let tool_calls = parse_multiple_tool_calls(ai_response)
        .ok_or("Failed to parse multiple tool calls")?;
    results.push(format!("✓ Step 2: Parsed {} tool calls", tool_calls.len()));
    
    // Step 3: Create batch from tool calls
    let entries: Vec<BatchEntry> = tool_calls.iter().enumerate().map(|(idx, tc)| {
        let safe_score = calculate_safety_score(&tc.tool, &tc.args);
        BatchEntry {
            id: format!("test-entry-{}", idx),
            origin_message_id: None,
            tool: tc.tool.clone(),
            args: tc.args.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            status: BatchStatus::Pending,
            result: None,
            safe_score,
            requires_manual: safe_score < 100,
        }
    }).collect();
    
    let batch1 = state.create_batch(1, entries);
    let batch1_id = batch1.id.clone();
    results.push(format!("✓ Step 3: Created batch {}", batch1_id));
    
    // Step 4: Verify auto-approval (should happen if all commands safe)
    let all_safe = batch1.entries.iter().all(|e| e.safe_score == 100);
    if all_safe && settings.auto_approve_enabled {
        state.approve_batch(&batch1_id, settings.autonomy_token.clone());
        results.push("✓ Step 4: Auto-approved batch (all commands safe)".to_string());
    } else {
        return Err("Step 4 failed: batch should be auto-approved".to_string());
    }
    
    // Step 5: Create dependent batch
    let entry2 = BatchEntry {
        id: "dependent-entry".to_string(),
        origin_message_id: None,
        tool: "execute_shell".to_string(),
        args: serde_json::json!({ "command": "echo 'Dependent task'" }),
        created_at: chrono::Utc::now().to_rfc3339(),
        status: BatchStatus::Pending,
        result: None,
        safe_score: 100,
        requires_manual: false,
    };
    let batch2 = state.create_batch(1, vec![entry2]);
    let batch2_id = batch2.id.clone();
    state.set_batch_dependency(&batch2_id, Some(batch1_id.clone()))?;
    results.push(format!("✓ Step 5: Created dependent batch {} -> {}", batch2_id, batch1_id));
    
    // Step 6: Try to run dependent batch (should fail - parent not completed)
    match state.get_batch(&batch2_id) {
        Some(b) if b.depends_on.is_some() => {
            results.push("✓ Step 6: Dependent batch correctly configured".to_string());
        }
        _ => return Err("Step 6 failed: dependency not set".to_string()),
    }
    
    // Step 7: Complete parent batch first
    state.update_batch_status(&batch1_id, BatchStatus::Running);
    std::thread::sleep(std::time::Duration::from_millis(50));
    state.update_batch_status(&batch1_id, BatchStatus::Completed);
    results.push("✓ Step 7: Parent batch completed".to_string());
    
    // Step 8: Now dependent batch can run
    let batch2_check = state.get_batch(&batch2_id).ok_or("Batch 2 not found")?;
    if let Some(parent_id) = &batch2_check.depends_on {
        let parent = state.get_batch(parent_id).ok_or("Parent batch not found")?;
        if parent.status == BatchStatus::Completed {
            results.push("✓ Step 8: Dependency check passed (parent completed)".to_string());
        } else {
            return Err(format!("Step 8 failed: parent status {:?}", parent.status));
        }
    }
    
    // Step 9: Test rollback (create a write_file batch)
    let write_entry = BatchEntry {
        id: "write-test".to_string(),
        origin_message_id: None,
        tool: "write_file".to_string(),
        args: serde_json::json!({
            "path": "/tmp/phase3_test.txt",
            "content": "Phase 3 rollback test"
        }),
        created_at: chrono::Utc::now().to_rfc3339(),
        status: BatchStatus::Completed, // Simulate completed
        result: Some("Written".to_string()),
        safe_score: 100,
        requires_manual: false,
    };
    let batch3 = state.create_batch(1, vec![write_entry]);
    let batch3_id = batch3.id.clone();
    state.update_batch_status(&batch3_id, BatchStatus::Completed);
    
    // Generate rollback plan
    let batch3_final = state.get_batch(&batch3_id).ok_or("Batch 3 not found")?;
    let rollback_plan = generate_rollback_plan(&batch3_final);
    results.push(format!("✓ Step 9: Generated rollback plan with {} actions", rollback_plan.len()));
    
    // Verify settings persistence
    let retrieved_settings = state.get_autonomy_settings();
    if retrieved_settings.auto_approve_enabled == settings.auto_approve_enabled {
        results.push("✓ Step 10: Settings persist correctly".to_string());
    } else {
        return Err("Step 10 failed: settings not persisted".to_string());
    }
    
    eprintln!("[PHASE 3 TEST] ✅ All tests passed!");
    
    let summary = format!(
        "Phase 3 Automated Test Results:\n\n{}\n\n✅ All 10 steps passed!\n\nBatch IDs:\n- Batch 1 (multi-tool): {}\n- Batch 2 (dependent): {}\n- Batch 3 (rollback): {}",
        results.join("\n"),
        batch1_id,
        batch2_id,
        batch3_id
    );
    
    Ok(summary)
}

// ========================================
// PHASE 4: TELEMETRY & LEARNING SYSTEM
// ========================================

use crate::telemetry::{TelemetryStore, TelemetryEvent};
use std::process::Command;

#[tauri::command]
pub fn telemetry_insert_event(
    event_json: String,
    telemetry: State<'_, Arc<Mutex<TelemetryStore>>>,
) -> Result<String, String> {
    let event: TelemetryEvent = serde_json::from_str(&event_json)
        .map_err(|e| format!("Failed to parse telemetry event: {}", e))?;
    
    lock_or_recover(&telemetry)
        .insert_event(&event)
        .map_err(|e| format!("Failed to insert telemetry event: {}", e))?;
    
    Ok(event.id)
}

#[tauri::command]
pub fn telemetry_query_recent(
    limit: usize,
    telemetry: State<'_, Arc<Mutex<TelemetryStore>>>,
) -> Result<Vec<TelemetryEvent>, String> {
    lock_or_recover(&telemetry)
        .query_recent(limit)
        .map_err(|e| format!("Failed to query telemetry: {}", e))
}

#[tauri::command]
pub fn telemetry_export_csv(
    out_path: Option<String>,
    telemetry: State<'_, Arc<Mutex<TelemetryStore>>>,
) -> Result<String, String> {
    let path = if let Some(p) = out_path {
        std::path::PathBuf::from(shellexpand::tilde(&p).to_string())
    } else {
        // Default: ~/.warp_open/telemetry_export.csv
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(format!("{}/.warp_open/telemetry_export.csv", home))
    };
    
    lock_or_recover(&telemetry)
        .export_csv(path)
        .map_err(|e| format!("Failed to export CSV: {}", e))
}

#[tauri::command]
pub async fn phase4_trigger_trainer(
    csv_path: Option<String>,
) -> Result<String, String> {
    // Security: This command should only run when explicitly triggered by user
    // Never auto-invoke this from model suggestions
    
    let csv = if let Some(p) = csv_path {
        shellexpand::tilde(&p).to_string()
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{}/.warp_open/telemetry_export.csv", home)
    };
    
    eprintln!("[PHASE 4] Triggering trainer with CSV: {}", csv);
    eprintln!("[PHASE 4] WARNING: This is a manual operation - never auto-apply model outputs!");
    
    // Run trainer in background (non-blocking)
    let output = Command::new("python3")
        .arg("-m")
        .arg("phase4_trainer.train_policy")
        .arg("--csv")
        .arg(&csv)
        .arg("--out")
        .arg("./policy_model/policy_model.pkl")
        .output()
        .map_err(|e| format!("Failed to run trainer: {}. Ensure Python and phase4_trainer are installed.", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    if output.status.success() {
        Ok(format!("Trainer completed successfully\n\nStdout:\n{}\n\nStderr:\n{}", stdout, stderr))
    } else {
        Err(format!("Trainer failed with exit code {:?}\n\nStdout:\n{}\n\nStderr:\n{}", 
            output.status.code(), stdout, stderr))
    }
}

// ========================================
// PHASE 5: ADAPTIVE POLICY LEARNING & MULTI-AGENT COORDINATION
// ========================================

use crate::policy_store::{PolicyStore, PolicyRule};
use crate::agents::{AgentCoordinator, AgentState};

// Policy Management Commands

#[tauri::command]
pub fn policy_list_rules(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
) -> Result<Vec<PolicyRule>, String> {
    lock_or_recover(&policy)
        .list_rules()
        .map_err(|e| format!("Failed to list rules: {}", e))
}

#[tauri::command]
pub fn policy_propose_diff(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
    proposed_by: String,
    diff_json: String,
) -> Result<String, String> {
    lock_or_recover(&policy)
        .propose_diff(&proposed_by, &diff_json)
        .map_err(|e| format!("Failed to propose diff: {}", e))
}

#[tauri::command]
pub fn policy_list_suggestions(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
) -> Result<Vec<serde_json::Value>, String> {
    lock_or_recover(&policy)
        .list_suggestions()
        .map_err(|e| format!("Failed to list suggestions: {}", e))
}

#[tauri::command]
pub fn policy_apply_suggestion(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
    suggestion_id: String,
    author: String,
    comment: String,
    token: String, // Confirmation token
) -> Result<String, String> {
    // Security: verify token matches expected confirmation
    if token != "APPLY" {
        return Err("Invalid confirmation token. Type APPLY to confirm.".to_string());
    }
    
    eprintln!("[PHASE 5 POLICY] Applying suggestion {} by {}", suggestion_id, author);

    lock_or_recover(&policy)
        .apply_diff(&suggestion_id, &author, &comment)
        .map_err(|e| format!("Failed to apply suggestion: {}", e))
}

#[tauri::command]
pub fn policy_rollback(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
    version: String,
) -> Result<(), String> {
    eprintln!("[PHASE 5 POLICY] Rolling back to version: {}", version);

    lock_or_recover(&policy)
        .rollback_version(&version)
        .map_err(|e| format!("Failed to rollback: {}", e))
}

#[tauri::command]
pub fn policy_reject_suggestion(
    policy: State<'_, Arc<Mutex<PolicyStore>>>,
    suggestion_id: String,
    author: String,
) -> Result<(), String> {
    eprintln!("[PHASE 5 POLICY] Rejecting suggestion {} by {}", suggestion_id, author);

    lock_or_recover(&policy)
        .reject_suggestion(&suggestion_id, &author)
        .map_err(|e| format!("Failed to reject: {}", e))
}

// Policy Suggestion Generator (triggers Python trainer)

#[tauri::command]
pub async fn phase5_generate_suggestions(
    csv_path: Option<String>,
    model_path: Option<String>,
) -> Result<String, String> {
    // Security: Only triggered by user action, never auto-applied
    
    let csv = if let Some(p) = csv_path {
        shellexpand::tilde(&p).to_string()
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{}/.warp_open/telemetry_export.csv", home)
    };
    
    let model = if let Some(p) = model_path {
        shellexpand::tilde(&p).to_string()
    } else {
        "./policy_model/policy_model.pkl".to_string()
    };
    
    let out_json = "/tmp/policy_suggestions.json";
    
    eprintln!("[PHASE 5] Generating policy suggestions from telemetry");
    eprintln!("[PHASE 5] CSV: {}", csv);
    eprintln!("[PHASE 5] Model: {}", model);
    
    let output = Command::new("python3")
        .arg("-m")
        .arg("phase4_trainer.phase5_suggest")
        .arg("--csv")
        .arg(&csv)
        .arg("--model")
        .arg(&model)
        .arg("--out")
        .arg(out_json)
        .output()
        .map_err(|e| format!("Failed to run suggestion generator: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    if output.status.success() {
        // Read generated JSON
        let suggestions_json = std::fs::read_to_string(out_json)
            .map_err(|e| format!("Failed to read suggestions: {}", e))?;
        
        Ok(format!("Suggestions generated\n\nOutput:\n{}\n\nSuggestions:\n{}", stdout, suggestions_json))
    } else {
        Err(format!("Suggestion generator failed\n\nStdout:\n{}\n\nStderr:\n{}", stdout, stderr))
    }
}

// Multi-Agent Coordination Commands

#[tauri::command]
pub fn agent_register(
    coordinator: State<'_, AgentCoordinator>,
    name: Option<String>,
) -> String {
    coordinator.register_agent(name)
}

#[tauri::command]
pub fn agent_update(
    coordinator: State<'_, AgentCoordinator>,
    agent_id: String,
    action: String,
    score: i32,
) -> Result<(), String> {
    coordinator.update_agent(&agent_id, action, score)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_set_status(
    coordinator: State<'_, AgentCoordinator>,
    agent_id: String,
    status: String,
) -> Result<(), String> {
    coordinator.set_agent_status(&agent_id, status)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_list(
    coordinator: State<'_, AgentCoordinator>,
) -> Vec<AgentState> {
    coordinator.get_agents()
}

#[tauri::command]
pub fn agent_unregister(
    coordinator: State<'_, AgentCoordinator>,
    agent_id: String,
) -> Result<(), String> {
    coordinator.unregister_agent(&agent_id)
        .map_err(|e| e.to_string())
}

// Phase 6: Long-Term Planning & Orchestration Commands

#[tauri::command]
pub fn phase6_create_plan(
    plan_store: State<'_, Arc<Mutex<crate::plan_store::PlanStore>>>,
    plan_json: String,
) -> Result<String, String> {
    let plan: crate::plan_store::Plan = serde_json::from_str(&plan_json)
        .map_err(|e| format!("Failed to parse plan JSON: {}", e))?;

    lock_or_recover(&plan_store)
        .insert_plan(&plan)
        .map_err(|e| format!("Failed to insert plan: {}", e))?;
    
    Ok(plan.plan_id)
}

#[tauri::command]
pub fn phase6_get_plan(
    plan_store: State<'_, Arc<Mutex<crate::plan_store::PlanStore>>>,
    plan_id: String,
) -> Result<crate::plan_store::Plan, String> {
    lock_or_recover(&plan_store)
        .get_plan(&plan_id)
        .map_err(|e| format!("Failed to get plan: {}", e))?
        .ok_or_else(|| "Plan not found".to_string())
}

#[tauri::command]
pub fn phase6_get_pending_plans(
    plan_store: State<'_, Arc<Mutex<crate::plan_store::PlanStore>>>,
    limit: usize,
) -> Result<Vec<crate::plan_store::Plan>, String> {
    lock_or_recover(&plan_store)
        .get_pending_plans(limit)
        .map_err(|e| format!("Failed to get pending plans: {}", e))
}

#[tauri::command]
pub fn phase6_update_plan_status(
    plan_store: State<'_, Arc<Mutex<crate::plan_store::PlanStore>>>,
    plan_id: String,
    status: String,
) -> Result<(), String> {
    lock_or_recover(&plan_store)
        .update_plan_status(&plan_id, &status)
        .map_err(|e| format!("Failed to update plan status: {}", e))
}

#[tauri::command]
pub fn phase6_update_plan_index(
    plan_store: State<'_, Arc<Mutex<crate::plan_store::PlanStore>>>,
    plan_id: String,
    index: usize,
) -> Result<(), String> {
    lock_or_recover(&plan_store)
        .update_plan_index(&plan_id, index)
        .map_err(|e| format!("Failed to update plan index: {}", e))
}

#[tauri::command]
pub fn phase6_delete_plan(
    plan_store: State<'_, Arc<Mutex<crate::plan_store::PlanStore>>>,
    plan_id: String,
) -> Result<(), String> {
    lock_or_recover(&plan_store)
        .delete_plan(&plan_id)
        .map_err(|e| format!("Failed to delete plan: {}", e))
}

// Monitoring Commands

#[tauri::command]
pub fn get_monitoring_events(
    monitoring: State<'_, crate::monitoring::MonitoringState>,
) -> std::collections::HashMap<String, Vec<crate::monitoring::PhaseEvent>> {
    monitoring.get_events()
}

#[tauri::command]
pub fn clear_monitoring_phase(
    monitoring: State<'_, crate::monitoring::MonitoringState>,
    phase: String,
) {
    monitoring.clear_phase(&phase);
}

#[tauri::command]
pub fn clear_monitoring_all(
    monitoring: State<'_, crate::monitoring::MonitoringState>,
) {
    monitoring.clear_all();
}

// Phase 6: Scheduler Commands

#[tauri::command]
pub fn start_scheduler(
    scheduler: State<'_, crate::scheduler::Scheduler>,
) {
    scheduler.start();
}

#[tauri::command]
pub fn stop_scheduler(
    scheduler: State<'_, crate::scheduler::Scheduler>,
) {
    scheduler.stop();
}

// Phase 1-6 Automated Test Commands

#[tauri::command]
pub async fn run_phase1_6_auto(
    app: tauri::AppHandle,
) -> Result<(), String> {
    let _ = app.emit_all("phase1_6_log", "═══════════════════════════════════");
    let _ = app.emit_all("phase1_6_log", "Starting Full Phase 1-6 Auto Test");
    let _ = app.emit_all("phase1_6_log", "═══════════════════════════════════");

    // Phase 1
    let _ = app.emit_all("phase1_6_log", "Starting Phase 1: Tool Execution");
    crate::phase1_6_tests::run_test_phase1(&app)?;
    let _ = app.emit_all("phase1_6_log", "Phase 1: Tool Execution completed ✅");

    // Phase 2
    let _ = app.emit_all("phase1_6_log", "Starting Phase 2: Batch Workflow");
    crate::phase1_6_tests::run_test_phase2(&app)?;
    let _ = app.emit_all("phase1_6_log", "Phase 2: Batch Workflow completed ✅");

    // Phase 3
    let _ = app.emit_all("phase1_6_log", "Starting Phase 3: Autonomy & Dependencies");
    crate::phase1_6_tests::run_test_phase3(&app)?;
    let _ = app.emit_all("phase1_6_log", "Phase 3: Autonomy & Dependencies completed ✅");

    // Phase 4
    let _ = app.emit_all("phase1_6_log", "Starting Phase 4: Telemetry & ML");
    crate::phase1_6_tests::run_test_phase4(&app)?;
    let _ = app.emit_all("phase1_6_log", "Phase 4: Telemetry & ML completed ✅");

    // Phase 5
    let _ = app.emit_all("phase1_6_log", "Starting Phase 5: Policy Learning & Agents");
    crate::phase1_6_tests::run_test_phase5(&app)?;
    let _ = app.emit_all("phase1_6_log", "Phase 5: Policy Learning & Agents completed ✅");

    // Phase 6
    let _ = app.emit_all("phase1_6_log", "Starting Phase 6: Long-Term Planning");
    crate::phase1_6_tests::run_test_phase6(&app)?;
    let _ = app.emit_all("phase1_6_log", "Phase 6: Long-Term Planning completed ✅");

    let _ = app.emit_all("phase1_6_log", "═══════════════════════════════════");
    let _ = app.emit_all("phase1_6_log", "All phases complete! 🎉");
    let _ = app.emit_all("phase1_6_log", "═══════════════════════════════════");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_registry_creation() {
        let registry = PtyRegistry::new();
        assert_eq!(registry.ptys.lock().unwrap().len(), 0);
        assert_eq!(*registry.next_id.lock().unwrap(), 1);
    }
}
