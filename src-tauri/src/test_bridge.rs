use tauri::{AppHandle, Manager};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use crate::conversation::ConversationState;

pub struct TestBridge {
    enabled: bool,
    port: u16,
}

impl TestBridge {
    pub fn new() -> Self {
        let enabled = std::env::var("WARP_OPEN_TEST_MODE").unwrap_or_default() == "1";
        let port = std::env::var("WARP_OPEN_WS_PORT")
            .unwrap_or_else(|_| "9223".to_string())
            .parse()
            .unwrap_or(9223);
        
        Self { enabled, port }
    }
    
    pub async fn start(&self, app_handle: AppHandle) {
        if !self.enabled {
            return;
        }
        
        println!("[TestBridge] Starting WebSocket server on port {}", self.port);
        
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind test WebSocket");
        
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let app = app_handle.clone();
                
                tokio::spawn(async move {
                    let ws_stream = accept_async(stream).await.expect("Failed to accept WebSocket");
                    let (mut write, mut read) = ws_stream.split();
                    
                    println!("[TestBridge] Client connected");
                    
                    // Send ready message
                    let _ = write.send(Message::Text(json!({
                        "type": "ready"
                    }).to_string())).await;
                    
                    while let Some(msg) = read.next().await {
                        match msg {
                            Ok(Message::Text(text)) => {
                                if let Ok(json_msg) = serde_json::from_str::<serde_json::Value>(&text) {
                                    if json_msg["type"] == "send_message" {
                                        let content = json_msg["content"].as_str().unwrap_or("").to_string();
                                        
                                        // Get conversation state from app
                                        let state_result = app.try_state::<ConversationState>();
                                        
                                        if let Some(state) = state_result {
                                            // Get active tab ID
                                            if let Some(tab_id) = state.get_active_tab_id() {
                                                println!("[TestBridge] Sending message to tab {}: {}", tab_id, content);
                                                
                                                // Add user message
                                                state.add_message(tab_id, "user".to_string(), content.clone());
                                                
                                                // Notify frontend
                                                app.emit_all("conversation_updated", json!({
                                                    "tabId": tab_id
                                                })).ok();
                                                
                                                // Start AI response
                                                state.set_thinking(tab_id, true);
                                                app.emit_all("conversation_updated", json!({
                                                    "tabId": tab_id
                                                })).ok();
                                                
                                                // Get messages for AI
                                                let messages = state.get_messages_for_ai(tab_id);
                                                
                                                // Call AI in background
                                                let app_for_ai = app.clone();
                                                tokio::spawn(async move {
                                                    use crate::commands::ai_query_stream_internal;
                                                    // Get state from app in the spawned task
                                                    if let Some(state) = app_for_ai.try_state::<ConversationState>() {
                                                        let app_clone = app_for_ai.clone();
                                                        let _ = ai_query_stream_internal(tab_id, messages, state, app_clone, true).await;
                                                    }
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(Message::Close(_)) => break,
                            _ => {}
                        }
                    }
                    
                    println!("[TestBridge] Client disconnected");
                });
            }
        });
    }
}

pub fn broadcast_message(app: &AppHandle, message: serde_json::Value) {
    if std::env::var("WARP_OPEN_TEST_MODE").unwrap_or_default() == "1" {
        app.emit_all("test_message_update", message).ok();
    }
}
