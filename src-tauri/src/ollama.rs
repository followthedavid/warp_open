use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use reqwest;

#[derive(Debug, Serialize, Deserialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaResponse {
    response: String,
    done: bool,
}

#[tauri::command]
pub async fn query_ollama_stream(
    app_handle: AppHandle,
    prompt: String,
    model: Option<String>,
    session_id: String,
) -> Result<(), String> {
    let model_name = model.unwrap_or_else(|| "deepseek-coder:6.7b".to_string());

    let client = reqwest::Client::new();
    let url = "http://localhost:11434/api/generate";

    let request_body = OllamaRequest {
        model: model_name,
        prompt,
        stream: true,
    };

    let mut response = client
        .post(url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Ollama request failed: {}", e))?;

    let event_name = format!("ollama://stream/{}", session_id);

    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        let text = String::from_utf8_lossy(&chunk);
        for line in text.lines() {
            if let Ok(ollama_resp) = serde_json::from_str::<OllamaResponse>(line) {
                let _ = app_handle.emit_all(&event_name, ollama_resp.response.clone());
                if ollama_resp.done {
                    let _ = app_handle.emit_all(&format!("{}/done", event_name), true);
                    break;
                }
            }
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn query_ollama(
    prompt: String,
    model: Option<String>,
) -> Result<String, String> {
    let model_name = model.unwrap_or_else(|| "deepseek-coder:6.7b".to_string());
    let client = reqwest::Client::new();
    let url = "http://localhost:11434/api/generate";

    let request_body = serde_json::json!({
        "model": model_name,
        "prompt": prompt,
        "stream": false,
    });

    let response = client
        .post(url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Ollama request failed: {}", e))?
        .json::<OllamaResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    Ok(response.response)
}

#[tauri::command]
pub async fn list_ollama_models() -> Result<Vec<String>, String> {
    let client = reqwest::Client::new();
    let url = "http://localhost:11434/api/tags";

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to get models: {}", e))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Failed to parse models: {}", e))?;

    let models = response["models"]
        .as_array()
        .ok_or("No models found")?
        .iter()
        .filter_map(|m| m["name"].as_str().map(String::from))
        .collect();

    Ok(models)
}
