// Ollama Agent Integration
//
// Integrates the scaffolding system with Ollama to provide
// Claude-like agentic capabilities with local models.

use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use futures_util::StreamExt;

use crate::scaffolding::{
    AgentLoop, AgentState, LoopConfig,
    ContextManager, ContextConfig,
    ToolCache, CacheConfig, CachedResult,
    ModelRouter,
    ToolCall,
    self_correction::{SelfCorrectionEngine, SelfCorrectionConfig},
};
use crate::scaffolding::router::ModelConfig;

/// Configuration for streaming and timeout behavior
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    /// Timeout for initial response (seconds)
    pub initial_timeout_secs: u64,
    /// Timeout between chunks (seconds)
    pub chunk_timeout_secs: u64,
    /// Maximum total time for a single LLM call (seconds)
    pub max_total_time_secs: u64,
    /// Send progress update every N characters
    pub progress_interval_chars: usize,
    /// Maximum retries on timeout
    pub max_timeout_retries: u32,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            initial_timeout_secs: 60,      // 1 minute to start
            chunk_timeout_secs: 30,        // 30 seconds between chunks
            max_total_time_secs: 300,      // 5 minutes max per call
            progress_interval_chars: 50,    // Update every 50 chars
            max_timeout_retries: 2,
        }
    }
}

impl StreamingConfig {
    /// Configuration for very slow/low-power models
    pub fn patient() -> Self {
        Self {
            initial_timeout_secs: 120,     // 2 minutes to start
            chunk_timeout_secs: 60,        // 1 minute between chunks
            max_total_time_secs: 600,      // 10 minutes max
            progress_interval_chars: 20,   // Frequent updates
            max_timeout_retries: 3,
        }
    }
}

/// Configuration for the Ollama agent
#[derive(Debug, Clone)]
pub struct OllamaAgentConfig {
    pub ollama_url: String,
    pub default_model: String,
    pub loop_config: LoopConfig,
    pub context_config: ContextConfig,
    pub cache_config: CacheConfig,
    pub streaming_config: StreamingConfig,
}

impl Default for OllamaAgentConfig {
    fn default() -> Self {
        Self {
            ollama_url: "http://localhost:11434".to_string(),
            default_model: "qwen2.5:7b".to_string(),
            loop_config: LoopConfig::default(),
            context_config: ContextConfig::default(),
            cache_config: CacheConfig::default(),
            streaming_config: StreamingConfig::default(),
        }
    }
}

impl OllamaAgentConfig {
    /// Configuration optimized for low-power/slow models
    pub fn for_slow_models() -> Self {
        Self {
            ollama_url: "http://localhost:11434".to_string(),
            default_model: "qwen2.5:3b".to_string(),
            loop_config: LoopConfig::thorough(),  // More iterations allowed
            context_config: ContextConfig::default(),
            cache_config: CacheConfig::default(),
            streaming_config: StreamingConfig::patient(),
        }
    }
}

/// Events emitted by the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEvent {
    /// Agent started processing
    Started { task: String },
    /// Agent is thinking
    Thinking { content: String },
    /// Agent wants to execute a tool
    ToolRequest { tool: String, args: serde_json::Value },
    /// Tool execution result
    ToolResult { tool: String, success: bool, output: String },
    /// Verification result
    Verification { passed: bool, message: String },
    /// Agent completed
    Completed { answer: String, steps: u32 },
    /// Agent failed
    Failed { error: String },
    /// Progress update
    Progress { step: u32, total: u32, description: String },
    /// Streaming chunk received (prevents UI freeze)
    StreamingChunk { chars_received: usize, content_preview: String },
    /// LLM is generating (heartbeat to show it's not frozen)
    Heartbeat { elapsed_secs: u64, status: String },
    /// Retry happening due to timeout or error
    Retrying { attempt: u32, max_attempts: u32, reason: String },
}

/// The integrated Ollama agent
pub struct OllamaAgent {
    config: OllamaAgentConfig,
    agent_loop: AgentLoop,
    context: ContextManager,
    cache: ToolCache,
    router: ModelRouter,
    available_models: Vec<String>,
    self_correction: SelfCorrectionEngine,
}

impl OllamaAgent {
    pub fn new(config: OllamaAgentConfig) -> Self {
        let agent_loop = AgentLoop::new(config.loop_config.clone());
        let context = ContextManager::new(config.context_config.clone());
        let cache = ToolCache::new(config.cache_config.clone());
        let router = ModelRouter::new();
        let self_correction = SelfCorrectionEngine::new(SelfCorrectionConfig::default());

        Self {
            config,
            agent_loop,
            context,
            cache,
            router,
            available_models: Vec::new(),
            self_correction,
        }
    }

    /// Create agent optimized for slow/low-power models
    pub fn for_slow_models() -> Self {
        let config = OllamaAgentConfig::for_slow_models();
        let agent_loop = AgentLoop::new(config.loop_config.clone());
        let context = ContextManager::new(config.context_config.clone());
        let cache = ToolCache::new(config.cache_config.clone());
        let router = ModelRouter::new();
        // Use strict self-correction for unreliable models
        let self_correction = SelfCorrectionEngine::new(SelfCorrectionConfig::strict());

        Self {
            config,
            agent_loop,
            context,
            cache,
            router,
            available_models: Vec::new(),
            self_correction,
        }
    }

    /// Refresh available models from Ollama
    pub async fn refresh_models(&mut self) -> Result<(), String> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/tags", self.config.ollama_url);

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to get models: {}", e))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| format!("Failed to parse models: {}", e))?;

        self.available_models = response["models"]
            .as_array()
            .ok_or("No models found")?
            .iter()
            .filter_map(|m| m["name"].as_str().map(String::from))
            .collect();

        self.router.set_available_models(self.available_models.clone());
        self.agent_loop.set_available_models(self.available_models.clone());

        Ok(())
    }

    /// Start processing a task
    pub async fn process_task(
        &mut self,
        task: String,
        event_tx: mpsc::Sender<AgentEvent>,
    ) -> Result<String, String> {
        // Emit started event
        let _ = event_tx.send(AgentEvent::Started { task: task.clone() }).await;

        // Setup context with system prompt
        self.context.clear();
        self.context.add_system_prompt(self.get_system_prompt());
        self.context.add_user_message(task.clone());

        // Start the agent loop
        let start_result = self.agent_loop.start(&task);

        // If decomposition needed, do that first
        if start_result.needs_decomposition {
            let _ = event_tx.send(AgentEvent::Progress {
                step: 0,
                total: 0,
                description: "Decomposing complex task...".to_string(),
            }).await;

            let decomp_response = self.query_ollama_with_events(
                &start_result.prompt,
                &start_result.model_config,
                Some(&event_tx),
            ).await?;

            let _ = self.agent_loop.process_decomposition(&decomp_response, &task);
        }

        // Track step count for progress
        let mut step_count = 0u32;
        let estimated_steps = if start_result.needs_decomposition { 5 } else { 3 };

        // Main agent loop
        loop {
            let state = self.agent_loop.state();

            match state {
                AgentState::Completed => {
                    let result = self.agent_loop.get_result();
                    let answer = result.final_answer.unwrap_or_else(|| "Task completed".to_string());
                    let _ = event_tx.send(AgentEvent::Completed {
                        answer: answer.clone(),
                        steps: result.iterations,
                    }).await;
                    return Ok(answer);
                }
                AgentState::Failed => {
                    let result = self.agent_loop.get_result();
                    let error = result.error.unwrap_or_else(|| "Unknown error".to_string());
                    let _ = event_tx.send(AgentEvent::Failed { error: error.clone() }).await;
                    return Err(error);
                }
                AgentState::Thinking | AgentState::Planning => {
                    step_count += 1;
                    let _ = event_tx.send(AgentEvent::Progress {
                        step: step_count,
                        total: estimated_steps.max(step_count + 1),
                        description: format!("Thinking... (step {})", step_count),
                    }).await;

                    // Build context and query LLM with streaming
                    let context = self.context.build_context();
                    let model_config = self.router.route(&task);

                    let response = self.query_ollama_with_events(&context, &model_config, Some(&event_tx)).await?;

                    // Add response to context
                    self.context.add_assistant_message(response.clone());

                    // Emit thinking event (extract from response)
                    if let Some(thinking) = self.extract_thinking(&response) {
                        let _ = event_tx.send(AgentEvent::Thinking { content: thinking }).await;
                    }

                    // Process the response
                    let process_result = self.agent_loop.process_response(&response);

                    match process_result {
                        crate::scaffolding::agent_loop::ProcessResult::ExecuteTool { action } => {
                            let _ = event_tx.send(AgentEvent::ToolRequest {
                                tool: action.tool.clone(),
                                args: action.args.clone(),
                            }).await;

                            // Execute the tool
                            let (success, output) = self.execute_tool(&action).await;

                            let _ = event_tx.send(AgentEvent::ToolResult {
                                tool: action.tool.clone(),
                                success,
                                output: output.clone(),
                            }).await;

                            // Add result to context
                            self.context.add_tool_result(&action.tool, output.clone());

                            // Process tool result
                            let tool_action = self.agent_loop.process_tool_result(
                                &action.tool,
                                &action.args,
                                &output,
                                !success,
                            );

                            // Handle verification if needed
                            if let crate::scaffolding::agent_loop::ToolResultAction::Verify { prompt, model_config } = tool_action {
                                let verify_response = self.query_ollama(&prompt, &model_config).await?;
                                self.agent_loop.process_verification(&verify_response, &output);
                            }
                        }
                        crate::scaffolding::agent_loop::ProcessResult::Completed { answer } => {
                            let _ = event_tx.send(AgentEvent::Completed {
                                answer: answer.clone(),
                                steps: self.agent_loop.history().len() as u32,
                            }).await;
                            return Ok(answer);
                        }
                        crate::scaffolding::agent_loop::ProcessResult::NeedsRetry { feedback } => {
                            // Progressive retry with increasingly strict prompts
                            let retry_prompt = self.build_retry_prompt(&feedback, self.agent_loop.history().len());
                            self.context.add_user_message(retry_prompt);
                        }
                        crate::scaffolding::agent_loop::ProcessResult::Failed { error } => {
                            let _ = event_tx.send(AgentEvent::Failed { error: error.clone() }).await;
                            return Err(error);
                        }
                    }
                }
                _ => {
                    // For other states, continue the loop
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Query Ollama with streaming to prevent freezes
    async fn query_ollama(&self, prompt: &str, config: &ModelConfig) -> Result<String, String> {
        self.query_ollama_with_events(prompt, config, None).await
    }

    /// Query Ollama with streaming and event updates
    async fn query_ollama_with_events(
        &self,
        prompt: &str,
        config: &ModelConfig,
        event_tx: Option<&mpsc::Sender<AgentEvent>>,
    ) -> Result<String, String> {
        let streaming_config = &self.config.streaming_config;
        let mut attempts = 0;
        let max_attempts = streaming_config.max_timeout_retries + 1;

        while attempts < max_attempts {
            attempts += 1;

            match self.query_ollama_streaming_inner(prompt, config, event_tx, streaming_config).await {
                Ok(response) => return Ok(response),
                Err(e) if e.contains("timeout") && attempts < max_attempts => {
                    // Retry on timeout
                    if let Some(tx) = event_tx {
                        let _ = tx.send(AgentEvent::Retrying {
                            attempt: attempts,
                            max_attempts,
                            reason: format!("Timeout: {}", e),
                        }).await;
                    }
                    // Wait a bit before retry
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err("Max retries exceeded".to_string())
    }

    /// Inner streaming query with timeout handling
    async fn query_ollama_streaming_inner(
        &self,
        prompt: &str,
        config: &ModelConfig,
        event_tx: Option<&mpsc::Sender<AgentEvent>>,
        streaming_config: &StreamingConfig,
    ) -> Result<String, String> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| format!("Failed to create client: {}", e))?;

        let url = format!("{}/api/generate", self.config.ollama_url);
        let model_name = config.model_type.model_name();

        // Build system prompt for consistent formatting
        let system_prompt = self.get_consistency_system_prompt();

        // Wrap prompt with format enforcement
        let enforced_prompt = format!(
            "{}\n\n---\n\nUSER REQUEST:\n{}\n\n---\n\nRespond using EXACTLY the format shown. Start with <thinking> immediately.",
            system_prompt,
            prompt
        );

        let request_body = serde_json::json!({
            "model": model_name,
            "prompt": enforced_prompt,
            "stream": true,  // Enable streaming!
            "options": {
                "temperature": 0.2,
                "num_predict": config.max_tokens.min(1500),
                "top_p": 0.9,
                "repeat_penalty": 1.1,
                "stop": ["</action>", "</answer>", "USER REQUEST:", "---"]
            }
        });

        // Send request and get streaming response
        let response = tokio::time::timeout(
            tokio::time::Duration::from_secs(streaming_config.initial_timeout_secs),
            client.post(&url).json(&request_body).send()
        )
        .await
        .map_err(|_| "timeout: Initial connection timed out".to_string())?
        .map_err(|e| format!("Ollama request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Ollama returned status: {}", response.status()));
        }

        // Process streaming response
        let mut stream = response.bytes_stream();
        let mut full_response = String::new();
        let mut last_chunk_time = std::time::Instant::now();
        let start_time = std::time::Instant::now();
        let mut last_progress_len = 0;

        // Heartbeat task - sends periodic updates
        let heartbeat_tx = event_tx.cloned();
        let heartbeat_handle = if heartbeat_tx.is_some() {
            let tx = heartbeat_tx.unwrap();
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
                let start = std::time::Instant::now();
                loop {
                    interval.tick().await;
                    let elapsed = start.elapsed().as_secs();
                    let _ = tx.send(AgentEvent::Heartbeat {
                        elapsed_secs: elapsed,
                        status: format!("Generating... ({}s)", elapsed),
                    }).await;
                }
            }))
        } else {
            None
        };

        loop {
            // Check total time limit
            if start_time.elapsed().as_secs() > streaming_config.max_total_time_secs {
                if let Some(handle) = heartbeat_handle {
                    handle.abort();
                }
                return Err("timeout: Max total time exceeded".to_string());
            }

            // Wait for next chunk with timeout
            let chunk_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(streaming_config.chunk_timeout_secs),
                stream.next()
            ).await;

            match chunk_result {
                Ok(Some(Ok(bytes))) => {
                    last_chunk_time = std::time::Instant::now();

                    // Parse the streaming JSON response
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        for line in text.lines() {
                            if line.is_empty() {
                                continue;
                            }
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                                if let Some(response_text) = json["response"].as_str() {
                                    full_response.push_str(response_text);

                                    // Send progress update periodically
                                    if let Some(tx) = event_tx {
                                        if full_response.len() - last_progress_len >= streaming_config.progress_interval_chars {
                                            let preview = if full_response.len() > 100 {
                                                format!("...{}", &full_response[full_response.len()-100..])
                                            } else {
                                                full_response.clone()
                                            };
                                            let _ = tx.send(AgentEvent::StreamingChunk {
                                                chars_received: full_response.len(),
                                                content_preview: preview,
                                            }).await;
                                            last_progress_len = full_response.len();
                                        }
                                    }
                                }

                                // Check if done
                                if json["done"].as_bool() == Some(true) {
                                    if let Some(handle) = heartbeat_handle {
                                        handle.abort();
                                    }
                                    // Post-process to ensure valid format
                                    return self.post_process_response(&full_response);
                                }
                            }
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    if let Some(handle) = heartbeat_handle {
                        handle.abort();
                    }
                    return Err(format!("Stream error: {}", e));
                }
                Ok(None) => {
                    // Stream ended
                    if let Some(handle) = heartbeat_handle {
                        handle.abort();
                    }
                    if full_response.is_empty() {
                        return Err("Empty response from Ollama".to_string());
                    }
                    return self.post_process_response(&full_response);
                }
                Err(_) => {
                    // Timeout waiting for chunk
                    if let Some(handle) = heartbeat_handle {
                        handle.abort();
                    }
                    if full_response.is_empty() {
                        return Err("timeout: No response received".to_string());
                    }
                    // We have partial response, try to use it
                    eprintln!("[WARN] Chunk timeout, using partial response ({} chars)", full_response.len());
                    return self.post_process_response(&full_response);
                }
            }
        }
    }

    /// System prompt optimized for consistent output formatting
    fn get_consistency_system_prompt(&self) -> &'static str {
        r#"You are a tool-calling AI. You MUST follow this EXACT format:

<thinking>
1. [What the user wants]
2. [What tool to use]
3. [The arguments needed]
</thinking>

<action>
{"tool": "TOOL_NAME", "args": {"key": "value"}}
</action>

TOOLS:
- read_file: {"path": "file.txt"}
- write_file: {"path": "file.txt", "content": "..."}
- edit_file: {"path": "file.txt", "old_string": "...", "new_string": "..."}
- glob_files: {"pattern": "*.rs"}
- grep_files: {"pattern": "search_term"}
- execute_shell: {"command": "ls -la"}
- done: {"summary": "What was accomplished"}

CRITICAL RULES:
1. Start with <thinking> IMMEDIATELY - no preamble
2. Exactly ONE <action> per response
3. JSON must be valid - use double quotes for strings
4. If task is complete, use: <answer>Summary here</answer>

EXAMPLE:
<thinking>
1. User wants to see main.rs contents
2. I will use read_file tool
3. Path argument is "main.rs"
</thinking>

<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>"#
    }

    /// Build progressively stricter retry prompts
    fn build_retry_prompt(&self, feedback: &str, retry_count: usize) -> String {
        match retry_count {
            0 => format!(
                "CORRECTION NEEDED: {}\n\nPlease try again using the exact format:\n<thinking>\n1. ...\n2. ...\n3. ...\n</thinking>\n\n<action>\n{{\"tool\": \"...\", \"args\": {{...}}}}\n</action>",
                feedback
            ),
            1 => format!(
                "⚠️ FORMAT ERROR: {}\n\nYou MUST respond with ONLY:\n\n<thinking>\n1. What I need to do\n2. Which tool to use\n3. What arguments\n</thinking>\n\n<action>\n{{\"tool\": \"read_file\", \"args\": {{\"path\": \"example.txt\"}}}}\n</action>\n\nCopy this format exactly. Replace the example with your actual tool call.",
                feedback
            ),
            _ => format!(
                "❌ FINAL ATTEMPT - STRICT FORMAT REQUIRED\n\n{}\n\nRespond with ONLY this structure (no other text):\n\n<thinking>\n1. [one sentence]\n2. [one sentence]\n3. [one sentence]\n</thinking>\n\n<action>\n{{\"tool\": \"TOOL_NAME\", \"args\": {{\"key\": \"value\"}}}}\n</action>\n\nValid tools: read_file, write_file, edit_file, glob_files, grep_files, execute_shell, done",
                feedback
            ),
        }
    }

    /// Post-process response to ensure valid format with self-correction
    fn post_process_response(&self, raw: &str) -> Result<String, String> {
        let trimmed = raw.trim();

        // First pass: basic structural fixes
        let mut response = trimmed.to_string();

        // If already has proper format, validate it
        if response.contains("<thinking>") && (response.contains("<action>") || response.contains("<answer>")) {
            // Validate with self-correction engine
            let validation = self.self_correction.validate(&response);
            if validation.is_valid {
                return Ok(response);
            }

            // Try auto-correction
            if let Some(corrected) = self.self_correction.try_auto_correct(&response) {
                let revalidation = self.self_correction.validate(&corrected);
                if revalidation.is_valid || !revalidation.has_errors() {
                    return Ok(corrected);
                }
            }

            // If still invalid but we have the structure, return with warning
            if !validation.has_errors() {
                return Ok(response);
            }
        }

        // Try to extract JSON and wrap it
        if let Some(json_start) = response.find('{') {
            if let Some(json_end) = response.rfind('}') {
                let json_str = &response[json_start..=json_end];
                // Validate JSON
                if serde_json::from_str::<serde_json::Value>(json_str).is_ok() {
                    // Wrap with minimal thinking
                    let wrapped = format!(
                        "<thinking>\n1. Processing request\n2. Executing tool\n3. Returning result\n</thinking>\n\n<action>\n{}\n</action>",
                        json_str
                    );
                    return Ok(wrapped);
                }
            }
        }

        // Check if it looks like a final answer
        if !response.contains("tool") && !response.contains('{') && !response.is_empty() {
            let wrapped = format!(
                "<thinking>\n1. Task analysis complete\n2. No further tools needed\n3. Providing answer\n</thinking>\n\n<answer>\n{}\n</answer>",
                response
            );
            return Ok(wrapped);
        }

        // Last resort: try auto-correction on raw response
        if let Some(corrected) = self.self_correction.try_auto_correct(&response) {
            return Ok(corrected);
        }

        // Return as-is and let the validator handle it
        Ok(response)
    }

    /// Run multi-pass correction on a problematic response
    async fn multi_pass_correction(
        &self,
        original_response: &str,
        config: &ModelConfig,
        event_tx: Option<&mpsc::Sender<AgentEvent>>,
        max_passes: u32,
    ) -> Result<String, String> {
        let mut current_response = original_response.to_string();
        let mut pass = 0;

        while pass < max_passes {
            pass += 1;

            // Validate current response
            let validation = self.self_correction.validate(&current_response);

            if validation.is_valid {
                return Ok(current_response);
            }

            // If no errors (just warnings), accept it
            if !validation.has_errors() {
                return Ok(current_response);
            }

            // Try auto-correction first (fast, no LLM call)
            if let Some(corrected) = self.self_correction.try_auto_correct(&current_response) {
                let revalidation = self.self_correction.validate(&corrected);
                if revalidation.is_valid || !revalidation.has_errors() {
                    return Ok(corrected);
                }
                current_response = corrected;
            }

            // If we have a correction prompt, ask the LLM to fix it
            if let Some(correction_prompt) = &validation.correction_prompt {
                if let Some(tx) = event_tx {
                    let _ = tx.send(AgentEvent::Retrying {
                        attempt: pass,
                        max_attempts: max_passes,
                        reason: format!("Self-correction pass {} - {} issues", pass, validation.error_count()),
                    }).await;
                }

                // Build context with original response and correction instructions
                let full_prompt = format!(
                    "Your previous response was:\n\n{}\n\n{}",
                    current_response,
                    correction_prompt
                );

                // Query LLM for correction
                match self.query_ollama_streaming_inner(&full_prompt, config, event_tx, &self.config.streaming_config).await {
                    Ok(corrected) => {
                        current_response = corrected;
                    }
                    Err(e) => {
                        eprintln!("[WARN] Correction pass {} failed: {}", pass, e);
                        // Continue with what we have
                    }
                }
            }
        }

        // Return best effort
        Ok(current_response)
    }

    /// Execute a tool and return (success, output)
    async fn execute_tool(&mut self, action: &ToolCall) -> (bool, String) {
        // Check cache first
        if let Some(cached) = self.cache.get(&action.tool, &action.args) {
            return (cached.success, cached.output);
        }

        // Execute based on tool type
        let result = match action.tool.as_str() {
            "read_file" => self.tool_read_file(&action.args).await,
            "write_file" => self.tool_write_file(&action.args).await,
            "edit_file" => self.tool_edit_file(&action.args).await,
            "glob_files" => self.tool_glob_files(&action.args).await,
            "grep_files" => self.tool_grep_files(&action.args).await,
            "execute_shell" => self.tool_execute_shell(&action.args).await,
            "done" => {
                let summary = action.args.get("summary")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Task completed");
                Ok(summary.to_string())
            }
            _ => Err(format!("Unknown tool: {}", action.tool)),
        };

        let (success, output) = match result {
            Ok(output) => (true, output),
            Err(error) => (false, error),
        };

        // Cache if appropriate
        if crate::scaffolding::tool_cache::should_cache(&action.tool, success) {
            self.cache.set(&action.tool, &action.args, CachedResult {
                success,
                output: output.clone(),
                hash: None,
            });
        }

        // Invalidate cache if this tool modifies files
        if crate::scaffolding::tool_cache::invalidates_cache(&action.tool) {
            if let Some(path) = action.args.get("path").and_then(|p| p.as_str()) {
                self.cache.invalidate_file(path);
            }
        }

        (success, output)
    }

    async fn tool_read_file(&self, args: &serde_json::Value) -> Result<String, String> {
        let path = args.get("path")
            .and_then(|p| p.as_str())
            .ok_or("Missing path argument")?;

        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("Failed to read file: {}", e))
    }

    async fn tool_write_file(&self, args: &serde_json::Value) -> Result<String, String> {
        let path = args.get("path")
            .and_then(|p| p.as_str())
            .ok_or("Missing path argument")?;

        let content = args.get("content")
            .and_then(|c| c.as_str())
            .ok_or("Missing content argument")?;

        tokio::fs::write(path, content)
            .await
            .map_err(|e| format!("Failed to write file: {}", e))?;

        Ok(format!("File written: {}", path))
    }

    async fn tool_edit_file(&self, args: &serde_json::Value) -> Result<String, String> {
        let path = args.get("path")
            .and_then(|p| p.as_str())
            .ok_or("Missing path argument")?;

        let old_string = args.get("old_string")
            .and_then(|s| s.as_str())
            .ok_or("Missing old_string argument")?;

        let new_string = args.get("new_string")
            .and_then(|s| s.as_str())
            .ok_or("Missing new_string argument")?;

        let replace_all = args.get("replace_all")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);

        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("Failed to read file: {}", e))?;

        if !content.contains(old_string) {
            return Err("old_string not found in file".to_string());
        }

        let new_content = if replace_all {
            content.replace(old_string, new_string)
        } else {
            content.replacen(old_string, new_string, 1)
        };

        tokio::fs::write(path, new_content)
            .await
            .map_err(|e| format!("Failed to write file: {}", e))?;

        Ok("Edit successful".to_string())
    }

    async fn tool_glob_files(&self, args: &serde_json::Value) -> Result<String, String> {
        let pattern = args.get("pattern")
            .and_then(|p| p.as_str())
            .ok_or("Missing pattern argument")?;

        let path = args.get("path")
            .and_then(|p| p.as_str())
            .unwrap_or(".");

        let full_pattern = format!("{}/{}", path, pattern);

        let matches: Vec<String> = glob::glob(&full_pattern)
            .map_err(|e| format!("Invalid pattern: {}", e))?
            .filter_map(|r| r.ok())
            .map(|p| p.display().to_string())
            .collect();

        if matches.is_empty() {
            Ok("No matches found".to_string())
        } else {
            Ok(matches.join("\n"))
        }
    }

    async fn tool_grep_files(&self, args: &serde_json::Value) -> Result<String, String> {
        let pattern = args.get("pattern")
            .and_then(|p| p.as_str())
            .ok_or("Missing pattern argument")?;

        let path = args.get("path")
            .and_then(|p| p.as_str())
            .unwrap_or(".");

        let output = tokio::process::Command::new("grep")
            .args(["-r", "-n", pattern, path])
            .output()
            .await
            .map_err(|e| format!("Failed to run grep: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() && stdout.is_empty() {
            if !stderr.is_empty() {
                return Err(stderr.to_string());
            }
            return Ok("No matches found".to_string());
        }

        Ok(stdout.to_string())
    }

    async fn tool_execute_shell(&self, args: &serde_json::Value) -> Result<String, String> {
        let command = args.get("command")
            .and_then(|c| c.as_str())
            .ok_or("Missing command argument")?;

        let output = tokio::process::Command::new("sh")
            .args(["-c", command])
            .output()
            .await
            .map_err(|e| format!("Failed to execute command: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            return Err(format!("Command failed: {}\n{}", stderr, stdout));
        }

        Ok(format!("{}{}", stdout, stderr))
    }

    fn get_system_prompt(&self) -> String {
        r#"You are an AI assistant with access to tools. You MUST think step-by-step before acting.

IMPORTANT: Format your response EXACTLY like this:

<thinking>
1. What is the user asking for?
2. What information do I need?
3. What tool should I use?
4. What could go wrong?
</thinking>

<action>
{"tool": "tool_name", "args": {"arg1": "value1"}}
</action>

Available tools:
- read_file: Read file contents. Args: path (string)
- write_file: Write content to file. Args: path (string), content (string)
- edit_file: Edit file by replacing text. Args: path (string), old_string (string), new_string (string), replace_all (bool, optional)
- glob_files: Find files by pattern. Args: pattern (string), path (string, optional)
- grep_files: Search file contents. Args: pattern (string), path (string, optional)
- execute_shell: Run shell command. Args: command (string)
- done: Signal task completion. Args: summary (string)

RULES:
- ALWAYS include <thinking> with at least 3 numbered points
- ONE action per response
- Use <answer> when the task is FULLY complete
- Be careful with file operations - read before editing
"#.to_string()
    }

    fn extract_thinking(&self, response: &str) -> Option<String> {
        let re = regex::Regex::new(r"(?s)<thinking>(.*?)</thinking>").ok()?;
        re.captures(response)?
            .get(1)
            .map(|m| m.as_str().trim().to_string())
    }

    /// Reset the agent for a new task
    pub fn reset(&mut self) {
        self.agent_loop.reset();
        self.context.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> &crate::scaffolding::tool_cache::CacheStats {
        self.cache.stats()
    }

    /// Get available models
    pub fn available_models(&self) -> &[String] {
        &self.available_models
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_creation() {
        let agent = OllamaAgent::new(OllamaAgentConfig::default());
        assert!(agent.available_models().is_empty());
    }

    #[test]
    fn test_extract_thinking() {
        let agent = OllamaAgent::new(OllamaAgentConfig::default());

        let response = r#"
<thinking>
1. First point
2. Second point
3. Third point
</thinking>

<action>
{"tool": "read_file", "args": {"path": "test.rs"}}
</action>
"#;

        let thinking = agent.extract_thinking(response);
        assert!(thinking.is_some());
        assert!(thinking.unwrap().contains("First point"));
    }

    #[test]
    fn test_system_prompt() {
        let agent = OllamaAgent::new(OllamaAgentConfig::default());
        let prompt = agent.get_system_prompt();

        assert!(prompt.contains("<thinking>"));
        assert!(prompt.contains("read_file"));
        assert!(prompt.contains("edit_file"));
    }

    #[test]
    fn test_reset() {
        let mut agent = OllamaAgent::new(OllamaAgentConfig::default());
        agent.context.add_user_message("Test".to_string());
        agent.reset();
        // Context should be cleared
    }

    #[tokio::test]
    async fn test_tool_read_file_missing() {
        let agent = OllamaAgent::new(OllamaAgentConfig::default());
        let args = serde_json::json!({"path": "/nonexistent/file.txt"});
        let result = agent.tool_read_file(&args).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tool_glob_files() {
        let agent = OllamaAgent::new(OllamaAgentConfig::default());
        let args = serde_json::json!({"pattern": "*.rs", "path": "src"});
        let result = agent.tool_glob_files(&args).await;
        // Should succeed even if no matches (just returns "No matches found")
        assert!(result.is_ok());
    }
}
