// Agent Loop
//
// The main orchestrator that runs the agentic loop:
// 1. Receive task
// 2. Decompose if complex
// 3. Think step-by-step
// 4. Execute tool
// 5. Verify result
// 6. Recover from errors
// 7. Loop until done

use serde::{Deserialize, Serialize};
use crate::scaffolding::{
    chain_of_thought::ChainOfThoughtEnforcer,
    decomposer::{TaskDecomposer, TaskPlan},
    error_recovery::ErrorRecovery,
    examples::ExampleLibrary,
    json_validator::ToolCall,
    router::{ModelRouter, ModelConfig, ModelStats},
    verifier::{SelfVerifier, VerificationResult},
};

/// Configuration for the agent loop
#[derive(Debug, Clone)]
pub struct LoopConfig {
    /// Maximum iterations before giving up
    pub max_iterations: u32,
    /// Maximum retries per action
    pub max_retries: u32,
    /// Whether to decompose complex tasks
    pub enable_decomposition: bool,
    /// Whether to verify each action
    pub enable_verification: bool,
    /// Whether to use few-shot examples
    pub enable_examples: bool,
    /// Number of examples to include
    pub example_count: usize,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            max_iterations: 20,
            max_retries: 3,
            enable_decomposition: true,
            enable_verification: true,
            enable_examples: true,
            example_count: 2,
        }
    }
}

impl LoopConfig {
    /// Configuration for fast, simple tasks
    pub fn fast() -> Self {
        Self {
            max_iterations: 5,
            max_retries: 1,
            enable_decomposition: false,
            enable_verification: false,
            enable_examples: false,
            example_count: 0,
        }
    }

    /// Configuration for thorough, complex tasks
    pub fn thorough() -> Self {
        Self {
            max_iterations: 30,
            max_retries: 5,
            enable_decomposition: true,
            enable_verification: true,
            enable_examples: true,
            example_count: 3,
        }
    }
}

/// State of the agent loop
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    /// Initial state, ready to start
    Ready,
    /// Planning/decomposing the task
    Planning,
    /// Thinking about the next action
    Thinking,
    /// Executing a tool
    Executing,
    /// Verifying the result
    Verifying,
    /// Recovering from an error
    Recovering,
    /// Task completed successfully
    Completed,
    /// Task failed after all retries
    Failed,
    /// Waiting for user input
    WaitingForUser,
}

/// A single step in the agent's execution history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub step_number: u32,
    pub thinking: String,
    pub action: Option<ToolCall>,
    pub result: Option<String>,
    pub verification: Option<VerificationResult>,
    pub was_retry: bool,
}

/// Result of the agent loop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResult {
    pub success: bool,
    pub final_answer: Option<String>,
    pub steps: Vec<ExecutionStep>,
    pub iterations: u32,
    pub state: AgentState,
    pub error: Option<String>,
}

/// The main agent loop orchestrator
pub struct AgentLoop {
    config: LoopConfig,
    cot_enforcer: ChainOfThoughtEnforcer,
    decomposer: TaskDecomposer,
    verifier: SelfVerifier,
    recovery: ErrorRecovery,
    examples: ExampleLibrary,
    router: ModelRouter,
    stats: ModelStats,

    // Runtime state
    state: AgentState,
    current_plan: Option<TaskPlan>,
    steps: Vec<ExecutionStep>,
    iteration: u32,
    retry_count: u32,
}

impl AgentLoop {
    pub fn new(config: LoopConfig) -> Self {
        Self {
            config,
            cot_enforcer: ChainOfThoughtEnforcer::new(),
            decomposer: TaskDecomposer::new(),
            verifier: SelfVerifier::new(),
            recovery: ErrorRecovery::new(),
            examples: ExampleLibrary::new(),
            router: ModelRouter::new(),
            stats: ModelStats::default(),

            state: AgentState::Ready,
            current_plan: None,
            steps: Vec::new(),
            iteration: 0,
            retry_count: 0,
        }
    }

    pub fn with_strict_cot(mut self) -> Self {
        self.cot_enforcer = ChainOfThoughtEnforcer::strict();
        self
    }

    /// Get the current state
    pub fn state(&self) -> AgentState {
        self.state
    }

    /// Get execution statistics
    pub fn stats(&self) -> &ModelStats {
        &self.stats
    }

    /// Get the execution history
    pub fn history(&self) -> &[ExecutionStep] {
        &self.steps
    }

    /// Set available models for routing
    pub fn set_available_models(&mut self, models: Vec<String>) {
        self.router.set_available_models(models);
    }

    /// Start processing a task - returns the initial prompt to send to LLM
    pub fn start(&mut self, task: &str) -> AgentStartResult {
        self.state = AgentState::Planning;
        self.steps.clear();
        self.iteration = 0;
        self.retry_count = 0;
        self.current_plan = None;

        // Check if task needs decomposition
        if self.config.enable_decomposition && self.decomposer.needs_decomposition(task) {
            // Return decomposition prompt first
            return AgentStartResult {
                prompt: self.decomposer.get_decomposition_prompt(task),
                model_config: self.router.for_decomposition(),
                needs_decomposition: true,
            };
        }

        // Simple task - create single-step plan
        self.current_plan = Some(self.decomposer.create_simple_plan(task));
        self.state = AgentState::Thinking;

        // Build the action prompt
        let prompt = self.build_action_prompt(task, None);
        let model_config = self.router.route(task);

        AgentStartResult {
            prompt,
            model_config,
            needs_decomposition: false,
        }
    }

    /// Process decomposition response from LLM
    pub fn process_decomposition(&mut self, response: &str, original_task: &str) -> Result<AgentActionPrompt, String> {
        let subtasks = self.decomposer.parse_decomposition(response)
            .map_err(|e| e)?;

        self.current_plan = Some(TaskPlan::new(original_task, subtasks));
        self.state = AgentState::Thinking;

        let prompt = self.build_action_prompt(original_task, None);
        let model_config = self.router.route(original_task);

        Ok(AgentActionPrompt { prompt, model_config })
    }

    /// Build the prompt for the next action
    fn build_action_prompt(&self, task: &str, previous_result: Option<&str>) -> String {
        let mut prompt = String::new();

        // Add chain-of-thought template
        prompt.push_str(self.cot_enforcer.get_prompt_template());

        // Add few-shot examples if enabled
        if self.config.enable_examples {
            let examples = self.examples.format_for_prompt(task, self.config.example_count);
            prompt.push_str(&examples);
        }

        // Add task context
        if let Some(plan) = &self.current_plan {
            if let Some(subtask_prompt) = self.decomposer.get_subtask_prompt(plan) {
                prompt.push_str("\n\n");
                prompt.push_str(&subtask_prompt);
            }
        } else {
            prompt.push_str("\n\nUSER REQUEST:\n");
            prompt.push_str(task);
        }

        // Add previous result context
        if let Some(result) = previous_result {
            prompt.push_str("\n\nPREVIOUS RESULT:\n");
            // Truncate long results
            if result.len() > 2000 {
                prompt.push_str(&result[..2000]);
                prompt.push_str("\n... (truncated)");
            } else {
                prompt.push_str(result);
            }
        }

        // Add history summary if we have steps
        if !self.steps.is_empty() {
            prompt.push_str("\n\nEXECUTION HISTORY:\n");
            for step in self.steps.iter().rev().take(3) {
                if let Some(action) = &step.action {
                    prompt.push_str(&format!("- {}: ", action.tool));
                    if let Some(result) = &step.result {
                        let short = if result.len() > 100 {
                            format!("{}...", &result[..100])
                        } else {
                            result.clone()
                        };
                        prompt.push_str(&short);
                    }
                    prompt.push('\n');
                }
            }
        }

        prompt.push_str("\n\nNow think step-by-step and respond:");
        prompt
    }

    /// Process LLM response and extract the action
    pub fn process_response(&mut self, response: &str) -> ProcessResult {
        self.iteration += 1;

        // Check iteration limit
        if self.iteration > self.config.max_iterations {
            self.state = AgentState::Failed;
            return ProcessResult::Failed {
                error: format!("Exceeded maximum iterations ({})", self.config.max_iterations),
            };
        }

        // Parse the response with chain-of-thought enforcement
        let parsed = match self.cot_enforcer.parse(response) {
            Ok(p) => p,
            Err(e) => {
                return ProcessResult::NeedsRetry {
                    feedback: format!("Invalid response format: {}. Please follow the exact format.", e),
                };
            }
        };

        // Record the step
        let step = ExecutionStep {
            step_number: self.iteration,
            thinking: parsed.thinking.clone(),
            action: parsed.action.clone(),
            result: None,
            verification: None,
            was_retry: self.retry_count > 0,
        };
        self.steps.push(step);

        // Check if this is a final answer
        if parsed.is_final_answer {
            self.state = AgentState::Completed;
            return ProcessResult::Completed {
                answer: parsed.final_answer.unwrap_or_else(|| "Task completed.".to_string()),
            };
        }

        // We have an action to execute
        if let Some(action) = parsed.action {
            self.state = AgentState::Executing;
            return ProcessResult::ExecuteTool { action };
        }

        // No action and not final - need more thinking
        ProcessResult::NeedsRetry {
            feedback: "Your response didn't include an action or final answer. Please provide one.".to_string(),
        }
    }

    /// Process tool execution result
    pub fn process_tool_result(
        &mut self,
        tool: &str,
        args: &serde_json::Value,
        result: &str,
        is_error: bool,
    ) -> ToolResultAction {
        // Update the last step with the result
        if let Some(step) = self.steps.last_mut() {
            step.result = Some(result.to_string());
        }

        // Handle errors
        if is_error {
            self.state = AgentState::Recovering;

            // Check if recoverable
            if !self.recovery.is_recoverable(result) {
                self.state = AgentState::Failed;
                return ToolResultAction::Failed {
                    error: result.to_string(),
                };
            }

            // Check retry limit
            self.retry_count += 1;
            if self.retry_count > self.config.max_retries {
                self.state = AgentState::Failed;
                return ToolResultAction::Failed {
                    error: format!("Failed after {} retries: {}", self.config.max_retries, result),
                };
            }

            // Generate recovery prompt
            let original_intent = self.current_plan
                .as_ref()
                .and_then(|p| p.current())
                .map(|s| s.description.as_str())
                .unwrap_or("Complete the task");

            let recovery_prompt = self.recovery.get_recovery_prompt(
                tool,
                args,
                result,
                original_intent,
            );

            return ToolResultAction::Retry {
                prompt: recovery_prompt,
                model_config: self.router.for_recovery(),
            };
        }

        // Success! Reset retry counter
        self.retry_count = 0;

        // Verification if enabled
        if self.config.enable_verification {
            self.state = AgentState::Verifying;

            let original_intent = self.current_plan
                .as_ref()
                .and_then(|p| p.current())
                .map(|s| s.description.as_str())
                .unwrap_or("Complete the task");

            let verification_prompt = self.verifier.get_verification_prompt(
                tool,
                args,
                result,
                original_intent,
            );

            return ToolResultAction::Verify {
                prompt: verification_prompt,
                model_config: self.router.for_verification(),
            };
        }

        // No verification - continue to next step
        self.advance_plan(result)
    }

    /// Process verification response
    pub fn process_verification(&mut self, response: &str, tool_result: &str) -> ToolResultAction {
        let verification = self.verifier.parse_verification(response);

        // Update the last step with verification
        if let Some(step) = self.steps.last_mut() {
            step.verification = Some(verification.clone());
        }

        match verification {
            VerificationResult::Verified { .. } => {
                // Good! Advance to next step
                self.advance_plan(tool_result)
            }
            VerificationResult::Failed { reason } => {
                self.retry_count += 1;
                if self.retry_count > self.config.max_retries {
                    self.state = AgentState::Failed;
                    return ToolResultAction::Failed {
                        error: format!("Verification failed: {}", reason),
                    };
                }

                // Get original context for retry
                let task = self.current_plan
                    .as_ref()
                    .map(|p| p.original_task.as_str())
                    .unwrap_or("Complete the task");

                self.state = AgentState::Thinking;
                ToolResultAction::Continue {
                    prompt: self.build_action_prompt(task, Some(&format!("VERIFICATION FAILED: {}\n\nOriginal result: {}", reason, tool_result))),
                    model_config: self.router.route(task),
                }
            }
            VerificationResult::Retry { suggestion } => {
                self.retry_count += 1;
                if self.retry_count > self.config.max_retries {
                    self.state = AgentState::Failed;
                    return ToolResultAction::Failed {
                        error: "Exceeded retry limit during verification".to_string(),
                    };
                }

                self.state = AgentState::Thinking;
                let task = self.current_plan
                    .as_ref()
                    .map(|p| p.original_task.as_str())
                    .unwrap_or("Complete the task");

                ToolResultAction::Continue {
                    prompt: self.build_action_prompt(task, Some(&format!("RETRY SUGGESTED: {}\n\nPrevious result: {}", suggestion, tool_result))),
                    model_config: self.router.route(task),
                }
            }
            VerificationResult::Uncertain { reason: _ } => {
                // Treat as success but log the uncertainty
                self.advance_plan(tool_result)
            }
        }
    }

    /// Advance to the next step in the plan
    fn advance_plan(&mut self, result: &str) -> ToolResultAction {
        if let Some(plan) = &mut self.current_plan {
            plan.complete_current(result.to_string());

            if plan.is_complete {
                self.state = AgentState::Completed;
                return ToolResultAction::Completed {
                    summary: format!("Completed {} steps successfully", plan.subtasks.len()),
                };
            }
        }

        // Continue to next step
        self.state = AgentState::Thinking;
        let task = self.current_plan
            .as_ref()
            .map(|p| p.original_task.as_str())
            .unwrap_or("Complete the task");

        ToolResultAction::Continue {
            prompt: self.build_action_prompt(task, Some(result)),
            model_config: self.router.route(task),
        }
    }

    /// Get the final result
    pub fn get_result(&self) -> AgentResult {
        AgentResult {
            success: self.state == AgentState::Completed,
            final_answer: self.steps.last().and_then(|s| s.result.clone()),
            steps: self.steps.clone(),
            iterations: self.iteration,
            state: self.state,
            error: if self.state == AgentState::Failed {
                Some("Task failed".to_string())
            } else {
                None
            },
        }
    }

    /// Reset the agent for a new task
    pub fn reset(&mut self) {
        self.state = AgentState::Ready;
        self.current_plan = None;
        self.steps.clear();
        self.iteration = 0;
        self.retry_count = 0;
    }
}

impl Default for AgentLoop {
    fn default() -> Self {
        Self::new(LoopConfig::default())
    }
}

/// Result from starting the agent
#[derive(Debug)]
pub struct AgentStartResult {
    pub prompt: String,
    pub model_config: ModelConfig,
    pub needs_decomposition: bool,
}

/// Result from processing decomposition
#[derive(Debug)]
pub struct AgentActionPrompt {
    pub prompt: String,
    pub model_config: ModelConfig,
}

/// Result from processing LLM response
#[derive(Debug)]
pub enum ProcessResult {
    /// Need to execute a tool
    ExecuteTool { action: ToolCall },
    /// Task completed with answer
    Completed { answer: String },
    /// Need to retry with feedback
    NeedsRetry { feedback: String },
    /// Task failed
    Failed { error: String },
}

/// Action to take after tool result
#[derive(Debug)]
pub enum ToolResultAction {
    /// Continue to next step
    Continue {
        prompt: String,
        model_config: ModelConfig,
    },
    /// Verify the result
    Verify {
        prompt: String,
        model_config: ModelConfig,
    },
    /// Retry due to error
    Retry {
        prompt: String,
        model_config: ModelConfig,
    },
    /// Task completed
    Completed { summary: String },
    /// Task failed
    Failed { error: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_agent_loop() {
        let agent = AgentLoop::new(LoopConfig::default());
        assert_eq!(agent.state(), AgentState::Ready);
    }

    #[test]
    fn test_start_simple_task() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        let result = agent.start("read main.rs");

        assert!(!result.needs_decomposition);
        assert!(result.prompt.contains("read main.rs") || result.prompt.contains("USER REQUEST"));
        assert_eq!(agent.state(), AgentState::Thinking);
    }

    #[test]
    fn test_start_complex_task() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        let result = agent.start("create a new module and then add tests and run them");

        assert!(result.needs_decomposition);
        assert_eq!(agent.state(), AgentState::Planning);
    }

    #[test]
    fn test_process_valid_response() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        agent.start("read main.rs");

        let response = r#"
<thinking>
1. The user wants to read a file
2. I need to use read_file tool
3. The path is main.rs
4. This should show the file contents
</thinking>

<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>
"#;

        let result = agent.process_response(response);
        assert!(matches!(result, ProcessResult::ExecuteTool { .. }));
        assert_eq!(agent.state(), AgentState::Executing);
    }

    #[test]
    fn test_process_final_answer() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        agent.start("what is 2+2");

        let response = r#"
<thinking>
1. User asks a simple math question
2. The answer is 4
3. No tools needed
</thinking>

<answer>
The answer is 4.
</answer>
"#;

        let result = agent.process_response(response);
        assert!(matches!(result, ProcessResult::Completed { .. }));
        assert_eq!(agent.state(), AgentState::Completed);
    }

    #[test]
    fn test_iteration_limit() {
        let config = LoopConfig {
            max_iterations: 2,
            ..Default::default()
        };
        let mut agent = AgentLoop::new(config);
        agent.start("do something");

        // First iteration
        let response = r#"
<thinking>
1. Step 1
2. Step 2
3. Step 3
</thinking>

<action>
{"tool": "read_file", "args": {"path": "test.rs"}}
</action>
"#;
        agent.process_response(response);
        agent.process_response(response);

        // Third should fail
        let result = agent.process_response(response);
        assert!(matches!(result, ProcessResult::Failed { .. }));
    }

    #[test]
    fn test_tool_result_with_error() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        agent.start("read missing.rs");

        let response = r#"
<thinking>
1. Read the file
2. Use read_file
3. Path is missing.rs
</thinking>

<action>
{"tool": "read_file", "args": {"path": "missing.rs"}}
</action>
"#;
        agent.process_response(response);

        let result = agent.process_tool_result(
            "read_file",
            &serde_json::json!({"path": "missing.rs"}),
            "Error: file not found",
            true,
        );

        assert!(matches!(result, ToolResultAction::Retry { .. }));
        assert_eq!(agent.state(), AgentState::Recovering);
    }

    #[test]
    fn test_tool_result_success_with_verification() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        agent.start("read main.rs");

        let response = r#"
<thinking>
1. Read the file
2. Use read_file
3. Path is main.rs
</thinking>

<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>
"#;
        agent.process_response(response);

        let result = agent.process_tool_result(
            "read_file",
            &serde_json::json!({"path": "main.rs"}),
            "fn main() {}",
            false,
        );

        assert!(matches!(result, ToolResultAction::Verify { .. }));
        assert_eq!(agent.state(), AgentState::Verifying);
    }

    #[test]
    fn test_verification_success() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        agent.start("read main.rs");

        // Simulate we're in verification state
        agent.state = AgentState::Verifying;

        let result = agent.process_verification(
            "VERIFIED: File contents look correct",
            "fn main() {}",
        );

        // Should complete since it's a simple task
        assert!(matches!(result, ToolResultAction::Completed { .. }));
    }

    #[test]
    fn test_verification_failed() {
        let config = LoopConfig {
            max_retries: 1,
            ..Default::default()
        };
        let mut agent = AgentLoop::new(config);
        agent.start("read main.rs");
        agent.state = AgentState::Verifying;

        let result = agent.process_verification(
            "FAILED: File not found in result",
            "Error output",
        );

        assert!(matches!(result, ToolResultAction::Continue { .. }));
    }

    #[test]
    fn test_fast_config() {
        let config = LoopConfig::fast();
        assert_eq!(config.max_iterations, 5);
        assert!(!config.enable_decomposition);
        assert!(!config.enable_verification);
    }

    #[test]
    fn test_thorough_config() {
        let config = LoopConfig::thorough();
        assert_eq!(config.max_iterations, 30);
        assert!(config.enable_decomposition);
        assert!(config.enable_verification);
    }

    #[test]
    fn test_reset() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        agent.start("test task");
        agent.process_response(r#"
<thinking>
1. A
2. B
3. C
</thinking>
<answer>Done</answer>
"#);

        agent.reset();

        assert_eq!(agent.state(), AgentState::Ready);
        assert!(agent.history().is_empty());
    }

    #[test]
    fn test_get_result() {
        let mut agent = AgentLoop::new(LoopConfig::default());
        agent.start("test");
        agent.process_response(r#"
<thinking>
1. Test
2. Test
3. Done
</thinking>
<answer>Completed!</answer>
"#);

        let result = agent.get_result();
        assert!(result.success);
        assert_eq!(result.state, AgentState::Completed);
    }
}
