// Chain-of-Thought Enforcer
//
// Forces the model to reason step-by-step before acting.
// This significantly improves accuracy on complex tasks.

use serde::{Deserialize, Serialize};
use regex::Regex;
use crate::scaffolding::json_validator::{ToolCall, ToolCallValidator, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonedResponse {
    pub thinking: String,
    pub action: Option<ToolCall>,
    pub is_final_answer: bool,
    pub final_answer: Option<String>,
}

#[derive(Debug)]
pub enum ChainOfThoughtError {
    MissingThinking,
    ThinkingTooShallow(usize), // number of lines
    InvalidAction(ValidationError),
    ParseError(String),
}

impl std::fmt::Display for ChainOfThoughtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingThinking => write!(f, "Response missing <thinking> section"),
            Self::ThinkingTooShallow(lines) => write!(f, "Thinking too shallow: only {} lines (need at least 3)", lines),
            Self::InvalidAction(e) => write!(f, "Invalid action: {}", e),
            Self::ParseError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

pub struct ChainOfThoughtEnforcer {
    validator: ToolCallValidator,
    min_thinking_lines: usize,
    require_numbered_steps: bool,
}

impl ChainOfThoughtEnforcer {
    pub fn new() -> Self {
        Self {
            validator: ToolCallValidator::new(),
            min_thinking_lines: 3,
            require_numbered_steps: false,
        }
    }

    pub fn strict() -> Self {
        Self {
            validator: ToolCallValidator::new(),
            min_thinking_lines: 4,
            require_numbered_steps: true,
        }
    }

    /// Parse a response that should contain thinking and action
    pub fn parse(&self, output: &str) -> Result<ReasonedResponse, ChainOfThoughtError> {
        let thinking = self.extract_thinking(output)?;
        self.validate_thinking(&thinking)?;

        // Check for final answer (no action needed)
        if let Some(answer) = self.extract_final_answer(output) {
            return Ok(ReasonedResponse {
                thinking,
                action: None,
                is_final_answer: true,
                final_answer: Some(answer),
            });
        }

        // Try to extract action
        let action = self.extract_action(output)?;

        Ok(ReasonedResponse {
            thinking,
            action: Some(action),
            is_final_answer: false,
            final_answer: None,
        })
    }

    /// Extract thinking section from output
    fn extract_thinking(&self, output: &str) -> Result<String, ChainOfThoughtError> {
        // Try <thinking> tags first
        let thinking_re = Regex::new(r"(?s)<thinking>(.*?)</thinking>").unwrap();
        if let Some(caps) = thinking_re.captures(output) {
            return Ok(caps.get(1).unwrap().as_str().trim().to_string());
        }

        // Try **Thinking:** markdown format
        let markdown_re = Regex::new(r"(?s)\*\*Thinking:?\*\*\s*(.*?)(?:\*\*Action|<action>|\{)").unwrap();
        if let Some(caps) = markdown_re.captures(output) {
            return Ok(caps.get(1).unwrap().as_str().trim().to_string());
        }

        // Try numbered list at the start
        let lines: Vec<&str> = output.lines().collect();
        let mut thinking_lines = Vec::new();
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.starts_with("1.") || trimmed.starts_with("2.") ||
               trimmed.starts_with("3.") || trimmed.starts_with("4.") ||
               trimmed.starts_with("- ") || trimmed.starts_with("* ") {
                thinking_lines.push(trimmed);
            } else if trimmed.starts_with('{') || trimmed.starts_with("<action>") {
                break;
            }
        }

        if !thinking_lines.is_empty() {
            return Ok(thinking_lines.join("\n"));
        }

        Err(ChainOfThoughtError::MissingThinking)
    }

    /// Validate that thinking is substantive
    fn validate_thinking(&self, thinking: &str) -> Result<(), ChainOfThoughtError> {
        let lines: Vec<&str> = thinking.lines()
            .filter(|l| !l.trim().is_empty())
            .collect();

        if lines.len() < self.min_thinking_lines {
            return Err(ChainOfThoughtError::ThinkingTooShallow(lines.len()));
        }

        if self.require_numbered_steps {
            let has_numbered = lines.iter().any(|l| {
                let t = l.trim();
                t.starts_with("1.") || t.starts_with("2.") || t.starts_with("3.")
            });
            if !has_numbered {
                return Err(ChainOfThoughtError::ParseError(
                    "Thinking must include numbered steps".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Extract action (tool call) from output
    fn extract_action(&self, output: &str) -> Result<ToolCall, ChainOfThoughtError> {
        self.validator.extract_and_validate(output)
            .map_err(ChainOfThoughtError::InvalidAction)
    }

    /// Extract final answer if present
    fn extract_final_answer(&self, output: &str) -> Option<String> {
        // Check for <answer> tags
        let answer_re = Regex::new(r"(?s)<answer>(.*?)</answer>").unwrap();
        if let Some(caps) = answer_re.captures(output) {
            return Some(caps.get(1).unwrap().as_str().trim().to_string());
        }

        // Check for **Answer:** markdown
        let markdown_re = Regex::new(r"(?s)\*\*Answer:?\*\*\s*(.*)$").unwrap();
        if let Some(caps) = markdown_re.captures(output) {
            return Some(caps.get(1).unwrap().as_str().trim().to_string());
        }

        // Check for "done" tool call
        if output.contains(r#""tool": "done""#) || output.contains(r#""tool":"done""#) {
            // Extract the summary from done tool
            if let Ok(tool_call) = self.validator.extract_and_validate(output) {
                if tool_call.tool == "done" {
                    if let Some(summary) = tool_call.args.get("summary") {
                        return summary.as_str().map(|s| s.to_string());
                    }
                }
            }
        }

        None
    }

    /// Generate the prompt template that enforces chain-of-thought
    pub fn get_prompt_template(&self) -> &'static str {
        r#"You are an AI assistant that thinks step-by-step before acting.

IMPORTANT: You MUST format your response EXACTLY like this:

<thinking>
1. What is the user asking for?
2. What information do I need?
3. What tool should I use?
4. What could go wrong?
</thinking>

<action>
{"tool": "tool_name", "args": {"arg1": "value1"}}
</action>

If you have completed the task and have a final answer:

<thinking>
1. What did I accomplish?
2. Is the task fully complete?
3. What is the final result?
</thinking>

<answer>
Your final response to the user.
</answer>

RULES:
- ALWAYS include <thinking> with at least 3 numbered points
- NEVER skip the thinking section
- ONE action per response
- Use <answer> only when the task is FULLY complete
"#
    }

    /// Wrap a user prompt with chain-of-thought instructions
    pub fn wrap_prompt(&self, user_prompt: &str, context: Option<&str>) -> String {
        let mut wrapped = self.get_prompt_template().to_string();

        if let Some(ctx) = context {
            wrapped.push_str("\n\nCONTEXT FROM PREVIOUS STEPS:\n");
            wrapped.push_str(ctx);
        }

        wrapped.push_str("\n\nUSER REQUEST:\n");
        wrapped.push_str(user_prompt);
        wrapped.push_str("\n\nNow think step-by-step and respond:");

        wrapped
    }
}

impl Default for ChainOfThoughtEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_response() {
        let enforcer = ChainOfThoughtEnforcer::new();
        let input = r#"
<thinking>
1. The user wants to read a file
2. I need to use the read_file tool
3. The path is main.rs
4. This should work if the file exists
</thinking>

<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>
"#;
        let result = enforcer.parse(input);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.thinking.contains("read a file"));
        assert!(response.action.is_some());
        assert_eq!(response.action.unwrap().tool, "read_file");
    }

    #[test]
    fn test_parse_final_answer() {
        let enforcer = ChainOfThoughtEnforcer::new();
        let input = r#"
<thinking>
1. I have completed the task
2. The file was created successfully
3. I can now provide the final answer
</thinking>

<answer>
The file has been created at src/main.rs with the requested content.
</answer>
"#;
        let result = enforcer.parse(input);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_final_answer);
        assert!(response.final_answer.is_some());
        assert!(response.action.is_none());
    }

    #[test]
    fn test_reject_shallow_thinking() {
        let enforcer = ChainOfThoughtEnforcer::new();
        let input = r#"
<thinking>
I'll read the file.
</thinking>

<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>
"#;
        let result = enforcer.parse(input);
        assert!(matches!(result, Err(ChainOfThoughtError::ThinkingTooShallow(_))));
    }

    #[test]
    fn test_missing_thinking() {
        let enforcer = ChainOfThoughtEnforcer::new();
        let input = r#"{"tool": "read_file", "args": {"path": "main.rs"}}"#;
        let result = enforcer.parse(input);
        assert!(matches!(result, Err(ChainOfThoughtError::MissingThinking)));
    }

    #[test]
    fn test_parse_markdown_thinking() {
        let enforcer = ChainOfThoughtEnforcer::new();
        let input = r#"
**Thinking:**
1. User wants to list files
2. I should use glob_files
3. Pattern should be **/*
4. This will find all files

**Action:**
{"tool": "glob_files", "args": {"pattern": "**/*"}}
"#;
        let result = enforcer.parse(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_mode_requires_numbers() {
        let enforcer = ChainOfThoughtEnforcer::strict();
        let input = r#"
<thinking>
- I need to read the file
- The path is main.rs
- I'll use read_file
- Should work fine
</thinking>

<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>
"#;
        let result = enforcer.parse(input);
        assert!(matches!(result, Err(ChainOfThoughtError::ParseError(_))));
    }
}
