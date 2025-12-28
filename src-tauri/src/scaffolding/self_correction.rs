// Self-Correction Loop for Low-Power LLMs
//
// Implements multi-pass validation to ensure low-power models
// achieve the same results as high-end models, even if slower.

use serde::{Deserialize, Serialize};
use crate::scaffolding::json_validator::{ToolCall, ToolCallValidator, ValidationError};

/// Configuration for self-correction behavior
#[derive(Debug, Clone)]
pub struct SelfCorrectionConfig {
    /// Maximum correction attempts per response
    pub max_correction_attempts: u32,
    /// Whether to validate JSON structure
    pub validate_json: bool,
    /// Whether to check tool arguments
    pub validate_args: bool,
    /// Whether to perform semantic validation
    pub validate_semantics: bool,
    /// Minimum thinking steps required
    pub min_thinking_steps: usize,
    /// Whether to require explicit reasoning
    pub require_reasoning: bool,
}

impl Default for SelfCorrectionConfig {
    fn default() -> Self {
        Self {
            max_correction_attempts: 3,
            validate_json: true,
            validate_args: true,
            validate_semantics: true,
            min_thinking_steps: 3,
            require_reasoning: true,
        }
    }
}

impl SelfCorrectionConfig {
    /// Strict configuration for very unreliable models
    pub fn strict() -> Self {
        Self {
            max_correction_attempts: 5,
            validate_json: true,
            validate_args: true,
            validate_semantics: true,
            min_thinking_steps: 4,
            require_reasoning: true,
        }
    }
}

/// Validation issue found in a response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: IssueSeverity,
    pub category: IssueCategory,
    pub message: String,
    pub suggestion: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    Error,      // Must fix - cannot proceed
    Warning,    // Should fix - may cause problems
    Info,       // Optional improvement
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueCategory {
    MissingThinking,
    InsufficientThinking,
    InvalidJson,
    MissingTool,
    InvalidTool,
    MissingArgs,
    InvalidArgs,
    LogicError,
    Unclear,
}

/// Result of validating a response
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub corrected_response: Option<String>,
    pub correction_prompt: Option<String>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            issues: Vec::new(),
            corrected_response: None,
            correction_prompt: None,
        }
    }

    pub fn invalid(issues: Vec<ValidationIssue>) -> Self {
        Self {
            is_valid: false,
            issues,
            corrected_response: None,
            correction_prompt: None,
        }
    }

    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|i| i.severity == IssueSeverity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.severity == IssueSeverity::Error).count()
    }
}

/// Self-correction engine for improving LLM outputs
pub struct SelfCorrectionEngine {
    config: SelfCorrectionConfig,
    validator: ToolCallValidator,
}

impl SelfCorrectionEngine {
    pub fn new(config: SelfCorrectionConfig) -> Self {
        Self {
            config,
            validator: ToolCallValidator::new(),
        }
    }

    /// Validate a response and return issues
    pub fn validate(&self, response: &str) -> ValidationResult {
        let mut issues = Vec::new();

        // 1. Check for thinking section
        if self.config.require_reasoning {
            if let Some(thinking_issues) = self.validate_thinking(response) {
                issues.extend(thinking_issues);
            }
        }

        // 2. Check for action section
        if let Some(action_issues) = self.validate_action(response) {
            issues.extend(action_issues);
        }

        // 3. Validate JSON if present
        if self.config.validate_json {
            if let Some(json_issues) = self.validate_json_structure(response) {
                issues.extend(json_issues);
            }
        }

        // 4. Validate tool and args
        if self.config.validate_args {
            if let Some(arg_issues) = self.validate_tool_args(response) {
                issues.extend(arg_issues);
            }
        }

        // 5. Semantic validation
        if self.config.validate_semantics {
            if let Some(semantic_issues) = self.validate_semantics(response) {
                issues.extend(semantic_issues);
            }
        }

        if issues.is_empty() {
            ValidationResult::valid()
        } else {
            let mut result = ValidationResult::invalid(issues.clone());
            result.correction_prompt = Some(self.build_correction_prompt(&issues));
            result
        }
    }

    /// Validate thinking section
    fn validate_thinking(&self, response: &str) -> Option<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        // Check for <thinking> tags
        if !response.contains("<thinking>") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Error,
                category: IssueCategory::MissingThinking,
                message: "Response must include <thinking> section".to_string(),
                suggestion: "Add <thinking>\\n1. ...\\n2. ...\\n3. ...\\n</thinking> before your action".to_string(),
            });
            return Some(issues);
        }

        // Extract thinking content
        if let (Some(start), Some(end)) = (response.find("<thinking>"), response.find("</thinking>")) {
            let thinking = &response[start + 10..end].trim();

            // Count numbered steps
            let step_count = thinking.lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    trimmed.starts_with("1.") || trimmed.starts_with("2.") ||
                    trimmed.starts_with("3.") || trimmed.starts_with("4.") ||
                    trimmed.starts_with("5.") || trimmed.starts_with("-") ||
                    trimmed.starts_with("•")
                })
                .count();

            if step_count < self.config.min_thinking_steps {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Warning,
                    category: IssueCategory::InsufficientThinking,
                    message: format!(
                        "Thinking section has {} steps, but {} are recommended",
                        step_count, self.config.min_thinking_steps
                    ),
                    suggestion: "Add more numbered reasoning steps to your thinking".to_string(),
                });
            }

            // Check thinking content is substantive
            if thinking.len() < 50 {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Warning,
                    category: IssueCategory::InsufficientThinking,
                    message: "Thinking section is too brief".to_string(),
                    suggestion: "Explain your reasoning more thoroughly".to_string(),
                });
            }
        }

        if issues.is_empty() { None } else { Some(issues) }
    }

    /// Validate action section
    fn validate_action(&self, response: &str) -> Option<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        // Must have either <action> or <answer>
        let has_action = response.contains("<action>");
        let has_answer = response.contains("<answer>");

        if !has_action && !has_answer {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Error,
                category: IssueCategory::MissingTool,
                message: "Response must include <action> or <answer> section".to_string(),
                suggestion: "Add <action>\\n{\"tool\": \"...\", \"args\": {...}}\\n</action>".to_string(),
            });
        }

        // Check for closing tags
        if has_action && !response.contains("</action>") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Error,
                category: IssueCategory::InvalidJson,
                message: "Missing </action> closing tag".to_string(),
                suggestion: "Make sure to close your action with </action>".to_string(),
            });
        }

        if has_answer && !response.contains("</answer>") {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::Unclear,
                message: "Missing </answer> closing tag".to_string(),
                suggestion: "Close your answer with </answer>".to_string(),
            });
        }

        if issues.is_empty() { None } else { Some(issues) }
    }

    /// Validate JSON structure
    fn validate_json_structure(&self, response: &str) -> Option<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        // Extract action content
        if let (Some(start), Some(end)) = (response.find("<action>"), response.find("</action>")) {
            let action_content = response[start + 8..end].trim();

            // Try to parse JSON
            match serde_json::from_str::<serde_json::Value>(action_content) {
                Ok(_) => {}, // Valid JSON
                Err(e) => {
                    // Check for common issues
                    let error_msg = e.to_string();

                    if error_msg.contains("key must be a string") || action_content.contains(": '") {
                        issues.push(ValidationIssue {
                            severity: IssueSeverity::Error,
                            category: IssueCategory::InvalidJson,
                            message: "JSON uses single quotes instead of double quotes".to_string(),
                            suggestion: "Use double quotes for all strings: \"key\": \"value\"".to_string(),
                        });
                    } else if error_msg.contains("trailing comma") {
                        issues.push(ValidationIssue {
                            severity: IssueSeverity::Error,
                            category: IssueCategory::InvalidJson,
                            message: "JSON has trailing comma".to_string(),
                            suggestion: "Remove the trailing comma before } or ]".to_string(),
                        });
                    } else {
                        issues.push(ValidationIssue {
                            severity: IssueSeverity::Error,
                            category: IssueCategory::InvalidJson,
                            message: format!("Invalid JSON: {}", error_msg),
                            suggestion: "Check JSON syntax: {\"tool\": \"name\", \"args\": {\"key\": \"value\"}}".to_string(),
                        });
                    }
                }
            }
        }

        if issues.is_empty() { None } else { Some(issues) }
    }

    /// Validate tool and arguments
    fn validate_tool_args(&self, response: &str) -> Option<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        // Try to extract and validate tool call
        match self.validator.extract_and_validate(response) {
            Ok(tool_call) => {
                // Additional arg validation
                if let Some(arg_issues) = self.check_arg_values(&tool_call) {
                    issues.extend(arg_issues);
                }
            }
            Err(ValidationError::UnknownTool(tool)) => {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Error,
                    category: IssueCategory::InvalidTool,
                    message: format!("Unknown tool: {}", tool),
                    suggestion: "Valid tools: read_file, write_file, edit_file, glob_files, grep_files, execute_shell, done".to_string(),
                });
            }
            Err(ValidationError::InvalidArgument { tool, message }) => {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Error,
                    category: IssueCategory::InvalidArgs,
                    message: format!("Invalid argument for {}: {}", tool, message),
                    suggestion: "Check the required arguments for this tool".to_string(),
                });
            }
            Err(ValidationError::MissingField(field)) => {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Error,
                    category: IssueCategory::MissingArgs,
                    message: format!("Missing required field: {}", field),
                    suggestion: "Include both 'tool' and 'args' in your JSON".to_string(),
                });
            }
            Err(_) => {
                // Other errors already handled by JSON validation
            }
        }

        if issues.is_empty() { None } else { Some(issues) }
    }

    /// Check specific argument values
    fn check_arg_values(&self, tool_call: &ToolCall) -> Option<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        match tool_call.tool.as_str() {
            "read_file" | "write_file" | "edit_file" => {
                if let Some(path) = tool_call.args.get("path").and_then(|p| p.as_str()) {
                    // Check for placeholder paths
                    if path.contains("<") || path.contains(">") || path == "path/to/file" {
                        issues.push(ValidationIssue {
                            severity: IssueSeverity::Error,
                            category: IssueCategory::InvalidArgs,
                            message: "Path contains placeholder text".to_string(),
                            suggestion: "Use an actual file path, not a placeholder".to_string(),
                        });
                    }
                    // Check for empty path
                    if path.trim().is_empty() {
                        issues.push(ValidationIssue {
                            severity: IssueSeverity::Error,
                            category: IssueCategory::InvalidArgs,
                            message: "Path is empty".to_string(),
                            suggestion: "Provide a valid file path".to_string(),
                        });
                    }
                }
            }
            "execute_shell" => {
                if let Some(cmd) = tool_call.args.get("command").and_then(|c| c.as_str()) {
                    // Check for dangerous commands
                    let dangerous = ["rm -rf /", ":(){ :|:& };:", "mkfs", "> /dev/sda"];
                    if dangerous.iter().any(|d| cmd.contains(d)) {
                        issues.push(ValidationIssue {
                            severity: IssueSeverity::Error,
                            category: IssueCategory::LogicError,
                            message: "Command appears dangerous".to_string(),
                            suggestion: "Use a safer command".to_string(),
                        });
                    }
                }
            }
            _ => {}
        }

        if issues.is_empty() { None } else { Some(issues) }
    }

    /// Semantic validation - check if the response makes sense
    fn validate_semantics(&self, response: &str) -> Option<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        // Check for contradictions in thinking vs action
        if let (Some(thinking_start), Some(thinking_end)) = (response.find("<thinking>"), response.find("</thinking>")) {
            let thinking = response[thinking_start + 10..thinking_end].to_lowercase();

            if let (Some(action_start), Some(action_end)) = (response.find("<action>"), response.find("</action>")) {
                let action = &response[action_start + 8..action_end];

                // Check if thinking mentions one tool but action uses another
                if thinking.contains("read") && !thinking.contains("write") && action.contains("write_file") {
                    issues.push(ValidationIssue {
                        severity: IssueSeverity::Warning,
                        category: IssueCategory::LogicError,
                        message: "Thinking mentions reading but action writes".to_string(),
                        suggestion: "Make sure your action matches your reasoning".to_string(),
                    });
                }
            }
        }

        if issues.is_empty() { None } else { Some(issues) }
    }

    /// Build a prompt to help the model correct its response
    pub fn build_correction_prompt(&self, issues: &[ValidationIssue]) -> String {
        let mut prompt = String::from("Your previous response had issues:\n\n");

        for (i, issue) in issues.iter().enumerate() {
            let severity = match issue.severity {
                IssueSeverity::Error => "❌ ERROR",
                IssueSeverity::Warning => "⚠️ WARNING",
                IssueSeverity::Info => "ℹ️ INFO",
            };
            prompt.push_str(&format!("{}. {} - {}\n   Fix: {}\n\n", i + 1, severity, issue.message, issue.suggestion));
        }

        prompt.push_str("\nPlease correct your response. Remember:\n");
        prompt.push_str("1. Start with <thinking> containing numbered steps\n");
        prompt.push_str("2. Then <action> with valid JSON: {\"tool\": \"name\", \"args\": {...}}\n");
        prompt.push_str("3. Use double quotes for all JSON strings\n");
        prompt.push_str("4. Make sure tool name is valid\n\n");
        prompt.push_str("Corrected response:");

        prompt
    }

    /// Attempt to auto-correct a response if possible
    pub fn try_auto_correct(&self, response: &str) -> Option<String> {
        // Try to fix common issues automatically

        let mut corrected = response.to_string();

        // Fix 1: Add missing thinking if we have an action
        if !corrected.contains("<thinking>") && corrected.contains("<action>") {
            corrected = format!(
                "<thinking>\n1. Processing the request\n2. Determining appropriate action\n3. Executing tool\n</thinking>\n\n{}",
                corrected
            );
        }

        // Fix 2: Add missing closing tags
        if corrected.contains("<action>") && !corrected.contains("</action>") {
            corrected.push_str("\n</action>");
        }

        // The JSON repair is handled by the validator, so just return
        // the structurally corrected response
        if corrected != response {
            Some(corrected)
        } else {
            None
        }
    }
}

impl Default for SelfCorrectionEngine {
    fn default() -> Self {
        Self::new(SelfCorrectionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_response() {
        let engine = SelfCorrectionEngine::default();

        let response = r#"
<thinking>
1. The user wants to read a file
2. I should use the read_file tool
3. The path is main.rs
</thinking>

<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>
"#;

        let result = engine.validate(response);
        assert!(result.is_valid, "Valid response should pass: {:?}", result.issues);
    }

    #[test]
    fn test_missing_thinking() {
        let engine = SelfCorrectionEngine::default();

        let response = r#"
<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>
"#;

        let result = engine.validate(response);
        assert!(!result.is_valid);
        assert!(result.issues.iter().any(|i| i.category == IssueCategory::MissingThinking));
    }

    #[test]
    fn test_invalid_json() {
        let engine = SelfCorrectionEngine::default();

        let response = r#"
<thinking>
1. Reading file
2. Using tool
3. Done
</thinking>

<action>
{'tool': 'read_file', 'args': {'path': 'main.rs'}}
</action>
"#;

        let result = engine.validate(response);
        assert!(!result.is_valid);
        assert!(result.issues.iter().any(|i| i.category == IssueCategory::InvalidJson));
    }

    #[test]
    fn test_unknown_tool() {
        let engine = SelfCorrectionEngine::default();

        let response = r#"
<thinking>
1. Reading file
2. Using tool
3. Done
</thinking>

<action>
{"tool": "hack_planet", "args": {"path": "main.rs"}}
</action>
"#;

        let result = engine.validate(response);
        assert!(!result.is_valid);
        assert!(result.issues.iter().any(|i| i.category == IssueCategory::InvalidTool));
    }

    #[test]
    fn test_auto_correct() {
        let engine = SelfCorrectionEngine::default();

        // Missing thinking
        let response = r#"<action>
{"tool": "read_file", "args": {"path": "main.rs"}}
</action>"#;

        let corrected = engine.try_auto_correct(response);
        assert!(corrected.is_some());
        assert!(corrected.unwrap().contains("<thinking>"));
    }

    #[test]
    fn test_correction_prompt() {
        let issues = vec![
            ValidationIssue {
                severity: IssueSeverity::Error,
                category: IssueCategory::InvalidJson,
                message: "Invalid JSON".to_string(),
                suggestion: "Fix the syntax".to_string(),
            }
        ];

        let engine = SelfCorrectionEngine::default();
        let prompt = engine.build_correction_prompt(&issues);

        assert!(prompt.contains("ERROR"));
        assert!(prompt.contains("Invalid JSON"));
        assert!(prompt.contains("Fix the syntax"));
    }
}
