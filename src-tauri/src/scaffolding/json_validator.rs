// JSON Validation Layer
//
// Forces Ollama to output valid, structured JSON tool calls
// and validates them against expected schemas.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    pub args: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Unknown tool: {0}")]
    UnknownTool(String),

    #[error("Invalid argument for {tool}: {message}")]
    InvalidArgument { tool: String, message: String },

    #[error("Output too long: {0} chars (max {1})")]
    OutputTooLong(usize, usize),

    #[error("No tool call found in response")]
    NoToolCall,
}

/// Known tools and their required/optional arguments
#[derive(Debug, Clone)]
pub struct ToolSchema {
    pub name: String,
    pub required_args: Vec<String>,
    pub optional_args: Vec<String>,
    pub description: String,
}

pub struct ToolCallValidator {
    schemas: HashMap<String, ToolSchema>,
    max_output_length: usize,
}

impl ToolCallValidator {
    pub fn new() -> Self {
        let mut schemas = HashMap::new();

        // Define all known tools
        schemas.insert("read_file".to_string(), ToolSchema {
            name: "read_file".to_string(),
            required_args: vec!["path".to_string()],
            optional_args: vec![],
            description: "Read contents of a file".to_string(),
        });

        schemas.insert("write_file".to_string(), ToolSchema {
            name: "write_file".to_string(),
            required_args: vec!["path".to_string(), "content".to_string()],
            optional_args: vec![],
            description: "Write content to a file".to_string(),
        });

        schemas.insert("edit_file".to_string(), ToolSchema {
            name: "edit_file".to_string(),
            required_args: vec!["path".to_string(), "old_string".to_string(), "new_string".to_string()],
            optional_args: vec!["replace_all".to_string()],
            description: "Make surgical edits to a file".to_string(),
        });

        schemas.insert("execute_shell".to_string(), ToolSchema {
            name: "execute_shell".to_string(),
            required_args: vec!["command".to_string()],
            optional_args: vec!["timeout".to_string(), "cwd".to_string()],
            description: "Execute a shell command".to_string(),
        });

        schemas.insert("glob_files".to_string(), ToolSchema {
            name: "glob_files".to_string(),
            required_args: vec!["pattern".to_string()],
            optional_args: vec!["path".to_string(), "limit".to_string()],
            description: "Find files matching a glob pattern".to_string(),
        });

        schemas.insert("grep_files".to_string(), ToolSchema {
            name: "grep_files".to_string(),
            required_args: vec!["pattern".to_string()],
            optional_args: vec!["path".to_string(), "file_pattern".to_string(), "case_insensitive".to_string()],
            description: "Search file contents with regex".to_string(),
        });

        schemas.insert("web_fetch".to_string(), ToolSchema {
            name: "web_fetch".to_string(),
            required_args: vec!["url".to_string()],
            optional_args: vec![],
            description: "Fetch content from a URL".to_string(),
        });

        // Special "done" tool to signal task completion
        schemas.insert("done".to_string(), ToolSchema {
            name: "done".to_string(),
            required_args: vec!["summary".to_string()],
            optional_args: vec![],
            description: "Signal that the task is complete".to_string(),
        });

        Self {
            schemas,
            max_output_length: 10000,
        }
    }

    /// Extract and validate a tool call from raw LLM output
    pub fn extract_and_validate(&self, output: &str) -> Result<ToolCall, ValidationError> {
        // Check length
        if output.len() > self.max_output_length {
            return Err(ValidationError::OutputTooLong(output.len(), self.max_output_length));
        }

        // Try to find JSON in the output
        let json_str = self.extract_json(output)?;

        // Parse JSON
        let value: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| ValidationError::InvalidJson(e.to_string()))?;

        // Validate structure
        self.validate_structure(&value)?;

        // Parse into ToolCall
        let tool_call: ToolCall = serde_json::from_value(value)
            .map_err(|e| ValidationError::InvalidJson(e.to_string()))?;

        // Validate against schema
        self.validate_against_schema(&tool_call)?;

        Ok(tool_call)
    }

    /// Extract JSON from potentially messy LLM output
    fn extract_json(&self, output: &str) -> Result<String, ValidationError> {
        let trimmed = output.trim();

        // Case 1: Output is already clean JSON
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            if let Ok(json) = self.repair_json(trimmed) {
                return Ok(json);
            }
        }

        // Case 2: JSON in <action> tags
        if let Some(start) = trimmed.find("<action>") {
            if let Some(end) = trimmed.find("</action>") {
                let inner = trimmed[start + 8..end].trim();
                if inner.starts_with('{') {
                    if let Ok(json) = self.repair_json(inner) {
                        return Ok(json);
                    }
                }
            }
        }

        // Case 3: JSON in ```json code blocks
        if let Some(start) = trimmed.find("```json") {
            if let Some(end) = trimmed[start..].find("```\n").or(trimmed[start..].rfind("```")) {
                let inner = trimmed[start + 7..start + end].trim();
                if inner.starts_with('{') {
                    if let Ok(json) = self.repair_json(inner) {
                        return Ok(json);
                    }
                }
            }
        }

        // Case 4: Find first { and last }
        if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
            if end > start {
                let potential_json = &trimmed[start..=end];
                if let Ok(json) = self.repair_json(potential_json) {
                    return Ok(json);
                }
            }
        }

        Err(ValidationError::NoToolCall)
    }

    /// Attempt to repair common JSON errors from LLMs
    fn repair_json(&self, input: &str) -> Result<String, String> {
        // First, try parsing as-is
        if serde_json::from_str::<serde_json::Value>(input).is_ok() {
            return Ok(input.to_string());
        }

        let mut fixed = input.to_string();

        // Fix 1: Replace single quotes with double quotes (but not inside strings)
        fixed = self.fix_quotes(&fixed);

        // Fix 2: Add missing quotes around unquoted keys
        fixed = self.fix_unquoted_keys(&fixed);

        // Fix 3: Remove trailing commas
        fixed = self.fix_trailing_commas(&fixed);

        // Fix 4: Fix boolean/null values
        fixed = fixed.replace("True", "true")
            .replace("False", "false")
            .replace("None", "null");

        // Fix 5: Escape unescaped newlines in strings
        fixed = self.fix_newlines_in_strings(&fixed);

        // Try parsing the fixed version
        if serde_json::from_str::<serde_json::Value>(&fixed).is_ok() {
            return Ok(fixed);
        }

        // Fix 6: Try to extract just the tool call structure
        if let Some(tool_json) = self.extract_tool_structure(&fixed) {
            return Ok(tool_json);
        }

        Err(format!("Could not repair JSON: {}", input))
    }

    /// Fix single quotes to double quotes
    fn fix_quotes(&self, input: &str) -> String {
        // Simple approach: replace all single quotes with double quotes in JSON context
        // This works because valid JSON always uses double quotes
        let mut result = String::with_capacity(input.len());
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let c = chars[i];

            if c == '\'' {
                // Look ahead to see if this is a string delimiter in JSON context
                // Check what's before: should be : [ , { or whitespace
                let before = if i > 0 { chars[i - 1] } else { '{' };
                let is_start = before == ':' || before == '[' || before == ',' || before == '{' || before.is_whitespace();

                if is_start {
                    // Find the closing quote
                    let mut j = i + 1;
                    while j < chars.len() {
                        if chars[j] == '\'' && (j + 1 >= chars.len() ||
                            chars[j + 1] == ',' || chars[j + 1] == '}' ||
                            chars[j + 1] == ']' || chars[j + 1] == ':' ||
                            chars[j + 1].is_whitespace()) {
                            // Found closing quote, replace both
                            result.push('"');
                            // Copy content between quotes
                            for k in (i + 1)..j {
                                result.push(chars[k]);
                            }
                            result.push('"');
                            i = j + 1;
                            break;
                        }
                        j += 1;
                    }
                    if i <= j {
                        // Didn't find closing, just push the char
                        result.push(c);
                        i += 1;
                    }
                    continue;
                }
            }

            result.push(c);
            i += 1;
        }
        result
    }

    /// Fix unquoted keys like {tool: "read"} -> {"tool": "read"}
    fn fix_unquoted_keys(&self, input: &str) -> String {
        let re = regex::Regex::new(r#"(\{|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:"#).unwrap();
        re.replace_all(input, r#"$1"$2":"#).to_string()
    }

    /// Remove trailing commas before } or ]
    fn fix_trailing_commas(&self, input: &str) -> String {
        let re = regex::Regex::new(r",\s*([\}\]])").unwrap();
        re.replace_all(input, "$1").to_string()
    }

    /// Fix unescaped newlines inside strings
    fn fix_newlines_in_strings(&self, input: &str) -> String {
        let mut result = String::new();
        let mut in_string = false;
        let mut escape_next = false;

        for c in input.chars() {
            if escape_next {
                result.push(c);
                escape_next = false;
                continue;
            }

            if c == '\\' {
                result.push(c);
                escape_next = true;
                continue;
            }

            if c == '"' {
                in_string = !in_string;
                result.push(c);
            } else if c == '\n' && in_string {
                result.push_str("\\n");
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Try to extract a valid tool structure from malformed JSON
    fn extract_tool_structure(&self, input: &str) -> Option<String> {
        // Try to find tool name
        let tool_re = regex::Regex::new(r#"["']?tool["']?\s*[:=]\s*["']?([a-z_]+)["']?"#).ok()?;
        let tool_match = tool_re.captures(input)?;
        let tool_name = tool_match.get(1)?.as_str();

        // Try to find args
        let args_re = regex::Regex::new(r#"["']?args["']?\s*[:=]\s*(\{[^}]*\})"#).ok()?;
        let args_str = if let Some(args_match) = args_re.captures(input) {
            args_match.get(1)?.as_str().to_string()
        } else {
            // Try to reconstruct args from known patterns
            self.reconstruct_args(input, tool_name)?
        };

        // Validate args is valid JSON
        let args_fixed = self.fix_quotes(&args_str);
        if serde_json::from_str::<serde_json::Value>(&args_fixed).is_ok() {
            return Some(format!(r#"{{"tool": "{}", "args": {}}}"#, tool_name, args_fixed));
        }

        None
    }

    /// Try to reconstruct args from common patterns
    fn reconstruct_args(&self, input: &str, tool_name: &str) -> Option<String> {
        match tool_name {
            "read_file" | "write_file" | "edit_file" | "glob_files" => {
                // Look for path
                let path_re = regex::Regex::new(r#"["']?path["']?\s*[:=]\s*["']([^"']+)["']"#).ok()?;
                if let Some(path_match) = path_re.captures(input) {
                    let path = path_match.get(1)?.as_str();
                    return Some(format!(r#"{{"path": "{}"}}"#, path));
                }
            }
            "execute_shell" => {
                // Look for command
                let cmd_re = regex::Regex::new(r#"["']?command["']?\s*[:=]\s*["']([^"']+)["']"#).ok()?;
                if let Some(cmd_match) = cmd_re.captures(input) {
                    let cmd = cmd_match.get(1)?.as_str();
                    return Some(format!(r#"{{"command": "{}"}}"#, cmd));
                }
            }
            "grep_files" => {
                // Look for pattern
                let pattern_re = regex::Regex::new(r#"["']?pattern["']?\s*[:=]\s*["']([^"']+)["']"#).ok()?;
                if let Some(pattern_match) = pattern_re.captures(input) {
                    let pattern = pattern_match.get(1)?.as_str();
                    return Some(format!(r#"{{"pattern": "{}"}}"#, pattern));
                }
            }
            _ => {}
        }
        None
    }

    /// Validate basic structure (has tool and args)
    fn validate_structure(&self, value: &serde_json::Value) -> Result<(), ValidationError> {
        let obj = value.as_object()
            .ok_or_else(|| ValidationError::InvalidJson("Expected object".to_string()))?;

        if !obj.contains_key("tool") {
            return Err(ValidationError::MissingField("tool".to_string()));
        }

        if !obj.contains_key("args") {
            return Err(ValidationError::MissingField("args".to_string()));
        }

        Ok(())
    }

    /// Validate against tool-specific schema
    fn validate_against_schema(&self, tool_call: &ToolCall) -> Result<(), ValidationError> {
        let schema = self.schemas.get(&tool_call.tool)
            .ok_or_else(|| ValidationError::UnknownTool(tool_call.tool.clone()))?;

        let args = tool_call.args.as_object()
            .ok_or_else(|| ValidationError::InvalidArgument {
                tool: tool_call.tool.clone(),
                message: "args must be an object".to_string(),
            })?;

        // Check required args
        for required in &schema.required_args {
            if !args.contains_key(required) {
                return Err(ValidationError::InvalidArgument {
                    tool: tool_call.tool.clone(),
                    message: format!("missing required argument: {}", required),
                });
            }
        }

        // Check for unknown args (warning, not error)
        let known_args: Vec<&String> = schema.required_args.iter()
            .chain(schema.optional_args.iter())
            .collect();

        for key in args.keys() {
            if !known_args.contains(&key) {
                eprintln!("[WARN] Unknown argument '{}' for tool '{}'", key, tool_call.tool);
            }
        }

        Ok(())
    }

    /// Get list of available tools for prompt construction
    pub fn get_tool_descriptions(&self) -> String {
        self.schemas.values()
            .map(|s| {
                let args = s.required_args.iter()
                    .map(|a| format!("{} (required)", a))
                    .chain(s.optional_args.iter().map(|a| format!("{} (optional)", a)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("- {}: {} [args: {}]", s.name, s.description, args)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Check if a tool name is valid
    pub fn is_valid_tool(&self, name: &str) -> bool {
        self.schemas.contains_key(name)
    }
}

impl Default for ToolCallValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_json_extraction() {
        let validator = ToolCallValidator::new();
        let input = r#"{"tool": "read_file", "args": {"path": "test.rs"}}"#;
        let result = validator.extract_and_validate(input);
        assert!(result.is_ok());
        let tool_call = result.unwrap();
        assert_eq!(tool_call.tool, "read_file");
    }

    #[test]
    fn test_repair_single_quotes() {
        let validator = ToolCallValidator::new();
        let input = r#"{'tool': 'read_file', 'args': {'path': 'test.rs'}}"#;
        let result = validator.extract_and_validate(input);
        assert!(result.is_ok(), "Should repair single quotes");
    }

    #[test]
    fn test_repair_unquoted_keys() {
        let validator = ToolCallValidator::new();
        let input = r#"{tool: "read_file", args: {path: "test.rs"}}"#;
        let result = validator.extract_and_validate(input);
        assert!(result.is_ok(), "Should repair unquoted keys");
    }

    #[test]
    fn test_repair_trailing_comma() {
        let validator = ToolCallValidator::new();
        let input = r#"{"tool": "read_file", "args": {"path": "test.rs",}}"#;
        let result = validator.extract_and_validate(input);
        assert!(result.is_ok(), "Should repair trailing commas");
    }

    #[test]
    fn test_repair_mixed_issues() {
        let validator = ToolCallValidator::new();
        let input = r#"{tool: 'execute_shell', args: {command: 'ls -la',}}"#;
        let result = validator.extract_and_validate(input);
        assert!(result.is_ok(), "Should repair multiple issues");
    }

    #[test]
    fn test_extract_from_verbose_output() {
        let validator = ToolCallValidator::new();
        let input = r#"
I'll help you read the file.

Let me use the read_file tool:

{"tool": "read_file", "args": {"path": "main.rs"}}

This will show the contents.
"#;
        let result = validator.extract_and_validate(input);
        assert!(result.is_ok(), "Should extract JSON from verbose output");
    }

    #[test]
    fn test_json_in_action_tags() {
        let validator = ToolCallValidator::new();
        let input = r#"
<thinking>
I need to read the file.
</thinking>

<action>
{"tool": "read_file", "args": {"path": "test.rs"}}
</action>
"#;
        let result = validator.extract_and_validate(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_json_in_code_block() {
        let validator = ToolCallValidator::new();
        let input = r#"
Here's what I'll do:

```json
{"tool": "execute_shell", "args": {"command": "ls -la"}}
```
"#;
        let result = validator.extract_and_validate(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_required_arg() {
        let validator = ToolCallValidator::new();
        let input = r#"{"tool": "read_file", "args": {}}"#;
        let result = validator.extract_and_validate(input);
        assert!(matches!(result, Err(ValidationError::InvalidArgument { .. })));
    }

    #[test]
    fn test_unknown_tool() {
        let validator = ToolCallValidator::new();
        let input = r#"{"tool": "hack_the_planet", "args": {}}"#;
        let result = validator.extract_and_validate(input);
        assert!(matches!(result, Err(ValidationError::UnknownTool(_))));
    }

    #[test]
    fn test_no_json_found() {
        let validator = ToolCallValidator::new();
        let input = "I think we should read the file but I'm not sure how.";
        let result = validator.extract_and_validate(input);
        assert!(matches!(result, Err(ValidationError::NoToolCall)));
    }

    #[test]
    fn test_all_tools_have_schemas() {
        let validator = ToolCallValidator::new();
        let expected_tools = vec![
            "read_file", "write_file", "edit_file", "execute_shell",
            "glob_files", "grep_files", "web_fetch", "done"
        ];
        for tool in expected_tools {
            assert!(validator.is_valid_tool(tool), "Missing schema for: {}", tool);
        }
    }
}
