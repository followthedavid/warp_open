// AI Response Parser for Phase 3
// Detects multiple tool calls in AI responses and parses them

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ParsedToolCall {
    pub tool: String,
    pub args: Value,
}

/// Parse AI response and extract multiple tool calls
/// Returns vector of tool calls if 2+ found, None otherwise
pub fn parse_multiple_tool_calls(response: &str) -> Option<Vec<ParsedToolCall>> {
    let mut tool_calls = Vec::new();
    
    // Look for JSON blocks that contain "tool" field
    // Pattern: {"tool":"...", "args":{...}}
    
    let lines: Vec<&str> = response.lines().collect();
    let mut current_json = String::new();
    let mut in_json = false;
    let mut brace_count = 0;
    
    for line in lines {
        let trimmed = line.trim();
        
        // Check if line starts a JSON object
        if trimmed.starts_with('{') {
            in_json = true;
            brace_count = 0;
            current_json.clear();
        }
        
        if in_json {
            current_json.push_str(trimmed);
            
            // Count braces
            for ch in trimmed.chars() {
                match ch {
                    '{' => brace_count += 1,
                    '}' => brace_count -= 1,
                    _ => {}
                }
            }
            
            // Complete JSON object
            if brace_count == 0 && !current_json.is_empty() {
                if let Ok(json) = serde_json::from_str::<Value>(&current_json) {
                    // Check if this is a tool call
                    if let Some(tool) = json.get("tool").and_then(|t| t.as_str()) {
                        if let Some(args) = json.get("args") {
                            tool_calls.push(ParsedToolCall {
                                tool: tool.to_string(),
                                args: args.clone(),
                            });
                            eprintln!("[AI Parser] Found tool call: {}", tool);
                        }
                    }
                }
                in_json = false;
                current_json.clear();
            }
        }
    }
    
    // Only return if we found 2 or more tool calls
    if tool_calls.len() >= 2 {
        eprintln!("[AI Parser] Found {} tool calls, creating batch", tool_calls.len());
        Some(tool_calls)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_single_tool_call() {
        let response = r#"{"tool":"execute_shell","args":{"command":"ls"}}"#;
        let result = parse_multiple_tool_calls(response);
        assert!(result.is_none()); // Should return None for single call
    }
    
    #[test]
    fn test_multiple_tool_calls() {
        let response = r#"
{"tool":"execute_shell","args":{"command":"echo test"}}
{"tool":"execute_shell","args":{"command":"pwd"}}
{"tool":"read_file","args":{"path":"test.txt"}}
        "#;
        let result = parse_multiple_tool_calls(response);
        assert!(result.is_some());
        let calls = result.unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].tool, "execute_shell");
        assert_eq!(calls[1].tool, "execute_shell");
        assert_eq!(calls[2].tool, "read_file");
    }
    
    #[test]
    fn test_mixed_content() {
        let response = r#"
Here are the commands I'll run:
{"tool":"execute_shell","args":{"command":"echo test"}}
And then:
{"tool":"execute_shell","args":{"command":"pwd"}}
        "#;
        let result = parse_multiple_tool_calls(response);
        assert!(result.is_some());
        let calls = result.unwrap();
        assert_eq!(calls.len(), 2);
    }
}
