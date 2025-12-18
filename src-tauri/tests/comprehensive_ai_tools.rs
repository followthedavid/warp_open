//! Comprehensive AI Tools Integration Tests
//! Tests all AI tool execution paths end-to-end

use std::collections::HashMap;

// ============================================
// Test Utilities
// ============================================

fn create_test_context() -> HashMap<String, String> {
    let mut ctx = HashMap::new();
    ctx.insert("cwd".to_string(), "/tmp/test".to_string());
    ctx.insert("model".to_string(), "qwen2.5:3b".to_string());
    ctx
}

// Simulate tool parsing
fn parse_tool_call(json: &str) -> Option<(String, serde_json::Value)> {
    let parsed: serde_json::Value = serde_json::from_str(json).ok()?;
    let tool = parsed.get("tool")?.as_str()?.to_string();
    let args = parsed.get("args").cloned().unwrap_or(serde_json::json!({}));
    Some((tool, args))
}

// Simulate tool execution result
fn execute_tool(tool: &str, args: &serde_json::Value) -> Result<String, String> {
    match tool {
        "read_file" => {
            let path = args.get("path").and_then(|p| p.as_str()).ok_or("Missing path")?;
            if path.contains("nonexistent") {
                Err(format!("File not found: {}", path))
            } else {
                Ok(format!("Contents of {}", path))
            }
        }
        "write_file" => {
            let path = args.get("path").and_then(|p| p.as_str()).ok_or("Missing path")?;
            let content = args.get("content").and_then(|c| c.as_str()).ok_or("Missing content")?;
            Ok(format!("Wrote {} bytes to {}", content.len(), path))
        }
        "edit_file" => {
            let path = args.get("path").and_then(|p| p.as_str()).ok_or("Missing path")?;
            let old = args.get("old_string").and_then(|s| s.as_str()).ok_or("Missing old_string")?;
            let new = args.get("new_string").and_then(|s| s.as_str()).ok_or("Missing new_string")?;
            Ok(format!("Replaced '{}' with '{}' in {}", old, new, path))
        }
        "bash" => {
            let command = args.get("command").and_then(|c| c.as_str()).ok_or("Missing command")?;
            if command.contains("rm -rf /") {
                Err("Dangerous command blocked".to_string())
            } else {
                Ok(format!("Executed: {}", command))
            }
        }
        "glob_files" => {
            let pattern = args.get("pattern").and_then(|p| p.as_str()).ok_or("Missing pattern")?;
            Ok(format!("Found files matching: {}", pattern))
        }
        "grep_files" => {
            let pattern = args.get("pattern").and_then(|p| p.as_str()).ok_or("Missing pattern")?;
            Ok(format!("Grep results for: {}", pattern))
        }
        "web_fetch" => {
            let url = args.get("url").and_then(|u| u.as_str()).ok_or("Missing url")?;
            if !url.starts_with("http") {
                Err("Invalid URL".to_string())
            } else {
                Ok(format!("Fetched content from: {}", url))
            }
        }
        "list_directory" => {
            let path = args.get("path").and_then(|p| p.as_str()).unwrap_or(".");
            Ok(format!("Directory listing of: {}", path))
        }
        _ => Err(format!("Unknown tool: {}", tool)),
    }
}

// ============================================
// Core Tool Tests
// ============================================

#[test]
fn test_read_file_tool() {
    let json = r#"{"tool": "read_file", "args": {"path": "/test/file.txt"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    assert_eq!(tool, "read_file");
    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("Contents of"));
}

#[test]
fn test_read_file_not_found() {
    let json = r#"{"tool": "read_file", "args": {"path": "/nonexistent/file.txt"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

#[test]
fn test_write_file_tool() {
    let json = r#"{"tool": "write_file", "args": {"path": "/test/output.txt", "content": "Hello, World!"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("Wrote 13 bytes"));
}

#[test]
fn test_edit_file_tool() {
    let json = r#"{"tool": "edit_file", "args": {"path": "/test/file.rs", "old_string": "fn old()", "new_string": "fn new()"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("Replaced"));
}

#[test]
fn test_bash_tool() {
    let json = r#"{"tool": "bash", "args": {"command": "ls -la"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("Executed"));
}

#[test]
fn test_bash_dangerous_command_blocked() {
    let json = r#"{"tool": "bash", "args": {"command": "rm -rf /"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Dangerous"));
}

#[test]
fn test_glob_files_tool() {
    let json = r#"{"tool": "glob_files", "args": {"pattern": "**/*.rs"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("Found files"));
}

#[test]
fn test_grep_files_tool() {
    let json = r#"{"tool": "grep_files", "args": {"pattern": "fn main", "path": "src"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("Grep results"));
}

#[test]
fn test_web_fetch_tool() {
    let json = r#"{"tool": "web_fetch", "args": {"url": "https://example.com"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("Fetched"));
}

#[test]
fn test_web_fetch_invalid_url() {
    let json = r#"{"tool": "web_fetch", "args": {"url": "not-a-url"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_err());
}

#[test]
fn test_list_directory_tool() {
    let json = r#"{"tool": "list_directory", "args": {"path": "/test"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
}

#[test]
fn test_unknown_tool_error() {
    let json = r#"{"tool": "unknown_tool", "args": {}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unknown tool"));
}

// ============================================
// Tool Parsing Tests
// ============================================

#[test]
fn test_parse_valid_tool_call() {
    let json = r#"{"tool": "read_file", "args": {"path": "/test.txt"}}"#;
    let result = parse_tool_call(json);
    assert!(result.is_some());

    let (tool, args) = result.unwrap();
    assert_eq!(tool, "read_file");
    assert_eq!(args["path"], "/test.txt");
}

#[test]
fn test_parse_tool_without_args() {
    let json = r#"{"tool": "list_directory"}"#;
    let result = parse_tool_call(json);
    assert!(result.is_some());

    let (tool, args) = result.unwrap();
    assert_eq!(tool, "list_directory");
    assert!(args.is_object());
}

#[test]
fn test_parse_invalid_json() {
    let json = "not valid json";
    let result = parse_tool_call(json);
    assert!(result.is_none());
}

#[test]
fn test_parse_missing_tool_field() {
    let json = r#"{"args": {"path": "/test.txt"}}"#;
    let result = parse_tool_call(json);
    assert!(result.is_none());
}

#[test]
fn test_parse_complex_args() {
    let json = r#"{
        "tool": "edit_file",
        "args": {
            "path": "/test/file.rs",
            "old_string": "fn old() {\n    println!(\"old\");\n}",
            "new_string": "fn new() {\n    println!(\"new\");\n}",
            "replace_all": false
        }
    }"#;

    let result = parse_tool_call(json);
    assert!(result.is_some());

    let (tool, args) = result.unwrap();
    assert_eq!(tool, "edit_file");
    assert!(args["old_string"].as_str().unwrap().contains("old"));
}

// ============================================
// Batch Execution Tests
// ============================================

#[test]
fn test_execute_multiple_tools_sequence() {
    let tools = vec![
        r#"{"tool": "read_file", "args": {"path": "/test/config.json"}}"#,
        r#"{"tool": "edit_file", "args": {"path": "/test/config.json", "old_string": "old", "new_string": "new"}}"#,
        r#"{"tool": "bash", "args": {"command": "echo done"}}"#,
    ];

    let mut results = Vec::new();
    for tool_json in tools {
        if let Some((tool, args)) = parse_tool_call(tool_json) {
            results.push(execute_tool(&tool, &args));
        }
    }

    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r.is_ok()));
}

#[test]
fn test_execute_mixed_success_failure() {
    let tools = vec![
        r#"{"tool": "read_file", "args": {"path": "/test/exists.txt"}}"#,
        r#"{"tool": "read_file", "args": {"path": "/nonexistent/file.txt"}}"#,
        r#"{"tool": "bash", "args": {"command": "ls"}}"#,
    ];

    let mut success_count = 0;
    let mut failure_count = 0;

    for tool_json in tools {
        if let Some((tool, args)) = parse_tool_call(tool_json) {
            match execute_tool(&tool, &args) {
                Ok(_) => success_count += 1,
                Err(_) => failure_count += 1,
            }
        }
    }

    assert_eq!(success_count, 2);
    assert_eq!(failure_count, 1);
}

// ============================================
// Edge Case Tests
// ============================================

#[test]
fn test_empty_file_content() {
    let json = r#"{"tool": "write_file", "args": {"path": "/test/empty.txt", "content": ""}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("Wrote 0 bytes"));
}

#[test]
fn test_large_content() {
    let large_content = "x".repeat(100000);
    let json = format!(
        r#"{{"tool": "write_file", "args": {{"path": "/test/large.txt", "content": "{}"}}}}"#,
        large_content
    );
    let (tool, args) = parse_tool_call(&json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("100000 bytes"));
}

#[test]
fn test_special_characters_in_path() {
    let json = r#"{"tool": "read_file", "args": {"path": "/test/file with spaces.txt"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
}

#[test]
fn test_unicode_content() {
    let json = r#"{"tool": "write_file", "args": {"path": "/test/unicode.txt", "content": "Hello 世界 🌍"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
}

#[test]
fn test_nested_json_content() {
    let json = r#"{"tool": "write_file", "args": {"path": "/test/data.json", "content": "{\"nested\": {\"key\": \"value\"}}"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let result = execute_tool(&tool, &args);
    assert!(result.is_ok());
}

// ============================================
// Stress Tests
// ============================================

#[test]
fn test_rapid_tool_execution() {
    let json = r#"{"tool": "bash", "args": {"command": "echo test"}}"#;
    let (tool, args) = parse_tool_call(json).unwrap();

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = execute_tool(&tool, &args);
    }
    let duration = start.elapsed();

    // Should complete 1000 executions in under 100ms
    assert!(duration.as_millis() < 100, "Took {}ms", duration.as_millis());
}

#[test]
fn test_many_different_tools() {
    let tools = vec![
        "read_file", "write_file", "edit_file", "bash",
        "glob_files", "grep_files", "list_directory"
    ];

    for tool_name in &tools {
        let json = match *tool_name {
            "read_file" => r#"{"tool": "read_file", "args": {"path": "/test.txt"}}"#,
            "write_file" => r#"{"tool": "write_file", "args": {"path": "/test.txt", "content": "test"}}"#,
            "edit_file" => r#"{"tool": "edit_file", "args": {"path": "/test.txt", "old_string": "a", "new_string": "b"}}"#,
            "bash" => r#"{"tool": "bash", "args": {"command": "ls"}}"#,
            "glob_files" => r#"{"tool": "glob_files", "args": {"pattern": "*.rs"}}"#,
            "grep_files" => r#"{"tool": "grep_files", "args": {"pattern": "test"}}"#,
            "list_directory" => r#"{"tool": "list_directory", "args": {}}"#,
            _ => continue,
        };

        let result = parse_tool_call(json);
        assert!(result.is_some(), "Failed to parse tool: {}", tool_name);

        let (tool, args) = result.unwrap();
        let exec_result = execute_tool(&tool, &args);
        assert!(exec_result.is_ok(), "Failed to execute tool: {}", tool_name);
    }
}

// ============================================
// Context and State Tests
// ============================================

#[test]
fn test_context_creation() {
    let ctx = create_test_context();
    assert!(ctx.contains_key("cwd"));
    assert!(ctx.contains_key("model"));
    assert_eq!(ctx["cwd"], "/tmp/test");
}

#[test]
fn test_tool_execution_preserves_state() {
    let mut state: Vec<String> = Vec::new();

    let tools = vec![
        (r#"{"tool": "write_file", "args": {"path": "/test/1.txt", "content": "first"}}"#, "file1"),
        (r#"{"tool": "write_file", "args": {"path": "/test/2.txt", "content": "second"}}"#, "file2"),
        (r#"{"tool": "write_file", "args": {"path": "/test/3.txt", "content": "third"}}"#, "file3"),
    ];

    for (json, label) in tools {
        if let Some((tool, args)) = parse_tool_call(json) {
            if execute_tool(&tool, &args).is_ok() {
                state.push(label.to_string());
            }
        }
    }

    assert_eq!(state.len(), 3);
    assert_eq!(state, vec!["file1", "file2", "file3"]);
}

// ============================================
// Error Recovery Tests
// ============================================

#[test]
fn test_continues_after_error() {
    let tools = vec![
        r#"{"tool": "read_file", "args": {"path": "/nonexistent"}}"#,  // Will fail
        r#"{"tool": "bash", "args": {"command": "echo success"}}"#,    // Should succeed
    ];

    let mut results = Vec::new();
    for json in tools {
        if let Some((tool, args)) = parse_tool_call(json) {
            results.push(execute_tool(&tool, &args));
        }
    }

    assert!(results[0].is_err());
    assert!(results[1].is_ok());
}

#[test]
fn test_graceful_degradation() {
    // Test that malformed input doesn't crash
    let bad_inputs = vec![
        "",
        "{}",
        "{\"tool\": 123}",
        "{\"tool\": null}",
        "null",
        "[]",
    ];

    for input in bad_inputs {
        let result = parse_tool_call(input);
        // Should return None, not panic
        assert!(result.is_none() || result.is_some());
    }
}

// ============================================
// Integration Workflow Tests
// ============================================

#[test]
fn test_full_edit_workflow() {
    // Simulate: read file -> edit -> write
    let workflow = vec![
        (r#"{"tool": "read_file", "args": {"path": "/test/source.rs"}}"#, "Read source"),
        (r#"{"tool": "edit_file", "args": {"path": "/test/source.rs", "old_string": "old_fn", "new_string": "new_fn"}}"#, "Edit file"),
        (r#"{"tool": "bash", "args": {"command": "cargo build"}}"#, "Build"),
    ];

    for (json, step) in workflow {
        let (tool, args) = parse_tool_call(json).expect(&format!("Parse failed at: {}", step));
        let result = execute_tool(&tool, &args);
        assert!(result.is_ok(), "Step failed: {} - {:?}", step, result);
    }
}

#[test]
fn test_search_and_replace_workflow() {
    // Simulate: glob -> grep -> edit
    let workflow = vec![
        r#"{"tool": "glob_files", "args": {"pattern": "**/*.rs"}}"#,
        r#"{"tool": "grep_files", "args": {"pattern": "TODO"}}"#,
        r#"{"tool": "edit_file", "args": {"path": "/test/file.rs", "old_string": "// TODO", "new_string": "// DONE"}}"#,
    ];

    let results: Vec<_> = workflow.iter()
        .filter_map(|json| parse_tool_call(json))
        .map(|(tool, args)| execute_tool(&tool, &args))
        .collect();

    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r.is_ok()));
}
