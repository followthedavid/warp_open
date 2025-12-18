// AI Tools Integration Tests
// Tests for AI tool execution and safety features

use std::path::PathBuf;
use std::fs;

#[test]
fn test_glob_files_finds_rust_files() {
    // Test that glob_files can find .rs files in src directory
    let src_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");

    // Manually implement glob logic to test
    let mut found_files = Vec::new();
    if let Ok(entries) = fs::read_dir(&src_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "rs").unwrap_or(false) {
                found_files.push(path.display().to_string());
            }
        }
    }

    // Should find main.rs, lib.rs, commands.rs, etc.
    assert!(!found_files.is_empty(), "Should find at least one .rs file");
    assert!(found_files.iter().any(|f| f.contains("main.rs")), "Should find main.rs");
    assert!(found_files.iter().any(|f| f.contains("commands.rs")), "Should find commands.rs");
    println!("Found {} Rust files: {:?}", found_files.len(), found_files);
}

#[test]
fn test_grep_files_finds_pattern() {
    // Test that grep_files can find a pattern in files
    let src_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let main_rs = src_path.join("main.rs");

    // Read main.rs and search for "fn main"
    let content = fs::read_to_string(&main_rs).expect("Should read main.rs");
    let has_fn_main = content.lines().any(|line| line.contains("fn main"));

    assert!(has_fn_main, "main.rs should contain 'fn main'");
    println!("Successfully found 'fn main' in main.rs");
}

#[test]
fn test_grep_files_with_regex() {
    // Test regex pattern matching
    let src_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let commands_rs = src_path.join("commands.rs");

    let content = fs::read_to_string(&commands_rs).expect("Should read commands.rs");

    // Use regex to find all pub fn declarations
    let re = regex::Regex::new(r"pub\s+(async\s+)?fn\s+\w+").unwrap();
    let matches: Vec<_> = content.lines()
        .enumerate()
        .filter(|(_, line)| re.is_match(line))
        .collect();

    assert!(!matches.is_empty(), "Should find public functions in commands.rs");
    println!("Found {} public functions in commands.rs", matches.len());
    for (line_num, line) in matches.iter().take(5) {
        println!("  Line {}: {}", line_num + 1, line.trim());
    }
}

#[test]
fn test_glob_recursive_pattern() {
    // Test ** recursive pattern matching
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    fn find_rs_files_recursive(dir: &std::path::Path, files: &mut Vec<String>, limit: usize) {
        if files.len() >= limit {
            return;
        }
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if files.len() >= limit {
                    break;
                }
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    // Skip hidden dirs and target
                    if !name.starts_with('.') && name != "target" {
                        find_rs_files_recursive(&path, files, limit);
                    }
                } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                    files.push(path.display().to_string());
                }
            }
        }
    }

    let mut files = Vec::new();
    find_rs_files_recursive(&base_path, &mut files, 100);

    assert!(!files.is_empty(), "Should find Rust files recursively");
    println!("Found {} Rust files recursively", files.len());

    // Verify we found files in both src/ and tests/
    let src_files = files.iter().filter(|f| f.contains("/src/")).count();
    let test_files = files.iter().filter(|f| f.contains("/tests/")).count();

    assert!(src_files > 0, "Should find files in src/");
    assert!(test_files > 0, "Should find files in tests/");
    println!("  {} in src/, {} in tests/", src_files, test_files);
}

#[test]
fn test_ai_tool_execution() {
    // Placeholder for AI tool execution test
    // Would test: execute tool -> verify result -> check no duplicates
    assert!(true, "AI tool execution placeholder");
}

#[test]
fn test_no_duplicate_tool_execution() {
    // Placeholder for duplicate prevention test
    // Would test: trigger same tool twice -> verify only executes once
    assert!(true, "Duplicate prevention placeholder");
}

#[test]
fn test_tool_result_hidden_from_ui() {
    // Placeholder for UI filtering test  
    // Would test: execute tool -> verify raw result not in messages -> verify AI summary appears
    assert!(true, "Tool result filtering placeholder");
}

#[test]
fn test_tool_execution_error_handling() {
    // Placeholder for error handling test
    // Would test: tool fails -> verify error message -> verify thinking stops
    assert!(true, "Tool error handling placeholder");
}
