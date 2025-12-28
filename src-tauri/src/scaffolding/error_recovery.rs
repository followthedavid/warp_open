// Error Recovery System
//
// Teaches the model common recovery patterns for errors.
// Enables automatic retry with intelligent fixes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStrategy {
    pub error_pattern: String,
    pub suggestion: String,
    pub alternative_tool: Option<String>,
    pub example_fix: Option<String>,
}

pub struct ErrorRecovery {
    strategies: HashMap<String, Vec<RecoveryStrategy>>,
}

impl ErrorRecovery {
    pub fn new() -> Self {
        let mut strategies: HashMap<String, Vec<RecoveryStrategy>> = HashMap::new();

        // File not found strategies
        strategies.insert("file_not_found".to_string(), vec![
            RecoveryStrategy {
                error_pattern: "not found".to_string(),
                suggestion: "The file doesn't exist. Try using glob_files to find similar files.".to_string(),
                alternative_tool: Some("glob_files".to_string()),
                example_fix: Some(r#"{"tool": "glob_files", "args": {"pattern": "**/*.rs"}}"#.to_string()),
            },
            RecoveryStrategy {
                error_pattern: "no such file".to_string(),
                suggestion: "Check the path. It might be relative vs absolute, or the file might be in a subdirectory.".to_string(),
                alternative_tool: Some("glob_files".to_string()),
                example_fix: None,
            },
        ]);

        // Permission errors
        strategies.insert("permission".to_string(), vec![
            RecoveryStrategy {
                error_pattern: "permission denied".to_string(),
                suggestion: "Permission denied. Try a different location or check if the file is read-only.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
            RecoveryStrategy {
                error_pattern: "access denied".to_string(),
                suggestion: "Cannot access this path. Try using the current directory or /tmp.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
        ]);

        // Syntax/parse errors
        strategies.insert("syntax".to_string(), vec![
            RecoveryStrategy {
                error_pattern: "syntax error".to_string(),
                suggestion: "There's a syntax error in the code. Re-read the file and identify the issue.".to_string(),
                alternative_tool: Some("read_file".to_string()),
                example_fix: None,
            },
            RecoveryStrategy {
                error_pattern: "parse error".to_string(),
                suggestion: "The code couldn't be parsed. Check for missing semicolons, brackets, or quotes.".to_string(),
                alternative_tool: Some("read_file".to_string()),
                example_fix: None,
            },
            RecoveryStrategy {
                error_pattern: "unexpected token".to_string(),
                suggestion: "Unexpected token in code. Review the edit and fix the syntax.".to_string(),
                alternative_tool: Some("read_file".to_string()),
                example_fix: None,
            },
        ]);

        // Edit-specific errors
        strategies.insert("edit".to_string(), vec![
            RecoveryStrategy {
                error_pattern: "old_string not found".to_string(),
                suggestion: "The exact string to replace wasn't found. Read the file first to see the actual content.".to_string(),
                alternative_tool: Some("read_file".to_string()),
                example_fix: None,
            },
            RecoveryStrategy {
                error_pattern: "multiple matches".to_string(),
                suggestion: "Multiple matches found. Make the old_string more specific or use replace_all.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
        ]);

        // Command errors
        strategies.insert("command".to_string(), vec![
            RecoveryStrategy {
                error_pattern: "command not found".to_string(),
                suggestion: "The command doesn't exist. Check spelling or try an alternative.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
            RecoveryStrategy {
                error_pattern: "exit code".to_string(),
                suggestion: "Command exited with error. Check the output for details.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
            RecoveryStrategy {
                error_pattern: "timeout".to_string(),
                suggestion: "Command timed out. It might be stuck or taking too long.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
        ]);

        // Network errors
        strategies.insert("network".to_string(), vec![
            RecoveryStrategy {
                error_pattern: "connection refused".to_string(),
                suggestion: "Cannot connect to server. Check if the URL is correct.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
            RecoveryStrategy {
                error_pattern: "timeout".to_string(),
                suggestion: "Network request timed out. The server might be slow or unreachable.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
            RecoveryStrategy {
                error_pattern: "404".to_string(),
                suggestion: "Page not found (404). Check the URL.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
        ]);

        // Grep/search errors
        strategies.insert("search".to_string(), vec![
            RecoveryStrategy {
                error_pattern: "no matches".to_string(),
                suggestion: "No matches found. Try a broader search pattern or different file types.".to_string(),
                alternative_tool: None,
                example_fix: Some(r#"{"tool": "grep_files", "args": {"pattern": ".*keyword.*", "case_insensitive": true}}"#.to_string()),
            },
            RecoveryStrategy {
                error_pattern: "invalid regex".to_string(),
                suggestion: "Invalid regex pattern. Escape special characters or simplify the pattern.".to_string(),
                alternative_tool: None,
                example_fix: None,
            },
        ]);

        Self { strategies }
    }

    /// Find matching recovery strategies for an error
    pub fn find_strategies(&self, error: &str) -> Vec<&RecoveryStrategy> {
        let lower = error.to_lowercase();
        let mut matches = Vec::new();

        for strategies in self.strategies.values() {
            for strategy in strategies {
                if lower.contains(&strategy.error_pattern.to_lowercase()) {
                    matches.push(strategy);
                }
            }
        }

        matches
    }

    /// Get the best recovery suggestion for an error
    pub fn get_suggestion(&self, error: &str) -> Option<&RecoveryStrategy> {
        self.find_strategies(error).first().copied()
    }

    /// Generate a recovery prompt for the LLM
    pub fn get_recovery_prompt(
        &self,
        tool: &str,
        args: &serde_json::Value,
        error: &str,
        original_intent: &str,
    ) -> String {
        let strategies = self.find_strategies(error);

        let mut prompt = format!(r#"The previous action FAILED.

Tool: {}
Arguments: {}

Error: {}

Original intent: {}
"#, tool, serde_json::to_string_pretty(args).unwrap_or_default(), error, original_intent);

        if !strategies.is_empty() {
            prompt.push_str("\nRECOVERY SUGGESTIONS:\n");
            for (i, strategy) in strategies.iter().enumerate() {
                prompt.push_str(&format!("{}. {}\n", i + 1, strategy.suggestion));
                if let Some(alt) = &strategy.alternative_tool {
                    prompt.push_str(&format!("   Alternative tool: {}\n", alt));
                }
                if let Some(example) = &strategy.example_fix {
                    prompt.push_str(&format!("   Example: {}\n", example));
                }
            }
        } else {
            prompt.push_str("\nNo specific recovery pattern found. Analyze the error and try a different approach.\n");
        }

        prompt.push_str(r#"
Think about what went wrong and output a DIFFERENT action to try.

<thinking>
1. What does the error mean?
2. What should I do differently?
3. What tool should I use now?
</thinking>

<action>
{"tool": "...", "args": {...}}
</action>
"#);

        prompt
    }

    /// Check if an error is recoverable
    pub fn is_recoverable(&self, error: &str) -> bool {
        let lower = error.to_lowercase();

        // Non-recoverable errors
        let non_recoverable = [
            "out of memory",
            "disk full",
            "fatal",
            "panic",
            "segmentation fault",
            "killed",
        ];

        if non_recoverable.iter().any(|e| lower.contains(e)) {
            return false;
        }

        // If we have strategies, it's recoverable
        !self.find_strategies(error).is_empty()
    }

    /// Classify the error type
    pub fn classify_error(&self, error: &str) -> ErrorType {
        let lower = error.to_lowercase();

        if lower.contains("not found") || lower.contains("no such file") {
            return ErrorType::NotFound;
        }
        if lower.contains("permission") || lower.contains("access denied") {
            return ErrorType::Permission;
        }
        if lower.contains("syntax") || lower.contains("parse") {
            return ErrorType::Syntax;
        }
        if lower.contains("timeout") {
            return ErrorType::Timeout;
        }
        if lower.contains("connection") || lower.contains("network") {
            return ErrorType::Network;
        }

        ErrorType::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorType {
    NotFound,
    Permission,
    Syntax,
    Timeout,
    Network,
    Unknown,
}

impl Default for ErrorRecovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_strategies_file_not_found() {
        let recovery = ErrorRecovery::new();
        let strategies = recovery.find_strategies("Error: file not found at /path/to/file");
        assert!(!strategies.is_empty());
        assert!(strategies[0].suggestion.contains("glob_files"));
    }

    #[test]
    fn test_find_strategies_permission() {
        let recovery = ErrorRecovery::new();
        let strategies = recovery.find_strategies("Permission denied: /etc/passwd");
        assert!(!strategies.is_empty());
    }

    #[test]
    fn test_find_strategies_syntax() {
        let recovery = ErrorRecovery::new();
        let strategies = recovery.find_strategies("Syntax error on line 42");
        assert!(!strategies.is_empty());
    }

    #[test]
    fn test_is_recoverable() {
        let recovery = ErrorRecovery::new();

        assert!(recovery.is_recoverable("file not found"));
        assert!(recovery.is_recoverable("permission denied"));
        assert!(recovery.is_recoverable("syntax error"));

        assert!(!recovery.is_recoverable("out of memory"));
        assert!(!recovery.is_recoverable("fatal error"));
    }

    #[test]
    fn test_classify_error() {
        let recovery = ErrorRecovery::new();

        assert_eq!(recovery.classify_error("file not found"), ErrorType::NotFound);
        assert_eq!(recovery.classify_error("permission denied"), ErrorType::Permission);
        assert_eq!(recovery.classify_error("syntax error"), ErrorType::Syntax);
        assert_eq!(recovery.classify_error("connection refused"), ErrorType::Network);
        assert_eq!(recovery.classify_error("something weird"), ErrorType::Unknown);
    }

    #[test]
    fn test_recovery_prompt_generation() {
        let recovery = ErrorRecovery::new();
        let prompt = recovery.get_recovery_prompt(
            "read_file",
            &serde_json::json!({"path": "missing.rs"}),
            "Error: file not found",
            "Read the main source file"
        );

        assert!(prompt.contains("FAILED"));
        assert!(prompt.contains("RECOVERY SUGGESTIONS"));
        assert!(prompt.contains("<thinking>"));
        assert!(prompt.contains("<action>"));
    }
}
