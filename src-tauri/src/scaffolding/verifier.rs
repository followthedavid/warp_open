// Self-Verification Loop
//
// Makes the model check its own work after each action.
// Catches mistakes before they compound.

use serde::{Deserialize, Serialize};
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationResult {
    Verified { reason: String },
    Failed { reason: String },
    Retry { suggestion: String },
    Uncertain { reason: String },
}

impl VerificationResult {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    pub fn should_retry(&self) -> bool {
        matches!(self, Self::Retry { .. })
    }

    pub fn get_retry_suggestion(&self) -> Option<&str> {
        match self {
            Self::Retry { suggestion } => Some(suggestion),
            _ => None,
        }
    }
}

pub struct SelfVerifier {
    max_retries: u32,
}

impl SelfVerifier {
    pub fn new() -> Self {
        Self { max_retries: 3 }
    }

    pub fn with_max_retries(max_retries: u32) -> Self {
        Self { max_retries }
    }

    /// Generate prompt to verify an action result
    pub fn get_verification_prompt(
        &self,
        tool: &str,
        args: &serde_json::Value,
        result: &str,
        original_intent: &str,
    ) -> String {
        format!(r#"You just executed this action:

Tool: {}
Arguments: {}

Result:
{}

Original intent: {}

Did this action achieve what was intended?

Respond with EXACTLY one of these formats:
- VERIFIED: [brief reason why it succeeded]
- FAILED: [what went wrong]
- RETRY: [what to do differently]
- UNCERTAIN: [what's unclear]

Be strict. If something looks wrong, say FAILED or RETRY.
"#, tool, serde_json::to_string_pretty(args).unwrap_or_default(), result, original_intent)
    }

    /// Parse verification response from LLM
    pub fn parse_verification(&self, response: &str) -> VerificationResult {
        let trimmed = response.trim();

        // Try to match patterns
        if let Some(rest) = trimmed.strip_prefix("VERIFIED:") {
            return VerificationResult::Verified {
                reason: rest.trim().to_string(),
            };
        }

        if let Some(rest) = trimmed.strip_prefix("FAILED:") {
            return VerificationResult::Failed {
                reason: rest.trim().to_string(),
            };
        }

        if let Some(rest) = trimmed.strip_prefix("RETRY:") {
            return VerificationResult::Retry {
                suggestion: rest.trim().to_string(),
            };
        }

        if let Some(rest) = trimmed.strip_prefix("UNCERTAIN:") {
            return VerificationResult::Uncertain {
                reason: rest.trim().to_string(),
            };
        }

        // Try regex for more flexible matching
        let verified_re = Regex::new(r"(?i)^verified\s*:?\s*(.*)").unwrap();
        let failed_re = Regex::new(r"(?i)^failed\s*:?\s*(.*)").unwrap();
        let retry_re = Regex::new(r"(?i)^retry\s*:?\s*(.*)").unwrap();

        if let Some(caps) = verified_re.captures(trimmed) {
            return VerificationResult::Verified {
                reason: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
            };
        }

        if let Some(caps) = failed_re.captures(trimmed) {
            return VerificationResult::Failed {
                reason: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
            };
        }

        if let Some(caps) = retry_re.captures(trimmed) {
            return VerificationResult::Retry {
                suggestion: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
            };
        }

        // Check for success/failure keywords
        let lower = trimmed.to_lowercase();
        if lower.contains("success") || lower.contains("correct") || lower.contains("worked") {
            return VerificationResult::Verified {
                reason: trimmed.to_string(),
            };
        }

        if lower.contains("error") || lower.contains("wrong") || lower.contains("failed") {
            return VerificationResult::Failed {
                reason: trimmed.to_string(),
            };
        }

        if lower.contains("try") || lower.contains("instead") || lower.contains("should") {
            return VerificationResult::Retry {
                suggestion: trimmed.to_string(),
            };
        }

        // Default to uncertain
        VerificationResult::Uncertain {
            reason: trimmed.to_string(),
        }
    }

    /// Check if result looks like an error (quick heuristic check)
    pub fn looks_like_error(&self, result: &str) -> bool {
        let lower = result.to_lowercase();
        let error_indicators = [
            "error:", "failed", "not found", "permission denied",
            "no such file", "cannot", "unable to", "exception",
            "panic", "fatal", "denied", "invalid",
        ];

        error_indicators.iter().any(|indicator| lower.contains(indicator))
    }

    /// Check if result looks like success
    pub fn looks_like_success(&self, result: &str) -> bool {
        let lower = result.to_lowercase();

        // Empty result might be success for some operations
        if result.trim().is_empty() {
            return false; // Uncertain, not success
        }

        // Explicit success indicators
        let success_indicators = [
            "success", "completed", "created", "written",
            "ok", "done", "finished",
        ];

        if success_indicators.iter().any(|i| lower.contains(i)) {
            return true;
        }

        // No error indicators = probably success
        !self.looks_like_error(result)
    }

    /// Get max retries
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }
}

impl Default for SelfVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification context for tracking retry attempts
#[derive(Debug, Clone)]
pub struct VerificationContext {
    pub tool: String,
    pub original_args: serde_json::Value,
    pub original_intent: String,
    pub attempts: Vec<VerificationAttempt>,
}

#[derive(Debug, Clone)]
pub struct VerificationAttempt {
    pub args: serde_json::Value,
    pub result: String,
    pub verification: VerificationResult,
}

impl VerificationContext {
    pub fn new(tool: &str, args: serde_json::Value, intent: &str) -> Self {
        Self {
            tool: tool.to_string(),
            original_args: args,
            original_intent: intent.to_string(),
            attempts: Vec::new(),
        }
    }

    pub fn add_attempt(&mut self, args: serde_json::Value, result: String, verification: VerificationResult) {
        self.attempts.push(VerificationAttempt {
            args,
            result,
            verification,
        });
    }

    pub fn attempt_count(&self) -> usize {
        self.attempts.len()
    }

    pub fn last_result(&self) -> Option<&VerificationResult> {
        self.attempts.last().map(|a| &a.verification)
    }

    /// Get summary of attempts for retry context
    pub fn get_retry_context(&self) -> String {
        if self.attempts.is_empty() {
            return String::new();
        }

        let mut context = String::from("Previous attempts:\n");
        for (i, attempt) in self.attempts.iter().enumerate() {
            context.push_str(&format!(
                "\nAttempt {}: {} -> {:?}",
                i + 1,
                serde_json::to_string(&attempt.args).unwrap_or_default(),
                attempt.verification
            ));
        }
        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_verified() {
        let verifier = SelfVerifier::new();

        let result = verifier.parse_verification("VERIFIED: The file was created successfully");
        assert!(matches!(result, VerificationResult::Verified { .. }));

        let result = verifier.parse_verification("Verified: looks good");
        assert!(matches!(result, VerificationResult::Verified { .. }));
    }

    #[test]
    fn test_parse_failed() {
        let verifier = SelfVerifier::new();

        let result = verifier.parse_verification("FAILED: File not found");
        assert!(matches!(result, VerificationResult::Failed { .. }));

        let result = verifier.parse_verification("failed: permission denied");
        assert!(matches!(result, VerificationResult::Failed { .. }));
    }

    #[test]
    fn test_parse_retry() {
        let verifier = SelfVerifier::new();

        let result = verifier.parse_verification("RETRY: Use the correct path /src/main.rs");
        assert!(matches!(result, VerificationResult::Retry { .. }));

        if let VerificationResult::Retry { suggestion } = result {
            assert!(suggestion.contains("correct path"));
        }
    }

    #[test]
    fn test_looks_like_error() {
        let verifier = SelfVerifier::new();

        assert!(verifier.looks_like_error("Error: file not found"));
        assert!(verifier.looks_like_error("Permission denied"));
        assert!(verifier.looks_like_error("Cannot read file"));

        assert!(!verifier.looks_like_error("File contents here"));
        assert!(!verifier.looks_like_error("fn main() {}"));
    }

    #[test]
    fn test_looks_like_success() {
        let verifier = SelfVerifier::new();

        assert!(verifier.looks_like_success("File created successfully"));
        assert!(verifier.looks_like_success("fn main() { println!(\"hello\"); }"));

        assert!(!verifier.looks_like_success("Error: not found"));
        assert!(!verifier.looks_like_success("")); // Empty is uncertain
    }

    #[test]
    fn test_verification_context() {
        let mut ctx = VerificationContext::new(
            "read_file",
            serde_json::json!({"path": "test.rs"}),
            "Read the test file"
        );

        assert_eq!(ctx.attempt_count(), 0);

        ctx.add_attempt(
            serde_json::json!({"path": "test.rs"}),
            "Error: not found".to_string(),
            VerificationResult::Failed { reason: "File not found".to_string() }
        );

        assert_eq!(ctx.attempt_count(), 1);
        assert!(matches!(ctx.last_result(), Some(VerificationResult::Failed { .. })));
    }
}
