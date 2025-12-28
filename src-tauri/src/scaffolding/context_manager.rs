// Context Window Manager
//
// Manages the limited context window of local LLMs.
// Intelligently compresses, summarizes, and prioritizes context.

use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};

/// Configuration for context window management
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Maximum tokens to send to the model
    pub max_tokens: usize,
    /// Reserved tokens for model response
    pub response_reserve: usize,
    /// Maximum file content size before truncation
    pub max_file_content: usize,
    /// Maximum number of conversation turns to keep
    pub max_turns: usize,
    /// Enable context compression
    pub enable_compression: bool,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_tokens: 8000,      // Conservative for local models
            response_reserve: 2000, // Reserve for response
            max_file_content: 4000, // Truncate large files
            max_turns: 10,          // Keep recent conversation
            enable_compression: true,
        }
    }
}

impl ContextConfig {
    /// Configuration for small models (3B params)
    pub fn small_model() -> Self {
        Self {
            max_tokens: 4000,
            response_reserve: 1000,
            max_file_content: 2000,
            max_turns: 5,
            enable_compression: true,
        }
    }

    /// Configuration for medium models (7B params)
    pub fn medium_model() -> Self {
        Self::default()
    }

    /// Configuration for large models (14B+ params)
    pub fn large_model() -> Self {
        Self {
            max_tokens: 16000,
            response_reserve: 4000,
            max_file_content: 8000,
            max_turns: 20,
            enable_compression: true,
        }
    }
}

/// A single item in the context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextItem {
    pub item_type: ContextItemType,
    pub content: String,
    pub priority: u8, // 0 = lowest, 255 = highest
    pub timestamp: u64,
    pub token_estimate: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextItemType {
    SystemPrompt,
    UserMessage,
    AssistantMessage,
    ToolResult,
    FileContent,
    Example,
    Summary,
}

impl ContextItemType {
    /// Default priority for this item type
    pub fn default_priority(&self) -> u8 {
        match self {
            Self::SystemPrompt => 255,  // Always keep
            Self::UserMessage => 200,   // Very important
            Self::AssistantMessage => 150,
            Self::ToolResult => 180,    // Recent results important
            Self::FileContent => 120,   // Can be re-read
            Self::Example => 100,       // Nice to have
            Self::Summary => 250,       // Compressed history
        }
    }
}

/// Manages context for LLM calls
pub struct ContextManager {
    config: ContextConfig,
    items: VecDeque<ContextItem>,
    file_cache: HashMap<String, CachedFile>,
}

#[derive(Debug, Clone)]
struct CachedFile {
    content: String,
    truncated_content: String,
    hash: String,
    last_accessed: u64,
}

impl ContextManager {
    pub fn new(config: ContextConfig) -> Self {
        Self {
            config,
            items: VecDeque::new(),
            file_cache: HashMap::new(),
        }
    }

    /// Add a system prompt (highest priority)
    pub fn add_system_prompt(&mut self, content: String) {
        self.add_item(ContextItemType::SystemPrompt, content, 255);
    }

    /// Add a user message
    pub fn add_user_message(&mut self, content: String) {
        self.add_item(ContextItemType::UserMessage, content, 200);
    }

    /// Add an assistant message
    pub fn add_assistant_message(&mut self, content: String) {
        self.add_item(ContextItemType::AssistantMessage, content, 150);
    }

    /// Add a tool result
    pub fn add_tool_result(&mut self, tool: &str, result: String) {
        let formatted = format!("[{}]: {}", tool, result);
        self.add_item(ContextItemType::ToolResult, formatted, 180);
    }

    /// Add file content with caching and truncation
    pub fn add_file_content(&mut self, path: &str, content: String) {
        let hash = format!("{:x}", md5::compute(&content));

        // Check cache
        if let Some(cached) = self.file_cache.get(path) {
            if cached.hash == hash {
                // Same content, use cached truncated version
                self.add_item(ContextItemType::FileContent, cached.truncated_content.clone(), 120);
                return;
            }
        }

        // Truncate if needed
        let truncated = self.truncate_file_content(&content);

        // Cache it
        self.file_cache.insert(path.to_string(), CachedFile {
            content: content.clone(),
            truncated_content: truncated.clone(),
            hash,
            last_accessed: self.current_timestamp(),
        });

        self.add_item(ContextItemType::FileContent, truncated, 120);
    }

    /// Add few-shot examples (lower priority)
    pub fn add_example(&mut self, example: String) {
        self.add_item(ContextItemType::Example, example, 100);
    }

    /// Add a summary (replaces compressed items)
    pub fn add_summary(&mut self, summary: String) {
        self.add_item(ContextItemType::Summary, summary, 250);
    }

    fn add_item(&mut self, item_type: ContextItemType, content: String, priority: u8) {
        let token_estimate = self.estimate_tokens(&content);

        self.items.push_back(ContextItem {
            item_type,
            content,
            priority,
            timestamp: self.current_timestamp(),
            token_estimate,
        });

        // Enforce turn limit
        while self.items.len() > self.config.max_turns * 2 {
            self.compress_oldest();
        }
    }

    /// Build the context string for the LLM
    pub fn build_context(&mut self) -> String {
        // Calculate available tokens
        let available = self.config.max_tokens - self.config.response_reserve;

        // Sort items by priority (keeping order within same priority)
        let mut items: Vec<_> = self.items.iter().collect();
        items.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Build context within token budget
        let mut context = String::new();
        let mut used_tokens = 0;

        for item in items {
            if used_tokens + item.token_estimate > available {
                if self.config.enable_compression {
                    // Try to fit a truncated version
                    let remaining = available - used_tokens;
                    if remaining > 100 {
                        let truncated = self.truncate_to_tokens(&item.content, remaining);
                        context.push_str(&truncated);
                        context.push('\n');
                    }
                }
                break;
            }

            context.push_str(&item.content);
            context.push('\n');
            used_tokens += item.token_estimate;
        }

        context
    }

    /// Get current token usage estimate
    pub fn token_usage(&self) -> usize {
        self.items.iter().map(|i| i.token_estimate).sum()
    }

    /// Clear all context
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Clear file cache
    pub fn clear_cache(&mut self) {
        self.file_cache.clear();
    }

    /// Compress the oldest items into a summary
    fn compress_oldest(&mut self) {
        if self.items.len() < 4 {
            return;
        }

        // Remove oldest non-system items
        let mut removed = Vec::new();
        let mut count = 0;

        while count < 3 && !self.items.is_empty() {
            if let Some(item) = self.items.front() {
                if item.item_type != ContextItemType::SystemPrompt {
                    if let Some(item) = self.items.pop_front() {
                        removed.push(item);
                        count += 1;
                    }
                } else {
                    // Skip system prompt, try next
                    if self.items.len() > 1 {
                        let _ = self.items.pop_front(); // Remove temporarily
                    }
                    break;
                }
            } else {
                break;
            }
        }

        // Create summary of removed items
        if !removed.is_empty() {
            let summary = self.create_summary(&removed);
            self.items.push_front(ContextItem {
                item_type: ContextItemType::Summary,
                content: summary,
                priority: 250,
                timestamp: self.current_timestamp(),
                token_estimate: 50, // Summaries are short
            });
        }
    }

    fn create_summary(&self, items: &[ContextItem]) -> String {
        let mut summary = String::from("[Earlier context summary: ");

        for item in items {
            let brief = match item.item_type {
                ContextItemType::UserMessage => "User asked something",
                ContextItemType::AssistantMessage => "Assistant responded",
                ContextItemType::ToolResult => "Tool executed",
                ContextItemType::FileContent => "File was read",
                _ => continue,
            };
            summary.push_str(brief);
            summary.push_str(". ");
        }

        summary.push(']');
        summary
    }

    fn truncate_file_content(&self, content: &str) -> String {
        if content.len() <= self.config.max_file_content {
            return content.to_string();
        }

        // Keep beginning and end
        let half = self.config.max_file_content / 2;
        let start = &content[..half];
        let end = &content[content.len() - half..];

        format!("{}\n\n... [truncated {} chars] ...\n\n{}", start, content.len() - self.config.max_file_content, end)
    }

    fn truncate_to_tokens(&self, content: &str, max_tokens: usize) -> String {
        let max_chars = max_tokens * 4; // Rough estimate
        if content.len() <= max_chars {
            return content.to_string();
        }

        format!("{}... [truncated]", &content[..max_chars])
    }

    fn estimate_tokens(&self, text: &str) -> usize {
        // Rough estimate: ~4 chars per token for English
        (text.len() / 4).max(1)
    }

    fn current_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl Default for ContextManager {
    fn default() -> Self {
        Self::new(ContextConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_items() {
        let mut manager = ContextManager::new(ContextConfig::default());

        manager.add_system_prompt("You are a helpful assistant.".to_string());
        manager.add_user_message("Hello!".to_string());
        manager.add_assistant_message("Hi there!".to_string());

        assert_eq!(manager.items.len(), 3);
    }

    #[test]
    fn test_token_estimation() {
        let manager = ContextManager::new(ContextConfig::default());

        // 100 chars should be ~25 tokens
        let text = "a".repeat(100);
        assert_eq!(manager.estimate_tokens(&text), 25);
    }

    #[test]
    fn test_file_truncation() {
        let config = ContextConfig {
            max_file_content: 100,
            ..Default::default()
        };
        let manager = ContextManager::new(config);

        let long_content = "x".repeat(200);
        let truncated = manager.truncate_file_content(&long_content);

        assert!(truncated.contains("truncated"));
        assert!(truncated.len() < 200);
    }

    #[test]
    fn test_file_caching() {
        let mut manager = ContextManager::new(ContextConfig::default());

        let content = "fn main() {}".to_string();
        manager.add_file_content("main.rs", content.clone());
        manager.add_file_content("main.rs", content.clone());

        // Should only have 2 items (both reads), but cache hit
        assert_eq!(manager.items.len(), 2);
        assert_eq!(manager.file_cache.len(), 1);
    }

    #[test]
    fn test_build_context() {
        let mut manager = ContextManager::new(ContextConfig::default());

        manager.add_system_prompt("System".to_string());
        manager.add_user_message("User".to_string());

        let context = manager.build_context();
        assert!(context.contains("System"));
        assert!(context.contains("User"));
    }

    #[test]
    fn test_priority_ordering() {
        let mut manager = ContextManager::new(ContextConfig::default());

        manager.add_example("Example".to_string()); // Priority 100
        manager.add_system_prompt("System".to_string()); // Priority 255
        manager.add_user_message("User".to_string()); // Priority 200

        let context = manager.build_context();

        // System should come before User, User before Example
        let sys_pos = context.find("System").unwrap();
        let user_pos = context.find("User").unwrap();
        let ex_pos = context.find("Example").unwrap();

        assert!(sys_pos < user_pos);
        assert!(user_pos < ex_pos);
    }

    #[test]
    fn test_compression() {
        let config = ContextConfig {
            max_turns: 2,
            ..Default::default()
        };
        let mut manager = ContextManager::new(config);

        // Add more items than max_turns allows
        for i in 0..10 {
            manager.add_user_message(format!("Message {}", i));
        }

        // Should have compressed some items
        assert!(manager.items.len() <= 6); // max_turns * 2 + some summaries
    }

    #[test]
    fn test_clear() {
        let mut manager = ContextManager::new(ContextConfig::default());

        manager.add_user_message("Test".to_string());
        manager.add_file_content("test.rs", "content".to_string());

        assert!(!manager.items.is_empty());
        assert!(!manager.file_cache.is_empty());

        manager.clear();
        assert!(manager.items.is_empty());

        manager.clear_cache();
        assert!(manager.file_cache.is_empty());
    }

    #[test]
    fn test_config_presets() {
        let small = ContextConfig::small_model();
        let large = ContextConfig::large_model();

        assert!(small.max_tokens < large.max_tokens);
        assert!(small.max_file_content < large.max_file_content);
    }

    #[test]
    fn test_token_usage() {
        let mut manager = ContextManager::new(ContextConfig::default());

        manager.add_user_message("Hello world".to_string());
        manager.add_assistant_message("Hi there!".to_string());

        assert!(manager.token_usage() > 0);
    }
}
