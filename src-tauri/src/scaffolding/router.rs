// Model Router
//
// Routes tasks to the best available model based on task complexity.
// Uses smaller models for simple tasks, larger for complex ones.

use serde::{Deserialize, Serialize};
use crate::scaffolding::examples::TaskType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelType {
    /// Fast, small model for simple tasks (autocomplete, simple reads)
    Fast,
    /// Balanced model for most tasks
    Balanced,
    /// Large model for complex reasoning
    Powerful,
    /// Code-specialized model
    Code,
}

impl ModelType {
    /// Get the Ollama model name for this type
    pub fn model_name(&self) -> &'static str {
        match self {
            Self::Fast => "qwen2.5:3b",
            Self::Balanced => "qwen2.5:7b",
            Self::Powerful => "qwen2.5:14b",
            Self::Code => "qwen2.5-coder:7b",
        }
    }

    /// Get fallback model if primary not available
    pub fn fallback(&self) -> &'static str {
        match self {
            Self::Fast => "qwen2.5:7b",
            Self::Balanced => "qwen2.5:3b",
            Self::Powerful => "qwen2.5:7b",
            Self::Code => "qwen2.5:7b",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub model_type: ModelType,
    pub temperature: f32,
    pub max_tokens: u32,
    pub top_p: f32,
}

impl ModelConfig {
    pub fn for_type(model_type: ModelType) -> Self {
        match model_type {
            ModelType::Fast => Self {
                model_type,
                temperature: 0.1,
                max_tokens: 100,
                top_p: 0.9,
            },
            ModelType::Balanced => Self {
                model_type,
                temperature: 0.3,
                max_tokens: 2000,
                top_p: 0.95,
            },
            ModelType::Powerful => Self {
                model_type,
                temperature: 0.5,
                max_tokens: 4000,
                top_p: 0.95,
            },
            ModelType::Code => Self {
                model_type,
                temperature: 0.2,
                max_tokens: 3000,
                top_p: 0.9,
            },
        }
    }
}

pub struct ModelRouter {
    available_models: Vec<String>,
}

impl ModelRouter {
    pub fn new() -> Self {
        Self {
            available_models: Vec::new(),
        }
    }

    /// Set the list of available Ollama models
    pub fn set_available_models(&mut self, models: Vec<String>) {
        self.available_models = models;
    }

    /// Check if a specific model is available
    pub fn is_available(&self, model: &str) -> bool {
        self.available_models.iter().any(|m| m.contains(model))
    }

    /// Route based on task type from examples module
    pub fn route_task_type(&self, task_type: TaskType) -> ModelConfig {
        let model_type = match task_type {
            // Simple operations - use fast model
            TaskType::ReadFile | TaskType::FindFiles | TaskType::Explain => ModelType::Fast,

            // Search and simple edits - balanced
            TaskType::SearchCode | TaskType::WriteFile => ModelType::Balanced,

            // Complex operations - powerful
            TaskType::MultiStep | TaskType::Refactor | TaskType::Debug => ModelType::Powerful,

            // Code operations - code-specialized
            TaskType::EditFile | TaskType::RunCommand => ModelType::Code,
        };

        let config = ModelConfig::for_type(model_type);
        self.ensure_available(config)
    }

    /// Route based on task description
    pub fn route(&self, task: &str) -> ModelConfig {
        let complexity = self.estimate_complexity(task);
        let needs_code = self.needs_code_model(task);
        let is_read_only = self.is_read_only_task(task);

        // Don't use code model for simple read operations, even on code files
        let model_type = if needs_code && !is_read_only {
            ModelType::Code
        } else {
            match complexity {
                0..=2 => ModelType::Fast,
                3..=5 => ModelType::Balanced,
                _ => ModelType::Powerful,
            }
        };

        let config = ModelConfig::for_type(model_type);
        self.ensure_available(config)
    }

    /// Check if task is read-only (doesn't modify files)
    fn is_read_only_task(&self, task: &str) -> bool {
        let lower = task.to_lowercase();

        let read_only_indicators = [
            "read", "show", "display", "list", "find", "search",
            "what", "where", "explain", "describe", "cat", "view",
        ];

        let write_indicators = [
            "edit", "change", "modify", "update", "create", "write",
            "fix", "refactor", "implement", "add", "remove", "delete",
        ];

        let has_read = read_only_indicators.iter().any(|w| lower.contains(w));
        let has_write = write_indicators.iter().any(|w| lower.contains(w));

        has_read && !has_write
    }

    /// Estimate task complexity on 0-10 scale
    fn estimate_complexity(&self, task: &str) -> u32 {
        let lower = task.to_lowercase();
        let mut score = 0u32;

        // Length-based complexity
        let words = task.split_whitespace().count();
        if words > 20 {
            score += 2;
        } else if words > 10 {
            score += 1;
        }

        // Multi-step indicators
        let multi_step = [" and ", " then ", " after ", " before ", "multiple", "several"];
        score += multi_step.iter().filter(|w| lower.contains(*w)).count() as u32;

        // Complex task indicators
        let complex = [
            "refactor", "implement", "design", "architect", "migrate",
            "optimize", "rewrite", "create", "build", "debug",
        ];
        score += complex.iter().filter(|w| lower.contains(*w)).count() as u32 * 2;

        // Simple task indicators (reduce score)
        let simple = ["read", "show", "list", "find", "search", "what", "where"];
        let simple_count = simple.iter().filter(|w| lower.contains(*w)).count() as u32;
        score = score.saturating_sub(simple_count);

        score.min(10)
    }

    /// Check if task needs code-specialized model
    fn needs_code_model(&self, task: &str) -> bool {
        let lower = task.to_lowercase();

        let code_indicators = [
            "function", "class", "method", "variable", "type",
            "struct", "impl", "trait", "interface", "module",
            "async", "await", "import", "export", "return",
            "compile", "syntax", "error", "bug", "fix",
            ".rs", ".ts", ".js", ".py", ".go", ".java",
        ];

        code_indicators.iter().any(|w| lower.contains(w))
    }

    /// Ensure the model is available, fall back if not
    fn ensure_available(&self, config: ModelConfig) -> ModelConfig {
        if self.available_models.is_empty() {
            // No availability info, return as-is
            return config;
        }

        let primary = config.model_type.model_name();
        if self.is_available(primary) {
            return config;
        }

        // Try fallback
        let fallback = config.model_type.fallback();
        if self.is_available(fallback) {
            // Return config with fallback model
            // Note: We keep the same parameters but the caller should use fallback()
            return config;
        }

        // Last resort: use whatever is available
        // Keep original config, caller will need to handle unavailability
        config
    }

    /// Get model for autocomplete (always fast)
    pub fn for_autocomplete(&self) -> ModelConfig {
        let config = ModelConfig::for_type(ModelType::Fast);
        ModelConfig {
            max_tokens: 50, // Very short for autocomplete
            temperature: 0.1, // Low creativity
            ..config
        }
    }

    /// Get model for verification (always fast)
    pub fn for_verification(&self) -> ModelConfig {
        let config = ModelConfig::for_type(ModelType::Fast);
        ModelConfig {
            max_tokens: 100,
            temperature: 0.0, // Deterministic
            ..config
        }
    }

    /// Get model for task decomposition (balanced)
    pub fn for_decomposition(&self) -> ModelConfig {
        ModelConfig::for_type(ModelType::Balanced)
    }

    /// Get model for error recovery (balanced, needs reasoning)
    pub fn for_recovery(&self) -> ModelConfig {
        let config = ModelConfig::for_type(ModelType::Balanced);
        ModelConfig {
            temperature: 0.4, // Slightly more creative for finding alternatives
            ..config
        }
    }
}

impl Default for ModelRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for model usage tracking
#[derive(Debug, Default, Clone)]
pub struct ModelStats {
    pub fast_calls: u32,
    pub balanced_calls: u32,
    pub powerful_calls: u32,
    pub code_calls: u32,
    pub total_tokens: u64,
}

impl ModelStats {
    pub fn record(&mut self, model_type: ModelType, tokens: u32) {
        match model_type {
            ModelType::Fast => self.fast_calls += 1,
            ModelType::Balanced => self.balanced_calls += 1,
            ModelType::Powerful => self.powerful_calls += 1,
            ModelType::Code => self.code_calls += 1,
        }
        self.total_tokens += tokens as u64;
    }

    pub fn total_calls(&self) -> u32 {
        self.fast_calls + self.balanced_calls + self.powerful_calls + self.code_calls
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_simple_task() {
        let router = ModelRouter::new();
        let config = router.route("read the file main.rs");
        assert_eq!(config.model_type, ModelType::Fast);
    }

    #[test]
    fn test_route_complex_task() {
        let router = ModelRouter::new();
        // Complex task without code indicators -> Powerful
        // "design" and "architect" and "and" trigger high complexity
        let config = router.route("design and architect a new microservices architecture with multiple service boundaries and data flow patterns");
        assert_eq!(config.model_type, ModelType::Powerful);
    }

    #[test]
    fn test_route_code_refactor_task() {
        let router = ModelRouter::new();
        // Code refactoring task -> Code model
        let config = router.route("refactor the authentication system and implement caching");
        assert_eq!(config.model_type, ModelType::Code);
    }

    #[test]
    fn test_route_code_task() {
        let router = ModelRouter::new();
        let config = router.route("fix the syntax error in the function");
        assert_eq!(config.model_type, ModelType::Code);
    }

    #[test]
    fn test_route_task_type() {
        let router = ModelRouter::new();

        let config = router.route_task_type(TaskType::ReadFile);
        assert_eq!(config.model_type, ModelType::Fast);

        let config = router.route_task_type(TaskType::MultiStep);
        assert_eq!(config.model_type, ModelType::Powerful);

        let config = router.route_task_type(TaskType::EditFile);
        assert_eq!(config.model_type, ModelType::Code);
    }

    #[test]
    fn test_for_autocomplete() {
        let router = ModelRouter::new();
        let config = router.for_autocomplete();
        assert_eq!(config.max_tokens, 50);
        assert_eq!(config.temperature, 0.1);
    }

    #[test]
    fn test_for_verification() {
        let router = ModelRouter::new();
        let config = router.for_verification();
        assert_eq!(config.temperature, 0.0);
    }

    #[test]
    fn test_complexity_estimation() {
        let router = ModelRouter::new();

        // Simple task
        let simple = router.estimate_complexity("read main.rs");
        assert!(simple <= 2);

        // Complex task
        let complex = router.estimate_complexity(
            "refactor the authentication module and then implement caching layer"
        );
        assert!(complex >= 5);
    }

    #[test]
    fn test_needs_code_model() {
        let router = ModelRouter::new();

        assert!(router.needs_code_model("fix the function syntax error"));
        assert!(router.needs_code_model("update the .rs file"));
        assert!(!router.needs_code_model("show me what files exist"));
    }

    #[test]
    fn test_model_stats() {
        let mut stats = ModelStats::default();

        stats.record(ModelType::Fast, 50);
        stats.record(ModelType::Fast, 30);
        stats.record(ModelType::Powerful, 500);

        assert_eq!(stats.fast_calls, 2);
        assert_eq!(stats.powerful_calls, 1);
        assert_eq!(stats.total_calls(), 3);
        assert_eq!(stats.total_tokens, 580);
    }

    #[test]
    fn test_available_models() {
        let mut router = ModelRouter::new();
        router.set_available_models(vec![
            "qwen2.5:7b".to_string(),
            "qwen2.5:3b".to_string(),
        ]);

        assert!(router.is_available("qwen2.5:7b"));
        assert!(router.is_available("qwen2.5:3b"));
        assert!(!router.is_available("qwen2.5:14b"));
    }

    #[test]
    fn test_model_names() {
        assert_eq!(ModelType::Fast.model_name(), "qwen2.5:3b");
        assert_eq!(ModelType::Balanced.model_name(), "qwen2.5:7b");
        assert_eq!(ModelType::Powerful.model_name(), "qwen2.5:14b");
        assert_eq!(ModelType::Code.model_name(), "qwen2.5-coder:7b");
    }

    #[test]
    fn test_fallback_models() {
        assert_eq!(ModelType::Fast.fallback(), "qwen2.5:7b");
        assert_eq!(ModelType::Powerful.fallback(), "qwen2.5:7b");
    }
}
