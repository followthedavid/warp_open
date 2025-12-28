// Scaffolding System for Ollama Parity with Claude
//
// This module implements techniques to make local LLMs perform
// at near-Claude levels through structured prompting and validation.

pub mod json_validator;
pub mod chain_of_thought;
pub mod examples;
pub mod decomposer;
pub mod verifier;
pub mod error_recovery;
pub mod router;
pub mod agent_loop;
pub mod context_manager;
pub mod tool_cache;
pub mod ollama_agent;
pub mod self_correction;

// Re-export main types
pub use json_validator::{ToolCall, ToolCallValidator, ValidationError};
pub use chain_of_thought::{ReasonedResponse, ChainOfThoughtEnforcer};
pub use examples::{Example, ExampleLibrary};
pub use decomposer::{SubTask, TaskDecomposer};
pub use verifier::{VerificationResult, SelfVerifier};
pub use error_recovery::{RecoveryStrategy, ErrorRecovery};
pub use router::{ModelType, ModelRouter};
pub use agent_loop::{AgentLoop, AgentState, LoopConfig};
pub use context_manager::{ContextManager, ContextConfig};
pub use tool_cache::{ToolCache, CacheConfig, CachedResult};
pub use ollama_agent::{OllamaAgent, OllamaAgentConfig, AgentEvent, StreamingConfig};
pub use self_correction::{SelfCorrectionEngine, SelfCorrectionConfig, ValidationResult as CorrectionResult};
