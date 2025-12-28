/**
 * Scaffolded Agent System
 *
 * A complete framework for making small local LLMs capable of
 * complex multi-step coding tasks with safeguards.
 *
 * Components:
 * - ContextManager: Sliding window context with summarization
 * - ConstrainedOutput: JSON schema enforcement for tool calls
 * - Verifier: Syntax and safety checking before execution
 * - RecoveryHandler: Checkpoint and rollback on failure
 * - Orchestrator: Task queue and state machine
 * - ModelRouter: Intelligent model selection and fallback
 * - PatternCache: Reusable code patterns to reduce LLM calls
 * - ScaffoldedAgent: Unified agent combining all components
 */

// Core components
export { ContextManager, type ContextState, type Message, type FileSnippet } from './ContextManager';
export { ConstrainedOutput, type AgentAction, type ActionType, type ValidationResult } from './ConstrainedOutput';
export { Verifier, type VerificationResult } from './Verifier';
export { RecoveryHandler, type Checkpoint, type ActionRecord, type FileBackup } from './RecoveryHandler';
export { Orchestrator, type Task, type TaskStep, type TaskState, type OrchestratorConfig } from './Orchestrator';
export { ModelRouter, type TaskType, type ModelTier, type ModelConfig, type RoutingResult, type ModelPerformance } from './ModelRouter';
export { PatternCache, type CodePattern, type PatternMatch, type PatternExample } from './PatternCache';

// Main agent
export { ScaffoldedAgent, useScaffoldedAgent, type AgentConfig, type AgentMessage, type AgentStats } from './ScaffoldedAgent';

// Default export
export { ScaffoldedAgent as default } from './ScaffoldedAgent';
