/**
 * ModelRouter - Intelligent model selection
 *
 * Routes tasks to the most appropriate model by:
 * - Classifying task complexity
 * - Matching task type to model strengths
 * - Falling back on failure
 * - Tracking model performance
 */

import { invoke } from '@tauri-apps/api/tauri';

export type TaskType =
  | 'code_generation'
  | 'code_explanation'
  | 'code_review'
  | 'debugging'
  | 'refactoring'
  | 'planning'
  | 'summarization'
  | 'classification'
  | 'general'
  | 'uncensored';

export type ModelTier = 'tiny' | 'small' | 'medium' | 'large' | 'api';

export interface ModelConfig {
  name: string;
  tier: ModelTier;
  strengths: TaskType[];
  contextWindow: number;
  avgResponseTime: number;  // ms
  successRate: number;      // 0-1
  isLocal: boolean;
  apiEndpoint?: string;
}

export interface RoutingResult {
  model: string;
  reason: string;
  alternatives: string[];
}

export interface ModelPerformance {
  model: string;
  taskType: TaskType;
  successCount: number;
  failureCount: number;
  avgResponseTime: number;
  lastUsed: number;
}

export class ModelRouter {
  private models: Map<string, ModelConfig>;
  private performance: Map<string, ModelPerformance>;
  private defaultModel: string;

  constructor() {
    this.models = new Map();
    this.performance = new Map();
    this.defaultModel = 'qwen2.5-coder:1.5b';

    // Initialize with known models
    this.registerBuiltinModels();
  }

  /**
   * Register built-in model configurations
   */
  private registerBuiltinModels(): void {
    // Tiny models - fast classification and simple tasks
    this.registerModel({
      name: 'tinydolphin:1.1b',
      tier: 'tiny',
      strengths: ['classification', 'summarization', 'uncensored', 'general'],
      contextWindow: 2048,
      avgResponseTime: 2000,
      successRate: 0.7,
      isLocal: true
    });

    // Small coding models - primary workhorses
    this.registerModel({
      name: 'qwen2.5-coder:1.5b',
      tier: 'small',
      strengths: ['code_generation', 'code_explanation', 'debugging', 'refactoring'],
      contextWindow: 4096,
      avgResponseTime: 3500,
      successRate: 0.85,
      isLocal: true
    });

    this.registerModel({
      name: 'tinydolphin:1.1b',
      tier: 'small',
      strengths: ['code_generation', 'general'],
      contextWindow: 4096,
      avgResponseTime: 4500,
      successRate: 0.80,
      isLocal: true
    });

    this.registerModel({
      name: 'coder-uncensored:latest',
      tier: 'small',
      strengths: ['code_generation', 'debugging', 'code_explanation'],
      contextWindow: 4096,
      avgResponseTime: 3500,
      successRate: 0.82,
      isLocal: true
    });

    this.registerModel({
      name: 'stablelm2:1.6b',
      tier: 'small',
      strengths: ['code_generation', 'general', 'code_explanation'],
      contextWindow: 4096,
      avgResponseTime: 4000,
      successRate: 0.80,
      isLocal: true
    });

    // API models - fallback for complex tasks
    this.registerModel({
      name: 'claude-haiku',
      tier: 'api',
      strengths: ['planning', 'code_review', 'code_generation', 'debugging', 'refactoring'],
      contextWindow: 100000,
      avgResponseTime: 2000,
      successRate: 0.95,
      isLocal: false,
      apiEndpoint: 'anthropic'
    });
  }

  /**
   * Register a model configuration
   */
  registerModel(config: ModelConfig): void {
    this.models.set(config.name, config);
  }

  /**
   * Classify task type from description
   */
  classifyTask(description: string): TaskType {
    const lower = description.toLowerCase();

    // Code generation indicators
    if (/\b(write|create|implement|add|build|generate)\b.*\b(function|class|component|api|endpoint|module)\b/i.test(description)) {
      return 'code_generation';
    }

    // Debugging indicators
    if (/\b(fix|debug|error|bug|issue|problem|broken|not working)\b/i.test(description)) {
      return 'debugging';
    }

    // Code explanation
    if (/\b(explain|what does|how does|understand|describe)\b/i.test(description)) {
      return 'code_explanation';
    }

    // Code review
    if (/\b(review|check|audit|analyze|improve)\b.*\b(code|implementation)\b/i.test(description)) {
      return 'code_review';
    }

    // Refactoring
    if (/\b(refactor|restructure|reorganize|clean up|optimize)\b/i.test(description)) {
      return 'refactoring';
    }

    // Planning
    if (/\b(plan|design|architect|outline|strategy|approach)\b/i.test(description)) {
      return 'planning';
    }

    // Summarization
    if (/\b(summarize|summary|brief|overview|tldr)\b/i.test(description)) {
      return 'summarization';
    }

    // Uncensored content
    if (/\b(keylog|exploit|hack|bypass|crack|inject)\b/i.test(description)) {
      return 'uncensored';
    }

    return 'general';
  }

  /**
   * Estimate task complexity (1-5)
   */
  estimateComplexity(description: string): number {
    let complexity = 1;

    // Length indicates complexity
    if (description.length > 200) complexity++;
    if (description.length > 500) complexity++;

    // Multiple requirements
    const requirements = (description.match(/\b(and|also|plus|additionally|then)\b/gi) || []).length;
    complexity += Math.min(requirements, 2);

    // Technical terms
    const technicalTerms = (description.match(/\b(api|database|authentication|async|concurrent|distributed|architecture)\b/gi) || []).length;
    if (technicalTerms > 2) complexity++;

    return Math.min(complexity, 5);
  }

  /**
   * Route a task to the best model
   */
  async route(description: string, options: {
    preferLocal?: boolean;
    maxTier?: ModelTier;
    excludeModels?: string[];
  } = {}): Promise<RoutingResult> {
    const taskType = this.classifyTask(description);
    const complexity = this.estimateComplexity(description);

    // Determine required tier based on complexity
    let requiredTier: ModelTier = 'small';
    if (complexity >= 4) requiredTier = 'medium';
    if (complexity >= 5) requiredTier = 'large';

    // Apply max tier constraint
    const tierOrder: ModelTier[] = ['tiny', 'small', 'medium', 'large', 'api'];
    const maxTierIndex = tierOrder.indexOf(options.maxTier || 'api');
    const requiredTierIndex = tierOrder.indexOf(requiredTier);
    if (requiredTierIndex > maxTierIndex) {
      requiredTier = options.maxTier || 'api';
    }

    // Find matching models
    const candidates = Array.from(this.models.values())
      .filter(m => {
        if (options.excludeModels?.includes(m.name)) return false;
        if (options.preferLocal && !m.isLocal) return false;
        if (tierOrder.indexOf(m.tier) < tierOrder.indexOf(requiredTier)) return false;
        return true;
      })
      .filter(m => m.strengths.includes(taskType) || m.strengths.includes('general'))
      .sort((a, b) => {
        // Prefer models strong in this task type
        const aStrength = a.strengths.includes(taskType) ? 1 : 0;
        const bStrength = b.strengths.includes(taskType) ? 1 : 0;
        if (aStrength !== bStrength) return bStrength - aStrength;

        // Then by performance
        const aPerfKey = `${a.name}:${taskType}`;
        const bPerfKey = `${b.name}:${taskType}`;
        const aPerf = this.performance.get(aPerfKey);
        const bPerf = this.performance.get(bPerfKey);

        if (aPerf && bPerf) {
          const aRate = aPerf.successCount / (aPerf.successCount + aPerf.failureCount);
          const bRate = bPerf.successCount / (bPerf.successCount + bPerf.failureCount);
          if (Math.abs(aRate - bRate) > 0.1) return bRate - aRate;
        }

        // Then by tier (prefer smaller)
        return tierOrder.indexOf(a.tier) - tierOrder.indexOf(b.tier);
      });

    if (candidates.length === 0) {
      // Fallback to default
      return {
        model: this.defaultModel,
        reason: 'No matching models found, using default',
        alternatives: []
      };
    }

    const selected = candidates[0];
    const alternatives = candidates.slice(1, 4).map(m => m.name);

    return {
      model: selected.name,
      reason: `Selected ${selected.name} (${selected.tier}) for ${taskType} task (complexity ${complexity})`,
      alternatives
    };
  }

  /**
   * Record model performance
   */
  recordPerformance(
    model: string,
    taskType: TaskType,
    success: boolean,
    responseTime: number
  ): void {
    const key = `${model}:${taskType}`;
    const existing = this.performance.get(key) || {
      model,
      taskType,
      successCount: 0,
      failureCount: 0,
      avgResponseTime: 0,
      lastUsed: 0
    };

    if (success) {
      existing.successCount++;
    } else {
      existing.failureCount++;
    }

    // Update average response time
    const totalCalls = existing.successCount + existing.failureCount;
    existing.avgResponseTime =
      (existing.avgResponseTime * (totalCalls - 1) + responseTime) / totalCalls;
    existing.lastUsed = Date.now();

    this.performance.set(key, existing);
  }

  /**
   * Get available models
   */
  async getAvailableModels(): Promise<string[]> {
    try {
      const models = await invoke<string[]>('list_ollama_models');
      return models.filter(m => this.models.has(m));
    } catch (e) {
      return Array.from(this.models.keys()).filter(m =>
        this.models.get(m)?.isLocal
      );
    }
  }

  /**
   * Check if a model is available
   */
  async isModelAvailable(model: string): Promise<boolean> {
    const available = await this.getAvailableModels();
    return available.includes(model);
  }

  /**
   * Get model configuration
   */
  getModelConfig(model: string): ModelConfig | undefined {
    return this.models.get(model);
  }

  /**
   * Get performance statistics
   */
  getPerformanceStats(): Map<string, ModelPerformance> {
    return new Map(this.performance);
  }

  /**
   * Get fallback chain for a model
   */
  getFallbackChain(model: string, taskType: TaskType): string[] {
    const config = this.models.get(model);
    if (!config) return [this.defaultModel];

    const tierOrder: ModelTier[] = ['tiny', 'small', 'medium', 'large', 'api'];
    const currentTierIndex = tierOrder.indexOf(config.tier);

    return Array.from(this.models.values())
      .filter(m =>
        m.name !== model &&
        (m.strengths.includes(taskType) || m.strengths.includes('general')) &&
        tierOrder.indexOf(m.tier) >= currentTierIndex
      )
      .sort((a, b) => tierOrder.indexOf(a.tier) - tierOrder.indexOf(b.tier))
      .map(m => m.name);
  }
}

export default ModelRouter;
