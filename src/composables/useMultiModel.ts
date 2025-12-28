/**
 * Multi-Model AI Support
 * Enables using multiple AI models from different providers
 *
 * Supported Providers:
 * - Ollama (local, default)
 * - LM Studio (local)
 * - OpenAI API (optional, cloud)
 * - Anthropic API (optional, cloud)
 *
 * Features:
 * - Model routing based on task type
 * - Fallback chains for reliability
 * - Quality/speed tradeoffs
 * - Cost tracking for API models
 * - Provider health checking
 */

import { ref, computed, reactive } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export type ProviderType = 'ollama' | 'lmstudio' | 'openai' | 'anthropic';

export interface ModelConfig {
  id: string;
  name: string;
  provider: ProviderType;
  model: string;
  endpoint?: string;
  apiKey?: string;
  maxTokens: number;
  temperature: number;
  capabilities: ModelCapability[];
  costPer1kTokens?: number;  // For cloud providers
  speed: 'fast' | 'medium' | 'slow';
  quality: 'low' | 'medium' | 'high';
}

export type ModelCapability =
  | 'code'           // Good at code generation
  | 'chat'           // Good at conversation
  | 'reasoning'      // Good at complex reasoning
  | 'summarization'  // Good at summarizing
  | 'command'        // Good at generating shell commands
  | 'fast';          // Optimized for speed

export type TaskType = 'command' | 'code' | 'chat' | 'analysis' | 'summarize';

export interface ModelResponse {
  content: string;
  model: string;
  provider: ProviderType;
  tokensUsed?: number;
  latencyMs: number;
  cached?: boolean;
}

export interface ProviderHealth {
  provider: ProviderType;
  healthy: boolean;
  latencyMs?: number;
  lastCheck: Date;
  error?: string;
}

export interface UsageStats {
  provider: ProviderType;
  model: string;
  requests: number;
  tokensUsed: number;
  totalLatencyMs: number;
  errors: number;
}

// ============================================================================
// DEFAULT CONFIGURATIONS
// ============================================================================

const DEFAULT_MODELS: ModelConfig[] = [
  // Ollama models (local)
  {
    id: 'ollama-qwen-coder',
    name: 'Qwen 2.5 Coder (1.5B)',
    provider: 'ollama',
    model: 'qwen2.5-coder:1.5b',
    endpoint: 'http://localhost:11434',
    maxTokens: 2048,
    temperature: 0.1,
    capabilities: ['code', 'command', 'fast'],
    speed: 'fast',
    quality: 'medium'
  },
  {
    id: 'ollama-tinydolphin',
    name: 'TinyDolphin (1.1B)',
    provider: 'ollama',
    model: 'tinydolphin:1.1b',
    endpoint: 'http://localhost:11434',
    maxTokens: 2048,
    temperature: 0.3,
    capabilities: ['chat', 'fast'],
    speed: 'fast',
    quality: 'low'
  },
  {
    id: 'ollama-stablelm',
    name: 'StableLM 2 (1.6B)',
    provider: 'ollama',
    model: 'stablelm2:1.6b',
    endpoint: 'http://localhost:11434',
    maxTokens: 2048,
    temperature: 0.2,
    capabilities: ['chat', 'reasoning', 'fast'],
    speed: 'fast',
    quality: 'medium'
  },

  // LM Studio (local)
  {
    id: 'lmstudio-default',
    name: 'LM Studio Model',
    provider: 'lmstudio',
    model: 'local-model',
    endpoint: 'http://localhost:1234',
    maxTokens: 4096,
    temperature: 0.2,
    capabilities: ['code', 'chat', 'reasoning'],
    speed: 'medium',
    quality: 'medium'
  },

  // OpenAI (cloud, optional)
  {
    id: 'openai-gpt4o-mini',
    name: 'GPT-4o Mini',
    provider: 'openai',
    model: 'gpt-4o-mini',
    endpoint: 'https://api.openai.com/v1',
    maxTokens: 4096,
    temperature: 0.1,
    capabilities: ['code', 'chat', 'reasoning', 'command'],
    costPer1kTokens: 0.00015,
    speed: 'medium',
    quality: 'high'
  },
  {
    id: 'openai-gpt4o',
    name: 'GPT-4o',
    provider: 'openai',
    model: 'gpt-4o',
    endpoint: 'https://api.openai.com/v1',
    maxTokens: 4096,
    temperature: 0.1,
    capabilities: ['code', 'chat', 'reasoning', 'command', 'summarization'],
    costPer1kTokens: 0.005,
    speed: 'slow',
    quality: 'high'
  },

  // Anthropic (cloud, optional)
  {
    id: 'anthropic-haiku',
    name: 'Claude 3.5 Haiku',
    provider: 'anthropic',
    model: 'claude-3-5-haiku-latest',
    endpoint: 'https://api.anthropic.com/v1',
    maxTokens: 4096,
    temperature: 0.1,
    capabilities: ['code', 'chat', 'command', 'fast'],
    costPer1kTokens: 0.001,
    speed: 'fast',
    quality: 'high'
  },
  {
    id: 'anthropic-sonnet',
    name: 'Claude 3.5 Sonnet',
    provider: 'anthropic',
    model: 'claude-3-5-sonnet-latest',
    endpoint: 'https://api.anthropic.com/v1',
    maxTokens: 4096,
    temperature: 0.1,
    capabilities: ['code', 'chat', 'reasoning', 'command', 'summarization'],
    costPer1kTokens: 0.003,
    speed: 'medium',
    quality: 'high'
  }
];

// Task to capability mapping
const TASK_CAPABILITIES: Record<TaskType, ModelCapability[]> = {
  command: ['command', 'code', 'fast'],
  code: ['code', 'reasoning'],
  chat: ['chat'],
  analysis: ['reasoning', 'code'],
  summarize: ['summarization', 'chat']
};

// ============================================================================
// STATE
// ============================================================================

const models = ref<ModelConfig[]>([...DEFAULT_MODELS]);
const activeModelId = ref<string>('ollama-qwen-coder');
const providerHealth = ref<Map<ProviderType, ProviderHealth>>(new Map());
const usageStats = reactive<Map<string, UsageStats>>(new Map());
const apiKeys = ref<Map<ProviderType, string>>(new Map());

// Load settings from localStorage
function loadSettings() {
  try {
    const saved = localStorage.getItem('warp_multi_model_settings');
    if (saved) {
      const data = JSON.parse(saved);
      if (data.activeModelId) activeModelId.value = data.activeModelId;
      if (data.apiKeys) {
        for (const [provider, key] of Object.entries(data.apiKeys)) {
          apiKeys.value.set(provider as ProviderType, key as string);
        }
      }
    }
  } catch (e) {
    console.error('[MultiModel] Failed to load settings:', e);
  }
}

function saveSettings() {
  try {
    const data = {
      activeModelId: activeModelId.value,
      apiKeys: Object.fromEntries(apiKeys.value)
    };
    localStorage.setItem('warp_multi_model_settings', JSON.stringify(data));
  } catch (e) {
    console.error('[MultiModel] Failed to save settings:', e);
  }
}

// Initialize
loadSettings();

// ============================================================================
// PROVIDER IMPLEMENTATIONS
// ============================================================================

async function queryOllama(model: ModelConfig, prompt: string, options?: { stream?: boolean }): Promise<ModelResponse> {
  const startTime = Date.now();
  const endpoint = model.endpoint || 'http://localhost:11434';

  const response = await fetch(`${endpoint}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: model.model,
      prompt,
      stream: options?.stream ?? false,
      options: {
        temperature: model.temperature,
        num_predict: model.maxTokens
      }
    })
  });

  if (!response.ok) {
    throw new Error(`Ollama error: ${response.status}`);
  }

  const data = await response.json();
  return {
    content: data.response,
    model: model.model,
    provider: 'ollama',
    tokensUsed: data.eval_count,
    latencyMs: Date.now() - startTime
  };
}

async function queryLMStudio(model: ModelConfig, prompt: string): Promise<ModelResponse> {
  const startTime = Date.now();
  const endpoint = model.endpoint || 'http://localhost:1234';

  // LM Studio uses OpenAI-compatible API
  const response = await fetch(`${endpoint}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: model.model,
      messages: [{ role: 'user', content: prompt }],
      temperature: model.temperature,
      max_tokens: model.maxTokens
    })
  });

  if (!response.ok) {
    throw new Error(`LM Studio error: ${response.status}`);
  }

  const data = await response.json();
  return {
    content: data.choices[0]?.message?.content || '',
    model: model.model,
    provider: 'lmstudio',
    tokensUsed: data.usage?.total_tokens,
    latencyMs: Date.now() - startTime
  };
}

async function queryOpenAI(model: ModelConfig, prompt: string): Promise<ModelResponse> {
  const startTime = Date.now();
  const apiKey = model.apiKey || apiKeys.value.get('openai');

  if (!apiKey) {
    throw new Error('OpenAI API key not configured');
  }

  const response = await fetch(`${model.endpoint}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: model.model,
      messages: [{ role: 'user', content: prompt }],
      temperature: model.temperature,
      max_tokens: model.maxTokens
    })
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(`OpenAI error: ${error.error?.message || response.status}`);
  }

  const data = await response.json();
  return {
    content: data.choices[0]?.message?.content || '',
    model: model.model,
    provider: 'openai',
    tokensUsed: data.usage?.total_tokens,
    latencyMs: Date.now() - startTime
  };
}

async function queryAnthropic(model: ModelConfig, prompt: string): Promise<ModelResponse> {
  const startTime = Date.now();
  const apiKey = model.apiKey || apiKeys.value.get('anthropic');

  if (!apiKey) {
    throw new Error('Anthropic API key not configured');
  }

  const response = await fetch(`${model.endpoint}/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: model.model,
      max_tokens: model.maxTokens,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(`Anthropic error: ${error.error?.message || response.status}`);
  }

  const data = await response.json();
  return {
    content: data.content[0]?.text || '',
    model: model.model,
    provider: 'anthropic',
    tokensUsed: data.usage?.input_tokens + data.usage?.output_tokens,
    latencyMs: Date.now() - startTime
  };
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useMultiModel() {
  /**
   * Query the active model
   */
  async function query(prompt: string, options?: {
    modelId?: string;
    taskType?: TaskType;
    stream?: boolean;
  }): Promise<ModelResponse> {
    const modelId = options?.modelId || activeModelId.value;
    const model = models.value.find(m => m.id === modelId);

    if (!model) {
      throw new Error(`Model not found: ${modelId}`);
    }

    // Update stats
    const statsKey = `${model.provider}:${model.model}`;
    if (!usageStats.has(statsKey)) {
      usageStats.set(statsKey, {
        provider: model.provider,
        model: model.model,
        requests: 0,
        tokensUsed: 0,
        totalLatencyMs: 0,
        errors: 0
      });
    }

    try {
      let response: ModelResponse;

      switch (model.provider) {
        case 'ollama':
          response = await queryOllama(model, prompt, options);
          break;
        case 'lmstudio':
          response = await queryLMStudio(model, prompt);
          break;
        case 'openai':
          response = await queryOpenAI(model, prompt);
          break;
        case 'anthropic':
          response = await queryAnthropic(model, prompt);
          break;
        default:
          throw new Error(`Unknown provider: ${model.provider}`);
      }

      // Update stats
      const stats = usageStats.get(statsKey)!;
      stats.requests++;
      stats.tokensUsed += response.tokensUsed || 0;
      stats.totalLatencyMs += response.latencyMs;

      return response;
    } catch (error) {
      const stats = usageStats.get(statsKey)!;
      stats.errors++;
      throw error;
    }
  }

  /**
   * Query with fallback chain
   */
  async function queryWithFallback(prompt: string, options?: {
    modelIds?: string[];
    taskType?: TaskType;
  }): Promise<ModelResponse> {
    const modelIds = options?.modelIds || getFallbackChain(options?.taskType);

    let lastError: Error | null = null;

    for (const modelId of modelIds) {
      try {
        console.log(`[MultiModel] Trying ${modelId}...`);
        return await query(prompt, { modelId, taskType: options?.taskType });
      } catch (error) {
        console.warn(`[MultiModel] ${modelId} failed:`, error);
        lastError = error instanceof Error ? error : new Error(String(error));
      }
    }

    throw lastError || new Error('All models failed');
  }

  /**
   * Get best model for a task type
   */
  function getBestModel(taskType: TaskType, options?: {
    preferLocal?: boolean;
    preferSpeed?: boolean;
    preferQuality?: boolean;
  }): ModelConfig | null {
    const requiredCapabilities = TASK_CAPABILITIES[taskType] || [];
    const preferLocal = options?.preferLocal ?? true;
    const preferSpeed = options?.preferSpeed ?? false;

    // Filter models with required capabilities
    let candidates = models.value.filter(m =>
      requiredCapabilities.some(cap => m.capabilities.includes(cap))
    );

    // Filter by local preference
    if (preferLocal) {
      const localModels = candidates.filter(m =>
        m.provider === 'ollama' || m.provider === 'lmstudio'
      );
      if (localModels.length > 0) {
        candidates = localModels;
      }
    }

    // Sort by preference
    candidates.sort((a, b) => {
      if (preferSpeed) {
        const speedOrder = { fast: 0, medium: 1, slow: 2 };
        return speedOrder[a.speed] - speedOrder[b.speed];
      }
      const qualityOrder = { high: 0, medium: 1, low: 2 };
      return qualityOrder[a.quality] - qualityOrder[b.quality];
    });

    return candidates[0] || null;
  }

  /**
   * Get fallback chain for reliability
   */
  function getFallbackChain(taskType?: TaskType): string[] {
    const chain: string[] = [];

    // Add active model first
    chain.push(activeModelId.value);

    // Add other local models
    const localModels = models.value.filter(m =>
      (m.provider === 'ollama' || m.provider === 'lmstudio') &&
      m.id !== activeModelId.value
    );
    chain.push(...localModels.map(m => m.id));

    // Add cloud models if API keys configured
    if (apiKeys.value.has('openai')) {
      chain.push('openai-gpt4o-mini');
    }
    if (apiKeys.value.has('anthropic')) {
      chain.push('anthropic-haiku');
    }

    return chain;
  }

  /**
   * Check provider health
   */
  async function checkHealth(provider: ProviderType): Promise<ProviderHealth> {
    const startTime = Date.now();

    try {
      switch (provider) {
        case 'ollama':
          await fetch('http://localhost:11434/api/tags');
          break;
        case 'lmstudio':
          await fetch('http://localhost:1234/v1/models');
          break;
        case 'openai':
          if (!apiKeys.value.has('openai')) throw new Error('No API key');
          // Just check if we have a key, don't waste tokens
          break;
        case 'anthropic':
          if (!apiKeys.value.has('anthropic')) throw new Error('No API key');
          break;
      }

      const health: ProviderHealth = {
        provider,
        healthy: true,
        latencyMs: Date.now() - startTime,
        lastCheck: new Date()
      };
      providerHealth.value.set(provider, health);
      return health;
    } catch (error) {
      const health: ProviderHealth = {
        provider,
        healthy: false,
        lastCheck: new Date(),
        error: String(error)
      };
      providerHealth.value.set(provider, health);
      return health;
    }
  }

  /**
   * Check all providers
   */
  async function checkAllHealth(): Promise<Map<ProviderType, ProviderHealth>> {
    const providers: ProviderType[] = ['ollama', 'lmstudio', 'openai', 'anthropic'];
    await Promise.all(providers.map(p => checkHealth(p)));
    return providerHealth.value;
  }

  /**
   * Set API key for a provider
   */
  function setApiKey(provider: ProviderType, key: string): void {
    apiKeys.value.set(provider, key);
    saveSettings();
  }

  /**
   * Set active model
   */
  function setActiveModel(modelId: string): void {
    if (!models.value.find(m => m.id === modelId)) {
      throw new Error(`Model not found: ${modelId}`);
    }
    activeModelId.value = modelId;
    saveSettings();
  }

  /**
   * Get available models (healthy providers only)
   */
  const availableModels = computed(() => {
    return models.value.filter(m => {
      const health = providerHealth.value.get(m.provider);
      // Include if health unknown or healthy
      return !health || health.healthy;
    });
  });

  /**
   * Get active model config
   */
  const activeModel = computed(() => {
    return models.value.find(m => m.id === activeModelId.value);
  });

  /**
   * Get usage statistics
   */
  function getUsageStats(): UsageStats[] {
    return Array.from(usageStats.values());
  }

  /**
   * Get estimated cost (for cloud providers)
   */
  function getEstimatedCost(): number {
    let total = 0;
    for (const stats of usageStats.values()) {
      const model = models.value.find(m =>
        m.provider === stats.provider && m.model === stats.model
      );
      if (model?.costPer1kTokens) {
        total += (stats.tokensUsed / 1000) * model.costPer1kTokens;
      }
    }
    return total;
  }

  /**
   * Add custom model configuration
   */
  function addModel(config: ModelConfig): void {
    const existing = models.value.findIndex(m => m.id === config.id);
    if (existing >= 0) {
      models.value[existing] = config;
    } else {
      models.value.push(config);
    }
  }

  /**
   * Remove model configuration
   */
  function removeModel(modelId: string): void {
    const index = models.value.findIndex(m => m.id === modelId);
    if (index >= 0) {
      models.value.splice(index, 1);
    }
  }

  /**
   * Get local models from Ollama
   */
  async function discoverOllamaModels(): Promise<ModelConfig[]> {
    try {
      const response = await fetch('http://localhost:11434/api/tags');
      if (!response.ok) return [];

      const data = await response.json();
      const discovered: ModelConfig[] = [];

      for (const model of data.models || []) {
        const existing = models.value.find(m =>
          m.provider === 'ollama' && m.model === model.name
        );
        if (!existing) {
          discovered.push({
            id: `ollama-${model.name.replace(/[:.]/g, '-')}`,
            name: model.name,
            provider: 'ollama',
            model: model.name,
            endpoint: 'http://localhost:11434',
            maxTokens: 2048,
            temperature: 0.2,
            capabilities: ['chat'],
            speed: 'medium',
            quality: 'medium'
          });
        }
      }

      // Add discovered models
      for (const model of discovered) {
        addModel(model);
      }

      return discovered;
    } catch {
      return [];
    }
  }

  return {
    // State
    models: computed(() => models.value),
    activeModelId: computed(() => activeModelId.value),
    activeModel,
    availableModels,
    providerHealth: computed(() => providerHealth.value),

    // Core
    query,
    queryWithFallback,
    getBestModel,
    getFallbackChain,

    // Health
    checkHealth,
    checkAllHealth,

    // Configuration
    setActiveModel,
    setApiKey,
    addModel,
    removeModel,
    discoverOllamaModels,

    // Stats
    getUsageStats,
    getEstimatedCost
  };
}

export default useMultiModel;
