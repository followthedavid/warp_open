import { ref } from 'vue';
import Anthropic from '@anthropic-ai/sdk';

export type AIMode = 'auto' | 'local' | 'claude' | 'hybrid' | 'agent';

export interface ClaudeConfig {
  apiKey: string;
  model: string;
}

const apiKey = ref<string>('');
const selectedMode = ref<AIMode>('local'); // Default to local only
const isClaudeAvailable = ref(false);

export function useClaude() {
  let anthropic: Anthropic | null = null;

  // Initialize Claude client
  function initClaude(config: ClaudeConfig) {
    try {
      apiKey.value = config.apiKey;
      anthropic = new Anthropic({
        apiKey: config.apiKey,
        dangerouslyAllowBrowser: true // Only for development/local use
      });
      isClaudeAvailable.value = true;
      console.log('[Claude] Initialized successfully');
    } catch (error) {
      console.error('[Claude] Initialization failed:', error);
      isClaudeAvailable.value = false;
    }
  }

  // Query Claude directly
  async function queryClaude(
    message: string,
    conversationHistory: Array<{ role: string; content: string }> = []
  ): Promise<string> {
    if (!anthropic) {
      throw new Error('Claude not initialized. Please set API key.');
    }

    try {
      // Build messages array from conversation history
      const messages = [
        ...conversationHistory
          .filter(msg => msg.role !== 'system')
          .map(msg => ({
            role: msg.role as 'user' | 'assistant',
            content: msg.content
          })),
        {
          role: 'user' as const,
          content: message
        }
      ];

      const response = await anthropic.messages.create({
        model: 'claude-sonnet-4-5-20250929',
        max_tokens: 4096,
        messages
      });

      const textContent = response.content.find(block => block.type === 'text');
      return textContent?.type === 'text' ? textContent.text : '';
    } catch (error) {
      console.error('[Claude] Query failed:', error);
      throw error;
    }
  }

  // Query Claude with Ollama as a tool (orchestration mode)
  async function queryClaudeWithOllamaTool(
    message: string,
    conversationHistory: Array<{ role: string; content: string }> = [],
    ollamaQueryFn: (prompt: string) => Promise<string>
  ): Promise<{ response: string; usedOllama: boolean }> {
    if (!anthropic) {
      throw new Error('Claude not initialized. Please set API key.');
    }

    try {
      const messages = [
        ...conversationHistory
          .filter(msg => msg.role !== 'system')
          .map(msg => ({
            role: msg.role as 'user' | 'assistant',
            content: msg.content
          })),
        {
          role: 'user' as const,
          content: message
        }
      ];

      let usedOllama = false;

      const response = await anthropic.messages.create({
        model: 'claude-sonnet-4-5-20250929',
        max_tokens: 4096,
        tools: [
          {
            name: 'query_local_ollama',
            description: 'Query the local Ollama AI model for simple programming questions, code examples, explanations, or straightforward queries. Use this for efficiency when the question doesn\'t require complex reasoning. The local model is fast and free.',
            input_schema: {
              type: 'object',
              properties: {
                prompt: {
                  type: 'string',
                  description: 'The question or prompt to send to the local Ollama model'
                }
              },
              required: ['prompt']
            }
          }
        ],
        messages
      });

      // Check if Claude wants to use the tool
      const toolUse = response.content.find(block => block.type === 'tool_use');

      if (toolUse && toolUse.type === 'tool_use' && toolUse.name === 'query_local_ollama') {
        console.log('[Claude] Delegating to Ollama:', toolUse.input);
        usedOllama = true;

        // Call Ollama
        const ollamaResponse = await ollamaQueryFn((toolUse.input as any).prompt);

        // Send Ollama's response back to Claude for final formatting
        const finalResponse = await anthropic.messages.create({
          model: 'claude-sonnet-4-5-20250929',
          max_tokens: 4096,
          messages: [
            ...messages,
            {
              role: 'assistant' as const,
              content: response.content
            },
            {
              role: 'user' as const,
              content: [
                {
                  type: 'tool_result' as const,
                  tool_use_id: toolUse.id,
                  content: ollamaResponse
                }
              ]
            }
          ]
        });

        const textContent = finalResponse.content.find(block => block.type === 'text');
        return {
          response: textContent?.type === 'text' ? textContent.text : ollamaResponse,
          usedOllama: true
        };
      }

      // Claude handled it directly
      const textContent = response.content.find(block => block.type === 'text');
      return {
        response: textContent?.type === 'text' ? textContent.text : '',
        usedOllama: false
      };
    } catch (error) {
      console.error('[Claude] Orchestration query failed:', error);
      throw error;
    }
  }

  // Set AI mode
  function setAIMode(mode: AIMode) {
    selectedMode.value = mode;
    console.log('[Claude] AI mode set to:', mode);
  }

  // Get current mode
  function getAIMode(): AIMode {
    return selectedMode.value;
  }

  return {
    apiKey,
    selectedMode,
    isClaudeAvailable,
    initClaude,
    queryClaude,
    queryClaudeWithOllamaTool,
    setAIMode,
    getAIMode
  };
}
