import { ref, computed } from 'vue';
import { v4 as uuidv4 } from 'uuid';
import { useClaude, type AIMode } from './useClaude';
import type { ExecutionTask } from './useCodeExecution';
import { useScaffoldedAgent, type AgentEvent, type AgentConfig } from './useScaffoldedAgent';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

// Dynamic imports for Tauri APIs (only available in desktop app)
type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
type ListenFn = <T>(event: string, handler: (event: { payload: T }) => void) => Promise<() => void>;
type UnlistenFn = () => void;

let invoke: InvokeFn | null = null;
let listen: ListenFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
  import('@tauri-apps/api/event').then(module => {
    listen = module.listen as ListenFn;
  });
}

export interface AIMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  streaming?: boolean;
  executionTask?: ExecutionTask; // For code execution messages
  isExecuting?: boolean; // Currently executing code
}

export interface AISession {
  id: string;
  messages: AIMessage[];
  model: string;
  isThinking: boolean;
  debugLogs?: string[];
  aiMode?: AIMode;
  executionMode?: boolean; // Enable code execution in chat
}

const sessions = ref<Map<string, AISession>>(new Map());
const availableModels = ref<string[]>([
  'qwen2.5-coder:1.5b',
  'tinydolphin:1.1b',
  'coder-uncensored:latest',
  'stablelm2:1.6b',
]);

export function useAI() {
  const claude = useClaude();
  const scaffoldedAgent = useScaffoldedAgent();

  // Load available models from Ollama
  async function refreshModels() {
    try {
      const models = await invoke<string[]>('list_ollama_models');
      availableModels.value = models;
    } catch (error) {
      console.error('Failed to load Ollama models:', error);
    }
  }

  // Create a new AI session
  function createSession(tabId: string, model = 'qwen2.5-coder:1.5b'): AISession {
    const session: AISession = {
      id: tabId,
      messages: [],
      model,
      isThinking: false,
      debugLogs: [],
      aiMode: claude.getAIMode(),
    };
    sessions.value.set(tabId, session);
    console.log(`[SESSION] Created new session for tab ${tabId}, total sessions: ${sessions.value.size}`);
    return session;
  }

  // Get or create session for a tab
  function getSession(tabId: string): AISession {
    let session = sessions.value.get(tabId);
    if (!session) {
      console.log(`[SESSION] No session found for tab ${tabId}, creating new one`);
      session = createSession(tabId);
    } else {
      console.log(`[SESSION] Found existing session for tab ${tabId}, messages: ${session.messages.length}`);
    }
    return session;
  }

  // Add message to session
  function addMessage(tabId: string, message: Omit<AIMessage, 'id' | 'timestamp'>): AIMessage {
    const session = getSession(tabId);
    const fullMessage: AIMessage = {
      ...message,
      id: uuidv4(),
      timestamp: new Date(),
    };
    session.messages.push(fullMessage);
    console.log(`[SESSION] Added ${message.role} message to ${tabId}, total messages: ${session.messages.length}`);
    return fullMessage;
  }

  // Helper to add debug logs
  function addDebugLog(tabId: string, message: string) {
    const session = sessions.value.get(tabId);
    if (session) {
      if (!session.debugLogs) session.debugLogs = [];
      const timestamp = new Date().toLocaleTimeString();
      session.debugLogs.push(`[${timestamp}] ${message}`);
      // Keep only last 50 logs
      if (session.debugLogs.length > 50) {
        session.debugLogs = session.debugLogs.slice(-50);
      }
    }
    console.log(message);
  }

  // Send prompt to Ollama with streaming
  async function sendPrompt(tabId: string, prompt: string, model?: string) {
    const session = getSession(tabId);
    const sessionModel = model || session.model;

    addDebugLog(tabId, `[START] Sending prompt to Ollama, model: ${sessionModel}`);

    // Don't allow multiple concurrent requests
    if (session.isThinking) {
      addDebugLog(tabId, '[BLOCKED] Already processing a request');
      return;
    }

    // Add user message
    addDebugLog(tabId, `[USER] Added user message: ${prompt.substring(0, 50)}...`);
    addMessage(tabId, {
      role: 'user',
      content: prompt,
    });

    // Create streaming assistant message
    const assistantMessage: AIMessage = {
      id: uuidv4(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      streaming: true,
    };
    addDebugLog(tabId, `[ASSISTANT] Created assistant message, total messages: ${session.messages.length + 1}`);
    session.messages.push(assistantMessage);
    session.isThinking = true;

    try {
      if (isTauri && invoke) {
        // Use Tauri backend
        const sessionId = uuidv4();
        let unlisten: UnlistenFn | null = null;
        let unlistenDone: UnlistenFn | null = null;

        // Listen for stream chunks
        unlisten = await listen<string>(`ollama://stream/${sessionId}`, (event) => {
          assistantMessage.content += event.payload;
        });

        // Listen for completion
        unlistenDone = await listen<boolean>(`ollama://stream/${sessionId}/done`, () => {
          assistantMessage.streaming = false;
          session.isThinking = false;
          if (unlisten) unlisten();
          if (unlistenDone) unlistenDone();
        });

        // Invoke Tauri command
        await invoke('query_ollama_stream', {
          prompt,
          model: sessionModel,
          sessionId,
        });
      } else {
        // Direct HTTP call to Ollama (browser mode)
        const response = await fetch('http://localhost:11434/api/generate', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: sessionModel,
            prompt: prompt,
            stream: true,
          }),
        });

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const reader = response.body?.getReader();
        const decoder = new TextDecoder();

        if (reader) {
          let buffer = '';
          let streamComplete = false;

          while (true) {
            const { done, value } = await reader.read();

            if (done) {
              addDebugLog(tabId, '[STREAM] Reader done, stream ended naturally');
              streamComplete = true;
              break;
            }

            // Decode the chunk
            const chunk = decoder.decode(value, { stream: true });
            buffer += chunk;

            // Split into lines (Ollama sends newline-delimited JSON)
            const lines = buffer.split('\n');

            // Keep the last line in buffer (might be incomplete JSON)
            buffer = lines.pop() || '';

            // Process each complete line
            for (const line of lines) {
              const trimmed = line.trim();
              if (!trimmed) continue;

              try {
                const json = JSON.parse(trimmed);

                // Append response token
                if (json.response && typeof json.response === 'string') {
                  assistantMessage.content += json.response;
                  if (assistantMessage.content.length % 100 === 0 || assistantMessage.content.length < 10) {
                    addDebugLog(tabId, `[STREAM] Content length: ${assistantMessage.content.length}`);
                  }
                }

                // Check for completion
                if (json.done === true) {
                  addDebugLog(tabId, '[STREAM] Done flag received, completing stream');
                  streamComplete = true;
                  break;
                }
              } catch (parseError) {
                addDebugLog(tabId, `[ERROR] Failed to parse JSON: ${trimmed.substring(0, 50)}`);
                // Continue processing other lines even if one fails
              }
            }

            // Exit outer loop if stream is complete
            if (streamComplete) {
              break;
            }
          }

          // Process any remaining content in buffer after stream ends
          if (buffer.trim()) {
            try {
              const json = JSON.parse(buffer.trim());
              console.log('[Ollama] Processing final buffer content');

              if (json.response && typeof json.response === 'string') {
                assistantMessage.content += json.response;
              }

              if (json.done === true) {
                streamComplete = true;
              }
            } catch (parseError) {
              console.warn('[Ollama] Could not parse final buffer:', buffer, parseError);
            }
          }

          // Final cleanup
          addDebugLog(tabId, `[COMPLETE] Stream finished, total length: ${assistantMessage.content.length}, total messages: ${session.messages.length}`);
          assistantMessage.streaming = false;
          session.isThinking = false;
        }

        assistantMessage.streaming = false;
        session.isThinking = false;
      }
    } catch (error) {
      addDebugLog(tabId, `[ERROR] Ollama error: ${error}`);
      assistantMessage.content = `Error: ${error}`;
      assistantMessage.streaming = false;
      session.isThinking = false;
    }
  }

  // Send prompt without streaming (simpler, for quick queries)
  async function sendPromptSimple(tabId: string, prompt: string, model?: string) {
    const session = getSession(tabId);
    const sessionModel = model || session.model;

    addMessage(tabId, {
      role: 'user',
      content: prompt,
    });

    session.isThinking = true;

    try {
      const response = await invoke<string>('query_ollama', {
        prompt,
        model: sessionModel,
      });

      addMessage(tabId, {
        role: 'assistant',
        content: response,
      });
    } catch (error) {
      addMessage(tabId, {
        role: 'assistant',
        content: `Error: ${error}`,
      });
    } finally {
      session.isThinking = false;
    }
  }

  // Clear session messages
  function clearSession(tabId: string) {
    const session = sessions.value.get(tabId);
    if (session) {
      console.log(`[SESSION] CLEARING session ${tabId}, had ${session.messages.length} messages`);
      session.messages = [];
      if (session.debugLogs) {
        session.debugLogs.push(`[${new Date().toLocaleTimeString()}] [SESSION CLEARED]`);
      }
    }
  }

  // Change model for session
  function setModel(tabId: string, model: string) {
    const session = getSession(tabId);
    session.model = model;
  }

  // Send prompt with routing based on AI mode
  async function sendPromptRouted(tabId: string, prompt: string, model?: string) {
    const session = getSession(tabId);
    const aiMode = session.aiMode || claude.getAIMode();

    addDebugLog(tabId, `[ROUTER] Mode: ${aiMode}`);

    switch (aiMode) {
      case 'local':
        // Always use Ollama
        return await sendPrompt(tabId, prompt, model);

      case 'claude':
        // Always use Claude API
        return await sendPromptClaude(tabId, prompt);

      case 'auto':
        // Claude orchestrates - decides whether to use Ollama or handle itself
        return await sendPromptOrchestrated(tabId, prompt);

      case 'hybrid':
        // Start with Ollama (user can escalate later)
        return await sendPrompt(tabId, prompt, model);

      case 'agent':
        // Use scaffolded agent with Claude-level capabilities
        return await sendPromptAgent(tabId, prompt, model);

      default:
        return await sendPrompt(tabId, prompt, model);
    }
  }

  // Send prompt to scaffolded agent (Claude-level local capabilities)
  async function sendPromptAgent(tabId: string, prompt: string, model?: string) {
    const session = getSession(tabId);

    if (session.isThinking) {
      addDebugLog(tabId, '[BLOCKED] Already processing a request');
      return;
    }

    addDebugLog(tabId, `[AGENT] Starting scaffolded agent task`);

    // Add user message
    addMessage(tabId, { role: 'user', content: prompt });

    // Create assistant message placeholder
    const assistantMessage: AIMessage = {
      id: uuidv4(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      streaming: true,
    };
    session.messages.push(assistantMessage);
    session.isThinking = true;

    try {
      // Configure agent
      const config: AgentConfig = {
        model: model || session.model,
      };

      // Track agent events for display
      let lastThinkingContent = '';

      // Start agent task with event callback
      const sessionId = await scaffoldedAgent.startTask(prompt, config, (event: AgentEvent) => {
        addDebugLog(tabId, `[AGENT] Event: ${event.type}`);

        // Build up the message content based on events
        switch (event.type) {
          case 'Started':
            assistantMessage.content = `🚀 Starting task: ${event.task}\n\n`;
            break;

          case 'Thinking':
            lastThinkingContent = event.content || '';
            assistantMessage.content += `💭 **Thinking:**\n${lastThinkingContent}\n\n`;
            break;

          case 'ToolRequest':
            assistantMessage.content += `🔧 **Using tool:** \`${event.tool}\`\n\`\`\`json\n${JSON.stringify(event.args, null, 2)}\n\`\`\`\n\n`;
            break;

          case 'ToolResult':
            const icon = event.success ? '✅' : '❌';
            const output = event.output || '';
            const truncatedOutput = output.length > 500 ? output.substring(0, 500) + '...' : output;
            assistantMessage.content += `${icon} **Result:**\n\`\`\`\n${truncatedOutput}\n\`\`\`\n\n`;
            break;

          case 'Progress':
            assistantMessage.content += `📊 Step ${event.step}/${event.total}: ${event.description}\n\n`;
            break;

          case 'Verification':
            const verifyIcon = event.passed ? '✓' : '⚠️';
            assistantMessage.content += `${verifyIcon} **Verification:** ${event.message}\n\n`;
            break;

          case 'Completed':
            assistantMessage.content += `\n---\n✨ **Task completed** (${event.steps} steps)\n\n${event.answer}`;
            assistantMessage.streaming = false;
            session.isThinking = false;
            break;

          case 'Failed':
            assistantMessage.content += `\n---\n❌ **Task failed:** ${event.error}`;
            assistantMessage.streaming = false;
            session.isThinking = false;
            break;

          case 'StreamingChunk':
            // Update progress indicator without adding to message
            addDebugLog(tabId, `[AGENT] Streaming: ${event.chars_received} chars`);
            break;

          case 'Heartbeat':
            // Show activity indicator
            addDebugLog(tabId, `[AGENT] ${event.status}`);
            break;

          case 'Retrying':
            assistantMessage.content += `🔄 **Retrying** (${event.attempt}/${event.max_attempts}): ${event.reason}\n\n`;
            addDebugLog(tabId, `[AGENT] Retry ${event.attempt}/${event.max_attempts}: ${event.reason}`);
            break;
        }
      });

      addDebugLog(tabId, `[AGENT] Task started with session ID: ${sessionId}`);

    } catch (error) {
      addDebugLog(tabId, `[ERROR] Agent task failed: ${error}`);
      assistantMessage.content = `Error starting agent: ${error}`;
      assistantMessage.streaming = false;
      session.isThinking = false;
    }
  }

  // Send prompt directly to Claude
  async function sendPromptClaude(tabId: string, prompt: string) {
    const session = getSession(tabId);

    if (!claude.isClaudeAvailable.value) {
      addDebugLog(tabId, '[ERROR] Claude not available, falling back to Ollama');
      return await sendPrompt(tabId, prompt);
    }

    if (session.isThinking) {
      addDebugLog(tabId, '[BLOCKED] Already processing a request');
      return;
    }

    addDebugLog(tabId, `[CLAUDE] Sending to Claude API`);

    // Add user message
    addMessage(tabId, { role: 'user', content: prompt });

    // Create assistant message placeholder
    const assistantMessage: AIMessage = {
      id: uuidv4(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      streaming: true,
    };
    session.messages.push(assistantMessage);
    session.isThinking = true;

    try {
      const conversationHistory = session.messages.slice(0, -1).map(msg => ({
        role: msg.role,
        content: msg.content
      }));

      const response = await claude.queryClaude(prompt, conversationHistory);
      assistantMessage.content = response;
      assistantMessage.streaming = false;
      session.isThinking = false;

      addDebugLog(tabId, `[CLAUDE] Response received, length: ${response.length}`);
    } catch (error) {
      addDebugLog(tabId, `[ERROR] Claude query failed: ${error}`);
      assistantMessage.content = `Error: ${error}`;
      assistantMessage.streaming = false;
      session.isThinking = false;
    }
  }

  // Send prompt with Claude orchestration
  async function sendPromptOrchestrated(tabId: string, prompt: string) {
    const session = getSession(tabId);

    if (!claude.isClaudeAvailable.value) {
      addDebugLog(tabId, '[WARN] Claude not available, using Ollama only');
      return await sendPrompt(tabId, prompt);
    }

    if (session.isThinking) {
      addDebugLog(tabId, '[BLOCKED] Already processing a request');
      return;
    }

    addDebugLog(tabId, `[ORCHESTRATE] Sending to Claude for orchestration`);

    // Add user message
    addMessage(tabId, { role: 'user', content: prompt });

    // Create assistant message placeholder
    const assistantMessage: AIMessage = {
      id: uuidv4(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      streaming: true,
    };
    session.messages.push(assistantMessage);
    session.isThinking = true;

    try {
      const conversationHistory = session.messages.slice(0, -1).map(msg => ({
        role: msg.role,
        content: msg.content
      }));

      // Helper function for Claude to call Ollama
      const ollamaQueryFn = async (ollamaPrompt: string): Promise<string> => {
        addDebugLog(tabId, `[ORCHESTRATE] Claude delegated to Ollama: ${ollamaPrompt.substring(0, 50)}...`);

        // Query Ollama directly (not via sendPrompt to avoid adding messages)
        const response = await fetch('http://localhost:11434/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: session.model,
            prompt: ollamaPrompt,
            stream: false // Non-streaming for tool use
          }),
        });

        const data = await response.json();
        return data.response || '';
      };

      const { response, usedOllama } = await claude.queryClaudeWithOllamaTool(
        prompt,
        conversationHistory,
        ollamaQueryFn
      );

      assistantMessage.content = response;
      assistantMessage.streaming = false;
      session.isThinking = false;

      addDebugLog(tabId, `[ORCHESTRATE] Complete, used Ollama: ${usedOllama}, length: ${response.length}`);
    } catch (error) {
      addDebugLog(tabId, `[ERROR] Orchestration failed: ${error}`);
      assistantMessage.content = `Error: ${error}`;
      assistantMessage.streaming = false;
      session.isThinking = false;
    }
  }

  // Escalate current conversation to Claude (for hybrid mode)
  async function escalateToClaude(tabId: string, messageId: string) {
    const session = getSession(tabId);
    const messageIndex = session.messages.findIndex(m => m.id === messageId);

    if (messageIndex === -1) return;

    addDebugLog(tabId, `[ESCALATE] Escalating to Claude`);

    // Get conversation up to this point
    const conversationHistory = session.messages.slice(0, messageIndex + 1).map(msg => ({
      role: msg.role,
      content: msg.content
    }));

    // Add system message
    addMessage(tabId, {
      role: 'system',
      content: '🔄 Escalated to Claude for review and improvement...'
    });

    // Create new assistant message
    const assistantMessage: AIMessage = {
      id: uuidv4(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      streaming: true,
    };
    session.messages.push(assistantMessage);
    session.isThinking = true;

    try {
      const response = await claude.queryClaude(
        "Please review and improve the previous response, or provide additional insights.",
        conversationHistory
      );

      assistantMessage.content = response;
      assistantMessage.streaming = false;
      session.isThinking = false;

      addDebugLog(tabId, `[ESCALATE] Claude response received`);
    } catch (error) {
      addDebugLog(tabId, `[ERROR] Escalation failed: ${error}`);
      assistantMessage.content = `Error: ${error}`;
      assistantMessage.streaming = false;
      session.isThinking = false;
    }
  }

  return {
    sessions,
    availableModels,
    refreshModels,
    createSession,
    getSession,
    addMessage,
    sendPrompt,
    sendPromptSimple,
    sendPromptRouted,
    sendPromptClaude,
    sendPromptOrchestrated,
    sendPromptAgent,
    escalateToClaude,
    clearSession,
    setModel,
    claude,
    scaffoldedAgent,
  };
}
