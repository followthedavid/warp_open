import { ref, computed } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { listen, UnlistenFn } from '@tauri-apps/api/event';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

export interface AgentEvent {
  type: 'Started' | 'Thinking' | 'ToolRequest' | 'ToolResult' | 'Verification' | 'Completed' | 'Failed' | 'Progress' | 'StreamingChunk' | 'Heartbeat' | 'Retrying';
  task?: string;
  content?: string;
  tool?: string;
  args?: Record<string, unknown>;
  success?: boolean;
  output?: string;
  passed?: boolean;
  message?: string;
  answer?: string;
  steps?: number;
  error?: string;
  step?: number;
  total?: number;
  description?: string;
  // New streaming event fields
  chars_received?: number;
  content_preview?: string;
  elapsed_secs?: number;
  status?: string;
  attempt?: number;
  max_attempts?: number;
  reason?: string;
}

export interface AgentConfig {
  ollama_url?: string;
  model?: string;
  fast?: boolean;
  thorough?: boolean;
}

export interface AgentSession {
  id: number;
  task: string;
  status: 'running' | 'completed' | 'failed';
  events: AgentEvent[];
  result?: string;
  error?: string;
  unlisteners: UnlistenFn[];
}

const activeSessions = ref<Map<number, AgentSession>>(new Map());
const ollamaStatus = ref<{ running: boolean; model_count: number } | null>(null);
const availableModels = ref<string[]>([]);

export function useScaffoldedAgent() {
  // Check if Ollama is running
  async function checkOllamaStatus(): Promise<{ running: boolean; model_count: number }> {
    if (!isTauri) {
      // Browser fallback
      try {
        const response = await fetch('http://localhost:11434/api/tags');
        if (response.ok) {
          const data = await response.json();
          const status = { running: true, model_count: data.models?.length || 0 };
          ollamaStatus.value = status;
          return status;
        }
      } catch {
        // Ollama not running
      }
      const status = { running: false, model_count: 0 };
      ollamaStatus.value = status;
      return status;
    }

    try {
      const status = await invoke<{ running: boolean; model_count: number }>('check_ollama_status');
      ollamaStatus.value = status;
      return status;
    } catch (error) {
      console.error('Failed to check Ollama status:', error);
      const status = { running: false, model_count: 0 };
      ollamaStatus.value = status;
      return status;
    }
  }

  // List available models
  async function listModels(): Promise<string[]> {
    if (!isTauri) {
      try {
        const response = await fetch('http://localhost:11434/api/tags');
        if (response.ok) {
          const data = await response.json();
          const models = data.models?.map((m: { name: string }) => m.name) || [];
          availableModels.value = models;
          return models;
        }
      } catch {
        // Ollama not running
      }
      return [];
    }

    try {
      const models = await invoke<string[]>('list_agent_models');
      availableModels.value = models;
      return models;
    } catch (error) {
      console.error('Failed to list models:', error);
      return [];
    }
  }

  // Start a new agent task
  async function startTask(
    task: string,
    config?: AgentConfig,
    onEvent?: (event: AgentEvent) => void
  ): Promise<number> {
    if (!isTauri) {
      throw new Error('Scaffolded agent requires Tauri backend');
    }

    try {
      const sessionId = await invoke<number>('start_agent_task', {
        task,
        config: config || null,
      });

      // Create session
      const session: AgentSession = {
        id: sessionId,
        task,
        status: 'running',
        events: [],
        unlisteners: [],
      };
      activeSessions.value.set(sessionId, session);

      // Listen for agent events
      const eventName = `agent://${sessionId}`;
      const unlisten = await listen<AgentEvent>(eventName, (event) => {
        const agentEvent = event.payload;
        session.events.push(agentEvent);

        // Call user callback
        if (onEvent) {
          onEvent(agentEvent);
        }

        // Update session status based on event
        if (agentEvent.type === 'Completed') {
          session.status = 'completed';
          session.result = agentEvent.answer;
        } else if (agentEvent.type === 'Failed') {
          session.status = 'failed';
          session.error = agentEvent.error;
        }
      });
      session.unlisteners.push(unlisten);

      // Listen for done event
      const doneName = `agent://${sessionId}/done`;
      const unlistenDone = await listen<{ success: boolean; result?: string; error?: string }>(doneName, (event) => {
        const { success, result, error } = event.payload;
        if (success) {
          session.status = 'completed';
          session.result = result;
        } else {
          session.status = 'failed';
          session.error = error;
        }

        // Cleanup listeners
        for (const fn of session.unlisteners) {
          fn();
        }
      });
      session.unlisteners.push(unlistenDone);

      return sessionId;
    } catch (error) {
      console.error('Failed to start agent task:', error);
      throw error;
    }
  }

  // Execute a single tool
  async function executeTool(
    tool: string,
    args: Record<string, unknown>
  ): Promise<{ success: boolean; output: string }> {
    if (!isTauri) {
      throw new Error('Tool execution requires Tauri backend');
    }

    try {
      const result = await invoke<{ success: boolean; output: string }>('execute_agent_tool', {
        tool,
        args,
      });
      return result;
    } catch (error) {
      console.error('Failed to execute tool:', error);
      return { success: false, output: String(error) };
    }
  }

  // Get session by ID
  function getSession(sessionId: number): AgentSession | undefined {
    return activeSessions.value.get(sessionId);
  }

  // Get all active sessions
  function getActiveSessions(): AgentSession[] {
    return Array.from(activeSessions.value.values()).filter(s => s.status === 'running');
  }

  // Cancel/cleanup a session
  function cancelSession(sessionId: number): void {
    const session = activeSessions.value.get(sessionId);
    if (session) {
      for (const fn of session.unlisteners) {
        fn();
      }
      session.status = 'failed';
      session.error = 'Cancelled by user';
    }
  }

  // Clear completed sessions
  function clearCompletedSessions(): void {
    for (const [id, session] of activeSessions.value.entries()) {
      if (session.status !== 'running') {
        activeSessions.value.delete(id);
      }
    }
  }

  // Format agent events as messages for display
  function formatEventsAsMessages(events: AgentEvent[]): { role: string; content: string }[] {
    const messages: { role: string; content: string }[] = [];

    for (const event of events) {
      switch (event.type) {
        case 'Started':
          messages.push({
            role: 'system',
            content: `🚀 Agent started: ${event.task}`,
          });
          break;

        case 'Thinking':
          messages.push({
            role: 'assistant',
            content: `💭 **Thinking:**\n${event.content}`,
          });
          break;

        case 'ToolRequest':
          messages.push({
            role: 'assistant',
            content: `🔧 **Executing tool:** \`${event.tool}\`\n\`\`\`json\n${JSON.stringify(event.args, null, 2)}\n\`\`\``,
          });
          break;

        case 'ToolResult':
          const icon = event.success ? '✅' : '❌';
          messages.push({
            role: 'system',
            content: `${icon} **Tool result:**\n\`\`\`\n${event.output}\n\`\`\``,
          });
          break;

        case 'Verification':
          const verifyIcon = event.passed ? '✓' : '⚠️';
          messages.push({
            role: 'system',
            content: `${verifyIcon} **Verification:** ${event.message}`,
          });
          break;

        case 'Progress':
          messages.push({
            role: 'system',
            content: `📊 **Progress:** Step ${event.step}/${event.total} - ${event.description}`,
          });
          break;

        case 'Completed':
          messages.push({
            role: 'assistant',
            content: `✨ **Task completed** (${event.steps} steps)\n\n${event.answer}`,
          });
          break;

        case 'Failed':
          messages.push({
            role: 'system',
            content: `❌ **Task failed:** ${event.error}`,
          });
          break;

        case 'StreamingChunk':
          // Don't add messages for streaming chunks - they're for UI updates
          break;

        case 'Heartbeat':
          // Update status indicator without adding messages
          messages.push({
            role: 'system',
            content: `⏳ ${event.status}`,
          });
          break;

        case 'Retrying':
          messages.push({
            role: 'system',
            content: `🔄 **Retrying** (${event.attempt}/${event.max_attempts}): ${event.reason}`,
          });
          break;
      }
    }

    return messages;
  }

  return {
    // State
    activeSessions: computed(() => activeSessions.value),
    ollamaStatus: computed(() => ollamaStatus.value),
    availableModels: computed(() => availableModels.value),

    // Methods
    checkOllamaStatus,
    listModels,
    startTask,
    executeTool,
    getSession,
    getActiveSessions,
    cancelSession,
    clearCompletedSessions,
    formatEventsAsMessages,
  };
}
