/**
 * useAgentMode - Claude Code-style agentic AI assistant
 *
 * Now powered by ScaffoldedAgent for:
 * - Intelligent model routing
 * - Context management with sliding window
 * - Automatic verification and recovery
 * - Pattern caching for faster responses
 */

import { ref, computed, watch } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { useTools, type ToolResult } from './useTools'
import {
  ScaffoldedAgent,
  useScaffoldedAgent,
  type AgentMessage as ScaffoldedMessage,
  type AgentAction
} from '../agents'

export interface AgentMessage {
  id: string
  role: 'user' | 'assistant' | 'tool' | 'system' | 'action'
  content: string
  timestamp: number
  toolCall?: { tool: string; params: Record<string, unknown>; result?: ToolResult }
  action?: AgentAction
  patternUsed?: string
}

export interface AgentContext {
  cwd: string
  recentFiles: string[]
  recentCommands: string[]
}

// Feature flags
const USE_SCAFFOLDED_AGENT = true  // Toggle to switch between old and new system

export function useAgentMode(paneId: string) {
  const tools = useTools()
  const messages = ref<AgentMessage[]>([])
  const isProcessing = ref(false)
  const context = ref<AgentContext>({ cwd: '~', recentFiles: [], recentCommands: [] })
  const model = ref('qwen2.5-coder:1.5b')
  const error = ref<string | null>(null)

  // Stats from scaffolded agent
  const stats = ref({
    tasksCompleted: 0,
    tasksFailed: 0,
    actionsExecuted: 0,
    patternsUsed: 0,
    rollbacks: 0,
    avgResponseTime: 0
  })

  // Initialize ScaffoldedAgent if enabled
  let scaffoldedAgent: ScaffoldedAgent | null = null

  if (USE_SCAFFOLDED_AGENT) {
    scaffoldedAgent = new ScaffoldedAgent({
      defaultModel: model.value,
      maxRetries: 3,
      maxStepsPerTask: 15,
      usePatternCache: true,
      preferLocalModels: true,
      autoVerify: true,
      autoRecover: true
    })

    // Set up callbacks
    scaffoldedAgent.setCallbacks({
      onMessage: (msg: ScaffoldedMessage) => {
        // Convert ScaffoldedMessage to our AgentMessage format
        const agentMsg: AgentMessage = {
          id: msg.id,
          role: msg.role === 'action' ? 'tool' : msg.role,
          content: msg.content,
          timestamp: msg.timestamp,
          action: msg.action,
          patternUsed: msg.patternUsed
        }

        // Convert action to toolCall format for UI compatibility
        if (msg.action) {
          agentMsg.toolCall = {
            tool: msg.action.action,
            params: {
              path: msg.action.path,
              content: msg.action.content,
              command: msg.action.command,
              pattern: msg.action.pattern
            },
            result: { success: true, output: msg.content }
          }
        }

        messages.value.push(agentMsg)
      },
      onStateChange: (state) => {
        // Could show task state in UI
        if (state === 'failed') {
          error.value = 'Task failed'
        }
      },
      onUserInput: async (question: string) => {
        // For now, return empty - could show a dialog
        console.log('Agent asking:', question)
        return ''
      }
    })
  }

  // Watch model changes
  watch(model, (newModel) => {
    if (scaffoldedAgent) {
      scaffoldedAgent.setModel(newModel)
    }
  })

  function genId(): string {
    return `msg-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`
  }

  function addMessage(msg: Omit<AgentMessage, 'id' | 'timestamp'>): AgentMessage {
    const m: AgentMessage = { ...msg, id: genId(), timestamp: Date.now() }
    messages.value.push(m)
    return m
  }

  // Legacy prompt builder for fallback mode
  function buildPrompt(userMsg: string): string {
    const hist = messages.value.slice(-10).map(m =>
      m.role === 'user' ? `User: ${m.content}` :
      m.role === 'assistant' ? `Assistant: ${m.content}` :
      `[Tool ${m.toolCall?.tool}: ${m.content.slice(0, 200)}]`
    ).join('\n')

    const systemPrompt = `You are an AI coding assistant. Use tools in XML format:
<tool name="Read"><param name="path">/path/file</param></tool>

Guidelines: Read before modifying, make minimal changes, be concise.`

    return `${systemPrompt}\n\n${tools.getToolsDocumentation()}\n\nCWD: ${context.value.cwd}\n\n${hist}\n\nUser: ${userMsg}`
  }

  async function queryLLM(prompt: string): Promise<string> {
    try {
      return await invoke<string>('query_ollama', { prompt, model: model.value })
    } catch (e) {
      return `Error: ${e}`
    }
  }

  async function processMessage(userMessage: string): Promise<void> {
    if (isProcessing.value) return
    isProcessing.value = true
    error.value = null

    try {
      if (USE_SCAFFOLDED_AGENT && scaffoldedAgent) {
        // Use the new scaffolded agent
        await scaffoldedAgent.process(userMessage)

        // Update stats
        const agentState = scaffoldedAgent.getState()
        stats.value = agentState.stats

        // Sync messages from agent
        const agentMessages = scaffoldedAgent.getMessages()
        messages.value = agentMessages.map(msg => ({
          id: msg.id,
          role: msg.role === 'action' ? 'tool' : msg.role as AgentMessage['role'],
          content: msg.content,
          timestamp: msg.timestamp,
          action: msg.action,
          patternUsed: msg.patternUsed,
          toolCall: msg.action ? {
            tool: msg.action.action,
            params: { path: msg.action.path, content: msg.action.content, command: msg.action.command },
            result: { success: true, output: msg.content }
          } : undefined
        }))

      } else {
        // Fallback to legacy mode
        addMessage({ role: 'user', content: userMessage })

        for (let i = 0; i < 10; i++) {
          const prompt = buildPrompt(userMessage)
          const response = await queryLLM(prompt)
          const toolCall = tools.parseToolCall(response)

          if (toolCall) {
            const result = await tools.executeTool(toolCall.tool, toolCall.params)
            addMessage({ role: 'tool', content: result.output || result.error || '', toolCall: { ...toolCall, result } })
            if (!result.success) break
          } else {
            addMessage({ role: 'assistant', content: response })
            break
          }
        }
      }
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Unknown error'
      addMessage({ role: 'system', content: `Error: ${error.value}` })
    } finally {
      isProcessing.value = false
    }
  }

  function updateContext(updates: Partial<AgentContext>): void {
    context.value = { ...context.value, ...updates }
  }

  function clearMessages(): void {
    messages.value = []
    if (scaffoldedAgent) {
      scaffoldedAgent.clearMessages()
    }
  }

  // New functions from ScaffoldedAgent
  async function undo(): Promise<{ success: boolean; message: string }> {
    if (scaffoldedAgent) {
      return await scaffoldedAgent.undo()
    }
    return { success: false, message: 'Scaffolded agent not enabled' }
  }

  function pause(): void {
    if (scaffoldedAgent) {
      scaffoldedAgent.pause()
    }
  }

  function resume(): void {
    if (scaffoldedAgent) {
      scaffoldedAgent.resume()
    }
  }

  function stop(): void {
    if (scaffoldedAgent) {
      scaffoldedAgent.stop()
    }
    isProcessing.value = false
  }

  function getStats() {
    return stats.value
  }

  return {
    messages: computed(() => messages.value),
    isProcessing: computed(() => isProcessing.value),
    context: computed(() => context.value),
    error: computed(() => error.value),
    stats: computed(() => stats.value),
    model,
    processMessage,
    updateContext,
    clearMessages,
    addMessage,
    // New controls
    undo,
    pause,
    resume,
    stop,
    getStats,
    // Expose scaffolded agent for advanced use
    scaffoldedAgent
  }
}

export type UseAgentModeReturn = ReturnType<typeof useAgentMode>
