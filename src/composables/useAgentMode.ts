/**
 * useAgentMode - Claude Code-style agentic AI assistant
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { useTools, type ToolResult } from './useTools'

export interface AgentMessage {
  id: string
  role: 'user' | 'assistant' | 'tool' | 'system'
  content: string
  timestamp: number
  toolCall?: { tool: string; params: Record<string, unknown>; result?: ToolResult }
}

export interface AgentContext {
  cwd: string
  recentFiles: string[]
  recentCommands: string[]
}

const SYSTEM_PROMPT = `You are an AI coding assistant. Use tools in XML format:
<tool name="Read"><param name="path">/path/file</param></tool>

Guidelines: Read before modifying, make minimal changes, be concise.`

export function useAgentMode(paneId: string) {
  const tools = useTools()
  const messages = ref<AgentMessage[]>([])
  const isProcessing = ref(false)
  const context = ref<AgentContext>({ cwd: '~', recentFiles: [], recentCommands: [] })
  const model = ref('qwen2.5-coder:7b')

  function genId(): string {
    return `msg-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`
  }

  function addMessage(msg: Omit<AgentMessage, 'id' | 'timestamp'>): AgentMessage {
    const m: AgentMessage = { ...msg, id: genId(), timestamp: Date.now() }
    messages.value.push(m)
    return m
  }

  function buildPrompt(userMsg: string): string {
    const hist = messages.value.slice(-10).map(m =>
      m.role === 'user' ? `User: ${m.content}` :
      m.role === 'assistant' ? `Assistant: ${m.content}` :
      `[Tool ${m.toolCall?.tool}: ${m.content.slice(0, 200)}]`
    ).join('\n')
    return `${SYSTEM_PROMPT}\n\n${tools.getToolsDocumentation()}\n\nCWD: ${context.value.cwd}\n\n${hist}\n\nUser: ${userMsg}`
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
    addMessage({ role: 'user', content: userMessage })

    try {
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
    } finally {
      isProcessing.value = false
    }
  }

  function updateContext(updates: Partial<AgentContext>): void {
    context.value = { ...context.value, ...updates }
  }

  function clearMessages(): void {
    messages.value = []
  }

  return {
    messages: computed(() => messages.value),
    isProcessing: computed(() => isProcessing.value),
    context: computed(() => context.value),
    model,
    processMessage,
    updateContext,
    clearMessages,
    addMessage
  }
}

export type UseAgentModeReturn = ReturnType<typeof useAgentMode>
