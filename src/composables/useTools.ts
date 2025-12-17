/**
 * useTools - Claude Code-style tool use framework
 *
 * Provides a framework for AI to execute tools like:
 * - File operations (read, write, edit)
 * - Shell commands
 * - Search (grep, glob)
 * - Web fetch
 *
 * This enables Claude Code-like functionality with local LLMs
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

export interface Tool {
  name: string
  description: string
  parameters: ToolParameter[]
  execute: (params: Record<string, unknown>) => Promise<ToolResult>
}

export interface ToolParameter {
  name: string
  type: 'string' | 'number' | 'boolean' | 'array' | 'object'
  description: string
  required: boolean
  default?: unknown
}

export interface ToolResult {
  success: boolean
  output: string
  error?: string
  metadata?: Record<string, unknown>
}

export interface ToolCall {
  id: string
  tool: string
  params: Record<string, unknown>
  status: 'pending' | 'running' | 'completed' | 'failed'
  result?: ToolResult
  startTime: number
  endTime?: number
}

// Tool execution history
const toolHistory = ref<ToolCall[]>([])
const MAX_HISTORY = 100

/**
 * Read file tool
 */
async function readFile(params: Record<string, unknown>): Promise<ToolResult> {
  const path = params.path as string
  if (!path) {
    return { success: false, output: '', error: 'Missing required parameter: path' }
  }

  try {
    const content = await invoke<string>('read_file', { path })
    return {
      success: true,
      output: content,
      metadata: { path, length: content.length }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to read file: ${error}`
    }
  }
}

/**
 * Write file tool
 */
async function writeFile(params: Record<string, unknown>): Promise<ToolResult> {
  const path = params.path as string
  const content = params.content as string

  if (!path || content === undefined) {
    return { success: false, output: '', error: 'Missing required parameters: path, content' }
  }

  try {
    await invoke<string>('write_file', { path, content })
    return {
      success: true,
      output: `Successfully wrote ${content.length} bytes to ${path}`,
      metadata: { path, bytesWritten: content.length }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to write file: ${error}`
    }
  }
}

/**
 * Execute shell command tool
 */
async function executeShell(params: Record<string, unknown>): Promise<ToolResult> {
  const command = params.command as string
  const cwd = params.cwd as string | undefined

  if (!command) {
    return { success: false, output: '', error: 'Missing required parameter: command' }
  }

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command,
      cwd: cwd || undefined
    })

    const output = result.stdout + (result.stderr ? `\n[stderr]\n${result.stderr}` : '')

    return {
      success: result.exit_code === 0,
      output,
      error: result.exit_code !== 0 ? `Exit code: ${result.exit_code}` : undefined,
      metadata: {
        exitCode: result.exit_code,
        command,
        cwd
      }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to execute command: ${error}`
    }
  }
}

/**
 * List directory tool
 */
async function listDirectory(params: Record<string, unknown>): Promise<ToolResult> {
  const path = (params.path as string) || '.'

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: `ls -la "${path}"`,
      cwd: undefined
    })

    return {
      success: result.exit_code === 0,
      output: result.stdout,
      error: result.stderr || undefined,
      metadata: { path }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to list directory: ${error}`
    }
  }
}

/**
 * Search files (grep) tool
 */
async function searchFiles(params: Record<string, unknown>): Promise<ToolResult> {
  const pattern = params.pattern as string
  const path = (params.path as string) || '.'
  const caseInsensitive = params.caseInsensitive as boolean

  if (!pattern) {
    return { success: false, output: '', error: 'Missing required parameter: pattern' }
  }

  const flags = caseInsensitive ? '-rni' : '-rn'
  const command = `grep ${flags} "${pattern}" "${path}" 2>/dev/null | head -100`

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command,
      cwd: undefined
    })

    const matches = result.stdout.split('\n').filter(l => l.trim()).length

    return {
      success: true,
      output: result.stdout || 'No matches found',
      metadata: { pattern, path, matchCount: matches }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Search failed: ${error}`
    }
  }
}

/**
 * Find files (glob) tool
 */
async function findFiles(params: Record<string, unknown>): Promise<ToolResult> {
  const pattern = params.pattern as string
  const path = (params.path as string) || '.'

  if (!pattern) {
    return { success: false, output: '', error: 'Missing required parameter: pattern' }
  }

  const command = `find "${path}" -name "${pattern}" 2>/dev/null | head -100`

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command,
      cwd: undefined
    })

    const files = result.stdout.split('\n').filter(l => l.trim())

    return {
      success: true,
      output: files.join('\n') || 'No files found',
      metadata: { pattern, path, fileCount: files.length }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Find failed: ${error}`
    }
  }
}

/**
 * Edit file tool (patch-based)
 */
async function editFile(params: Record<string, unknown>): Promise<ToolResult> {
  const path = params.path as string
  const oldText = params.oldText as string
  const newText = params.newText as string

  if (!path || oldText === undefined || newText === undefined) {
    return { success: false, output: '', error: 'Missing required parameters: path, oldText, newText' }
  }

  try {
    // Read current content
    const content = await invoke<string>('read_file', { path })

    // Check if oldText exists
    if (!content.includes(oldText)) {
      return {
        success: false,
        output: '',
        error: 'oldText not found in file'
      }
    }

    // Replace
    const newContent = content.replace(oldText, newText)

    // Write back
    await invoke<string>('write_file', { path, content: newContent })

    return {
      success: true,
      output: `Successfully edited ${path}`,
      metadata: {
        path,
        replacements: 1,
        oldLength: content.length,
        newLength: newContent.length
      }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to edit file: ${error}`
    }
  }
}

/**
 * Get current working directory
 */
async function getCwd(_params: Record<string, unknown>): Promise<ToolResult> {
  try {
    const cwd = await invoke<string>('current_working_dir')
    return {
      success: true,
      output: cwd,
      metadata: { cwd }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Failed to get cwd: ${error}`
    }
  }
}

// Define available tools
const TOOLS: Tool[] = [
  {
    name: 'Read',
    description: 'Read the contents of a file',
    parameters: [
      { name: 'path', type: 'string', description: 'Path to the file to read', required: true }
    ],
    execute: readFile
  },
  {
    name: 'Write',
    description: 'Write content to a file (creates or overwrites)',
    parameters: [
      { name: 'path', type: 'string', description: 'Path to the file to write', required: true },
      { name: 'content', type: 'string', description: 'Content to write', required: true }
    ],
    execute: writeFile
  },
  {
    name: 'Edit',
    description: 'Edit a file by replacing specific text',
    parameters: [
      { name: 'path', type: 'string', description: 'Path to the file to edit', required: true },
      { name: 'oldText', type: 'string', description: 'Text to find and replace', required: true },
      { name: 'newText', type: 'string', description: 'Replacement text', required: true }
    ],
    execute: editFile
  },
  {
    name: 'Bash',
    description: 'Execute a shell command',
    parameters: [
      { name: 'command', type: 'string', description: 'Command to execute', required: true },
      { name: 'cwd', type: 'string', description: 'Working directory', required: false }
    ],
    execute: executeShell
  },
  {
    name: 'Grep',
    description: 'Search for text patterns in files',
    parameters: [
      { name: 'pattern', type: 'string', description: 'Search pattern (regex)', required: true },
      { name: 'path', type: 'string', description: 'Path to search in', required: false, default: '.' },
      { name: 'caseInsensitive', type: 'boolean', description: 'Case insensitive search', required: false, default: false }
    ],
    execute: searchFiles
  },
  {
    name: 'Glob',
    description: 'Find files matching a pattern',
    parameters: [
      { name: 'pattern', type: 'string', description: 'File pattern (e.g., *.ts)', required: true },
      { name: 'path', type: 'string', description: 'Path to search in', required: false, default: '.' }
    ],
    execute: findFiles
  },
  {
    name: 'ListDir',
    description: 'List contents of a directory',
    parameters: [
      { name: 'path', type: 'string', description: 'Directory path', required: false, default: '.' }
    ],
    execute: listDirectory
  },
  {
    name: 'GetCwd',
    description: 'Get current working directory',
    parameters: [],
    execute: getCwd
  }
]

export function useTools() {
  const isExecuting = ref(false)
  const currentCall = ref<ToolCall | null>(null)

  // Available tools
  const tools = computed(() => TOOLS)

  // Tool history
  const history = computed(() => toolHistory.value)

  // Recent successful calls
  const recentCalls = computed(() =>
    toolHistory.value
      .filter(c => c.status === 'completed')
      .slice(-10)
  )

  /**
   * Get tool by name
   */
  function getTool(name: string): Tool | undefined {
    return TOOLS.find(t => t.name.toLowerCase() === name.toLowerCase())
  }

  /**
   * Execute a tool
   */
  async function executeTool(toolName: string, params: Record<string, unknown>): Promise<ToolResult> {
    const tool = getTool(toolName)
    if (!tool) {
      return {
        success: false,
        output: '',
        error: `Unknown tool: ${toolName}`
      }
    }

    // Create call record
    const call: ToolCall = {
      id: `call-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      tool: toolName,
      params,
      status: 'running',
      startTime: Date.now()
    }

    toolHistory.value.push(call)
    if (toolHistory.value.length > MAX_HISTORY) {
      toolHistory.value = toolHistory.value.slice(-MAX_HISTORY)
    }

    currentCall.value = call
    isExecuting.value = true

    try {
      const result = await tool.execute(params)

      call.result = result
      call.status = result.success ? 'completed' : 'failed'
      call.endTime = Date.now()

      return result
    } catch (error) {
      const errorResult: ToolResult = {
        success: false,
        output: '',
        error: `Tool execution failed: ${error}`
      }

      call.result = errorResult
      call.status = 'failed'
      call.endTime = Date.now()

      return errorResult
    } finally {
      isExecuting.value = false
      currentCall.value = null
    }
  }

  /**
   * Parse tool call from LLM response
   * Supports format: <tool name="ToolName"><param name="key">value</param></tool>
   */
  function parseToolCall(text: string): { tool: string; params: Record<string, unknown> } | null {
    // Try XML-style format
    const toolMatch = text.match(/<tool\s+name="([^"]+)">([\s\S]*?)<\/tool>/i)
    if (toolMatch) {
      const toolName = toolMatch[1]
      const paramsContent = toolMatch[2]

      const params: Record<string, unknown> = {}
      const paramMatches = paramsContent.matchAll(/<param\s+name="([^"]+)">([\s\S]*?)<\/param>/gi)

      for (const match of paramMatches) {
        params[match[1]] = match[2].trim()
      }

      return { tool: toolName, params }
    }

    // Try JSON format
    const jsonMatch = text.match(/```json\s*\n?\s*\{[\s\S]*?"tool"\s*:\s*"([^"]+)"[\s\S]*?\}\s*\n?```/i)
    if (jsonMatch) {
      try {
        const jsonStr = text.match(/```json\s*\n?([\s\S]*?)\n?```/i)?.[1]
        if (jsonStr) {
          const parsed = JSON.parse(jsonStr)
          return {
            tool: parsed.tool,
            params: parsed.params || {}
          }
        }
      } catch {}
    }

    // Try function call format: toolName(param1="value1", param2="value2")
    const funcMatch = text.match(/(\w+)\s*\(\s*([\s\S]*?)\s*\)/i)
    if (funcMatch) {
      const toolName = funcMatch[1]
      const argsStr = funcMatch[2]

      if (getTool(toolName)) {
        const params: Record<string, unknown> = {}
        const argMatches = argsStr.matchAll(/(\w+)\s*=\s*["']([^"']*?)["']/g)

        for (const match of argMatches) {
          params[match[1]] = match[2]
        }

        return { tool: toolName, params }
      }
    }

    return null
  }

  /**
   * Generate tool documentation for LLM context
   */
  function getToolsDocumentation(): string {
    const lines = ['# Available Tools\n']

    for (const tool of TOOLS) {
      lines.push(`## ${tool.name}`)
      lines.push(tool.description)
      lines.push('\nParameters:')

      if (tool.parameters.length === 0) {
        lines.push('- None')
      } else {
        for (const param of tool.parameters) {
          const req = param.required ? '(required)' : '(optional)'
          lines.push(`- ${param.name}: ${param.type} ${req} - ${param.description}`)
        }
      }
      lines.push('')
    }

    lines.push('\n## Usage Format')
    lines.push('Use XML format to call tools:')
    lines.push('```')
    lines.push('<tool name="ToolName">')
    lines.push('  <param name="paramName">value</param>')
    lines.push('</tool>')
    lines.push('```')

    return lines.join('\n')
  }

  /**
   * Clear history
   */
  function clearHistory(): void {
    toolHistory.value = []
  }

  return {
    // State
    tools,
    history,
    recentCalls,
    isExecuting: computed(() => isExecuting.value),
    currentCall: computed(() => currentCall.value),

    // Actions
    getTool,
    executeTool,
    parseToolCall,
    getToolsDocumentation,
    clearHistory
  }
}

export type UseToolsReturn = ReturnType<typeof useTools>
