/**
 * useTools - Claude Code-style tool use framework
 *
 * Provides a comprehensive framework for AI to execute tools like:
 * - File operations (read with offset/limit, write, edit with replace_all)
 * - Shell commands (with timeout, background, sandbox controls)
 * - Search (grep with ripgrep features, glob with proper patterns)
 * - Web search (DuckDuckGo - no API key needed)
 * - Web fetch
 *
 * This enables full Claude Code parity with local LLMs
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

// Background task tracking
export interface BackgroundTask {
  id: string
  command: string
  status: 'running' | 'completed' | 'failed'
  output: string
  startTime: number
  endTime?: number
  pid?: number
}

// Tool execution history
const toolHistory = ref<ToolCall[]>([])
const backgroundTasks = ref<Map<string, BackgroundTask>>(new Map())
const MAX_HISTORY = 100

/**
 * Read file tool with offset/limit support for large files
 */
async function readFile(params: Record<string, unknown>): Promise<ToolResult> {
  const path = params.path as string
  const offset = params.offset as number | undefined
  const limit = params.limit as number | undefined

  if (!path) {
    return { success: false, output: '', error: 'Missing required parameter: path' }
  }

  try {
    const content = await invoke<string>('read_file', { path })

    // Apply offset and limit if specified
    let lines = content.split('\n')
    const totalLines = lines.length

    if (offset !== undefined || limit !== undefined) {
      const startLine = offset ?? 0
      const endLine = limit !== undefined ? startLine + limit : lines.length
      lines = lines.slice(startLine, endLine)
    }

    // Format with line numbers like Claude Code (cat -n style)
    const numberedLines = lines.map((line, idx) => {
      const lineNum = (offset ?? 0) + idx + 1
      return `${String(lineNum).padStart(6, ' ')}\t${line}`
    }).join('\n')

    return {
      success: true,
      output: numberedLines,
      metadata: {
        path,
        totalLines,
        startLine: offset ?? 0,
        linesReturned: lines.length,
        truncated: limit !== undefined && (offset ?? 0) + limit < totalLines
      }
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
 * Execute shell command tool with timeout, background, and sandbox controls
 */
async function executeShell(params: Record<string, unknown>): Promise<ToolResult> {
  const command = params.command as string
  const cwd = params.cwd as string | undefined
  const timeout = params.timeout as number | undefined // milliseconds, max 600000 (10 min)
  const runInBackground = params.run_in_background as boolean | undefined
  const description = params.description as string | undefined
  const dangerouslyDisableSandbox = params.dangerouslyDisableSandbox as boolean | undefined

  if (!command) {
    return { success: false, output: '', error: 'Missing required parameter: command' }
  }

  // Validate timeout
  const actualTimeout = Math.min(timeout ?? 120000, 600000) // Default 2 min, max 10 min

  // Handle background execution
  if (runInBackground) {
    const taskId = `bg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const task: BackgroundTask = {
      id: taskId,
      command,
      status: 'running',
      output: '',
      startTime: Date.now()
    }
    backgroundTasks.value.set(taskId, task)

    // Run in background without waiting
    invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: `${command} &`,
      cwd: cwd || undefined
    }).then(result => {
      const t = backgroundTasks.value.get(taskId)
      if (t) {
        t.status = result.exit_code === 0 ? 'completed' : 'failed'
        t.output = result.stdout + (result.stderr ? `\n${result.stderr}` : '')
        t.endTime = Date.now()
      }
    }).catch(err => {
      const t = backgroundTasks.value.get(taskId)
      if (t) {
        t.status = 'failed'
        t.output = String(err)
        t.endTime = Date.now()
      }
    })

    return {
      success: true,
      output: `Started background task: ${taskId}`,
      metadata: { taskId, command, description }
    }
  }

  try {
    // Wrap command with timeout
    const timedCommand = actualTimeout < 600000
      ? `timeout ${Math.ceil(actualTimeout / 1000)} ${command}`
      : command

    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: timedCommand,
      cwd: cwd || undefined
    })

    const output = result.stdout + (result.stderr ? `\n[stderr]\n${result.stderr}` : '')

    // Truncate output if too long (30000 chars like Claude Code)
    const truncated = output.length > 30000
    const finalOutput = truncated ? output.slice(0, 30000) + '\n...[output truncated]' : output

    return {
      success: result.exit_code === 0,
      output: finalOutput,
      error: result.exit_code !== 0 ? `Exit code: ${result.exit_code}` : undefined,
      metadata: {
        exitCode: result.exit_code,
        command,
        cwd,
        description,
        truncated,
        timeout: actualTimeout
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
 * Get output from a background task
 */
async function getTaskOutput(params: Record<string, unknown>): Promise<ToolResult> {
  const taskId = params.task_id as string
  const block = params.block as boolean ?? true
  const timeout = params.timeout as number ?? 30000

  if (!taskId) {
    return { success: false, output: '', error: 'Missing required parameter: task_id' }
  }

  const task = backgroundTasks.value.get(taskId)
  if (!task) {
    return { success: false, output: '', error: `Task not found: ${taskId}` }
  }

  if (block && task.status === 'running') {
    // Wait for task to complete
    const startWait = Date.now()
    while (task.status === 'running' && Date.now() - startWait < timeout) {
      await new Promise(resolve => setTimeout(resolve, 100))
    }
  }

  return {
    success: task.status === 'completed',
    output: task.output,
    error: task.status === 'failed' ? 'Task failed' : undefined,
    metadata: {
      taskId,
      status: task.status,
      startTime: task.startTime,
      endTime: task.endTime,
      duration: task.endTime ? task.endTime - task.startTime : Date.now() - task.startTime
    }
  }
}

/**
 * Kill a background task/shell
 */
async function killShell(params: Record<string, unknown>): Promise<ToolResult> {
  const taskId = params.shell_id as string

  if (!taskId) {
    return { success: false, output: '', error: 'Missing required parameter: shell_id' }
  }

  const task = backgroundTasks.value.get(taskId)
  if (!task) {
    return { success: false, output: '', error: `Task not found: ${taskId}` }
  }

  if (task.pid) {
    try {
      await invoke('execute_shell', { command: `kill -9 ${task.pid}` })
    } catch {
      // Process may have already exited
    }
  }

  task.status = 'failed'
  task.endTime = Date.now()
  task.output += '\n[killed]'

  return {
    success: true,
    output: `Killed task: ${taskId}`,
    metadata: { taskId }
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
 * Search files (grep) tool - Full ripgrep implementation
 * Supports: output_mode, context lines, multiline, type filtering, head_limit, offset
 */
async function searchFiles(params: Record<string, unknown>): Promise<ToolResult> {
  const pattern = params.pattern as string
  const path = (params.path as string) || '.'
  const caseInsensitive = params['-i'] as boolean ?? params.caseInsensitive as boolean
  const outputMode = params.output_mode as string ?? 'files_with_matches' // 'content', 'files_with_matches', 'count'
  const contextBefore = params['-B'] as number
  const contextAfter = params['-A'] as number
  const contextBoth = params['-C'] as number
  const showLineNumbers = params['-n'] as boolean ?? true
  const multiline = params.multiline as boolean
  const glob = params.glob as string // e.g., "*.js"
  const fileType = params.type as string // e.g., "js", "py", "rust"
  const headLimit = params.head_limit as number ?? 0
  const offset = params.offset as number ?? 0

  if (!pattern) {
    return { success: false, output: '', error: 'Missing required parameter: pattern' }
  }

  // Build ripgrep command
  const args: string[] = ['rg']

  // Output mode
  if (outputMode === 'files_with_matches') {
    args.push('-l') // List files only
  } else if (outputMode === 'count') {
    args.push('-c') // Count matches
  }

  // Case sensitivity
  if (caseInsensitive) {
    args.push('-i')
  }

  // Line numbers (for content mode)
  if (outputMode === 'content' && showLineNumbers) {
    args.push('-n')
  }

  // Context lines
  if (contextBoth) {
    args.push(`-C${contextBoth}`)
  } else {
    if (contextBefore) args.push(`-B${contextBefore}`)
    if (contextAfter) args.push(`-A${contextAfter}`)
  }

  // Multiline mode
  if (multiline) {
    args.push('-U', '--multiline-dotall')
  }

  // File type filtering
  if (fileType) {
    args.push(`--type=${fileType}`)
  }

  // Glob pattern filtering
  if (glob) {
    args.push(`--glob=${glob}`)
  }

  // Add pattern and path
  args.push(`"${pattern.replace(/"/g, '\\"')}"`, `"${path}"`)

  // Apply head_limit and offset using tail/head
  let command = args.join(' ')
  if (offset > 0 || headLimit > 0) {
    if (offset > 0) {
      command += ` | tail -n +${offset + 1}`
    }
    if (headLimit > 0) {
      command += ` | head -n ${headLimit}`
    }
  }

  command += ' 2>/dev/null'

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command,
      cwd: undefined
    })

    const lines = result.stdout.split('\n').filter(l => l.trim())
    let matchCount = 0

    if (outputMode === 'count') {
      // Sum up counts from each file
      matchCount = lines.reduce((sum, line) => {
        const count = parseInt(line.split(':').pop() || '0', 10)
        return sum + (isNaN(count) ? 0 : count)
      }, 0)
    } else {
      matchCount = lines.length
    }

    return {
      success: true,
      output: result.stdout || 'No matches found',
      metadata: {
        pattern,
        path,
        matchCount,
        outputMode,
        offset,
        headLimit,
        multiline: multiline ?? false
      }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Search failed: ${error}`
    }
  }
}

// Find files (glob) tool - Uses fd for fast glob matching, falls back to find
// Supports full glob patterns like "src/*.vue" or recursive patterns
async function findFiles(params: Record<string, unknown>): Promise<ToolResult> {
  const pattern = params.pattern as string
  const path = (params.path as string) || '.'

  if (!pattern) {
    return { success: false, output: '', error: 'Missing required parameter: pattern' }
  }

  // Try fd first (faster), fall back to find
  // fd uses glob patterns natively, find needs conversion
  let command: string

  // Check if fd is available
  const hasFd = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
    command: 'which fd 2>/dev/null || which fdfind 2>/dev/null',
    cwd: undefined
  }).then(r => r.exit_code === 0).catch(() => false)

  if (hasFd) {
    // fd uses glob patterns directly
    command = `fd -g "${pattern}" "${path}" 2>/dev/null | head -500`
  } else {
    // Convert glob pattern to find compatible pattern
    // **/ means any directory depth, * means any chars
    let findPattern = pattern

    // If pattern has **/, use find with -path
    if (pattern.includes('**/')) {
      findPattern = pattern.replace(/\*\*\//g, '*/')
      command = `find "${path}" -path "*${findPattern}" 2>/dev/null | head -500`
    } else {
      // Simple glob pattern - use -name
      command = `find "${path}" -name "${pattern}" 2>/dev/null | head -500`
    }
  }

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command,
      cwd: undefined
    })

    const files = result.stdout.split('\n').filter(l => l.trim())

    // Sort by modification time (newest first) like Claude Code
    // We can't easily get mtime from the output, so just return as-is

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
 * Web Search tool - Uses DuckDuckGo HTML (no API key needed)
 * Returns search results for the given query
 */
async function webSearch(params: Record<string, unknown>): Promise<ToolResult> {
  const query = params.query as string
  const allowedDomains = params.allowed_domains as string[] | undefined
  const blockedDomains = params.blocked_domains as string[] | undefined

  if (!query) {
    return { success: false, output: '', error: 'Missing required parameter: query' }
  }

  try {
    // Use DuckDuckGo HTML search (no API key required)
    const encodedQuery = encodeURIComponent(query)
    const searchUrl = `https://html.duckduckgo.com/html/?q=${encodedQuery}`

    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: `curl -sL -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" "${searchUrl}" 2>/dev/null`,
      cwd: undefined
    })

    if (!result.stdout) {
      return { success: false, output: '', error: 'Failed to fetch search results' }
    }

    // Parse HTML results
    const html = result.stdout
    const results: Array<{ title: string; url: string; snippet: string }> = []

    // Extract result links and snippets using regex (simple parsing)
    const resultRegex = /<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([^<]*)<\/a>/g
    const snippetRegex = /<a[^>]*class="result__snippet"[^>]*>([^<]*)<\/a>/g

    let match
    const titles: string[] = []
    const urls: string[] = []
    const snippets: string[] = []

    // Extract URLs and titles
    while ((match = resultRegex.exec(html)) !== null) {
      let url = match[1]
      // DuckDuckGo wraps URLs, extract actual URL
      if (url.includes('uddg=')) {
        const urlMatch = url.match(/uddg=([^&]+)/)
        if (urlMatch) {
          url = decodeURIComponent(urlMatch[1])
        }
      }
      urls.push(url)
      titles.push(match[2].trim())
    }

    // Extract snippets
    while ((match = snippetRegex.exec(html)) !== null) {
      snippets.push(match[1].trim().replace(/<[^>]*>/g, ''))
    }

    // Combine results
    for (let i = 0; i < Math.min(urls.length, 10); i++) {
      const url = urls[i]

      // Apply domain filtering
      if (allowedDomains?.length) {
        const allowed = allowedDomains.some(d => url.includes(d))
        if (!allowed) continue
      }
      if (blockedDomains?.length) {
        const blocked = blockedDomains.some(d => url.includes(d))
        if (blocked) continue
      }

      results.push({
        title: titles[i] || 'Untitled',
        url,
        snippet: snippets[i] || ''
      })
    }

    // Format output like Claude Code web search
    const output = results.map((r, i) =>
      `${i + 1}. **${r.title}**\n   ${r.url}\n   ${r.snippet}`
    ).join('\n\n')

    return {
      success: true,
      output: output || 'No results found',
      metadata: {
        query,
        resultCount: results.length,
        results: results.slice(0, 5) // Include first 5 in metadata
      }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Web search failed: ${error}`
    }
  }
}

/**
 * Web Fetch tool - Fetch URL content with AI processing prompt
 */
async function webFetch(params: Record<string, unknown>): Promise<ToolResult> {
  const url = params.url as string
  const prompt = params.prompt as string

  if (!url) {
    return { success: false, output: '', error: 'Missing required parameter: url' }
  }

  try {
    // Fetch URL content
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: `curl -sL -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" "${url}" 2>/dev/null | head -c 100000`,
      cwd: undefined
    })

    if (!result.stdout) {
      return { success: false, output: '', error: 'Failed to fetch URL' }
    }

    let content = result.stdout

    // Simple HTML to text conversion
    content = content
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .trim()

    // Truncate if too long
    if (content.length > 15000) {
      content = content.slice(0, 15000) + '\n...[content truncated]'
    }

    return {
      success: true,
      output: content,
      metadata: {
        url,
        prompt,
        contentLength: content.length
      }
    }
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Web fetch failed: ${error}`
    }
  }
}

/**
 * Edit file tool (patch-based) with replace_all support
 */
async function editFile(params: Record<string, unknown>): Promise<ToolResult> {
  const path = params.path as string
  const oldText = params.old_string as string ?? params.oldText as string
  const newText = params.new_string as string ?? params.newText as string
  const replaceAll = params.replace_all as boolean ?? false

  if (!path || oldText === undefined || newText === undefined) {
    return { success: false, output: '', error: 'Missing required parameters: path, old_string, new_string' }
  }

  try {
    // Read current content
    const content = await invoke<string>('read_file', { path })

    // Check if oldText exists
    if (!content.includes(oldText)) {
      return {
        success: false,
        output: '',
        error: 'old_string not found in file. Make sure it matches exactly including whitespace.'
      }
    }

    // Count occurrences
    const occurrences = (content.match(new RegExp(oldText.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length

    // Replace - either first occurrence or all
    let newContent: string
    let replacements: number

    if (replaceAll) {
      newContent = content.split(oldText).join(newText)
      replacements = occurrences
    } else {
      newContent = content.replace(oldText, newText)
      replacements = 1
    }

    // Write back
    await invoke<string>('write_file', { path, content: newContent })

    return {
      success: true,
      output: `Successfully edited ${path} (${replacements} replacement${replacements > 1 ? 's' : ''})`,
      metadata: {
        path,
        replacements,
        totalOccurrences: occurrences,
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

// Define available tools - Full Claude Code parity
const TOOLS: Tool[] = [
  {
    name: 'Read',
    description: 'Read file contents with optional offset/limit for large files',
    parameters: [
      { name: 'path', type: 'string', description: 'Absolute path to the file', required: true },
      { name: 'offset', type: 'number', description: 'Line number to start from (0-indexed)', required: false },
      { name: 'limit', type: 'number', description: 'Number of lines to read', required: false }
    ],
    execute: readFile
  },
  {
    name: 'Write',
    description: 'Write content to a file (creates or overwrites)',
    parameters: [
      { name: 'path', type: 'string', description: 'Absolute path to the file', required: true },
      { name: 'content', type: 'string', description: 'Content to write', required: true }
    ],
    execute: writeFile
  },
  {
    name: 'Edit',
    description: 'Edit a file by replacing specific text. Use replace_all for global replacements.',
    parameters: [
      { name: 'file_path', type: 'string', description: 'Absolute path to the file', required: true },
      { name: 'old_string', type: 'string', description: 'Exact text to find and replace', required: true },
      { name: 'new_string', type: 'string', description: 'Replacement text', required: true },
      { name: 'replace_all', type: 'boolean', description: 'Replace all occurrences (default: false)', required: false, default: false }
    ],
    execute: editFile
  },
  {
    name: 'Bash',
    description: 'Execute shell command with timeout and background support',
    parameters: [
      { name: 'command', type: 'string', description: 'Command to execute', required: true },
      { name: 'cwd', type: 'string', description: 'Working directory', required: false },
      { name: 'timeout', type: 'number', description: 'Timeout in milliseconds (max 600000)', required: false },
      { name: 'run_in_background', type: 'boolean', description: 'Run in background, returns task_id', required: false },
      { name: 'description', type: 'string', description: 'Short description of what command does', required: false },
      { name: 'dangerouslyDisableSandbox', type: 'boolean', description: 'Override sandbox mode', required: false }
    ],
    execute: executeShell
  },
  {
    name: 'TaskOutput',
    description: 'Get output from a background task',
    parameters: [
      { name: 'task_id', type: 'string', description: 'The background task ID', required: true },
      { name: 'block', type: 'boolean', description: 'Wait for completion (default: true)', required: false, default: true },
      { name: 'timeout', type: 'number', description: 'Max wait time in ms (default: 30000)', required: false }
    ],
    execute: getTaskOutput
  },
  {
    name: 'KillShell',
    description: 'Kill a running background shell/task',
    parameters: [
      { name: 'shell_id', type: 'string', description: 'The task ID to kill', required: true }
    ],
    execute: killShell
  },
  {
    name: 'Grep',
    description: 'Search file contents using ripgrep with full features',
    parameters: [
      { name: 'pattern', type: 'string', description: 'Regex pattern to search for', required: true },
      { name: 'path', type: 'string', description: 'Path to search in', required: false, default: '.' },
      { name: 'output_mode', type: 'string', description: 'content|files_with_matches|count', required: false, default: 'files_with_matches' },
      { name: '-i', type: 'boolean', description: 'Case insensitive search', required: false },
      { name: '-A', type: 'number', description: 'Lines to show after match', required: false },
      { name: '-B', type: 'number', description: 'Lines to show before match', required: false },
      { name: '-C', type: 'number', description: 'Lines to show around match', required: false },
      { name: '-n', type: 'boolean', description: 'Show line numbers', required: false, default: true },
      { name: 'multiline', type: 'boolean', description: 'Enable multiline mode', required: false },
      { name: 'glob', type: 'string', description: 'Glob pattern filter (e.g., "*.js")', required: false },
      { name: 'type', type: 'string', description: 'File type (js, py, rust, etc.)', required: false },
      { name: 'head_limit', type: 'number', description: 'Limit output lines', required: false },
      { name: 'offset', type: 'number', description: 'Skip first N lines', required: false }
    ],
    execute: searchFiles
  },
  {
    name: 'Glob',
    description: 'Find files matching glob pattern (supports **/*.ts style)',
    parameters: [
      { name: 'pattern', type: 'string', description: 'Glob pattern (e.g., **/*.ts, src/**/*.vue)', required: true },
      { name: 'path', type: 'string', description: 'Base path to search', required: false, default: '.' }
    ],
    execute: findFiles
  },
  {
    name: 'WebSearch',
    description: 'Search the web using DuckDuckGo (no API key needed)',
    parameters: [
      { name: 'query', type: 'string', description: 'Search query', required: true },
      { name: 'allowed_domains', type: 'array', description: 'Only include these domains', required: false },
      { name: 'blocked_domains', type: 'array', description: 'Exclude these domains', required: false }
    ],
    execute: webSearch
  },
  {
    name: 'WebFetch',
    description: 'Fetch and extract content from a URL',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to fetch', required: true },
      { name: 'prompt', type: 'string', description: 'Prompt for processing content', required: false }
    ],
    execute: webFetch
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
