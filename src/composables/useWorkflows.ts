/**
 * useWorkflows - Warp-style workflows and snippets
 *
 * Workflows are reusable command templates that can:
 * - Have parameters (placeholders like {{name}})
 * - Be organized into categories
 * - Be shared and synced
 * - Have documentation and examples
 */

import { ref, computed, watch } from 'vue'

export interface WorkflowParameter {
  name: string
  description?: string
  defaultValue?: string
  required: boolean
  type: 'string' | 'path' | 'number' | 'select'
  options?: string[] // For select type
}

export interface Workflow {
  id: string
  name: string
  description: string
  command: string // Contains {{paramName}} placeholders
  parameters: WorkflowParameter[]
  category: string
  tags: string[]
  icon?: string
  createdAt: number
  updatedAt: number
  usageCount: number
  isFavorite: boolean
  isBuiltin: boolean
}

export interface WorkflowCategory {
  id: string
  name: string
  icon: string
  description?: string
}

// Built-in workflows
const BUILTIN_WORKFLOWS: Omit<Workflow, 'id' | 'createdAt' | 'updatedAt' | 'usageCount'>[] = [
  // Git workflows
  {
    name: 'Git Commit',
    description: 'Stage and commit changes with a message',
    command: 'git add {{files}} && git commit -m "{{message}}"',
    parameters: [
      { name: 'files', description: 'Files to stage (use . for all)', defaultValue: '.', required: true, type: 'string' },
      { name: 'message', description: 'Commit message', required: true, type: 'string' },
    ],
    category: 'git',
    tags: ['git', 'commit', 'version-control'],
    icon: '',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Git Push with Branch',
    description: 'Push current branch to remote',
    command: 'git push {{remote}} {{branch}}',
    parameters: [
      { name: 'remote', description: 'Remote name', defaultValue: 'origin', required: true, type: 'string' },
      { name: 'branch', description: 'Branch name', defaultValue: 'HEAD', required: true, type: 'string' },
    ],
    category: 'git',
    tags: ['git', 'push'],
    icon: '📤',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Git Create Branch',
    description: 'Create and switch to a new branch',
    command: 'git checkout -b {{branch_name}}',
    parameters: [
      { name: 'branch_name', description: 'New branch name', required: true, type: 'string' },
    ],
    category: 'git',
    tags: ['git', 'branch'],
    icon: '',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Git Stash',
    description: 'Stash changes with a message',
    command: 'git stash push -m "{{message}}"',
    parameters: [
      { name: 'message', description: 'Stash message', required: true, type: 'string' },
    ],
    category: 'git',
    tags: ['git', 'stash'],
    icon: '📦',
    isFavorite: false,
    isBuiltin: true,
  },

  // Docker workflows
  {
    name: 'Docker Build',
    description: 'Build a Docker image',
    command: 'docker build -t {{image_name}}:{{tag}} {{context}}',
    parameters: [
      { name: 'image_name', description: 'Image name', required: true, type: 'string' },
      { name: 'tag', description: 'Image tag', defaultValue: 'latest', required: true, type: 'string' },
      { name: 'context', description: 'Build context path', defaultValue: '.', required: true, type: 'path' },
    ],
    category: 'docker',
    tags: ['docker', 'build', 'container'],
    icon: '🐳',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Docker Run',
    description: 'Run a Docker container',
    command: 'docker run -d --name {{container_name}} -p {{host_port}}:{{container_port}} {{image}}',
    parameters: [
      { name: 'container_name', description: 'Container name', required: true, type: 'string' },
      { name: 'host_port', description: 'Host port', required: true, type: 'number' },
      { name: 'container_port', description: 'Container port', required: true, type: 'number' },
      { name: 'image', description: 'Image name', required: true, type: 'string' },
    ],
    category: 'docker',
    tags: ['docker', 'run', 'container'],
    icon: '▶️',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Docker Compose Up',
    description: 'Start services with docker-compose',
    command: 'docker-compose {{compose_file}} up {{detach}}',
    parameters: [
      { name: 'compose_file', description: 'Compose file flag', defaultValue: '', required: false, type: 'string' },
      { name: 'detach', description: 'Run detached', defaultValue: '-d', required: false, type: 'select', options: ['-d', ''] },
    ],
    category: 'docker',
    tags: ['docker', 'compose'],
    icon: '🚀',
    isFavorite: false,
    isBuiltin: true,
  },

  // NPM workflows
  {
    name: 'NPM Install Package',
    description: 'Install an npm package',
    command: 'npm install {{save_type}} {{package}}',
    parameters: [
      { name: 'package', description: 'Package name', required: true, type: 'string' },
      { name: 'save_type', description: 'Save type', defaultValue: '--save', required: true, type: 'select', options: ['--save', '--save-dev', '--global'] },
    ],
    category: 'npm',
    tags: ['npm', 'install', 'node'],
    icon: '📦',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'NPM Run Script',
    description: 'Run an npm script',
    command: 'npm run {{script}}',
    parameters: [
      { name: 'script', description: 'Script name', required: true, type: 'string' },
    ],
    category: 'npm',
    tags: ['npm', 'run', 'script'],
    icon: '▶️',
    isFavorite: false,
    isBuiltin: true,
  },

  // System workflows
  {
    name: 'Find Files',
    description: 'Find files matching a pattern',
    command: 'find {{path}} -name "{{pattern}}" {{type}}',
    parameters: [
      { name: 'path', description: 'Search path', defaultValue: '.', required: true, type: 'path' },
      { name: 'pattern', description: 'File pattern (e.g., *.js)', required: true, type: 'string' },
      { name: 'type', description: 'Type filter', defaultValue: '', required: false, type: 'select', options: ['', '-type f', '-type d'] },
    ],
    category: 'system',
    tags: ['find', 'search', 'files'],
    icon: '🔍',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Search in Files',
    description: 'Search for text in files',
    command: 'grep -r "{{pattern}}" {{path}} {{options}}',
    parameters: [
      { name: 'pattern', description: 'Search pattern', required: true, type: 'string' },
      { name: 'path', description: 'Search path', defaultValue: '.', required: true, type: 'path' },
      { name: 'options', description: 'Extra options', defaultValue: '-n', required: false, type: 'string' },
    ],
    category: 'system',
    tags: ['grep', 'search', 'text'],
    icon: '🔎',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Disk Usage',
    description: 'Show disk usage of a directory',
    command: 'du -sh {{path}}',
    parameters: [
      { name: 'path', description: 'Directory path', defaultValue: '.', required: true, type: 'path' },
    ],
    category: 'system',
    tags: ['disk', 'usage', 'space'],
    icon: '💾',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Watch File Changes',
    description: 'Watch a command output continuously',
    command: 'watch -n {{interval}} "{{command}}"',
    parameters: [
      { name: 'command', description: 'Command to watch', required: true, type: 'string' },
      { name: 'interval', description: 'Interval in seconds', defaultValue: '2', required: true, type: 'number' },
    ],
    category: 'system',
    tags: ['watch', 'monitor'],
    icon: '👁️',
    isFavorite: false,
    isBuiltin: true,
  },

  // Network workflows
  {
    name: 'HTTP Request',
    description: 'Make an HTTP request with curl',
    command: 'curl {{method}} {{headers}} "{{url}}"',
    parameters: [
      { name: 'url', description: 'Request URL', required: true, type: 'string' },
      { name: 'method', description: 'HTTP method', defaultValue: '-X GET', required: true, type: 'select', options: ['-X GET', '-X POST', '-X PUT', '-X DELETE'] },
      { name: 'headers', description: 'Headers', defaultValue: '-H "Content-Type: application/json"', required: false, type: 'string' },
    ],
    category: 'network',
    tags: ['curl', 'http', 'api'],
    icon: '🌐',
    isFavorite: false,
    isBuiltin: true,
  },
  {
    name: 'Check Port',
    description: 'Check if a port is open',
    command: 'nc -zv {{host}} {{port}}',
    parameters: [
      { name: 'host', description: 'Host address', defaultValue: 'localhost', required: true, type: 'string' },
      { name: 'port', description: 'Port number', required: true, type: 'number' },
    ],
    category: 'network',
    tags: ['port', 'network', 'check'],
    icon: '🔌',
    isFavorite: false,
    isBuiltin: true,
  },
]

const CATEGORIES: WorkflowCategory[] = [
  { id: 'git', name: 'Git', icon: '', description: 'Version control commands' },
  { id: 'docker', name: 'Docker', icon: '🐳', description: 'Container management' },
  { id: 'npm', name: 'NPM', icon: '📦', description: 'Node.js package management' },
  { id: 'system', name: 'System', icon: '💻', description: 'System utilities' },
  { id: 'network', name: 'Network', icon: '🌐', description: 'Network tools' },
  { id: 'custom', name: 'Custom', icon: '⭐', description: 'Your custom workflows' },
]

const STORAGE_KEY = 'warp_workflows'

function loadWorkflows(): Workflow[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      return JSON.parse(stored)
    }
  } catch {}
  return []
}

function saveWorkflows(workflows: Workflow[]): void {
  try {
    // Only save non-builtin workflows
    const custom = workflows.filter(w => !w.isBuiltin)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(custom))
  } catch {}
}

function generateId(): string {
  return `wf-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
}

function initializeBuiltins(): Workflow[] {
  const now = Date.now()
  return BUILTIN_WORKFLOWS.map((w, i) => ({
    ...w,
    id: `builtin-${i}`,
    createdAt: now,
    updatedAt: now,
    usageCount: 0,
  }))
}

export function useWorkflows() {
  const customWorkflows = ref<Workflow[]>(loadWorkflows())
  const builtinWorkflows = ref<Workflow[]>(initializeBuiltins())
  const searchQuery = ref('')
  const selectedCategory = ref<string | null>(null)

  // All workflows combined
  const allWorkflows = computed(() => [
    ...builtinWorkflows.value,
    ...customWorkflows.value,
  ])

  // Filtered workflows
  const filteredWorkflows = computed(() => {
    let result = allWorkflows.value

    // Filter by category
    if (selectedCategory.value) {
      result = result.filter(w => w.category === selectedCategory.value)
    }

    // Filter by search
    if (searchQuery.value) {
      const q = searchQuery.value.toLowerCase()
      result = result.filter(w =>
        w.name.toLowerCase().includes(q) ||
        w.description.toLowerCase().includes(q) ||
        w.tags.some(t => t.toLowerCase().includes(q)) ||
        w.command.toLowerCase().includes(q)
      )
    }

    return result
  })

  // Favorite workflows
  const favoriteWorkflows = computed(() =>
    allWorkflows.value.filter(w => w.isFavorite)
  )

  // Recent workflows (by usage)
  const recentWorkflows = computed(() =>
    [...allWorkflows.value]
      .filter(w => w.usageCount > 0)
      .sort((a, b) => b.usageCount - a.usageCount)
      .slice(0, 10)
  )

  // Categories with counts
  const categoriesWithCounts = computed(() =>
    CATEGORIES.map(cat => ({
      ...cat,
      count: allWorkflows.value.filter(w => w.category === cat.id).length,
    }))
  )

  /**
   * Create a new workflow
   */
  function createWorkflow(data: Omit<Workflow, 'id' | 'createdAt' | 'updatedAt' | 'usageCount' | 'isBuiltin'>): Workflow {
    const now = Date.now()
    const workflow: Workflow = {
      ...data,
      id: generateId(),
      createdAt: now,
      updatedAt: now,
      usageCount: 0,
      isBuiltin: false,
    }

    customWorkflows.value.push(workflow)
    saveWorkflows(customWorkflows.value)

    return workflow
  }

  /**
   * Update a workflow
   */
  function updateWorkflow(id: string, updates: Partial<Workflow>): boolean {
    const index = customWorkflows.value.findIndex(w => w.id === id)
    if (index === -1) return false

    customWorkflows.value[index] = {
      ...customWorkflows.value[index],
      ...updates,
      updatedAt: Date.now(),
    }
    saveWorkflows(customWorkflows.value)
    return true
  }

  /**
   * Delete a workflow
   */
  function deleteWorkflow(id: string): boolean {
    const index = customWorkflows.value.findIndex(w => w.id === id)
    if (index === -1) return false

    customWorkflows.value.splice(index, 1)
    saveWorkflows(customWorkflows.value)
    return true
  }

  /**
   * Toggle favorite
   */
  function toggleFavorite(id: string): void {
    // Check builtin first
    const builtinIdx = builtinWorkflows.value.findIndex(w => w.id === id)
    if (builtinIdx !== -1) {
      builtinWorkflows.value[builtinIdx].isFavorite = !builtinWorkflows.value[builtinIdx].isFavorite
      return
    }

    // Check custom
    const customIdx = customWorkflows.value.findIndex(w => w.id === id)
    if (customIdx !== -1) {
      customWorkflows.value[customIdx].isFavorite = !customWorkflows.value[customIdx].isFavorite
      saveWorkflows(customWorkflows.value)
    }
  }

  /**
   * Increment usage count
   */
  function recordUsage(id: string): void {
    // Check builtin first
    const builtinIdx = builtinWorkflows.value.findIndex(w => w.id === id)
    if (builtinIdx !== -1) {
      builtinWorkflows.value[builtinIdx].usageCount++
      return
    }

    // Check custom
    const customIdx = customWorkflows.value.findIndex(w => w.id === id)
    if (customIdx !== -1) {
      customWorkflows.value[customIdx].usageCount++
      saveWorkflows(customWorkflows.value)
    }
  }

  /**
   * Execute a workflow with parameters
   */
  function buildCommand(workflow: Workflow, paramValues: Record<string, string>): string {
    let command = workflow.command

    // Replace all placeholders
    for (const param of workflow.parameters) {
      const value = paramValues[param.name] ?? param.defaultValue ?? ''
      const placeholder = `{{${param.name}}}`
      command = command.replace(new RegExp(placeholder.replace(/[{}]/g, '\\$&'), 'g'), value)
    }

    // Clean up multiple spaces
    command = command.replace(/\s+/g, ' ').trim()

    return command
  }

  /**
   * Extract parameters from a command template
   */
  function extractParameters(command: string): string[] {
    const matches = command.match(/\{\{(\w+)\}\}/g) || []
    return [...new Set(matches.map(m => m.slice(2, -2)))]
  }

  /**
   * Export workflows as JSON
   */
  function exportWorkflows(): string {
    return JSON.stringify({
      version: 1,
      exportedAt: new Date().toISOString(),
      workflows: customWorkflows.value,
    }, null, 2)
  }

  /**
   * Import workflows from JSON
   */
  function importWorkflows(json: string): number {
    try {
      const data = JSON.parse(json)
      const workflows = data.workflows || data

      if (!Array.isArray(workflows)) {
        throw new Error('Invalid format')
      }

      let imported = 0
      for (const w of workflows) {
        if (w.name && w.command) {
          createWorkflow({
            name: w.name,
            description: w.description || '',
            command: w.command,
            parameters: w.parameters || [],
            category: w.category || 'custom',
            tags: w.tags || [],
            icon: w.icon,
            isFavorite: false,
          })
          imported++
        }
      }

      return imported
    } catch {
      return 0
    }
  }

  /**
   * Set category filter
   */
  function setCategory(category: string | null): void {
    selectedCategory.value = category
  }

  /**
   * Set search query
   */
  function setSearch(query: string): void {
    searchQuery.value = query
  }

  /**
   * Get workflow by ID
   */
  function getWorkflow(id: string): Workflow | undefined {
    return allWorkflows.value.find(w => w.id === id)
  }

  return {
    // State
    workflows: filteredWorkflows,
    allWorkflows,
    favoriteWorkflows,
    recentWorkflows,
    categories: categoriesWithCounts,
    searchQuery: computed(() => searchQuery.value),
    selectedCategory: computed(() => selectedCategory.value),

    // Actions
    createWorkflow,
    updateWorkflow,
    deleteWorkflow,
    toggleFavorite,
    recordUsage,
    buildCommand,
    extractParameters,
    setCategory,
    setSearch,
    getWorkflow,

    // Import/Export
    exportWorkflows,
    importWorkflows,
  }
}

export type UseWorkflowsReturn = ReturnType<typeof useWorkflows>
