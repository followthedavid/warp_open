/**
 * useNotebook - Warp-style Notebook Mode
 *
 * Notebook mode presents terminal output as interactive cells
 * similar to Jupyter notebooks, allowing:
 * - Code cells with syntax highlighting
 * - Markdown cells for documentation
 * - Cell execution and re-execution
 * - Cell reordering and organization
 * - Export to various formats
 * - Python and Node.js kernel support with state persistence
 */

import { ref, computed, onMounted } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { useKernelManager, type KernelType } from './useKernelManager'

export type CellType = 'code' | 'markdown' | 'output' | 'error'

export interface NotebookCell {
  id: string
  type: CellType
  content: string
  language?: string
  executionCount?: number
  output?: string
  error?: string
  startTime?: number
  endTime?: number
  collapsed: boolean
  metadata: Record<string, unknown>
}

export interface Notebook {
  id: string
  name: string
  cells: NotebookCell[]
  metadata: {
    createdAt: number
    updatedAt: number
    kernel?: KernelType
    kernelId?: string
    cwd?: string
  }
}

const STORAGE_KEY = 'warp_notebooks'

function loadNotebooks(): Notebook[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) return JSON.parse(stored)
  } catch {}
  return []
}

function saveNotebooks(notebooks: Notebook[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(notebooks))
  } catch {}
}

function genId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
}

export function useNotebook() {
  const notebooks = ref<Notebook[]>(loadNotebooks())
  const activeNotebookId = ref<string | null>(null)
  const activeCellId = ref<string | null>(null)
  const isExecuting = ref(false)

  // Kernel manager for Python/Node.js execution
  const kernelManager = useKernelManager()

  // Active notebook
  const activeNotebook = computed(() =>
    notebooks.value.find(n => n.id === activeNotebookId.value) || null
  )

  // Active cell
  const activeCell = computed(() =>
    activeNotebook.value?.cells.find(c => c.id === activeCellId.value) || null
  )

  // Current kernel type
  const currentKernel = computed(() =>
    activeNotebook.value?.metadata.kernel || 'shell'
  )

  /**
   * Create a new notebook
   */
  function createNotebook(name: string = 'Untitled Notebook'): Notebook {
    const now = Date.now()
    const notebook: Notebook = {
      id: `nb-${genId()}`,
      name,
      cells: [],
      metadata: {
        createdAt: now,
        updatedAt: now
      }
    }
    notebooks.value.push(notebook)
    saveNotebooks(notebooks.value)
    return notebook
  }

  /**
   * Open a notebook
   */
  function openNotebook(id: string): void {
    activeNotebookId.value = id
    activeCellId.value = activeNotebook.value?.cells[0]?.id || null
  }

  /**
   * Close the active notebook
   */
  function closeNotebook(): void {
    activeNotebookId.value = null
    activeCellId.value = null
  }

  /**
   * Delete a notebook
   */
  function deleteNotebook(id: string): void {
    const index = notebooks.value.findIndex(n => n.id === id)
    if (index !== -1) {
      notebooks.value.splice(index, 1)
      saveNotebooks(notebooks.value)
      if (activeNotebookId.value === id) {
        closeNotebook()
      }
    }
  }

  /**
   * Rename a notebook
   */
  function renameNotebook(id: string, name: string): void {
    const notebook = notebooks.value.find(n => n.id === id)
    if (notebook) {
      notebook.name = name
      notebook.metadata.updatedAt = Date.now()
      saveNotebooks(notebooks.value)
    }
  }

  /**
   * Add a cell to the active notebook
   */
  function addCell(type: CellType = 'code', content: string = '', afterId?: string): NotebookCell | null {
    if (!activeNotebook.value) return null

    const cell: NotebookCell = {
      id: `cell-${genId()}`,
      type,
      content,
      collapsed: false,
      metadata: {}
    }

    if (type === 'code') {
      cell.language = 'bash'
      cell.executionCount = 0
    }

    const cells = activeNotebook.value.cells
    if (afterId) {
      const index = cells.findIndex(c => c.id === afterId)
      if (index !== -1) {
        cells.splice(index + 1, 0, cell)
      } else {
        cells.push(cell)
      }
    } else {
      cells.push(cell)
    }

    activeNotebook.value.metadata.updatedAt = Date.now()
    saveNotebooks(notebooks.value)
    activeCellId.value = cell.id
    return cell
  }

  /**
   * Update a cell's content
   */
  function updateCell(cellId: string, updates: Partial<NotebookCell>): void {
    if (!activeNotebook.value) return

    const cell = activeNotebook.value.cells.find(c => c.id === cellId)
    if (cell) {
      Object.assign(cell, updates)
      activeNotebook.value.metadata.updatedAt = Date.now()
      saveNotebooks(notebooks.value)
    }
  }

  /**
   * Delete a cell
   */
  function deleteCell(cellId: string): void {
    if (!activeNotebook.value) return

    const cells = activeNotebook.value.cells
    const index = cells.findIndex(c => c.id === cellId)
    if (index !== -1) {
      cells.splice(index, 1)
      activeNotebook.value.metadata.updatedAt = Date.now()
      saveNotebooks(notebooks.value)

      // Select adjacent cell
      if (activeCellId.value === cellId) {
        activeCellId.value = cells[index]?.id || cells[index - 1]?.id || null
      }
    }
  }

  /**
   * Move a cell up or down
   */
  function moveCell(cellId: string, direction: 'up' | 'down'): void {
    if (!activeNotebook.value) return

    const cells = activeNotebook.value.cells
    const index = cells.findIndex(c => c.id === cellId)
    if (index === -1) return

    const newIndex = direction === 'up' ? index - 1 : index + 1
    if (newIndex < 0 || newIndex >= cells.length) return

    // Swap cells
    const temp = cells[index]
    cells[index] = cells[newIndex]
    cells[newIndex] = temp

    activeNotebook.value.metadata.updatedAt = Date.now()
    saveNotebooks(notebooks.value)
  }

  /**
   * Set the kernel type for the active notebook
   */
  async function setKernel(kernelType: KernelType): Promise<void> {
    if (!activeNotebook.value) return

    // Shutdown existing kernel if any
    if (activeNotebook.value.metadata.kernelId) {
      await kernelManager.shutdownKernel(activeNotebook.value.metadata.kernelId)
    }

    // Start new kernel
    const kernelId = await kernelManager.startKernel(kernelType, activeNotebook.value.id)

    activeNotebook.value.metadata.kernel = kernelType
    activeNotebook.value.metadata.kernelId = kernelId
    activeNotebook.value.metadata.updatedAt = Date.now()
    saveNotebooks(notebooks.value)
  }

  /**
   * Restart the current kernel (clears all state)
   */
  async function restartKernel(): Promise<boolean> {
    if (!activeNotebook.value?.metadata.kernelId) return false
    return kernelManager.restartKernel(activeNotebook.value.metadata.kernelId)
  }

  /**
   * Interrupt current execution
   */
  async function interruptExecution(): Promise<boolean> {
    if (!activeNotebook.value?.metadata.kernelId) return false
    return kernelManager.interruptKernel(activeNotebook.value.metadata.kernelId)
  }

  /**
   * Execute a code cell using the appropriate kernel
   */
  async function executeCell(cellId: string): Promise<void> {
    if (!activeNotebook.value || isExecuting.value) return

    const cell = activeNotebook.value.cells.find(c => c.id === cellId)
    if (!cell || cell.type !== 'code') return

    isExecuting.value = true
    cell.startTime = Date.now()
    cell.output = ''
    cell.error = undefined

    try {
      const kernelType = activeNotebook.value.metadata.kernel || 'shell'
      let kernelId = activeNotebook.value.metadata.kernelId

      // Auto-start kernel if needed (for Python/Node)
      if (kernelType !== 'shell' && !kernelId) {
        kernelId = await kernelManager.startKernel(kernelType, activeNotebook.value.id)
        activeNotebook.value.metadata.kernelId = kernelId
      }

      if (kernelId && kernelType !== 'shell') {
        // Use kernel manager for Python/Node execution with state
        const result = await kernelManager.executeCode(kernelId, cell.content)
        cell.output = result.output
        if (result.error) {
          cell.error = result.error
        }
        cell.executionCount = result.executionCount
      } else {
        // Fallback to shell execution
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command: cell.content,
          cwd: activeNotebook.value.metadata.cwd
        })
        cell.output = result.stdout
        if (result.stderr) {
          cell.error = result.stderr
        }
        cell.executionCount = (cell.executionCount || 0) + 1
      }
    } catch (error) {
      cell.error = `Execution failed: ${error}`
    } finally {
      cell.endTime = Date.now()
      isExecuting.value = false
      activeNotebook.value.metadata.updatedAt = Date.now()
      saveNotebooks(notebooks.value)
    }
  }

  /**
   * Execute all code cells
   */
  async function executeAll(): Promise<void> {
    if (!activeNotebook.value) return

    for (const cell of activeNotebook.value.cells) {
      if (cell.type === 'code') {
        await executeCell(cell.id)
      }
    }
  }

  /**
   * Clear all outputs
   */
  function clearOutputs(): void {
    if (!activeNotebook.value) return

    for (const cell of activeNotebook.value.cells) {
      if (cell.type === 'code') {
        cell.output = ''
        cell.error = undefined
      }
    }
    saveNotebooks(notebooks.value)
  }

  /**
   * Toggle cell collapse
   */
  function toggleCollapse(cellId: string): void {
    if (!activeNotebook.value) return

    const cell = activeNotebook.value.cells.find(c => c.id === cellId)
    if (cell) {
      cell.collapsed = !cell.collapsed
      saveNotebooks(notebooks.value)
    }
  }

  /**
   * Import from terminal blocks
   */
  function importFromBlocks(blocks: Array<{ command: string; output: string; exitCode?: number }>): Notebook {
    const notebook = createNotebook(`Import ${new Date().toLocaleString()}`)
    openNotebook(notebook.id)

    for (const block of blocks) {
      const cell = addCell('code', block.command)
      if (cell) {
        cell.output = block.output
        cell.executionCount = 1
        if (block.exitCode !== undefined && block.exitCode !== 0) {
          cell.error = `Exit code: ${block.exitCode}`
        }
      }
    }

    return notebook
  }

  /**
   * Export notebook to JSON
   */
  function exportToJson(id?: string): string {
    const nb = id
      ? notebooks.value.find(n => n.id === id)
      : activeNotebook.value

    if (!nb) return '{}'
    return JSON.stringify(nb, null, 2)
  }

  /**
   * Export notebook to Markdown
   */
  function exportToMarkdown(id?: string): string {
    const nb = id
      ? notebooks.value.find(n => n.id === id)
      : activeNotebook.value

    if (!nb) return ''

    const lines = [`# ${nb.name}\n`]

    for (const cell of nb.cells) {
      if (cell.type === 'markdown') {
        lines.push(cell.content)
        lines.push('')
      } else if (cell.type === 'code') {
        lines.push('```' + (cell.language || 'bash'))
        lines.push(cell.content)
        lines.push('```')
        if (cell.output) {
          lines.push('\n**Output:**')
          lines.push('```')
          lines.push(cell.output)
          lines.push('```')
        }
        lines.push('')
      }
    }

    return lines.join('\n')
  }

  /**
   * Export notebook as shell script
   */
  function exportToScript(id?: string): string {
    const nb = id
      ? notebooks.value.find(n => n.id === id)
      : activeNotebook.value

    if (!nb) return ''

    const lines = ['#!/bin/bash', '', `# ${nb.name}`, '']

    for (const cell of nb.cells) {
      if (cell.type === 'code') {
        if (cell.content.trim()) {
          lines.push(cell.content)
          lines.push('')
        }
      } else if (cell.type === 'markdown') {
        // Add as comments
        for (const line of cell.content.split('\n')) {
          lines.push(`# ${line}`)
        }
        lines.push('')
      }
    }

    return lines.join('\n')
  }

  /**
   * Select a cell
   */
  function selectCell(cellId: string | null): void {
    activeCellId.value = cellId
  }

  /**
   * Navigate to next/previous cell
   */
  function navigateCell(direction: 'next' | 'prev'): void {
    if (!activeNotebook.value || !activeCellId.value) return

    const cells = activeNotebook.value.cells
    const index = cells.findIndex(c => c.id === activeCellId.value)
    if (index === -1) return

    const newIndex = direction === 'next' ? index + 1 : index - 1
    if (newIndex >= 0 && newIndex < cells.length) {
      activeCellId.value = cells[newIndex].id
    }
  }

  return {
    // State
    notebooks: computed(() => notebooks.value),
    activeNotebook,
    activeCell,
    activeCellId: computed(() => activeCellId.value),
    isExecuting: computed(() => isExecuting.value),
    currentKernel,
    availableKernels: kernelManager.availableKernels,

    // Notebook operations
    createNotebook,
    openNotebook,
    closeNotebook,
    deleteNotebook,
    renameNotebook,

    // Cell operations
    addCell,
    updateCell,
    deleteCell,
    moveCell,
    toggleCollapse,
    selectCell,
    navigateCell,

    // Kernel operations
    setKernel,
    restartKernel,
    interruptExecution,
    detectKernels: kernelManager.detectAvailableKernels,

    // Execution
    executeCell,
    executeAll,
    clearOutputs,

    // Import/Export
    importFromBlocks,
    exportToJson,
    exportToMarkdown,
    exportToScript
  }
}

export type UseNotebookReturn = ReturnType<typeof useNotebook>
