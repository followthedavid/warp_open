/**
 * Claude Code Feature Parity - Index
 *
 * This module exports all the new features added to achieve
 * Claude Code and Warp Terminal parity.
 *
 * Features included:
 * - Enhanced tools (Grep, Glob, WebSearch, TaskOutput, KillShell)
 * - UI components (TodoPanel, AskUserQuestion, StatusBar, TestRunner)
 * - Composables (Markdown, DirectoryJump, EditorKeybindings, TodoList)
 */

// Tools
export { useTools } from '../composables/useTools'
export type { Tool, ToolResult, ToolCall, BackgroundTask } from '../composables/useTools'

// Todo List
export { useTodoList } from '../composables/useTodoList'
export type { TodoItem } from '../composables/useTodoList'

// Markdown Rendering
export { useMarkdown } from '../composables/useMarkdown'

// Directory Jumping (zoxide-style)
export { useDirectoryJump } from '../composables/useDirectoryJump'

// Editor Keybindings (Vim/Emacs)
export { useEditorKeybindings } from '../composables/useEditorKeybindings'
export type { KeybindingMode } from '../composables/useEditorKeybindings'

// Components are imported separately in Vue files:
// - TodoPanel.vue
// - AskUserQuestion.vue
// - AgentStatusBar.vue
// - TestRunnerPanel.vue
// - InlineAISuggestion.vue
// - ToolApprovalDialog.vue

/**
 * Quick setup function for integrating all features
 */
export function setupClaudeCodeFeatures() {
  const tools = useTools()
  const todoList = useTodoList()
  const markdown = useMarkdown()
  const directoryJump = useDirectoryJump()
  const editorKeybindings = useEditorKeybindings()

  return {
    tools,
    todoList,
    markdown,
    directoryJump,
    editorKeybindings
  }
}

export default setupClaudeCodeFeatures
