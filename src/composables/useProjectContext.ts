/**
 * Project Context Loader
 * Automatically loads .claude.md, .warp.md, or CLAUDE.md files for AI context
 * Similar to Claude Code's project-specific instructions
 */

import { ref, computed } from 'vue';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

export interface ProjectContext {
  content: string;
  filePath: string;
  loadedAt: Date;
  projectRoot: string;
}

// Supported context file names (in priority order)
const CONTEXT_FILES = [
  '.claude.md',
  'CLAUDE.md',
  '.warp.md',
  '.ai-context.md',
  'AI_CONTEXT.md',
  '.cursor/rules',
  '.github/copilot-instructions.md',
];

const projectContext = ref<ProjectContext | null>(null);
const isLoading = ref(false);
const error = ref<string | null>(null);

export function useProjectContext() {
  /**
   * Find and load project context file from a directory
   */
  async function loadProjectContext(directory: string): Promise<ProjectContext | null> {
    isLoading.value = true;
    error.value = null;

    try {
      // Try each context file in priority order
      for (const fileName of CONTEXT_FILES) {
        const filePath = `${directory}/${fileName}`;

        try {
          let content: string;

          if (isTauri && invoke) {
            content = await invoke<string>('read_file', { path: filePath });
          } else {
            // Browser fallback - try fetch
            const response = await fetch(`file://${filePath}`);
            if (!response.ok) continue;
            content = await response.text();
          }

          // Found a context file
          projectContext.value = {
            content,
            filePath,
            loadedAt: new Date(),
            projectRoot: directory,
          };

          console.log(`[ProjectContext] Loaded context from ${filePath}`);
          return projectContext.value;
        } catch {
          // File doesn't exist, try next one
          continue;
        }
      }

      // No context file found
      console.log(`[ProjectContext] No context file found in ${directory}`);
      projectContext.value = null;
      return null;
    } catch (e) {
      error.value = String(e);
      console.error('[ProjectContext] Error loading context:', e);
      return null;
    } finally {
      isLoading.value = false;
    }
  }

  /**
   * Get the context as a system message for AI
   */
  function getContextAsSystemMessage(): string | null {
    if (!projectContext.value) return null;

    return `[Project Context from ${projectContext.value.filePath}]
${projectContext.value.content}

[End Project Context]`;
  }

  /**
   * Clear loaded context
   */
  function clearContext() {
    projectContext.value = null;
  }

  /**
   * Create a default .claude.md template
   */
  async function createContextTemplate(directory: string): Promise<boolean> {
    const template = `# Project Context for AI Assistant

## Project Overview
<!-- Describe what this project does -->

## Tech Stack
<!-- List the main technologies used -->

## Code Style Guidelines
<!-- Any specific coding conventions to follow -->

## Important Files
<!-- Key files the AI should know about -->

## Common Tasks
<!-- Frequent operations and how to do them -->

## Testing Instructions
<!-- How to run tests -->

## Build Instructions
<!-- How to build the project -->

## Notes
<!-- Any other important information for the AI -->
`;

    try {
      if (isTauri && invoke) {
        await invoke('write_file', {
          path: `${directory}/.claude.md`,
          content: template,
        });
        return true;
      }
      return false;
    } catch (e) {
      error.value = String(e);
      return false;
    }
  }

  /**
   * Watch a directory for context file changes
   */
  async function watchForChanges(directory: string, callback: () => void) {
    // In Tauri, we could use fs watcher
    // For now, just reload periodically or on demand
    console.log(`[ProjectContext] Would watch ${directory} for changes`);
  }

  return {
    projectContext: computed(() => projectContext.value),
    isLoading: computed(() => isLoading.value),
    error: computed(() => error.value),
    loadProjectContext,
    getContextAsSystemMessage,
    clearContext,
    createContextTemplate,
    watchForChanges,
    CONTEXT_FILES,
  };
}
