/**
 * Inline Code Editor
 * Monaco-based code editing with LSP integration
 *
 * Features:
 * - Monaco editor integration
 * - LSP features (completion, hover, go-to-definition)
 * - Inline editing in terminal context
 * - Git diff visualization
 * - Auto-save and sync
 * - Multiple cursor support
 * - Minimap and code folding
 */

import { ref, computed, reactive, shallowRef, watch, onUnmounted } from 'vue';
import type { useLSP } from './useLSP';

// ============================================================================
// TYPES
// ============================================================================

export interface EditorInstance {
  id: string;
  filePath: string;
  language: string;
  content: string;
  originalContent: string;
  isDirty: boolean;
  isReadOnly: boolean;
  cursor: CursorPosition;
  selections: Selection[];
  viewState?: EditorViewState;
  model?: unknown;  // Monaco model reference
  editor?: unknown; // Monaco editor reference
}

export interface CursorPosition {
  lineNumber: number;
  column: number;
}

export interface Selection {
  startLineNumber: number;
  startColumn: number;
  endLineNumber: number;
  endColumn: number;
}

export interface EditorViewState {
  scrollTop: number;
  scrollLeft: number;
  cursorState: CursorPosition[];
  viewState: unknown;
}

export interface EditorConfig {
  theme: 'vs-dark' | 'vs-light' | 'hc-black';
  fontSize: number;
  fontFamily: string;
  tabSize: number;
  insertSpaces: boolean;
  wordWrap: 'off' | 'on' | 'wordWrapColumn' | 'bounded';
  minimap: boolean;
  lineNumbers: 'on' | 'off' | 'relative' | 'interval';
  renderWhitespace: 'none' | 'boundary' | 'selection' | 'trailing' | 'all';
  bracketPairColorization: boolean;
  autoSave: boolean;
  autoSaveDelay: number;
  formatOnSave: boolean;
  formatOnPaste: boolean;
  cursorBlinking: 'blink' | 'smooth' | 'phase' | 'expand' | 'solid';
  cursorStyle: 'line' | 'block' | 'underline' | 'line-thin' | 'block-outline' | 'underline-thin';
  smoothScrolling: boolean;
  mouseWheelZoom: boolean;
}

export interface DiffEditorInstance {
  id: string;
  filePath: string;
  originalContent: string;
  modifiedContent: string;
  language: string;
}

export interface SearchResult {
  lineNumber: number;
  column: number;
  length: number;
  match: string;
  preview: string;
}

export interface CodeLens {
  range: { startLineNumber: number; endLineNumber: number };
  command: {
    id: string;
    title: string;
    arguments?: unknown[];
  };
}

// ============================================================================
// DEFAULT CONFIGURATION
// ============================================================================

const DEFAULT_CONFIG: EditorConfig = {
  theme: 'vs-dark',
  fontSize: 14,
  fontFamily: "'JetBrains Mono', 'Fira Code', Menlo, Monaco, monospace",
  tabSize: 2,
  insertSpaces: true,
  wordWrap: 'on',
  minimap: true,
  lineNumbers: 'on',
  renderWhitespace: 'selection',
  bracketPairColorization: true,
  autoSave: true,
  autoSaveDelay: 1000,
  formatOnSave: true,
  formatOnPaste: true,
  cursorBlinking: 'blink',
  cursorStyle: 'line',
  smoothScrolling: true,
  mouseWheelZoom: true
};

// Language detection
const LANGUAGE_MAP: Record<string, string> = {
  '.ts': 'typescript',
  '.tsx': 'typescriptreact',
  '.js': 'javascript',
  '.jsx': 'javascriptreact',
  '.vue': 'vue',
  '.py': 'python',
  '.rs': 'rust',
  '.go': 'go',
  '.rb': 'ruby',
  '.php': 'php',
  '.java': 'java',
  '.kt': 'kotlin',
  '.swift': 'swift',
  '.c': 'c',
  '.cpp': 'cpp',
  '.h': 'c',
  '.hpp': 'cpp',
  '.cs': 'csharp',
  '.json': 'json',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.xml': 'xml',
  '.html': 'html',
  '.css': 'css',
  '.scss': 'scss',
  '.less': 'less',
  '.md': 'markdown',
  '.sql': 'sql',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.fish': 'shell',
  '.dockerfile': 'dockerfile',
  '.toml': 'toml',
  '.ini': 'ini',
  '.conf': 'ini',
  '.lua': 'lua',
  '.r': 'r',
  '.ex': 'elixir',
  '.exs': 'elixir',
  '.erl': 'erlang',
  '.hs': 'haskell',
  '.ml': 'ocaml',
  '.fs': 'fsharp',
  '.clj': 'clojure',
  '.scala': 'scala',
  '.groovy': 'groovy',
  '.pl': 'perl',
  '.pm': 'perl'
};

// ============================================================================
// STATE
// ============================================================================

const config = reactive<EditorConfig>({ ...DEFAULT_CONFIG });
const editors = reactive<Map<string, EditorInstance>>(new Map());
const diffEditors = reactive<Map<string, DiffEditorInstance>>(new Map());
const activeEditorId = ref<string | null>(null);
const isMonacoLoaded = ref(false);

let monaco: typeof import('monaco-editor') | null = null;
let autoSaveTimers = new Map<string, number>();
let lspInstance: ReturnType<typeof useLSP> | null = null;

// Check if Tauri
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

// ============================================================================
// PERSISTENCE
// ============================================================================

function loadConfig(): void {
  try {
    const saved = localStorage.getItem('warp_editor_config');
    if (saved) {
      Object.assign(config, JSON.parse(saved));
    }
  } catch (e) {
    console.error('[Editor] Failed to load config:', e);
  }
}

function saveConfig(): void {
  try {
    localStorage.setItem('warp_editor_config', JSON.stringify(config));
  } catch (e) {
    console.error('[Editor] Failed to save config:', e);
  }
}

// Initialize
loadConfig();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateId(): string {
  return Math.random().toString(36).substring(2, 11);
}

function detectLanguage(filePath: string): string {
  const ext = filePath.substring(filePath.lastIndexOf('.'));
  return LANGUAGE_MAP[ext.toLowerCase()] || 'plaintext';
}

function getUri(filePath: string): string {
  return `file://${filePath}`;
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useInlineEditor() {
  /**
   * Initialize Monaco editor
   */
  async function initMonaco(): Promise<boolean> {
    if (isMonacoLoaded.value && monaco) return true;

    try {
      // Dynamic import to avoid blocking
      monaco = await import('monaco-editor');

      // Configure Monaco
      monaco.editor.defineTheme('warp-dark', {
        base: 'vs-dark',
        inherit: true,
        rules: [
          { token: 'comment', foreground: '6A9955' },
          { token: 'keyword', foreground: 'C586C0' },
          { token: 'string', foreground: 'CE9178' },
          { token: 'number', foreground: 'B5CEA8' },
          { token: 'type', foreground: '4EC9B0' },
          { token: 'function', foreground: 'DCDCAA' },
          { token: 'variable', foreground: '9CDCFE' }
        ],
        colors: {
          'editor.background': '#1e1e1e',
          'editor.foreground': '#d4d4d4',
          'editor.lineHighlightBackground': '#2a2a2a',
          'editor.selectionBackground': '#264f78',
          'editorCursor.foreground': '#ffffff',
          'editorIndentGuide.background': '#404040',
          'editorIndentGuide.activeBackground': '#707070'
        }
      });

      isMonacoLoaded.value = true;
      console.log('[Editor] Monaco initialized');
      return true;
    } catch (e) {
      console.error('[Editor] Failed to load Monaco:', e);
      return false;
    }
  }

  /**
   * Set LSP instance for integration
   */
  function setLSP(lsp: ReturnType<typeof useLSP>): void {
    lspInstance = lsp;
  }

  /**
   * Open a file in editor
   */
  async function openFile(filePath: string, options?: {
    readOnly?: boolean;
    preview?: boolean;
    selection?: Selection;
  }): Promise<EditorInstance | null> {
    if (!await initMonaco() || !monaco) return null;

    // Check if already open
    const existing = Array.from(editors.values()).find(e => e.filePath === filePath);
    if (existing) {
      activeEditorId.value = existing.id;
      if (options?.selection) {
        setSelection(existing.id, options.selection);
      }
      return existing;
    }

    // Read file content
    let content: string;
    try {
      if (invoke) {
        content = await invoke<string>('read_file', { path: filePath });
      } else {
        const response = await fetch(filePath);
        content = await response.text();
      }
    } catch (e) {
      console.error('[Editor] Failed to read file:', e);
      return null;
    }

    const language = detectLanguage(filePath);

    const instance: EditorInstance = {
      id: generateId(),
      filePath,
      language,
      content,
      originalContent: content,
      isDirty: false,
      isReadOnly: options?.readOnly || false,
      cursor: { lineNumber: 1, column: 1 },
      selections: []
    };

    // Create Monaco model
    const uri = monaco.Uri.parse(getUri(filePath));
    const model = monaco.editor.createModel(content, language, uri);
    instance.model = model;

    editors.set(instance.id, instance);
    activeEditorId.value = instance.id;

    // Notify LSP
    if (lspInstance) {
      lspInstance.openDocument(getUri(filePath), language, content);
    }

    // Apply selection
    if (options?.selection) {
      setSelection(instance.id, options.selection);
    }

    console.log(`[Editor] Opened ${filePath}`);
    return instance;
  }

  /**
   * Close an editor
   */
  async function closeEditor(editorId: string, force = false): Promise<boolean> {
    const instance = editors.get(editorId);
    if (!instance) return true;

    // Check for unsaved changes
    if (instance.isDirty && !force) {
      // Would show confirmation dialog
      return false;
    }

    // Clear auto-save timer
    const timer = autoSaveTimers.get(editorId);
    if (timer) {
      clearTimeout(timer);
      autoSaveTimers.delete(editorId);
    }

    // Dispose Monaco model
    if (instance.model && monaco) {
      (instance.model as ReturnType<typeof monaco.editor.createModel>).dispose();
    }

    // Notify LSP
    if (lspInstance) {
      lspInstance.closeDocument(getUri(instance.filePath), instance.language);
    }

    editors.delete(editorId);

    // Update active editor
    if (activeEditorId.value === editorId) {
      const remaining = Array.from(editors.keys());
      activeEditorId.value = remaining.length > 0 ? remaining[remaining.length - 1] : null;
    }

    console.log(`[Editor] Closed ${instance.filePath}`);
    return true;
  }

  /**
   * Save editor content
   */
  async function saveFile(editorId: string): Promise<boolean> {
    const instance = editors.get(editorId);
    if (!instance || !instance.isDirty) return true;

    try {
      // Format on save
      if (config.formatOnSave && lspInstance) {
        const edits = await lspInstance.formatDocument(
          getUri(instance.filePath),
          instance.language,
          { tabSize: config.tabSize, insertSpaces: config.insertSpaces }
        );

        if (edits.length > 0) {
          instance.content = applyEdits(instance.content, edits);
        }
      }

      // Write file
      if (invoke) {
        await invoke('write_file', {
          path: instance.filePath,
          content: instance.content
        });
      }

      instance.originalContent = instance.content;
      instance.isDirty = false;

      // Update LSP
      if (lspInstance) {
        lspInstance.updateDocument(getUri(instance.filePath), instance.language, instance.content);
      }

      console.log(`[Editor] Saved ${instance.filePath}`);
      return true;
    } catch (e) {
      console.error('[Editor] Failed to save file:', e);
      return false;
    }
  }

  /**
   * Apply text edits
   */
  function applyEdits(content: string, edits: Array<{ range: { start: { line: number; character: number }; end: { line: number; character: number } }; newText: string }>): string {
    const lines = content.split('\n');

    // Sort edits in reverse order to apply from bottom to top
    const sorted = [...edits].sort((a, b) => {
      if (b.range.start.line !== a.range.start.line) {
        return b.range.start.line - a.range.start.line;
      }
      return b.range.start.character - a.range.start.character;
    });

    for (const edit of sorted) {
      const startLine = edit.range.start.line;
      const endLine = edit.range.end.line;
      const startChar = edit.range.start.character;
      const endChar = edit.range.end.character;

      if (startLine === endLine) {
        const line = lines[startLine];
        lines[startLine] = line.substring(0, startChar) + edit.newText + line.substring(endChar);
      } else {
        const startLineText = lines[startLine].substring(0, startChar);
        const endLineText = lines[endLine].substring(endChar);
        const newLines = edit.newText.split('\n');

        newLines[0] = startLineText + newLines[0];
        newLines[newLines.length - 1] = newLines[newLines.length - 1] + endLineText;

        lines.splice(startLine, endLine - startLine + 1, ...newLines);
      }
    }

    return lines.join('\n');
  }

  /**
   * Update editor content
   */
  function updateContent(editorId: string, content: string): void {
    const instance = editors.get(editorId);
    if (!instance) return;

    instance.content = content;
    instance.isDirty = content !== instance.originalContent;

    // Update Monaco model
    if (instance.model && monaco) {
      const model = instance.model as ReturnType<typeof monaco.editor.createModel>;
      if (model.getValue() !== content) {
        model.setValue(content);
      }
    }

    // Update LSP
    if (lspInstance) {
      lspInstance.updateDocument(getUri(instance.filePath), instance.language, content);
    }

    // Auto-save
    if (config.autoSave && instance.isDirty) {
      const existing = autoSaveTimers.get(editorId);
      if (existing) clearTimeout(existing);

      autoSaveTimers.set(editorId, window.setTimeout(() => {
        saveFile(editorId);
      }, config.autoSaveDelay));
    }
  }

  /**
   * Set cursor position
   */
  function setCursor(editorId: string, position: CursorPosition): void {
    const instance = editors.get(editorId);
    if (instance) {
      instance.cursor = position;
    }
  }

  /**
   * Set selection
   */
  function setSelection(editorId: string, selection: Selection): void {
    const instance = editors.get(editorId);
    if (instance) {
      instance.selections = [selection];
      instance.cursor = {
        lineNumber: selection.endLineNumber,
        column: selection.endColumn
      };
    }
  }

  /**
   * Get completions at cursor
   */
  async function getCompletions(editorId: string): Promise<Array<{
    label: string;
    kind: string;
    detail?: string;
    insertText: string;
  }>> {
    const instance = editors.get(editorId);
    if (!instance || !lspInstance) return [];

    const items = await lspInstance.getCompletions(
      getUri(instance.filePath),
      instance.language,
      {
        line: instance.cursor.lineNumber - 1,
        character: instance.cursor.column - 1
      }
    );

    return items.map(item => ({
      label: item.label,
      kind: item.kind,
      detail: item.detail,
      insertText: item.insertText || item.label
    }));
  }

  /**
   * Get hover info
   */
  async function getHover(editorId: string): Promise<{ contents: string } | null> {
    const instance = editors.get(editorId);
    if (!instance || !lspInstance) return null;

    const hover = await lspInstance.getHover(
      getUri(instance.filePath),
      instance.language,
      {
        line: instance.cursor.lineNumber - 1,
        character: instance.cursor.column - 1
      }
    );

    return hover ? { contents: hover.contents } : null;
  }

  /**
   * Go to definition
   */
  async function goToDefinition(editorId: string): Promise<boolean> {
    const instance = editors.get(editorId);
    if (!instance || !lspInstance) return false;

    const locations = await lspInstance.getDefinition(
      getUri(instance.filePath),
      instance.language,
      {
        line: instance.cursor.lineNumber - 1,
        character: instance.cursor.column - 1
      }
    );

    if (locations.length === 0) return false;

    const location = locations[0];
    const filePath = location.uri.replace('file://', '');

    await openFile(filePath, {
      selection: {
        startLineNumber: location.range.start.line + 1,
        startColumn: location.range.start.character + 1,
        endLineNumber: location.range.end.line + 1,
        endColumn: location.range.end.character + 1
      }
    });

    return true;
  }

  /**
   * Find references
   */
  async function findReferences(editorId: string): Promise<Array<{
    filePath: string;
    lineNumber: number;
    column: number;
    preview: string;
  }>> {
    const instance = editors.get(editorId);
    if (!instance || !lspInstance) return [];

    const locations = await lspInstance.getReferences(
      getUri(instance.filePath),
      instance.language,
      {
        line: instance.cursor.lineNumber - 1,
        character: instance.cursor.column - 1
      }
    );

    return locations.map(loc => ({
      filePath: loc.uri.replace('file://', ''),
      lineNumber: loc.range.start.line + 1,
      column: loc.range.start.character + 1,
      preview: ''  // Would need to read line from file
    }));
  }

  /**
   * Search in file
   */
  function searchInFile(editorId: string, query: string, options?: {
    regex?: boolean;
    caseSensitive?: boolean;
    wholeWord?: boolean;
  }): SearchResult[] {
    const instance = editors.get(editorId);
    if (!instance) return [];

    const results: SearchResult[] = [];
    const lines = instance.content.split('\n');

    let searchRegex: RegExp;
    try {
      let pattern = options?.regex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (options?.wholeWord) {
        pattern = `\\b${pattern}\\b`;
      }
      searchRegex = new RegExp(pattern, options?.caseSensitive ? 'g' : 'gi');
    } catch {
      return [];
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let match: RegExpExecArray | null;

      while ((match = searchRegex.exec(line)) !== null) {
        results.push({
          lineNumber: i + 1,
          column: match.index + 1,
          length: match[0].length,
          match: match[0],
          preview: line.trim()
        });
      }
    }

    return results;
  }

  /**
   * Replace in file
   */
  function replaceInFile(editorId: string, search: string, replace: string, options?: {
    regex?: boolean;
    caseSensitive?: boolean;
    wholeWord?: boolean;
    all?: boolean;
  }): number {
    const instance = editors.get(editorId);
    if (!instance) return 0;

    let searchRegex: RegExp;
    try {
      let pattern = options?.regex ? search : search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (options?.wholeWord) {
        pattern = `\\b${pattern}\\b`;
      }
      const flags = (options?.caseSensitive ? '' : 'i') + (options?.all ? 'g' : '');
      searchRegex = new RegExp(pattern, flags);
    } catch {
      return 0;
    }

    const matches = instance.content.match(new RegExp(searchRegex.source, searchRegex.flags + 'g')) || [];
    const count = options?.all ? matches.length : (matches.length > 0 ? 1 : 0);

    const newContent = instance.content.replace(searchRegex, replace);
    updateContent(editorId, newContent);

    return count;
  }

  /**
   * Open diff editor
   */
  async function openDiff(
    filePath: string,
    originalContent: string,
    modifiedContent: string
  ): Promise<DiffEditorInstance | null> {
    if (!await initMonaco() || !monaco) return null;

    const id = generateId();
    const language = detectLanguage(filePath);

    const instance: DiffEditorInstance = {
      id,
      filePath,
      originalContent,
      modifiedContent,
      language
    };

    diffEditors.set(id, instance);
    return instance;
  }

  /**
   * Update config
   */
  function updateConfig(newConfig: Partial<EditorConfig>): void {
    Object.assign(config, newConfig);
    saveConfig();

    // Apply to all editors
    if (monaco) {
      monaco.editor.setTheme(config.theme);
    }
  }

  /**
   * Get active editor
   */
  function getActiveEditor(): EditorInstance | null {
    if (!activeEditorId.value) return null;
    return editors.get(activeEditorId.value) || null;
  }

  /**
   * Format document
   */
  async function formatDocument(editorId: string): Promise<boolean> {
    const instance = editors.get(editorId);
    if (!instance || !lspInstance) return false;

    const edits = await lspInstance.formatDocument(
      getUri(instance.filePath),
      instance.language,
      { tabSize: config.tabSize, insertSpaces: config.insertSpaces }
    );

    if (edits.length === 0) return false;

    // Convert LSP edits to our format
    const convertedEdits = edits.map(edit => ({
      range: {
        start: { line: edit.range.start.line, character: edit.range.start.character },
        end: { line: edit.range.end.line, character: edit.range.end.character }
      },
      newText: edit.newText
    }));

    const newContent = applyEdits(instance.content, convertedEdits);
    updateContent(editorId, newContent);

    return true;
  }

  /**
   * Get all open editors
   */
  const openEditors = computed(() => Array.from(editors.values()));

  /**
   * Get dirty editors
   */
  const dirtyEditors = computed(() =>
    Array.from(editors.values()).filter(e => e.isDirty)
  );

  return {
    // State
    config: computed(() => config),
    editors: openEditors,
    dirtyEditors,
    activeEditor: computed(() => getActiveEditor()),
    activeEditorId: computed(() => activeEditorId.value),
    isMonacoLoaded: computed(() => isMonacoLoaded.value),

    // Initialization
    initMonaco,
    setLSP,

    // File operations
    openFile,
    closeEditor,
    saveFile,
    updateContent,

    // Navigation
    setCursor,
    setSelection,
    goToDefinition,
    findReferences,

    // Code intelligence
    getCompletions,
    getHover,
    formatDocument,

    // Search
    searchInFile,
    replaceInFile,

    // Diff
    openDiff,

    // Config
    updateConfig
  };
}

export default useInlineEditor;
