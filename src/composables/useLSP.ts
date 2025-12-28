/**
 * Language Server Protocol Support
 * Connect to LSP servers for intelligent code features
 *
 * Features:
 * - Auto-detect and start language servers
 * - Code completion, hover, go-to-definition
 * - Diagnostics (errors, warnings)
 * - Code actions and refactoring
 * - Workspace-wide symbol search
 * - Document formatting
 */

import { ref, computed, reactive, shallowRef } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export interface LSPServerConfig {
  id: string;
  name: string;
  languages: string[];
  command: string;
  args: string[];
  initializationOptions?: Record<string, unknown>;
  settings?: Record<string, unknown>;
  rootPatterns?: string[];  // Files that indicate project root (e.g., package.json)
}

export interface LSPServer {
  id: string;
  config: LSPServerConfig;
  status: 'starting' | 'running' | 'stopped' | 'error';
  capabilities: ServerCapabilities;
  workspaceRoot?: string;
  error?: string;
}

export interface ServerCapabilities {
  completionProvider?: boolean;
  hoverProvider?: boolean;
  definitionProvider?: boolean;
  referencesProvider?: boolean;
  documentSymbolProvider?: boolean;
  workspaceSymbolProvider?: boolean;
  codeActionProvider?: boolean;
  documentFormattingProvider?: boolean;
  renameProvider?: boolean;
  diagnosticProvider?: boolean;
}

export interface Position {
  line: number;
  character: number;
}

export interface Range {
  start: Position;
  end: Position;
}

export interface Location {
  uri: string;
  range: Range;
}

export interface Diagnostic {
  range: Range;
  severity: 'error' | 'warning' | 'info' | 'hint';
  code?: string | number;
  source?: string;
  message: string;
  relatedInformation?: Array<{
    location: Location;
    message: string;
  }>;
}

export interface CompletionItem {
  label: string;
  kind: CompletionKind;
  detail?: string;
  documentation?: string;
  insertText?: string;
  textEdit?: {
    range: Range;
    newText: string;
  };
  additionalTextEdits?: Array<{
    range: Range;
    newText: string;
  }>;
  sortText?: string;
  filterText?: string;
}

export type CompletionKind =
  | 'text' | 'method' | 'function' | 'constructor' | 'field'
  | 'variable' | 'class' | 'interface' | 'module' | 'property'
  | 'unit' | 'value' | 'enum' | 'keyword' | 'snippet'
  | 'color' | 'file' | 'reference' | 'folder' | 'constant'
  | 'struct' | 'event' | 'operator' | 'typeParameter';

export interface HoverInfo {
  contents: string;
  range?: Range;
}

export interface DocumentSymbol {
  name: string;
  kind: SymbolKind;
  range: Range;
  selectionRange: Range;
  detail?: string;
  children?: DocumentSymbol[];
}

export type SymbolKind =
  | 'file' | 'module' | 'namespace' | 'package' | 'class'
  | 'method' | 'property' | 'field' | 'constructor' | 'enum'
  | 'interface' | 'function' | 'variable' | 'constant' | 'string'
  | 'number' | 'boolean' | 'array' | 'object' | 'key'
  | 'null' | 'enumMember' | 'struct' | 'event' | 'operator'
  | 'typeParameter';

export interface CodeAction {
  title: string;
  kind?: string;
  diagnostics?: Diagnostic[];
  isPreferred?: boolean;
  edit?: WorkspaceEdit;
  command?: {
    title: string;
    command: string;
    arguments?: unknown[];
  };
}

export interface WorkspaceEdit {
  changes?: Record<string, TextEdit[]>;
  documentChanges?: Array<{
    textDocument: { uri: string; version: number };
    edits: TextEdit[];
  }>;
}

export interface TextEdit {
  range: Range;
  newText: string;
}

// ============================================================================
// DEFAULT SERVER CONFIGS
// ============================================================================

const DEFAULT_SERVERS: LSPServerConfig[] = [
  {
    id: 'typescript',
    name: 'TypeScript/JavaScript',
    languages: ['typescript', 'javascript', 'typescriptreact', 'javascriptreact'],
    command: 'typescript-language-server',
    args: ['--stdio'],
    rootPatterns: ['tsconfig.json', 'jsconfig.json', 'package.json'],
    settings: {
      typescript: {
        inlayHints: {
          includeInlayParameterNameHints: 'all',
          includeInlayFunctionParameterTypeHints: true,
          includeInlayVariableTypeHints: true
        }
      }
    }
  },
  {
    id: 'python',
    name: 'Python (Pylsp)',
    languages: ['python'],
    command: 'pylsp',
    args: [],
    rootPatterns: ['pyproject.toml', 'setup.py', 'requirements.txt'],
    settings: {
      pylsp: {
        plugins: {
          pycodestyle: { enabled: true },
          pyflakes: { enabled: true },
          pylint: { enabled: false }
        }
      }
    }
  },
  {
    id: 'rust',
    name: 'Rust Analyzer',
    languages: ['rust'],
    command: 'rust-analyzer',
    args: [],
    rootPatterns: ['Cargo.toml'],
    settings: {
      'rust-analyzer': {
        checkOnSave: { command: 'clippy' },
        inlayHints: { enable: true }
      }
    }
  },
  {
    id: 'go',
    name: 'Go (gopls)',
    languages: ['go'],
    command: 'gopls',
    args: ['serve'],
    rootPatterns: ['go.mod', 'go.sum'],
    settings: {
      gopls: {
        usePlaceholders: true,
        staticcheck: true
      }
    }
  },
  {
    id: 'vue',
    name: 'Vue (Volar)',
    languages: ['vue'],
    command: 'vue-language-server',
    args: ['--stdio'],
    rootPatterns: ['vite.config.ts', 'vue.config.js', 'package.json']
  },
  {
    id: 'html',
    name: 'HTML',
    languages: ['html'],
    command: 'vscode-html-language-server',
    args: ['--stdio'],
    rootPatterns: ['index.html']
  },
  {
    id: 'css',
    name: 'CSS/SCSS/Less',
    languages: ['css', 'scss', 'less'],
    command: 'vscode-css-language-server',
    args: ['--stdio'],
    rootPatterns: ['package.json']
  },
  {
    id: 'json',
    name: 'JSON',
    languages: ['json', 'jsonc'],
    command: 'vscode-json-language-server',
    args: ['--stdio'],
    rootPatterns: ['package.json', 'tsconfig.json']
  },
  {
    id: 'lua',
    name: 'Lua',
    languages: ['lua'],
    command: 'lua-language-server',
    args: [],
    rootPatterns: ['.luarc.json', '.luacheckrc']
  },
  {
    id: 'bash',
    name: 'Bash',
    languages: ['bash', 'sh', 'zsh'],
    command: 'bash-language-server',
    args: ['start'],
    rootPatterns: ['.bashrc', 'package.json']
  }
];

// ============================================================================
// STATE
// ============================================================================

const servers = reactive<Map<string, LSPServer>>(new Map());
const diagnostics = reactive<Map<string, Diagnostic[]>>(new Map());  // uri -> diagnostics
const availableConfigs = ref<LSPServerConfig[]>([...DEFAULT_SERVERS]);
const openDocuments = reactive<Map<string, { version: number; content: string }>>(new Map());

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
// CORE FUNCTIONS
// ============================================================================

export function useLSP() {
  /**
   * Start a language server
   */
  async function startServer(configId: string, workspaceRoot: string): Promise<LSPServer | null> {
    const config = availableConfigs.value.find(c => c.id === configId);
    if (!config) {
      console.error(`[LSP] Unknown server config: ${configId}`);
      return null;
    }

    // Check if already running
    const existing = servers.get(configId);
    if (existing && existing.status === 'running') {
      return existing;
    }

    const server: LSPServer = {
      id: configId,
      config,
      status: 'starting',
      capabilities: {},
      workspaceRoot
    };

    servers.set(configId, server);

    try {
      if (!invoke) {
        throw new Error('LSP not available in browser mode');
      }

      // Start server via Tauri
      const capabilities = await invoke<ServerCapabilities>('lsp_start_server', {
        serverId: configId,
        command: config.command,
        args: config.args,
        workspaceRoot,
        initializationOptions: config.initializationOptions,
        settings: config.settings
      });

      server.status = 'running';
      server.capabilities = capabilities;

      console.log(`[LSP] Started ${config.name} for ${workspaceRoot}`);
      return server;
    } catch (error) {
      server.status = 'error';
      server.error = error instanceof Error ? error.message : String(error);
      console.error(`[LSP] Failed to start ${config.name}:`, error);
      return null;
    }
  }

  /**
   * Stop a language server
   */
  async function stopServer(serverId: string): Promise<void> {
    const server = servers.get(serverId);
    if (!server) return;

    try {
      if (invoke) {
        await invoke('lsp_stop_server', { serverId });
      }
    } catch (e) {
      console.error(`[LSP] Error stopping server:`, e);
    }

    servers.delete(serverId);
  }

  /**
   * Get server for a language
   */
  function getServerForLanguage(languageId: string): LSPServer | null {
    for (const [, server] of servers) {
      if (server.config.languages.includes(languageId) && server.status === 'running') {
        return server;
      }
    }
    return null;
  }

  /**
   * Auto-detect and start servers for a workspace
   */
  async function autoStartServers(workspaceRoot: string): Promise<void> {
    if (!invoke) return;

    try {
      // Get list of files in workspace root
      const files = await invoke<string[]>('list_directory', { path: workspaceRoot });

      for (const config of availableConfigs.value) {
        // Check if any root pattern matches
        const hasRootPattern = config.rootPatterns?.some(pattern =>
          files.some(f => f.endsWith(pattern) || f === pattern)
        );

        if (hasRootPattern) {
          // Check if server command exists
          const exists = await invoke<boolean>('command_exists', { command: config.command });
          if (exists) {
            await startServer(config.id, workspaceRoot);
          }
        }
      }
    } catch (error) {
      console.error('[LSP] Auto-start failed:', error);
    }
  }

  /**
   * Open a document for tracking
   */
  async function openDocument(uri: string, languageId: string, content: string): Promise<void> {
    openDocuments.set(uri, { version: 1, content });

    const server = getServerForLanguage(languageId);
    if (!server || !invoke) return;

    try {
      await invoke('lsp_did_open', {
        serverId: server.id,
        uri,
        languageId,
        version: 1,
        text: content
      });
    } catch (e) {
      console.error('[LSP] didOpen failed:', e);
    }
  }

  /**
   * Update document content
   */
  async function updateDocument(uri: string, languageId: string, content: string): Promise<void> {
    const doc = openDocuments.get(uri);
    const version = doc ? doc.version + 1 : 1;
    openDocuments.set(uri, { version, content });

    const server = getServerForLanguage(languageId);
    if (!server || !invoke) return;

    try {
      await invoke('lsp_did_change', {
        serverId: server.id,
        uri,
        version,
        text: content
      });
    } catch (e) {
      console.error('[LSP] didChange failed:', e);
    }
  }

  /**
   * Close a document
   */
  async function closeDocument(uri: string, languageId: string): Promise<void> {
    openDocuments.delete(uri);

    const server = getServerForLanguage(languageId);
    if (!server || !invoke) return;

    try {
      await invoke('lsp_did_close', { serverId: server.id, uri });
    } catch (e) {
      console.error('[LSP] didClose failed:', e);
    }

    // Clear diagnostics
    diagnostics.delete(uri);
  }

  /**
   * Get completions at position
   */
  async function getCompletions(
    uri: string,
    languageId: string,
    position: Position
  ): Promise<CompletionItem[]> {
    const server = getServerForLanguage(languageId);
    if (!server?.capabilities.completionProvider || !invoke) return [];

    try {
      return await invoke<CompletionItem[]>('lsp_completion', {
        serverId: server.id,
        uri,
        position
      });
    } catch (e) {
      console.error('[LSP] Completion failed:', e);
      return [];
    }
  }

  /**
   * Get hover info at position
   */
  async function getHover(
    uri: string,
    languageId: string,
    position: Position
  ): Promise<HoverInfo | null> {
    const server = getServerForLanguage(languageId);
    if (!server?.capabilities.hoverProvider || !invoke) return null;

    try {
      return await invoke<HoverInfo | null>('lsp_hover', {
        serverId: server.id,
        uri,
        position
      });
    } catch (e) {
      console.error('[LSP] Hover failed:', e);
      return null;
    }
  }

  /**
   * Go to definition
   */
  async function getDefinition(
    uri: string,
    languageId: string,
    position: Position
  ): Promise<Location[]> {
    const server = getServerForLanguage(languageId);
    if (!server?.capabilities.definitionProvider || !invoke) return [];

    try {
      const result = await invoke<Location | Location[] | null>('lsp_definition', {
        serverId: server.id,
        uri,
        position
      });

      if (!result) return [];
      return Array.isArray(result) ? result : [result];
    } catch (e) {
      console.error('[LSP] Definition failed:', e);
      return [];
    }
  }

  /**
   * Find references
   */
  async function getReferences(
    uri: string,
    languageId: string,
    position: Position,
    includeDeclaration = true
  ): Promise<Location[]> {
    const server = getServerForLanguage(languageId);
    if (!server?.capabilities.referencesProvider || !invoke) return [];

    try {
      return await invoke<Location[]>('lsp_references', {
        serverId: server.id,
        uri,
        position,
        includeDeclaration
      });
    } catch (e) {
      console.error('[LSP] References failed:', e);
      return [];
    }
  }

  /**
   * Get document symbols
   */
  async function getDocumentSymbols(uri: string, languageId: string): Promise<DocumentSymbol[]> {
    const server = getServerForLanguage(languageId);
    if (!server?.capabilities.documentSymbolProvider || !invoke) return [];

    try {
      return await invoke<DocumentSymbol[]>('lsp_document_symbols', {
        serverId: server.id,
        uri
      });
    } catch (e) {
      console.error('[LSP] Document symbols failed:', e);
      return [];
    }
  }

  /**
   * Search workspace symbols
   */
  async function searchWorkspaceSymbols(query: string, languageId?: string): Promise<Array<{
    name: string;
    kind: SymbolKind;
    location: Location;
    containerName?: string;
  }>> {
    // Find a server with workspace symbol support
    let server: LSPServer | null = null;

    if (languageId) {
      server = getServerForLanguage(languageId);
    } else {
      for (const [, s] of servers) {
        if (s.capabilities.workspaceSymbolProvider && s.status === 'running') {
          server = s;
          break;
        }
      }
    }

    if (!server?.capabilities.workspaceSymbolProvider || !invoke) return [];

    try {
      return await invoke('lsp_workspace_symbols', {
        serverId: server.id,
        query
      });
    } catch (e) {
      console.error('[LSP] Workspace symbols failed:', e);
      return [];
    }
  }

  /**
   * Get code actions
   */
  async function getCodeActions(
    uri: string,
    languageId: string,
    range: Range,
    context?: { diagnostics?: Diagnostic[] }
  ): Promise<CodeAction[]> {
    const server = getServerForLanguage(languageId);
    if (!server?.capabilities.codeActionProvider || !invoke) return [];

    try {
      return await invoke<CodeAction[]>('lsp_code_actions', {
        serverId: server.id,
        uri,
        range,
        context: context || {}
      });
    } catch (e) {
      console.error('[LSP] Code actions failed:', e);
      return [];
    }
  }

  /**
   * Format document
   */
  async function formatDocument(uri: string, languageId: string, options?: {
    tabSize?: number;
    insertSpaces?: boolean;
  }): Promise<TextEdit[]> {
    const server = getServerForLanguage(languageId);
    if (!server?.capabilities.documentFormattingProvider || !invoke) return [];

    try {
      return await invoke<TextEdit[]>('lsp_format', {
        serverId: server.id,
        uri,
        options: options || { tabSize: 2, insertSpaces: true }
      });
    } catch (e) {
      console.error('[LSP] Format failed:', e);
      return [];
    }
  }

  /**
   * Rename symbol
   */
  async function rename(
    uri: string,
    languageId: string,
    position: Position,
    newName: string
  ): Promise<WorkspaceEdit | null> {
    const server = getServerForLanguage(languageId);
    if (!server?.capabilities.renameProvider || !invoke) return null;

    try {
      return await invoke<WorkspaceEdit | null>('lsp_rename', {
        serverId: server.id,
        uri,
        position,
        newName
      });
    } catch (e) {
      console.error('[LSP] Rename failed:', e);
      return null;
    }
  }

  /**
   * Apply workspace edit
   */
  async function applyWorkspaceEdit(edit: WorkspaceEdit): Promise<boolean> {
    if (!invoke) return false;

    try {
      // Apply changes to each file
      if (edit.changes) {
        for (const [uri, edits] of Object.entries(edit.changes)) {
          await invoke('apply_text_edits', { uri, edits });
        }
      }

      if (edit.documentChanges) {
        for (const change of edit.documentChanges) {
          await invoke('apply_text_edits', {
            uri: change.textDocument.uri,
            edits: change.edits
          });
        }
      }

      return true;
    } catch (e) {
      console.error('[LSP] Apply edit failed:', e);
      return false;
    }
  }

  /**
   * Get diagnostics for a document
   */
  function getDiagnostics(uri: string): Diagnostic[] {
    return diagnostics.get(uri) || [];
  }

  /**
   * Handle diagnostics update from server
   */
  function updateDiagnostics(uri: string, newDiagnostics: Diagnostic[]): void {
    diagnostics.set(uri, newDiagnostics);
  }

  /**
   * Get all diagnostics across workspace
   */
  const allDiagnostics = computed(() => {
    const result: Array<{ uri: string; diagnostic: Diagnostic }> = [];
    for (const [uri, diags] of diagnostics) {
      for (const diagnostic of diags) {
        result.push({ uri, diagnostic });
      }
    }
    return result;
  });

  /**
   * Get error count
   */
  const errorCount = computed(() =>
    allDiagnostics.value.filter(d => d.diagnostic.severity === 'error').length
  );

  /**
   * Get warning count
   */
  const warningCount = computed(() =>
    allDiagnostics.value.filter(d => d.diagnostic.severity === 'warning').length
  );

  /**
   * Add custom server config
   */
  function addServerConfig(config: LSPServerConfig): void {
    const existing = availableConfigs.value.findIndex(c => c.id === config.id);
    if (existing >= 0) {
      availableConfigs.value[existing] = config;
    } else {
      availableConfigs.value.push(config);
    }
  }

  /**
   * Stop all servers
   */
  async function stopAllServers(): Promise<void> {
    const serverIds = Array.from(servers.keys());
    await Promise.all(serverIds.map(id => stopServer(id)));
  }

  return {
    // State
    servers: computed(() => Array.from(servers.values())),
    availableConfigs: computed(() => availableConfigs.value),
    diagnostics: allDiagnostics,
    errorCount,
    warningCount,

    // Server management
    startServer,
    stopServer,
    stopAllServers,
    autoStartServers,
    getServerForLanguage,
    addServerConfig,

    // Document management
    openDocument,
    updateDocument,
    closeDocument,

    // Language features
    getCompletions,
    getHover,
    getDefinition,
    getReferences,
    getDocumentSymbols,
    searchWorkspaceSymbols,
    getCodeActions,
    formatDocument,
    rename,
    applyWorkspaceEdit,

    // Diagnostics
    getDiagnostics,
    updateDiagnostics
  };
}

export default useLSP;
