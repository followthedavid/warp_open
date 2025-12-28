/**
 * Persistent Agent Memory
 * Local-first memory system with cross-tab SSOT
 *
 * Features:
 * - Persistent memory across sessions
 * - Configurable storage location (internal/external drives)
 * - Cross-tab synchronization (all tabs share same memory)
 * - Private/unlogged session mode
 * - Automatic archiving to prevent bloat
 * - Storage quotas with smart cleanup
 * - Semantic search over history
 */

import { ref, computed, reactive, watch } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export interface MemoryConfig {
  // Storage locations
  primaryStoragePath: string;       // Default: ~/.warp-open/memory
  archiveStoragePath: string;       // External drive path for archives
  useExternalForActive: boolean;    // Store active memory on external too

  // Storage limits (to prevent bloat)
  maxInternalStorageMB: number;     // Max storage on internal drive
  maxConversationAge: number;       // Days before archiving
  maxMessagesPerConversation: number;

  // Privacy
  defaultPrivateMode: boolean;      // Start in private mode
  privateSessionRetention: number;  // Hours to keep private sessions (0 = immediate delete)

  // Sync
  syncIntervalMs: number;           // Cross-tab sync interval
  enableCrossTabSync: boolean;
}

export interface MemoryEntry {
  id: string;
  type: 'user' | 'assistant' | 'system' | 'tool_call' | 'tool_result';
  content: string;
  timestamp: Date;
  conversationId: string;
  tabId: string;
  metadata?: {
    model?: string;
    tokens?: number;
    duration?: number;
    toolName?: string;
    files?: string[];
    workingDirectory?: string;
  };
  embedding?: number[];  // For semantic search
  archived: boolean;
  private: boolean;
}

export interface Conversation {
  id: string;
  title: string;
  summary?: string;
  startedAt: Date;
  lastActivity: Date;
  messageCount: number;
  tabIds: string[];
  workingDirectory?: string;
  project?: string;
  tags?: string[];
  archived: boolean;
  private: boolean;
  storageLocation: 'internal' | 'external';
}

export interface MemoryStats {
  totalConversations: number;
  totalMessages: number;
  internalStorageUsedMB: number;
  externalStorageUsedMB: number;
  oldestMessage: Date | null;
  newestMessage: Date | null;
}

export interface SearchResult {
  entry: MemoryEntry;
  conversation: Conversation;
  score: number;
  snippet: string;
}

// ============================================================================
// DEFAULT CONFIGURATION
// ============================================================================

const DEFAULT_CONFIG: MemoryConfig = {
  primaryStoragePath: '~/.warp-open/memory',
  archiveStoragePath: '',  // User must configure
  useExternalForActive: false,

  maxInternalStorageMB: 500,        // 500MB max on internal
  maxConversationAge: 30,           // Archive after 30 days
  maxMessagesPerConversation: 1000,

  defaultPrivateMode: false,
  privateSessionRetention: 0,       // Delete immediately on close

  syncIntervalMs: 100,
  enableCrossTabSync: true
};

// ============================================================================
// STATE
// ============================================================================

const config = reactive<MemoryConfig>({ ...DEFAULT_CONFIG });
const conversations = reactive<Map<string, Conversation>>(new Map());
const entries = reactive<Map<string, MemoryEntry>>(new Map());
const currentConversationId = ref<string | null>(null);
const isPrivateMode = ref(false);
const tabId = ref<string>(generateTabId());

// Cross-tab communication
let broadcastChannel: BroadcastChannel | null = null;
let syncInterval: number | null = null;

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

function generateTabId(): string {
  return `tab_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}

function generateId(): string {
  return `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
}

async function getStoragePath(location: 'internal' | 'external'): Promise<string> {
  const basePath = location === 'external' && config.archiveStoragePath
    ? config.archiveStoragePath
    : config.primaryStoragePath;

  // Expand ~ to home directory
  if (invoke && basePath.startsWith('~')) {
    const home = await invoke<string>('get_home_dir');
    return basePath.replace('~', home);
  }

  return basePath;
}

async function loadFromDisk(): Promise<void> {
  if (!invoke) {
    // Browser mode - use localStorage
    loadFromLocalStorage();
    return;
  }

  try {
    const storagePath = await getStoragePath('internal');

    // Load conversations index
    const conversationsJson = await invoke<string>('read_file', {
      path: `${storagePath}/conversations.json`
    }).catch(() => '[]');

    const loadedConversations: Conversation[] = JSON.parse(conversationsJson);
    for (const conv of loadedConversations) {
      conv.startedAt = new Date(conv.startedAt);
      conv.lastActivity = new Date(conv.lastActivity);
      conversations.set(conv.id, conv);
    }

    // Load recent entries (not all - lazy load old ones)
    const recentConvs = loadedConversations
      .filter(c => !c.archived)
      .sort((a, b) => b.lastActivity.getTime() - a.lastActivity.getTime())
      .slice(0, 10);

    for (const conv of recentConvs) {
      await loadConversationEntries(conv.id);
    }

    console.log(`[Memory] Loaded ${conversations.size} conversations`);
  } catch (e) {
    console.error('[Memory] Failed to load from disk:', e);
  }
}

async function loadConversationEntries(conversationId: string): Promise<void> {
  if (!invoke) return;

  try {
    const storagePath = await getStoragePath('internal');
    const entriesJson = await invoke<string>('read_file', {
      path: `${storagePath}/entries/${conversationId}.json`
    }).catch(() => '[]');

    const loadedEntries: MemoryEntry[] = JSON.parse(entriesJson);
    for (const entry of loadedEntries) {
      entry.timestamp = new Date(entry.timestamp);
      entries.set(entry.id, entry);
    }
  } catch (e) {
    // Entries file might not exist yet
  }
}

async function saveToDisk(): Promise<void> {
  if (!invoke) {
    saveToLocalStorage();
    return;
  }

  try {
    const storagePath = await getStoragePath('internal');

    // Ensure directory exists
    await invoke('create_directory', { path: storagePath });
    await invoke('create_directory', { path: `${storagePath}/entries` });

    // Filter out private conversations if retention is 0
    const persistConversations = Array.from(conversations.values())
      .filter(c => !c.private || config.privateSessionRetention > 0);

    // Save conversations index
    await invoke('write_file', {
      path: `${storagePath}/conversations.json`,
      content: JSON.stringify(persistConversations, null, 2)
    });

    // Save entries by conversation
    const entriesByConv = new Map<string, MemoryEntry[]>();
    for (const entry of entries.values()) {
      if (entry.private && config.privateSessionRetention === 0) continue;

      if (!entriesByConv.has(entry.conversationId)) {
        entriesByConv.set(entry.conversationId, []);
      }
      entriesByConv.get(entry.conversationId)!.push(entry);
    }

    for (const [convId, convEntries] of entriesByConv) {
      await invoke('write_file', {
        path: `${storagePath}/entries/${convId}.json`,
        content: JSON.stringify(convEntries, null, 2)
      });
    }
  } catch (e) {
    console.error('[Memory] Failed to save to disk:', e);
  }
}

function loadFromLocalStorage(): void {
  try {
    const saved = localStorage.getItem('warp_agent_memory');
    if (saved) {
      const data = JSON.parse(saved);

      for (const conv of data.conversations || []) {
        conv.startedAt = new Date(conv.startedAt);
        conv.lastActivity = new Date(conv.lastActivity);
        conversations.set(conv.id, conv);
      }

      for (const entry of data.entries || []) {
        entry.timestamp = new Date(entry.timestamp);
        entries.set(entry.id, entry);
      }
    }
  } catch (e) {
    console.error('[Memory] Failed to load from localStorage:', e);
  }
}

function saveToLocalStorage(): void {
  try {
    const persistConversations = Array.from(conversations.values())
      .filter(c => !c.private || config.privateSessionRetention > 0);

    const persistEntries = Array.from(entries.values())
      .filter(e => !e.private || config.privateSessionRetention > 0);

    localStorage.setItem('warp_agent_memory', JSON.stringify({
      conversations: persistConversations,
      entries: persistEntries
    }));
  } catch (e) {
    console.error('[Memory] Failed to save to localStorage:', e);
  }
}

function loadConfig(): void {
  try {
    const saved = localStorage.getItem('warp_memory_config');
    if (saved) {
      Object.assign(config, JSON.parse(saved));
    }
  } catch (e) {
    console.error('[Memory] Failed to load config:', e);
  }
}

function saveConfig(): void {
  try {
    localStorage.setItem('warp_memory_config', JSON.stringify(config));
  } catch (e) {
    console.error('[Memory] Failed to save config:', e);
  }
}

// ============================================================================
// CROSS-TAB SYNC
// ============================================================================

interface SyncMessage {
  type: 'entry_added' | 'conversation_updated' | 'private_mode_changed' | 'request_sync' | 'full_sync';
  tabId: string;
  data: unknown;
  timestamp: number;
}

function initCrossTabSync(): void {
  if (!config.enableCrossTabSync) return;
  if (typeof BroadcastChannel === 'undefined') return;

  broadcastChannel = new BroadcastChannel('warp_agent_memory');

  broadcastChannel.onmessage = (event: MessageEvent<SyncMessage>) => {
    const message = event.data;
    if (message.tabId === tabId.value) return;  // Ignore own messages

    switch (message.type) {
      case 'entry_added':
        handleRemoteEntryAdded(message.data as MemoryEntry);
        break;
      case 'conversation_updated':
        handleRemoteConversationUpdated(message.data as Conversation);
        break;
      case 'private_mode_changed':
        // Other tabs don't affect our private mode
        break;
      case 'request_sync':
        sendFullSync();
        break;
      case 'full_sync':
        handleFullSync(message.data as { conversations: Conversation[]; entries: MemoryEntry[] });
        break;
    }
  };

  // Request sync from other tabs on startup
  broadcastChannel.postMessage({
    type: 'request_sync',
    tabId: tabId.value,
    data: null,
    timestamp: Date.now()
  });
}

function broadcast(message: Omit<SyncMessage, 'tabId' | 'timestamp'>): void {
  if (!broadcastChannel) return;

  broadcastChannel.postMessage({
    ...message,
    tabId: tabId.value,
    timestamp: Date.now()
  });
}

function handleRemoteEntryAdded(entry: MemoryEntry): void {
  entry.timestamp = new Date(entry.timestamp);
  entries.set(entry.id, entry);

  // Update conversation
  const conv = conversations.get(entry.conversationId);
  if (conv) {
    conv.lastActivity = entry.timestamp;
    conv.messageCount++;
    if (!conv.tabIds.includes(tabId.value)) {
      conv.tabIds.push(tabId.value);
    }
  }
}

function handleRemoteConversationUpdated(conv: Conversation): void {
  conv.startedAt = new Date(conv.startedAt);
  conv.lastActivity = new Date(conv.lastActivity);
  conversations.set(conv.id, conv);
}

function sendFullSync(): void {
  broadcast({
    type: 'full_sync',
    data: {
      conversations: Array.from(conversations.values()).filter(c => !c.private),
      entries: Array.from(entries.values()).filter(e => !e.private).slice(-100)
    }
  });
}

function handleFullSync(data: { conversations: Conversation[]; entries: MemoryEntry[] }): void {
  for (const conv of data.conversations) {
    conv.startedAt = new Date(conv.startedAt);
    conv.lastActivity = new Date(conv.lastActivity);
    if (!conversations.has(conv.id)) {
      conversations.set(conv.id, conv);
    }
  }

  for (const entry of data.entries) {
    entry.timestamp = new Date(entry.timestamp);
    if (!entries.has(entry.id)) {
      entries.set(entry.id, entry);
    }
  }
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useAgentMemory() {
  /**
   * Initialize memory system
   */
  async function initialize(): Promise<void> {
    loadConfig();
    await loadFromDisk();
    initCrossTabSync();

    // Start periodic save
    syncInterval = window.setInterval(() => {
      saveToDisk();
    }, 30000);  // Save every 30 seconds

    console.log('[Memory] Initialized');
  }

  /**
   * Shutdown and cleanup
   */
  async function shutdown(): Promise<void> {
    // Clean up private session if retention is 0
    if (config.privateSessionRetention === 0) {
      await clearPrivateData();
    }

    await saveToDisk();

    if (syncInterval) {
      clearInterval(syncInterval);
    }

    broadcastChannel?.close();
  }

  /**
   * Start a new conversation
   */
  function startConversation(options?: {
    title?: string;
    project?: string;
    workingDirectory?: string;
    private?: boolean;
  }): Conversation {
    const isPrivate = options?.private ?? isPrivateMode.value;

    const conversation: Conversation = {
      id: generateId(),
      title: options?.title || `Session ${new Date().toLocaleString()}`,
      startedAt: new Date(),
      lastActivity: new Date(),
      messageCount: 0,
      tabIds: [tabId.value],
      workingDirectory: options?.workingDirectory,
      project: options?.project,
      archived: false,
      private: isPrivate,
      storageLocation: config.useExternalForActive ? 'external' : 'internal'
    };

    conversations.set(conversation.id, conversation);
    currentConversationId.value = conversation.id;

    if (!isPrivate) {
      broadcast({ type: 'conversation_updated', data: conversation });
    }

    return conversation;
  }

  /**
   * Add a memory entry
   */
  function addEntry(
    type: MemoryEntry['type'],
    content: string,
    metadata?: MemoryEntry['metadata']
  ): MemoryEntry {
    // Create conversation if needed
    if (!currentConversationId.value) {
      startConversation();
    }

    const entry: MemoryEntry = {
      id: generateId(),
      type,
      content,
      timestamp: new Date(),
      conversationId: currentConversationId.value!,
      tabId: tabId.value,
      metadata,
      archived: false,
      private: isPrivateMode.value
    };

    entries.set(entry.id, entry);

    // Update conversation
    const conv = conversations.get(entry.conversationId);
    if (conv) {
      conv.lastActivity = entry.timestamp;
      conv.messageCount++;
    }

    // Broadcast to other tabs (unless private)
    if (!entry.private) {
      broadcast({ type: 'entry_added', data: entry });
    }

    // Check storage limits
    checkStorageLimits();

    return entry;
  }

  /**
   * Get conversation history
   */
  function getConversationHistory(conversationId?: string, limit?: number): MemoryEntry[] {
    const targetId = conversationId || currentConversationId.value;
    if (!targetId) return [];

    const convEntries = Array.from(entries.values())
      .filter(e => e.conversationId === targetId)
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    return limit ? convEntries.slice(-limit) : convEntries;
  }

  /**
   * Get context for AI (recent history formatted)
   */
  function getContextForAI(options?: {
    maxMessages?: number;
    maxTokens?: number;
    includeAllTabs?: boolean;
  }): string {
    const maxMessages = options?.maxMessages || 20;
    let contextEntries: MemoryEntry[];

    if (options?.includeAllTabs) {
      // Get recent entries from ALL conversations (cross-tab awareness)
      contextEntries = Array.from(entries.values())
        .filter(e => !e.archived)
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
        .slice(0, maxMessages * 2)
        .reverse();
    } else {
      contextEntries = getConversationHistory(undefined, maxMessages);
    }

    // Format for AI context
    const lines: string[] = [];

    for (const entry of contextEntries) {
      const prefix = entry.tabId !== tabId.value ? `[Tab ${entry.tabId.slice(-4)}] ` : '';

      switch (entry.type) {
        case 'user':
          lines.push(`${prefix}User: ${entry.content}`);
          break;
        case 'assistant':
          lines.push(`${prefix}Assistant: ${entry.content}`);
          break;
        case 'tool_call':
          lines.push(`${prefix}Tool(${entry.metadata?.toolName}): ${entry.content.substring(0, 200)}`);
          break;
        case 'tool_result':
          lines.push(`${prefix}Result: ${entry.content.substring(0, 500)}`);
          break;
        case 'system':
          lines.push(`${prefix}System: ${entry.content}`);
          break;
      }
    }

    return lines.join('\n');
  }

  /**
   * Search memory
   */
  function search(query: string, options?: {
    conversationId?: string;
    limit?: number;
    includeArchived?: boolean;
  }): SearchResult[] {
    const results: SearchResult[] = [];
    const queryLower = query.toLowerCase();
    const limit = options?.limit || 20;

    for (const entry of entries.values()) {
      if (entry.private) continue;
      if (!options?.includeArchived && entry.archived) continue;
      if (options?.conversationId && entry.conversationId !== options.conversationId) continue;

      const contentLower = entry.content.toLowerCase();
      if (contentLower.includes(queryLower)) {
        const conv = conversations.get(entry.conversationId);
        if (!conv) continue;

        // Simple scoring
        const exactMatch = contentLower === queryLower ? 1 : 0;
        const startsWith = contentLower.startsWith(queryLower) ? 0.5 : 0;
        const frequency = (contentLower.match(new RegExp(queryLower, 'g')) || []).length * 0.1;

        results.push({
          entry,
          conversation: conv,
          score: exactMatch + startsWith + frequency,
          snippet: getSnippet(entry.content, query)
        });
      }
    }

    return results
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }

  /**
   * Get snippet around match
   */
  function getSnippet(content: string, query: string, contextChars = 50): string {
    const index = content.toLowerCase().indexOf(query.toLowerCase());
    if (index < 0) return content.substring(0, 100);

    const start = Math.max(0, index - contextChars);
    const end = Math.min(content.length, index + query.length + contextChars);

    let snippet = content.substring(start, end);
    if (start > 0) snippet = '...' + snippet;
    if (end < content.length) snippet = snippet + '...';

    return snippet;
  }

  /**
   * Toggle private mode
   */
  function setPrivateMode(enabled: boolean): void {
    isPrivateMode.value = enabled;

    if (enabled && currentConversationId.value) {
      // Start new private conversation
      startConversation({ private: true });
    }

    broadcast({ type: 'private_mode_changed', data: enabled });
  }

  /**
   * Clear private data
   */
  async function clearPrivateData(): Promise<void> {
    // Remove private entries
    for (const [id, entry] of entries) {
      if (entry.private) {
        entries.delete(id);
      }
    }

    // Remove private conversations
    for (const [id, conv] of conversations) {
      if (conv.private) {
        conversations.delete(id);
      }
    }

    await saveToDisk();
  }

  /**
   * Archive old conversations
   */
  async function archiveOldConversations(): Promise<number> {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - config.maxConversationAge);

    let archived = 0;

    for (const conv of conversations.values()) {
      if (conv.archived || conv.private) continue;
      if (conv.lastActivity < cutoff) {
        conv.archived = true;
        archived++;

        // Move to external storage if configured
        if (config.archiveStoragePath) {
          await moveToExternal(conv.id);
        }
      }
    }

    if (archived > 0) {
      await saveToDisk();
      console.log(`[Memory] Archived ${archived} old conversations`);
    }

    return archived;
  }

  /**
   * Move conversation to external storage
   */
  async function moveToExternal(conversationId: string): Promise<void> {
    if (!invoke || !config.archiveStoragePath) return;

    const conv = conversations.get(conversationId);
    if (!conv) return;

    try {
      const externalPath = await getStoragePath('external');
      const convEntries = Array.from(entries.values())
        .filter(e => e.conversationId === conversationId);

      await invoke('create_directory', { path: `${externalPath}/entries` });

      await invoke('write_file', {
        path: `${externalPath}/entries/${conversationId}.json`,
        content: JSON.stringify(convEntries, null, 2)
      });

      // Remove from internal storage
      const internalPath = await getStoragePath('internal');
      await invoke('delete_file', {
        path: `${internalPath}/entries/${conversationId}.json`
      }).catch(() => {});

      conv.storageLocation = 'external';
    } catch (e) {
      console.error('[Memory] Failed to move to external:', e);
    }
  }

  /**
   * Check and enforce storage limits
   */
  async function checkStorageLimits(): Promise<void> {
    const stats = await getStats();

    if (stats.internalStorageUsedMB > config.maxInternalStorageMB) {
      console.log('[Memory] Storage limit exceeded, archiving old data...');
      await archiveOldConversations();

      // If still over, delete oldest archived
      const newStats = await getStats();
      if (newStats.internalStorageUsedMB > config.maxInternalStorageMB) {
        await pruneOldestArchived(10);
      }
    }
  }

  /**
   * Prune oldest archived conversations
   */
  async function pruneOldestArchived(count: number): Promise<void> {
    const archived = Array.from(conversations.values())
      .filter(c => c.archived && c.storageLocation === 'internal')
      .sort((a, b) => a.lastActivity.getTime() - b.lastActivity.getTime())
      .slice(0, count);

    for (const conv of archived) {
      // Delete entries
      for (const [id, entry] of entries) {
        if (entry.conversationId === conv.id) {
          entries.delete(id);
        }
      }
      conversations.delete(conv.id);
    }

    await saveToDisk();
  }

  /**
   * Get memory statistics
   */
  async function getStats(): Promise<MemoryStats> {
    let internalSize = 0;
    let externalSize = 0;
    let oldestMessage: Date | null = null;
    let newestMessage: Date | null = null;

    for (const entry of entries.values()) {
      const size = JSON.stringify(entry).length;
      const conv = conversations.get(entry.conversationId);

      if (conv?.storageLocation === 'external') {
        externalSize += size;
      } else {
        internalSize += size;
      }

      if (!oldestMessage || entry.timestamp < oldestMessage) {
        oldestMessage = entry.timestamp;
      }
      if (!newestMessage || entry.timestamp > newestMessage) {
        newestMessage = entry.timestamp;
      }
    }

    return {
      totalConversations: conversations.size,
      totalMessages: entries.size,
      internalStorageUsedMB: internalSize / (1024 * 1024),
      externalStorageUsedMB: externalSize / (1024 * 1024),
      oldestMessage,
      newestMessage
    };
  }

  /**
   * Update configuration
   */
  function updateConfig(newConfig: Partial<MemoryConfig>): void {
    Object.assign(config, newConfig);
    saveConfig();
  }

  /**
   * Get all conversations (for UI)
   */
  const allConversations = computed(() =>
    Array.from(conversations.values())
      .filter(c => !c.private || c.private === isPrivateMode.value)
      .sort((a, b) => b.lastActivity.getTime() - a.lastActivity.getTime())
  );

  /**
   * Get current conversation
   */
  const currentConversation = computed(() =>
    currentConversationId.value ? conversations.get(currentConversationId.value) : null
  );

  /**
   * Export memory (for backup)
   */
  async function exportMemory(): Promise<string> {
    const data = {
      exportedAt: new Date().toISOString(),
      config,
      conversations: Array.from(conversations.values()).filter(c => !c.private),
      entries: Array.from(entries.values()).filter(e => !e.private)
    };

    return JSON.stringify(data, null, 2);
  }

  /**
   * Import memory (from backup)
   */
  async function importMemory(jsonData: string): Promise<boolean> {
    try {
      const data = JSON.parse(jsonData);

      for (const conv of data.conversations || []) {
        conv.startedAt = new Date(conv.startedAt);
        conv.lastActivity = new Date(conv.lastActivity);
        conversations.set(conv.id, conv);
      }

      for (const entry of data.entries || []) {
        entry.timestamp = new Date(entry.timestamp);
        entries.set(entry.id, entry);
      }

      await saveToDisk();
      return true;
    } catch (e) {
      console.error('[Memory] Import failed:', e);
      return false;
    }
  }

  return {
    // State
    config: computed(() => config),
    conversations: allConversations,
    currentConversation,
    isPrivateMode: computed(() => isPrivateMode.value),
    tabId: computed(() => tabId.value),

    // Lifecycle
    initialize,
    shutdown,

    // Conversations
    startConversation,
    getConversationHistory,

    // Entries
    addEntry,
    getContextForAI,

    // Search
    search,

    // Privacy
    setPrivateMode,
    clearPrivateData,

    // Storage management
    archiveOldConversations,
    moveToExternal,
    checkStorageLimits,
    getStats,

    // Config
    updateConfig,

    // Import/Export
    exportMemory,
    importMemory
  };
}

export default useAgentMemory;
