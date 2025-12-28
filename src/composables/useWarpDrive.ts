/**
 * Warp Drive System
 * Cloud-based knowledge library for saving and sharing workflows, notebooks, and snippets.
 * Local-first implementation with optional sync.
 */

import { ref, computed, watch } from 'vue';

export type DriveItemType = 'workflow' | 'notebook' | 'snippet' | 'prompt' | 'env_vars';

export interface DriveItem {
  id: string;
  type: DriveItemType;
  name: string;
  description?: string;
  content: string;
  tags: string[];
  createdAt: number;
  updatedAt: number;
  isShared: boolean;
  shareUrl?: string;
  author?: string;
  version: number;
  parameters?: Array<{
    name: string;
    description?: string;
    default?: string;
    required?: boolean;
  }>;
}

export interface Workflow extends DriveItem {
  type: 'workflow';
  commands: string[];
  parameters: Array<{
    name: string;
    description?: string;
    default?: string;
    required?: boolean;
  }>;
}

export interface Notebook extends DriveItem {
  type: 'notebook';
  cells: Array<{
    id: string;
    type: 'markdown' | 'command' | 'output';
    content: string;
  }>;
}

export interface Snippet extends DriveItem {
  type: 'snippet';
  language?: string;
}

export interface Prompt extends DriveItem {
  type: 'prompt';
  category?: string;
}

export interface EnvVars extends DriveItem {
  type: 'env_vars';
  variables: Record<string, string>;
  masked: string[]; // Variable names that should be masked
}

export interface DriveFolder {
  id: string;
  name: string;
  parentId?: string;
  items: string[]; // Item IDs
  createdAt: number;
}

export interface DriveStats {
  totalItems: number;
  byType: Record<DriveItemType, number>;
  sharedCount: number;
  totalTags: number;
}

const STORAGE_KEY = 'warp_open_drive';
const FOLDERS_KEY = 'warp_open_drive_folders';

// State
const items = ref<Map<string, DriveItem>>(new Map());
const folders = ref<Map<string, DriveFolder>>(new Map());
const recentlyUsed = ref<string[]>([]);
const favorites = ref<Set<string>>(new Set());

// Load from storage
function loadDrive(): void {
  try {
    const storedItems = localStorage.getItem(STORAGE_KEY);
    if (storedItems) {
      const data = JSON.parse(storedItems);
      items.value = new Map(Object.entries(data.items || {}));
      recentlyUsed.value = data.recentlyUsed || [];
      favorites.value = new Set(data.favorites || []);
    }

    const storedFolders = localStorage.getItem(FOLDERS_KEY);
    if (storedFolders) {
      folders.value = new Map(Object.entries(JSON.parse(storedFolders)));
    }
  } catch (e) {
    console.error('[WarpDrive] Error loading:', e);
  }
}

// Save to storage
function saveDrive(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      items: Object.fromEntries(items.value),
      recentlyUsed: recentlyUsed.value,
      favorites: Array.from(favorites.value),
    }));
    localStorage.setItem(FOLDERS_KEY, JSON.stringify(Object.fromEntries(folders.value)));
  } catch (e) {
    console.error('[WarpDrive] Error saving:', e);
  }
}

// Initialize
loadDrive();

// Auto-save on changes
watch([items, folders, recentlyUsed, favorites], () => {
  saveDrive();
}, { deep: true });

function generateId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

export function useWarpDrive() {
  const allItems = computed(() => Array.from(items.value.values()));

  const workflows = computed(() =>
    allItems.value.filter(i => i.type === 'workflow') as Workflow[]
  );

  const notebooks = computed(() =>
    allItems.value.filter(i => i.type === 'notebook') as Notebook[]
  );

  const snippets = computed(() =>
    allItems.value.filter(i => i.type === 'snippet') as Snippet[]
  );

  const prompts = computed(() =>
    allItems.value.filter(i => i.type === 'prompt') as Prompt[]
  );

  const favoriteItems = computed(() =>
    allItems.value.filter(i => favorites.value.has(i.id))
  );

  const recentItems = computed(() =>
    recentlyUsed.value
      .map(id => items.value.get(id))
      .filter(Boolean) as DriveItem[]
  );

  /**
   * Create a new item
   */
  function createItem<T extends DriveItem>(item: Omit<T, 'id' | 'createdAt' | 'updatedAt' | 'version'>): T {
    const newItem = {
      ...item,
      id: generateId(item.type),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      version: 1,
    } as T;

    items.value.set(newItem.id, newItem);
    addToRecent(newItem.id);

    console.log(`[WarpDrive] Created ${item.type}: ${item.name}`);
    return newItem;
  }

  /**
   * Create a workflow
   */
  function createWorkflow(
    name: string,
    commands: string[],
    options?: {
      description?: string;
      tags?: string[];
      parameters?: Workflow['parameters'];
    }
  ): Workflow {
    return createItem<Workflow>({
      type: 'workflow',
      name,
      commands,
      content: commands.join('\n'),
      description: options?.description,
      tags: options?.tags || [],
      parameters: options?.parameters || [],
      isShared: false,
    });
  }

  /**
   * Create a notebook
   */
  function createNotebook(
    name: string,
    cells?: Notebook['cells'],
    options?: { description?: string; tags?: string[] }
  ): Notebook {
    return createItem<Notebook>({
      type: 'notebook',
      name,
      cells: cells || [{ id: generateId('cell'), type: 'markdown', content: `# ${name}` }],
      content: '',
      description: options?.description,
      tags: options?.tags || [],
      isShared: false,
    });
  }

  /**
   * Create a snippet
   */
  function createSnippet(
    name: string,
    content: string,
    options?: { description?: string; tags?: string[]; language?: string }
  ): Snippet {
    return createItem<Snippet>({
      type: 'snippet',
      name,
      content,
      language: options?.language,
      description: options?.description,
      tags: options?.tags || [],
      isShared: false,
    });
  }

  /**
   * Create a prompt template
   */
  function createPrompt(
    name: string,
    content: string,
    options?: { description?: string; tags?: string[]; category?: string }
  ): Prompt {
    return createItem<Prompt>({
      type: 'prompt',
      name,
      content,
      category: options?.category,
      description: options?.description,
      tags: options?.tags || [],
      isShared: false,
    });
  }

  /**
   * Update an item
   */
  function updateItem(itemId: string, updates: Partial<DriveItem>): void {
    const item = items.value.get(itemId);
    if (item) {
      Object.assign(item, {
        ...updates,
        updatedAt: Date.now(),
        version: item.version + 1,
      });
      addToRecent(itemId);
    }
  }

  /**
   * Delete an item
   */
  function deleteItem(itemId: string): boolean {
    const deleted = items.value.delete(itemId);
    if (deleted) {
      favorites.value.delete(itemId);
      recentlyUsed.value = recentlyUsed.value.filter(id => id !== itemId);

      // Remove from folders
      for (const folder of folders.value.values()) {
        folder.items = folder.items.filter(id => id !== itemId);
      }
    }
    return deleted;
  }

  /**
   * Get item by ID
   */
  function getItem(itemId: string): DriveItem | undefined {
    return items.value.get(itemId);
  }

  /**
   * Search items
   */
  function searchItems(query: string, options?: {
    type?: DriveItemType;
    tags?: string[];
    limit?: number;
  }): DriveItem[] {
    const lowerQuery = query.toLowerCase();
    let results = allItems.value.filter(item => {
      const matchesQuery =
        item.name.toLowerCase().includes(lowerQuery) ||
        item.description?.toLowerCase().includes(lowerQuery) ||
        item.content.toLowerCase().includes(lowerQuery) ||
        item.tags.some(t => t.toLowerCase().includes(lowerQuery));

      const matchesType = !options?.type || item.type === options.type;
      const matchesTags = !options?.tags?.length ||
        options.tags.some(t => item.tags.includes(t));

      return matchesQuery && matchesType && matchesTags;
    });

    if (options?.limit) {
      results = results.slice(0, options.limit);
    }

    return results;
  }

  /**
   * Get items by tag
   */
  function getByTag(tag: string): DriveItem[] {
    return allItems.value.filter(item => item.tags.includes(tag));
  }

  /**
   * Get all tags
   */
  function getAllTags(): string[] {
    const tags = new Set<string>();
    for (const item of items.value.values()) {
      for (const tag of item.tags) {
        tags.add(tag);
      }
    }
    return Array.from(tags).sort();
  }

  /**
   * Add to recently used
   */
  function addToRecent(itemId: string): void {
    recentlyUsed.value = [
      itemId,
      ...recentlyUsed.value.filter(id => id !== itemId),
    ].slice(0, 20);
  }

  /**
   * Toggle favorite
   */
  function toggleFavorite(itemId: string): boolean {
    if (favorites.value.has(itemId)) {
      favorites.value.delete(itemId);
      return false;
    } else {
      favorites.value.add(itemId);
      return true;
    }
  }

  /**
   * Create a folder
   */
  function createFolder(name: string, parentId?: string): DriveFolder {
    const folder: DriveFolder = {
      id: generateId('folder'),
      name,
      parentId,
      items: [],
      createdAt: Date.now(),
    };
    folders.value.set(folder.id, folder);
    return folder;
  }

  /**
   * Add item to folder
   */
  function addToFolder(itemId: string, folderId: string): void {
    const folder = folders.value.get(folderId);
    if (folder && !folder.items.includes(itemId)) {
      folder.items.push(itemId);
    }
  }

  /**
   * Remove item from folder
   */
  function removeFromFolder(itemId: string, folderId: string): void {
    const folder = folders.value.get(folderId);
    if (folder) {
      folder.items = folder.items.filter(id => id !== itemId);
    }
  }

  /**
   * Execute a workflow
   */
  function getWorkflowCommands(
    workflowId: string,
    params?: Record<string, string>
  ): string[] {
    const workflow = items.value.get(workflowId) as Workflow | undefined;
    if (!workflow || workflow.type !== 'workflow') {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    addToRecent(workflowId);

    // Substitute parameters
    let commands = [...workflow.commands];
    if (params) {
      commands = commands.map(cmd => {
        let result = cmd;
        for (const [key, value] of Object.entries(params)) {
          result = result.replace(new RegExp(`\\$\\{${key}\\}|\\$${key}`, 'g'), value);
        }
        return result;
      });
    }

    // Apply defaults for missing params
    if (workflow.parameters) {
      commands = commands.map(cmd => {
        let result = cmd;
        for (const param of workflow.parameters || []) {
          if (param.default) {
            result = result.replace(
              new RegExp(`\\$\\{${param.name}\\}|\\$${param.name}`, 'g'),
              param.default
            );
          }
        }
        return result;
      });
    }

    return commands;
  }

  /**
   * Generate share URL (local implementation - creates exportable data)
   */
  function shareItem(itemId: string): string {
    const item = items.value.get(itemId);
    if (!item) {
      throw new Error(`Item not found: ${itemId}`);
    }

    item.isShared = true;
    item.updatedAt = Date.now();

    // Create shareable data
    const shareData = btoa(JSON.stringify(item));
    item.shareUrl = `warp-drive://${shareData.slice(0, 20)}`;

    return item.shareUrl;
  }

  /**
   * Import shared item
   */
  function importSharedItem(shareData: string): DriveItem | null {
    try {
      const data = JSON.parse(atob(shareData));
      const newItem = {
        ...data,
        id: generateId(data.type),
        createdAt: Date.now(),
        updatedAt: Date.now(),
        isShared: false,
        shareUrl: undefined,
      };

      items.value.set(newItem.id, newItem);
      return newItem;
    } catch (error) {
      console.error('[WarpDrive] Import error:', error);
      return null;
    }
  }

  /**
   * Export all items
   */
  function exportDrive(): string {
    return JSON.stringify({
      items: Array.from(items.value.values()),
      folders: Array.from(folders.value.values()),
    }, null, 2);
  }

  /**
   * Import items from export
   */
  function importDrive(json: string): number {
    try {
      const data = JSON.parse(json);
      let count = 0;

      if (data.items) {
        for (const item of data.items) {
          if (!items.value.has(item.id)) {
            items.value.set(item.id, item);
            count++;
          }
        }
      }

      if (data.folders) {
        for (const folder of data.folders) {
          if (!folders.value.has(folder.id)) {
            folders.value.set(folder.id, folder);
          }
        }
      }

      return count;
    } catch (error) {
      console.error('[WarpDrive] Import error:', error);
      return 0;
    }
  }

  /**
   * Get statistics
   */
  function getStats(): DriveStats {
    const byType: Record<DriveItemType, number> = {
      workflow: 0,
      notebook: 0,
      snippet: 0,
      prompt: 0,
      env_vars: 0,
    };

    for (const item of items.value.values()) {
      byType[item.type]++;
    }

    return {
      totalItems: items.value.size,
      byType,
      sharedCount: allItems.value.filter(i => i.isShared).length,
      totalTags: getAllTags().length,
    };
  }

  return {
    // State
    allItems,
    workflows,
    notebooks,
    snippets,
    prompts,
    favoriteItems,
    recentItems,
    folders: computed(() => Array.from(folders.value.values())),

    // Item CRUD
    createItem,
    createWorkflow,
    createNotebook,
    createSnippet,
    createPrompt,
    updateItem,
    deleteItem,
    getItem,

    // Search
    searchItems,
    getByTag,
    getAllTags,

    // Organization
    toggleFavorite,
    addToRecent,
    createFolder,
    addToFolder,
    removeFromFolder,

    // Workflow execution
    getWorkflowCommands,

    // Sharing
    shareItem,
    importSharedItem,

    // Import/Export
    exportDrive,
    importDrive,
    getStats,
  };
}
