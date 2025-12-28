/**
 * Block Sharing System
 * Create and share permalinks for terminal input/output blocks.
 * Similar to Warp Terminal's block sharing feature.
 */

import { ref, computed } from 'vue';

export interface SharedBlock {
  id: string;
  command: string;
  output: string;
  exitCode?: number;
  directory: string;
  timestamp: number;
  duration?: number;
  environment?: {
    shell: string;
    os: string;
    gitBranch?: string;
  };
  annotations?: string;
  shareUrl: string;
  expiresAt?: number;
  views: number;
  isPublic: boolean;
}

export interface BlockSelection {
  startLine: number;
  endLine: number;
  content: string;
}

export interface ShareOptions {
  includeOutput: boolean;
  includeEnvironment: boolean;
  expirationDays?: number;
  isPublic: boolean;
  annotations?: string;
  redactSecrets?: boolean;
}

const STORAGE_KEY = 'warp_open_shared_blocks';
const MAX_STORED_BLOCKS = 100;

// Secret patterns for redaction
const SECRET_PATTERNS = [
  /(?:api[_-]?key|apikey)[=:]\s*['"]?[\w-]{20,}['"]?/gi,
  /(?:password|passwd|pwd)[=:]\s*['"]?[^\s'"]{8,}['"]?/gi,
  /(?:token|bearer)[=:]\s*['"]?[\w-]{20,}['"]?/gi,
  /sk-[a-zA-Z0-9]{48,}/g,
  /ghp_[a-zA-Z0-9]{36,}/g,
  /-----BEGIN [A-Z]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z]+ PRIVATE KEY-----/g,
];

// State
const sharedBlocks = ref<Map<string, SharedBlock>>(new Map());
const pendingShare = ref<SharedBlock | null>(null);

// Load from storage
function loadBlocks(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const blocks = JSON.parse(stored);
      sharedBlocks.value = new Map(Object.entries(blocks));
    }
  } catch (e) {
    console.error('[BlockSharing] Error loading:', e);
  }
}

// Save to storage
function saveBlocks(): void {
  try {
    // Prune expired and excess blocks
    const now = Date.now();
    const blocks = Array.from(sharedBlocks.value.entries())
      .filter(([_, block]) => !block.expiresAt || block.expiresAt > now)
      .slice(-MAX_STORED_BLOCKS);

    localStorage.setItem(STORAGE_KEY, JSON.stringify(Object.fromEntries(blocks)));
  } catch (e) {
    console.error('[BlockSharing] Error saving:', e);
  }
}

// Initialize
loadBlocks();

function generateBlockId(): string {
  return `blk_${Date.now()}_${Math.random().toString(36).substr(2, 8)}`;
}

function generateShareUrl(blockId: string): string {
  // In a real implementation, this would be an actual URL
  // For local-first, we use a data URL scheme
  const block = sharedBlocks.value.get(blockId);
  if (!block) return '';

  const data = btoa(JSON.stringify({
    id: block.id,
    command: block.command,
    output: block.output,
    directory: block.directory,
    timestamp: block.timestamp,
  }));

  return `warp-block://${data.slice(0, 30)}...`;
}

export function useBlockSharing() {
  const allBlocks = computed(() =>
    Array.from(sharedBlocks.value.values())
      .sort((a, b) => b.timestamp - a.timestamp)
  );

  const publicBlocks = computed(() =>
    allBlocks.value.filter(b => b.isPublic)
  );

  /**
   * Redact secrets from content
   */
  function redactSecrets(content: string): string {
    let result = content;
    for (const pattern of SECRET_PATTERNS) {
      result = result.replace(pattern, '[REDACTED]');
    }
    return result;
  }

  /**
   * Share a command block
   */
  function shareBlock(
    command: string,
    output: string,
    options: ShareOptions & {
      exitCode?: number;
      directory?: string;
      duration?: number;
      gitBranch?: string;
    }
  ): SharedBlock {
    let processedCommand = command;
    let processedOutput = output;

    // Redact secrets if requested
    if (options.redactSecrets) {
      processedCommand = redactSecrets(command);
      processedOutput = redactSecrets(output);
    }

    const blockId = generateBlockId();

    const block: SharedBlock = {
      id: blockId,
      command: processedCommand,
      output: options.includeOutput ? processedOutput : '',
      exitCode: options.exitCode,
      directory: options.directory || process.cwd?.() || '~',
      timestamp: Date.now(),
      duration: options.duration,
      environment: options.includeEnvironment ? {
        shell: 'zsh', // Would be detected
        os: navigator.platform || 'unknown',
        gitBranch: options.gitBranch,
      } : undefined,
      annotations: options.annotations,
      shareUrl: '',
      expiresAt: options.expirationDays
        ? Date.now() + options.expirationDays * 24 * 60 * 60 * 1000
        : undefined,
      views: 0,
      isPublic: options.isPublic,
    };

    sharedBlocks.value.set(blockId, block);
    block.shareUrl = generateShareUrl(blockId);
    saveBlocks();

    console.log(`[BlockSharing] Created share: ${block.shareUrl}`);
    return block;
  }

  /**
   * Share multiple blocks as a session
   */
  function shareSession(
    blocks: Array<{ command: string; output: string; exitCode?: number }>,
    options: ShareOptions
  ): SharedBlock[] {
    return blocks.map((block, index) =>
      shareBlock(block.command, block.output, {
        ...options,
        exitCode: block.exitCode,
        annotations: options.annotations
          ? `${options.annotations} (${index + 1}/${blocks.length})`
          : undefined,
      })
    );
  }

  /**
   * Get block by ID
   */
  function getBlock(blockId: string): SharedBlock | undefined {
    const block = sharedBlocks.value.get(blockId);
    if (block) {
      // Increment view count
      block.views++;
      saveBlocks();
    }
    return block;
  }

  /**
   * Import a shared block from URL/data
   */
  function importBlock(shareData: string): SharedBlock | null {
    try {
      // Handle our data URL format
      if (shareData.startsWith('warp-block://')) {
        // Would decode actual data in real implementation
        console.log('[BlockSharing] Import not fully implemented for local-first');
        return null;
      }

      // Handle raw JSON
      const data = JSON.parse(atob(shareData));
      const block: SharedBlock = {
        ...data,
        id: generateBlockId(),
        timestamp: Date.now(),
        views: 0,
        isPublic: false,
      };

      sharedBlocks.value.set(block.id, block);
      saveBlocks();

      return block;
    } catch (error) {
      console.error('[BlockSharing] Import error:', error);
      return null;
    }
  }

  /**
   * Delete a shared block
   */
  function deleteBlock(blockId: string): boolean {
    const deleted = sharedBlocks.value.delete(blockId);
    if (deleted) {
      saveBlocks();
    }
    return deleted;
  }

  /**
   * Update block annotations
   */
  function annotateBlock(blockId: string, annotations: string): void {
    const block = sharedBlocks.value.get(blockId);
    if (block) {
      block.annotations = annotations;
      saveBlocks();
    }
  }

  /**
   * Toggle block public status
   */
  function togglePublic(blockId: string): boolean {
    const block = sharedBlocks.value.get(blockId);
    if (block) {
      block.isPublic = !block.isPublic;
      saveBlocks();
      return block.isPublic;
    }
    return false;
  }

  /**
   * Copy block to clipboard
   */
  async function copyBlockToClipboard(blockId: string): Promise<boolean> {
    const block = sharedBlocks.value.get(blockId);
    if (!block) return false;

    try {
      const text = `$ ${block.command}\n${block.output}`;
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      console.error('[BlockSharing] Copy failed:', error);
      return false;
    }
  }

  /**
   * Copy share URL to clipboard
   */
  async function copyShareUrl(blockId: string): Promise<boolean> {
    const block = sharedBlocks.value.get(blockId);
    if (!block) return false;

    try {
      await navigator.clipboard.writeText(block.shareUrl);
      return true;
    } catch (error) {
      console.error('[BlockSharing] Copy URL failed:', error);
      return false;
    }
  }

  /**
   * Generate markdown for block
   */
  function toMarkdown(blockId: string): string {
    const block = sharedBlocks.value.get(blockId);
    if (!block) return '';

    let md = `\`\`\`bash\n$ ${block.command}\n`;
    if (block.output) {
      md += block.output + '\n';
    }
    md += '```\n';

    if (block.annotations) {
      md += `\n> ${block.annotations}\n`;
    }

    if (block.environment) {
      md += `\n*Executed on ${block.environment.os}`;
      if (block.environment.gitBranch) {
        md += ` (branch: ${block.environment.gitBranch})`;
      }
      md += '*\n';
    }

    return md;
  }

  /**
   * Search shared blocks
   */
  function searchBlocks(query: string): SharedBlock[] {
    const lowerQuery = query.toLowerCase();
    return allBlocks.value.filter(block =>
      block.command.toLowerCase().includes(lowerQuery) ||
      block.output.toLowerCase().includes(lowerQuery) ||
      block.annotations?.toLowerCase().includes(lowerQuery)
    );
  }

  /**
   * Get blocks by directory
   */
  function getBlocksByDirectory(directory: string): SharedBlock[] {
    return allBlocks.value.filter(block =>
      block.directory === directory ||
      block.directory.startsWith(directory + '/')
    );
  }

  /**
   * Export all blocks
   */
  function exportBlocks(): string {
    return JSON.stringify(Array.from(sharedBlocks.value.values()), null, 2);
  }

  /**
   * Clear expired blocks
   */
  function clearExpired(): number {
    const now = Date.now();
    let count = 0;

    for (const [id, block] of sharedBlocks.value) {
      if (block.expiresAt && block.expiresAt < now) {
        sharedBlocks.value.delete(id);
        count++;
      }
    }

    if (count > 0) {
      saveBlocks();
    }

    return count;
  }

  /**
   * Get statistics
   */
  function getStats() {
    const blocks = allBlocks.value;
    return {
      totalBlocks: blocks.length,
      publicBlocks: blocks.filter(b => b.isPublic).length,
      totalViews: blocks.reduce((sum, b) => sum + b.views, 0),
      expiringToday: blocks.filter(b =>
        b.expiresAt && b.expiresAt < Date.now() + 24 * 60 * 60 * 1000
      ).length,
    };
  }

  return {
    // State
    allBlocks,
    publicBlocks,
    pendingShare: computed(() => pendingShare.value),

    // Sharing
    shareBlock,
    shareSession,
    getBlock,
    importBlock,
    deleteBlock,

    // Editing
    annotateBlock,
    togglePublic,

    // Clipboard
    copyBlockToClipboard,
    copyShareUrl,

    // Export
    toMarkdown,
    exportBlocks,

    // Search
    searchBlocks,
    getBlocksByDirectory,

    // Utilities
    redactSecrets,
    clearExpired,
    getStats,
  };
}
