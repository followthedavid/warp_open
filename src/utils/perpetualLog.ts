/**
 * Perpetual Logging System for Claude Max
 * Maintains persistent memory of all AI operations, decisions, and learnings
 */

// Check if we're in Tauri environment
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

// Conditional imports - only use in Tauri/Node environment
let fs: any = null;
let path: any = null;

if (!isTauri && typeof process !== 'undefined') {
  // Node.js environment (for testing)
  fs = require('fs');
  path = require('path');
}

export type LogEntryType = 'goal' | 'plan' | 'step' | 'reflection' | 'improvement' | 'error' | 'success';
export type LogStatus = 'pending' | 'approved' | 'executed' | 'failed' | 'completed';

export interface PerpetualLogEntry {
  id: string;
  timestamp: string;
  type: LogEntryType;
  content: string;
  status: LogStatus;
  planId?: string;
  stepId?: string;
  goalId?: string;
  metadata?: Record<string, any>;
  embedding?: number[]; // For semantic search
}

const LOG_FILE = 'data/claude_perpetual_log.json';
const MAX_LOG_ENTRIES = 10000; // Keep last 10k entries, compress older ones

/**
 * Check if file operations are available
 */
function canUseFileSystem(): boolean {
  return fs !== null && path !== null;
}

/**
 * Ensure log file exists
 */
function ensureLogFile(): void {
  if (!canUseFileSystem()) {
    console.warn('[PerpetualLog] File system not available in browser mode');
    return;
  }

  const logPath = path.resolve(LOG_FILE);
  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(logPath)) {
    fs.writeFileSync(logPath, JSON.stringify([], null, 2));
  }
}

/**
 * Append a new entry to the perpetual log
 */
export function appendPerpetualLog(entry: Omit<PerpetualLogEntry, 'id' | 'timestamp'>): void {
  if (!canUseFileSystem()) {
    console.log(`[PerpetualLog] (Browser mode) ${entry.type}: ${entry.content.substring(0, 50)}...`);
    return;
  }

  ensureLogFile();

  const logPath = path.resolve(LOG_FILE);
  const logs: PerpetualLogEntry[] = JSON.parse(fs.readFileSync(logPath, 'utf-8'));

  const newEntry: PerpetualLogEntry = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    ...entry,
  };

  logs.push(newEntry);

  // Compress if too large
  const finalLogs = logs.length > MAX_LOG_ENTRIES
    ? compressOldLogs(logs)
    : logs;

  fs.writeFileSync(logPath, JSON.stringify(finalLogs, null, 2));

  console.log(`[PerpetualLog] Appended: ${entry.type} - ${entry.content.substring(0, 50)}...`);
}

/**
 * Get all logs (optionally filtered)
 */
export function getAllPerpetualLogs(filter?: {
  type?: LogEntryType;
  status?: LogStatus;
  planId?: string;
  goalId?: string;
  since?: Date;
}): PerpetualLogEntry[] {
  if (!canUseFileSystem()) {
    return [];
  }

  ensureLogFile();
  const logPath = path.resolve(LOG_FILE);
  let logs: PerpetualLogEntry[] = JSON.parse(fs.readFileSync(logPath, 'utf-8'));

  if (filter) {
    if (filter.type) {
      logs = logs.filter(l => l.type === filter.type);
    }
    if (filter.status) {
      logs = logs.filter(l => l.status === filter.status);
    }
    if (filter.planId) {
      logs = logs.filter(l => l.planId === filter.planId);
    }
    if (filter.goalId) {
      logs = logs.filter(l => l.goalId === filter.goalId);
    }
    if (filter.since) {
      logs = logs.filter(l => new Date(l.timestamp) >= filter.since);
    }
  }

  return logs;
}

/**
 * Get relevant context for Claude Max reasoning
 * Uses semantic similarity if embeddings are available, otherwise keyword matching
 */
export async function getRelevantContext(
  query: string,
  maxEntries: number = 50,
  filterTypes?: LogEntryType[]
): Promise<string> {
  if (!canUseFileSystem()) {
    return '';
  }

  ensureLogFile();
  const logPath = path.resolve(LOG_FILE);
  let logs: PerpetualLogEntry[] = JSON.parse(fs.readFileSync(logPath, 'utf-8'));

  // Filter by type if specified
  if (filterTypes && filterTypes.length > 0) {
    logs = logs.filter(l => filterTypes.includes(l.type));
  }

  // Score logs by relevance
  const queryLower = query.toLowerCase();
  const scored = logs.map(log => {
    const contentLower = log.content.toLowerCase();

    // Simple keyword-based scoring
    const queryWords = queryLower.split(/\s+/);
    const matchCount = queryWords.filter(word =>
      word.length > 3 && contentLower.includes(word)
    ).length;

    // Boost recent entries
    const recencyBoost = 1 + (new Date(log.timestamp).getTime() / Date.now()) * 0.5;

    // Boost successes over failures
    const statusBoost = log.status === 'completed' ? 1.2 :
                       log.status === 'failed' ? 0.8 : 1.0;

    const score = matchCount * recencyBoost * statusBoost;

    return { log, score };
  });

  // Sort by score and take top N
  const relevant = scored
    .filter(s => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, maxEntries)
    .map(s => s.log);

  // Format as context string
  return relevant.map(log =>
    `[${log.timestamp}] ${log.type.toUpperCase()}: ${log.content}\nStatus: ${log.status}`
  ).join('\n\n---\n\n');
}

/**
 * Get statistics about the perpetual log
 */
export function getLogStatistics(): {
  totalEntries: number;
  byType: Record<LogEntryType, number>;
  byStatus: Record<LogStatus, number>;
  successRate: number;
  oldestEntry?: string;
  newestEntry?: string;
} {
  if (!canUseFileSystem()) {
    return {
      totalEntries: 0,
      byType: {} as any,
      byStatus: {} as any,
      successRate: 0
    };
  }

  ensureLogFile();
  const logPath = path.resolve(LOG_FILE);
  const logs: PerpetualLogEntry[] = JSON.parse(fs.readFileSync(logPath, 'utf-8'));

  const byType: any = {};
  const byStatus: any = {};

  logs.forEach(log => {
    byType[log.type] = (byType[log.type] || 0) + 1;
    byStatus[log.status] = (byStatus[log.status] || 0) + 1;
  });

  const completed = byStatus['completed'] || 0;
  const failed = byStatus['failed'] || 0;
  const successRate = (completed + failed) > 0
    ? Math.round((completed / (completed + failed)) * 100)
    : 0;

  return {
    totalEntries: logs.length,
    byType,
    byStatus,
    successRate,
    oldestEntry: logs[0]?.timestamp,
    newestEntry: logs[logs.length - 1]?.timestamp,
  };
}

/**
 * Export logs to readable markdown format
 */
export function exportLogsToMarkdown(outputPath?: string): string {
  ensureLogFile();
  const logs: PerpetualLogEntry[] = JSON.parse(fs.readFileSync(LOG_FILE, 'utf-8'));
  const stats = getLogStatistics();

  let markdown = `# Claude Max Perpetual Log\n\n`;
  markdown += `Generated: ${new Date().toISOString()}\n\n`;
  markdown += `## Statistics\n\n`;
  markdown += `- Total Entries: ${stats.totalEntries}\n`;
  markdown += `- Success Rate: ${stats.successRate}%\n`;
  markdown += `- Date Range: ${stats.oldestEntry} to ${stats.newestEntry}\n\n`;

  markdown += `### By Type\n\n`;
  Object.entries(stats.byType).forEach(([type, count]) => {
    markdown += `- ${type}: ${count}\n`;
  });

  markdown += `\n### By Status\n\n`;
  Object.entries(stats.byStatus).forEach(([status, count]) => {
    markdown += `- ${status}: ${count}\n`;
  });

  markdown += `\n## Entries\n\n`;

  logs.forEach(log => {
    markdown += `### [${log.timestamp}] ${log.type}\n\n`;
    markdown += `**Status:** ${log.status}\n\n`;
    if (log.planId) markdown += `**Plan ID:** ${log.planId}\n\n`;
    if (log.goalId) markdown += `**Goal ID:** ${log.goalId}\n\n`;
    markdown += `${log.content}\n\n`;
    markdown += `---\n\n`;
  });

  if (outputPath) {
    fs.writeFileSync(outputPath, markdown);
    console.log(`[PerpetualLog] Exported to ${outputPath}`);
  }

  return markdown;
}

/**
 * Clear old logs (keep last N entries)
 */
export function compressOldLogs(logs: PerpetualLogEntry[]): PerpetualLogEntry[] {
  if (logs.length <= MAX_LOG_ENTRIES) return logs;

  // Keep last MAX_LOG_ENTRIES
  const recentLogs = logs.slice(-MAX_LOG_ENTRIES);

  // Archive older logs
  const archivePath = path.resolve(`data/archive/claude_log_${Date.now()}.json`);
  const archiveDir = path.dirname(archivePath);

  if (!fs.existsSync(archiveDir)) {
    fs.mkdirSync(archiveDir, { recursive: true });
  }

  const archivedLogs = logs.slice(0, -MAX_LOG_ENTRIES);
  fs.writeFileSync(archivePath, JSON.stringify(archivedLogs, null, 2));

  console.log(`[PerpetualLog] Archived ${archivedLogs.length} old entries to ${archivePath}`);

  return recentLogs;
}

/**
 * Search logs by keyword
 */
export function searchLogs(keyword: string, limit: number = 100): PerpetualLogEntry[] {
  ensureLogFile();
  const logs: PerpetualLogEntry[] = JSON.parse(fs.readFileSync(LOG_FILE, 'utf-8'));

  const keywordLower = keyword.toLowerCase();

  return logs
    .filter(log =>
      log.content.toLowerCase().includes(keywordLower) ||
      log.type.toLowerCase().includes(keywordLower)
    )
    .slice(-limit);
}

/**
 * Get recent activity summary
 */
export function getRecentActivity(hours: number = 24): {
  entries: PerpetualLogEntry[];
  summary: string;
} {
  ensureLogFile();
  const logs: PerpetualLogEntry[] = JSON.parse(fs.readFileSync(LOG_FILE, 'utf-8'));

  const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);
  const recentEntries = logs.filter(log => new Date(log.timestamp) >= cutoff);

  const byType: any = {};
  recentEntries.forEach(log => {
    byType[log.type] = (byType[log.type] || 0) + 1;
  });

  let summary = `Last ${hours} hours:\n`;
  summary += `- Total actions: ${recentEntries.length}\n`;
  Object.entries(byType).forEach(([type, count]) => {
    summary += `- ${type}: ${count}\n`;
  });

  return {
    entries: recentEntries,
    summary,
  };
}

// Helper functions
function generateId(): string {
  return `log-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}
