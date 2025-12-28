/**
 * AI Memory System
 * Persist conversation context and learned preferences across sessions
 */

import { ref, computed, watch } from 'vue';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

export interface MemoryEntry {
  id: string;
  type: 'fact' | 'preference' | 'context' | 'decision' | 'pattern';
  content: string;
  source: string; // conversation ID or 'user'
  timestamp: Date;
  importance: number; // 0-10
  tags: string[];
  expiresAt?: Date;
}

export interface ConversationSummary {
  id: string;
  title: string;
  summary: string;
  keyPoints: string[];
  timestamp: Date;
  projectPath?: string;
}

export interface AIMemoryState {
  entries: MemoryEntry[];
  summaries: ConversationSummary[];
  preferences: Record<string, string>;
  projectContexts: Record<string, string[]>; // project path -> memory IDs
}

const STORAGE_KEY = 'warp_open_ai_memory';
const MAX_ENTRIES = 500;
const MAX_SUMMARIES = 50;

const memoryState = ref<AIMemoryState>({
  entries: [],
  summaries: [],
  preferences: {},
  projectContexts: {},
});

export function useAIMemory() {
  /**
   * Load memory from storage
   */
  function loadMemory() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const data = JSON.parse(stored);
        memoryState.value = {
          ...data,
          entries: data.entries.map((e: MemoryEntry) => ({
            ...e,
            timestamp: new Date(e.timestamp),
            expiresAt: e.expiresAt ? new Date(e.expiresAt) : undefined,
          })),
          summaries: data.summaries.map((s: ConversationSummary) => ({
            ...s,
            timestamp: new Date(s.timestamp),
          })),
        };

        // Prune expired entries
        pruneExpired();
      }
    } catch (e) {
      console.error('[AIMemory] Error loading memory:', e);
    }
  }

  /**
   * Save memory to storage
   */
  function saveMemory() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(memoryState.value));
    } catch (e) {
      console.error('[AIMemory] Error saving memory:', e);
    }
  }

  /**
   * Remove expired entries
   */
  function pruneExpired() {
    const now = new Date();
    memoryState.value.entries = memoryState.value.entries.filter(
      e => !e.expiresAt || e.expiresAt > now
    );
  }

  /**
   * Add a memory entry
   */
  function remember(entry: Omit<MemoryEntry, 'id' | 'timestamp'>): MemoryEntry {
    const newEntry: MemoryEntry = {
      ...entry,
      id: generateId(),
      timestamp: new Date(),
    };

    memoryState.value.entries.push(newEntry);

    // Trim if too many entries (keep important ones)
    if (memoryState.value.entries.length > MAX_ENTRIES) {
      // Sort by importance and recency
      memoryState.value.entries.sort((a, b) => {
        const importanceWeight = (b.importance - a.importance) * 2;
        const recencyWeight =
          (b.timestamp.getTime() - a.timestamp.getTime()) / (1000 * 60 * 60 * 24); // days
        return importanceWeight - recencyWeight;
      });
      memoryState.value.entries = memoryState.value.entries.slice(0, MAX_ENTRIES);
    }

    saveMemory();
    return newEntry;
  }

  /**
   * Store a user preference
   */
  function setPreference(key: string, value: string) {
    memoryState.value.preferences[key] = value;
    saveMemory();
  }

  /**
   * Get a user preference
   */
  function getPreference(key: string): string | undefined {
    return memoryState.value.preferences[key];
  }

  /**
   * Summarize and store a conversation
   */
  async function summarizeConversation(
    conversationId: string,
    messages: Array<{ role: string; content: string }>,
    projectPath?: string,
    model: string = 'qwen2.5-coder:1.5b'
  ): Promise<ConversationSummary | null> {
    if (messages.length < 3) return null;

    // Build conversation text
    const conversationText = messages
      .slice(-20) // Last 20 messages
      .map(m => `${m.role}: ${m.content.substring(0, 500)}`)
      .join('\n\n');

    const prompt = `Summarize this conversation for future reference.
Extract:
1. A short title (5-10 words)
2. A brief summary (1-2 sentences)
3. Key points/decisions made (list of 3-5 items)

Conversation:
${conversationText}

Respond with ONLY valid JSON:
{"title":"...","summary":"...","keyPoints":["point 1","point 2"]}`;

    try {
      let response: string;

      if (isTauri && invoke) {
        response = await invoke<string>('query_ollama', { prompt, model });
      } else {
        const res = await fetch('http://localhost:11434/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, prompt, stream: false }),
        });
        const data = await res.json();
        response = data.response;
      }

      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);

        const summary: ConversationSummary = {
          id: conversationId,
          title: parsed.title,
          summary: parsed.summary,
          keyPoints: parsed.keyPoints || [],
          timestamp: new Date(),
          projectPath,
        };

        // Add to summaries
        memoryState.value.summaries.push(summary);

        // Trim if too many
        if (memoryState.value.summaries.length > MAX_SUMMARIES) {
          memoryState.value.summaries = memoryState.value.summaries.slice(-MAX_SUMMARIES);
        }

        saveMemory();
        return summary;
      }

      return null;
    } catch (e) {
      console.error('[AIMemory] Error summarizing conversation:', e);
      return null;
    }
  }

  /**
   * Extract facts from a conversation to remember
   */
  async function extractFacts(
    messages: Array<{ role: string; content: string }>,
    source: string,
    model: string = 'qwen2.5-coder:1.5b'
  ): Promise<MemoryEntry[]> {
    const conversationText = messages
      .slice(-10)
      .map(m => `${m.role}: ${m.content.substring(0, 300)}`)
      .join('\n\n');

    const prompt = `Extract important facts, decisions, or preferences from this conversation that should be remembered for future sessions.

Conversation:
${conversationText}

Respond with a JSON array of facts to remember:
[{"content":"...", "type":"fact|preference|decision", "importance":1-10, "tags":["tag1"]}]

Only include genuinely useful information. If nothing important, return empty array: []`;

    try {
      let response: string;

      if (isTauri && invoke) {
        response = await invoke<string>('query_ollama', { prompt, model });
      } else {
        const res = await fetch('http://localhost:11434/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, prompt, stream: false }),
        });
        const data = await res.json();
        response = data.response;
      }

      const jsonMatch = response.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        const facts = JSON.parse(jsonMatch[0]);
        const entries: MemoryEntry[] = [];

        for (const fact of facts) {
          if (fact.content && fact.importance >= 5) {
            entries.push(
              remember({
                type: fact.type || 'fact',
                content: fact.content,
                source,
                importance: fact.importance,
                tags: fact.tags || [],
              })
            );
          }
        }

        return entries;
      }

      return [];
    } catch (e) {
      console.error('[AIMemory] Error extracting facts:', e);
      return [];
    }
  }

  /**
   * Get relevant memories for a query
   */
  function recall(query: string, limit: number = 10): MemoryEntry[] {
    const queryLower = query.toLowerCase();
    const queryWords = queryLower.split(/\s+/);

    // Score each entry by relevance
    const scored = memoryState.value.entries.map(entry => {
      let score = 0;

      // Check content match
      const contentLower = entry.content.toLowerCase();
      for (const word of queryWords) {
        if (contentLower.includes(word)) {
          score += 2;
        }
      }

      // Check tag match
      for (const tag of entry.tags) {
        if (queryWords.includes(tag.toLowerCase())) {
          score += 3;
        }
      }

      // Weight by importance
      score *= (entry.importance / 10);

      // Recency bonus (last 24 hours)
      const hoursSince = (Date.now() - entry.timestamp.getTime()) / (1000 * 60 * 60);
      if (hoursSince < 24) {
        score *= 1.5;
      }

      return { entry, score };
    });

    // Sort by score and return top entries
    return scored
      .filter(s => s.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map(s => s.entry);
  }

  /**
   * Get memories for a specific project
   */
  function getProjectMemories(projectPath: string): MemoryEntry[] {
    const memoryIds = memoryState.value.projectContexts[projectPath] || [];
    return memoryState.value.entries.filter(e =>
      memoryIds.includes(e.id) || e.source.includes(projectPath)
    );
  }

  /**
   * Associate a memory with a project
   */
  function associateWithProject(memoryId: string, projectPath: string) {
    if (!memoryState.value.projectContexts[projectPath]) {
      memoryState.value.projectContexts[projectPath] = [];
    }
    if (!memoryState.value.projectContexts[projectPath].includes(memoryId)) {
      memoryState.value.projectContexts[projectPath].push(memoryId);
      saveMemory();
    }
  }

  /**
   * Format memories for AI context
   */
  function formatForContext(memories: MemoryEntry[]): string {
    if (memories.length === 0) return '';

    let context = '[Remembered Context]\n';
    for (const memory of memories) {
      context += `- ${memory.content} (${memory.type})\n`;
    }
    context += '[End Remembered Context]\n';

    return context;
  }

  /**
   * Clear all memory
   */
  function clearMemory() {
    memoryState.value = {
      entries: [],
      summaries: [],
      preferences: {},
      projectContexts: {},
    };
    localStorage.removeItem(STORAGE_KEY);
  }

  /**
   * Generate unique ID
   */
  function generateId(): string {
    return `mem-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Initialize
  loadMemory();

  return {
    entries: computed(() => memoryState.value.entries),
    summaries: computed(() => memoryState.value.summaries),
    preferences: computed(() => memoryState.value.preferences),
    remember,
    setPreference,
    getPreference,
    summarizeConversation,
    extractFacts,
    recall,
    getProjectMemories,
    associateWithProject,
    formatForContext,
    clearMemory,
  };
}
