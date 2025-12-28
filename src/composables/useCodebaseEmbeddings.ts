/**
 * Codebase Embeddings System
 * Semantic search using local embeddings via Ollama's nomic-embed-text model.
 * Indexes code files and enables natural language queries.
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

export interface EmbeddingChunk {
  id: string;
  filePath: string;
  content: string;
  startLine: number;
  endLine: number;
  embedding: number[];
  metadata: {
    language?: string;
    type?: 'function' | 'class' | 'module' | 'comment' | 'other';
    name?: string;
  };
}

export interface IndexedFile {
  path: string;
  lastModified: number;
  chunkCount: number;
  indexed: boolean;
}

export interface SearchResult {
  chunk: EmbeddingChunk;
  score: number;
  preview: string;
}

export interface IndexStats {
  totalFiles: number;
  totalChunks: number;
  indexedAt: number;
  projectPath: string;
}

// State
const indexedChunks = ref<Map<string, EmbeddingChunk>>(new Map());
const indexedFiles = ref<Map<string, IndexedFile>>(new Map());
const isIndexing = ref(false);
const indexProgress = ref(0);
const lastIndexTime = ref<number | null>(null);
const embeddingModel = ref('nomic-embed-text');

// File patterns to include/exclude
const INCLUDE_PATTERNS = [
  '**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx',
  '**/*.vue', '**/*.svelte',
  '**/*.py', '**/*.rb', '**/*.go', '**/*.rs',
  '**/*.java', '**/*.kt', '**/*.scala',
  '**/*.c', '**/*.cpp', '**/*.h', '**/*.hpp',
  '**/*.cs', '**/*.fs',
  '**/*.php', '**/*.swift',
  '**/*.md', '**/*.txt',
  '**/*.json', '**/*.yaml', '**/*.yml', '**/*.toml',
  '**/*.sh', '**/*.bash', '**/*.zsh',
  '**/*.sql',
  '**/*.html', '**/*.css', '**/*.scss',
];

const EXCLUDE_PATTERNS = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/target/**',
  '**/__pycache__/**',
  '**/venv/**',
  '**/.venv/**',
  '**/vendor/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
];

const CHUNK_SIZE = 100; // lines per chunk
const CHUNK_OVERLAP = 20; // overlap between chunks

function generateChunkId(filePath: string, startLine: number): string {
  return `${filePath}:${startLine}`;
}

function detectLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() || '';
  const langMap: Record<string, string> = {
    ts: 'typescript', tsx: 'typescript',
    js: 'javascript', jsx: 'javascript',
    vue: 'vue', svelte: 'svelte',
    py: 'python', rb: 'ruby', go: 'go', rs: 'rust',
    java: 'java', kt: 'kotlin', scala: 'scala',
    c: 'c', cpp: 'cpp', h: 'c', hpp: 'cpp',
    cs: 'csharp', fs: 'fsharp',
    php: 'php', swift: 'swift',
    md: 'markdown', txt: 'text',
    json: 'json', yaml: 'yaml', yml: 'yaml', toml: 'toml',
    sh: 'shell', bash: 'shell', zsh: 'shell',
    sql: 'sql',
    html: 'html', css: 'css', scss: 'scss',
  };
  return langMap[ext] || 'unknown';
}

function splitIntoChunks(content: string, filePath: string): Omit<EmbeddingChunk, 'embedding'>[] {
  const lines = content.split('\n');
  const chunks: Omit<EmbeddingChunk, 'embedding'>[] = [];
  const language = detectLanguage(filePath);

  for (let i = 0; i < lines.length; i += CHUNK_SIZE - CHUNK_OVERLAP) {
    const startLine = i + 1;
    const endLine = Math.min(i + CHUNK_SIZE, lines.length);
    const chunkContent = lines.slice(i, endLine).join('\n');

    if (chunkContent.trim().length === 0) continue;

    chunks.push({
      id: generateChunkId(filePath, startLine),
      filePath,
      content: chunkContent,
      startLine,
      endLine,
      metadata: {
        language,
        type: detectChunkType(chunkContent, language),
      },
    });
  }

  return chunks;
}

function detectChunkType(content: string, language: string): EmbeddingChunk['metadata']['type'] {
  // Simple heuristics for chunk type detection
  if (language === 'python') {
    if (/^class\s+\w+/.test(content)) return 'class';
    if (/^def\s+\w+/.test(content)) return 'function';
  } else if (['typescript', 'javascript'].includes(language)) {
    if (/^(export\s+)?(class|interface)\s+\w+/.test(content)) return 'class';
    if (/^(export\s+)?(function|const|let|var)\s+\w+\s*[=:]?\s*(async\s+)?\(/.test(content)) return 'function';
  } else if (language === 'rust') {
    if (/^(pub\s+)?struct\s+\w+/.test(content)) return 'class';
    if (/^(pub\s+)?fn\s+\w+/.test(content)) return 'function';
    if (/^(pub\s+)?impl\s+/.test(content)) return 'class';
  } else if (language === 'go') {
    if (/^type\s+\w+\s+struct/.test(content)) return 'class';
    if (/^func\s+/.test(content)) return 'function';
  }

  if (/^\/\*\*|^\/\/|^#|^"""/.test(content.trim())) return 'comment';

  return 'other';
}

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0;

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
  return magnitude === 0 ? 0 : dotProduct / magnitude;
}

export function useCodebaseEmbeddings() {
  const stats = computed<IndexStats>(() => ({
    totalFiles: indexedFiles.value.size,
    totalChunks: indexedChunks.value.size,
    indexedAt: lastIndexTime.value || 0,
    projectPath: '',
  }));

  /**
   * Get embedding from Ollama
   */
  async function getEmbedding(text: string): Promise<number[]> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    try {
      const response = await invoke<{ embedding: number[] }>('get_embedding', {
        model: embeddingModel.value,
        text: text.slice(0, 8000), // Limit text length
      });
      return response.embedding;
    } catch (error) {
      console.error('[Embeddings] Failed to get embedding:', error);
      return [];
    }
  }

  /**
   * Index a single file
   */
  async function indexFile(filePath: string): Promise<number> {
    if (!invoke) return 0;

    try {
      const content = await invoke<string>('read_file', { path: filePath });
      const chunks = splitIntoChunks(content, filePath);

      let indexed = 0;
      for (const chunk of chunks) {
        const embedding = await getEmbedding(chunk.content);
        if (embedding.length > 0) {
          const fullChunk: EmbeddingChunk = { ...chunk, embedding };
          indexedChunks.value.set(chunk.id, fullChunk);
          indexed++;
        }
      }

      indexedFiles.value.set(filePath, {
        path: filePath,
        lastModified: Date.now(),
        chunkCount: indexed,
        indexed: true,
      });

      return indexed;
    } catch (error) {
      console.error(`[Embeddings] Failed to index ${filePath}:`, error);
      return 0;
    }
  }

  /**
   * Index the entire codebase
   */
  async function indexCodebase(projectPath: string): Promise<IndexStats> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    isIndexing.value = true;
    indexProgress.value = 0;

    try {
      // Get all files matching patterns
      const allFiles: string[] = [];

      for (const pattern of INCLUDE_PATTERNS) {
        try {
          const files = await invoke<Array<{ path: string }>>('glob_files', {
            pattern,
            path: projectPath,
          });
          allFiles.push(...files.map(f => f.path));
        } catch {
          // Pattern didn't match anything, continue
        }
      }

      // Filter out excluded patterns
      const filesToIndex = allFiles.filter(file => {
        return !EXCLUDE_PATTERNS.some(pattern => {
          const regex = new RegExp(
            pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*')
          );
          return regex.test(file);
        });
      });

      // Deduplicate
      const uniqueFiles = [...new Set(filesToIndex)];

      console.log(`[Embeddings] Indexing ${uniqueFiles.length} files...`);

      let totalChunks = 0;
      for (let i = 0; i < uniqueFiles.length; i++) {
        const file = uniqueFiles[i];
        const chunks = await indexFile(file);
        totalChunks += chunks;
        indexProgress.value = ((i + 1) / uniqueFiles.length) * 100;
      }

      lastIndexTime.value = Date.now();

      console.log(`[Embeddings] Indexed ${totalChunks} chunks from ${uniqueFiles.length} files`);

      return {
        totalFiles: uniqueFiles.length,
        totalChunks,
        indexedAt: lastIndexTime.value,
        projectPath,
      };
    } finally {
      isIndexing.value = false;
      indexProgress.value = 100;
    }
  }

  /**
   * Semantic search across indexed codebase
   */
  async function search(query: string, limit: number = 10): Promise<SearchResult[]> {
    if (indexedChunks.value.size === 0) {
      console.warn('[Embeddings] No indexed chunks. Run indexCodebase first.');
      return [];
    }

    const queryEmbedding = await getEmbedding(query);
    if (queryEmbedding.length === 0) {
      return [];
    }

    const results: SearchResult[] = [];

    for (const chunk of indexedChunks.value.values()) {
      const score = cosineSimilarity(queryEmbedding, chunk.embedding);
      if (score > 0.5) { // Similarity threshold
        results.push({
          chunk,
          score,
          preview: chunk.content.slice(0, 200) + (chunk.content.length > 200 ? '...' : ''),
        });
      }
    }

    // Sort by score descending
    results.sort((a, b) => b.score - a.score);

    return results.slice(0, limit);
  }

  /**
   * Find similar code to a given snippet
   */
  async function findSimilar(code: string, limit: number = 5): Promise<SearchResult[]> {
    return search(code, limit);
  }

  /**
   * Get context for AI from semantic search
   */
  async function getRelevantContext(query: string, maxTokens: number = 4000): Promise<string> {
    const results = await search(query, 20);

    let context = '';
    let estimatedTokens = 0;

    for (const result of results) {
      const chunkText = `\n--- ${result.chunk.filePath}:${result.chunk.startLine}-${result.chunk.endLine} (${(result.score * 100).toFixed(1)}% match) ---\n${result.chunk.content}\n`;
      const chunkTokens = Math.ceil(chunkText.length / 4); // Rough token estimate

      if (estimatedTokens + chunkTokens > maxTokens) break;

      context += chunkText;
      estimatedTokens += chunkTokens;
    }

    return context;
  }

  /**
   * Clear the index
   */
  function clearIndex(): void {
    indexedChunks.value.clear();
    indexedFiles.value.clear();
    lastIndexTime.value = null;
  }

  /**
   * Remove a file from the index
   */
  function removeFile(filePath: string): void {
    // Remove all chunks for this file
    for (const [id, chunk] of indexedChunks.value) {
      if (chunk.filePath === filePath) {
        indexedChunks.value.delete(id);
      }
    }
    indexedFiles.value.delete(filePath);
  }

  /**
   * Update a single file in the index
   */
  async function updateFile(filePath: string): Promise<void> {
    removeFile(filePath);
    await indexFile(filePath);
  }

  /**
   * Check if indexing is needed
   */
  function needsReindex(): boolean {
    if (!lastIndexTime.value) return true;
    // Re-index if older than 1 hour
    return Date.now() - lastIndexTime.value > 3600000;
  }

  /**
   * Get files that match a query without full semantic search
   */
  async function quickFileSearch(query: string): Promise<string[]> {
    const results = await search(query, 20);
    const files = new Set<string>();

    for (const result of results) {
      files.add(result.chunk.filePath);
    }

    return Array.from(files);
  }

  /**
   * Set the embedding model
   */
  function setModel(model: string): void {
    embeddingModel.value = model;
  }

  /**
   * Export index for persistence
   */
  function exportIndex(): string {
    const data = {
      chunks: Array.from(indexedChunks.value.entries()),
      files: Array.from(indexedFiles.value.entries()),
      lastIndexTime: lastIndexTime.value,
    };
    return JSON.stringify(data);
  }

  /**
   * Import index from persistence
   */
  function importIndex(json: string): boolean {
    try {
      const data = JSON.parse(json);
      indexedChunks.value = new Map(data.chunks);
      indexedFiles.value = new Map(data.files);
      lastIndexTime.value = data.lastIndexTime;
      return true;
    } catch (error) {
      console.error('[Embeddings] Failed to import index:', error);
      return false;
    }
  }

  return {
    // State
    isIndexing: computed(() => isIndexing.value),
    indexProgress: computed(() => indexProgress.value),
    stats,
    indexedFiles: computed(() => Array.from(indexedFiles.value.values())),
    model: computed(() => embeddingModel.value),

    // Core methods
    indexCodebase,
    indexFile,
    search,
    findSimilar,
    getRelevantContext,

    // Management
    clearIndex,
    removeFile,
    updateFile,
    needsReindex,
    quickFileSearch,
    setModel,

    // Persistence
    exportIndex,
    importIndex,
  };
}
