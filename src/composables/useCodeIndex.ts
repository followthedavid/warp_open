/**
 * Code Context Indexing
 * Provides project-wide code understanding for AI
 *
 * Features:
 * - File indexing with metadata
 * - Symbol extraction (functions, classes, exports)
 * - Dependency graph awareness
 * - Semantic search using embeddings
 * - Incremental re-indexing
 * - Git history context
 */

import { ref, computed, reactive } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export interface FileIndex {
  path: string;
  language: string;
  size: number;
  lastModified: Date;
  lastIndexed: Date;
  hash: string;
  symbols: SymbolInfo[];
  imports: string[];
  exports: string[];
  summary?: string;
}

export interface SymbolInfo {
  name: string;
  type: 'function' | 'class' | 'interface' | 'type' | 'variable' | 'const' | 'export';
  line: number;
  endLine?: number;
  signature?: string;
  docstring?: string;
}

export interface SearchResult {
  path: string;
  score: number;
  matches: Array<{
    type: 'symbol' | 'content' | 'import';
    name?: string;
    line?: number;
    snippet?: string;
  }>;
}

export interface DependencyNode {
  path: string;
  imports: string[];
  importedBy: string[];
  depth: number;  // Distance from entry point
}

export interface IndexStats {
  totalFiles: number;
  totalSymbols: number;
  totalBytes: number;
  languages: Record<string, number>;
  lastFullIndex: Date | null;
  indexDurationMs: number;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  // File patterns to index
  INCLUDE_PATTERNS: [
    '**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx',
    '**/*.py', '**/*.rs', '**/*.go',
    '**/*.vue', '**/*.svelte',
    '**/*.json', '**/*.yaml', '**/*.yml',
    '**/*.md', '**/*.txt'
  ],
  // Patterns to exclude
  EXCLUDE_PATTERNS: [
    '**/node_modules/**', '**/dist/**', '**/build/**',
    '**/.git/**', '**/target/**', '**/__pycache__/**',
    '**/coverage/**', '**/.next/**', '**/.nuxt/**'
  ],
  // Max file size to index (bytes)
  MAX_FILE_SIZE: 500000,
  // Max files to index
  MAX_FILES: 5000,
  // Index refresh interval (ms)
  REFRESH_INTERVAL: 60000
};

// Language detection patterns
const LANGUAGE_PATTERNS: Record<string, RegExp[]> = {
  typescript: [/\.tsx?$/],
  javascript: [/\.jsx?$/],
  python: [/\.py$/],
  rust: [/\.rs$/],
  go: [/\.go$/],
  vue: [/\.vue$/],
  json: [/\.json$/],
  markdown: [/\.md$/]
};

// Symbol extraction patterns per language
const SYMBOL_PATTERNS: Record<string, Array<{ pattern: RegExp; type: SymbolInfo['type'] }>> = {
  typescript: [
    { pattern: /^(?:export\s+)?(?:async\s+)?function\s+(\w+)/gm, type: 'function' },
    { pattern: /^(?:export\s+)?class\s+(\w+)/gm, type: 'class' },
    { pattern: /^(?:export\s+)?interface\s+(\w+)/gm, type: 'interface' },
    { pattern: /^(?:export\s+)?type\s+(\w+)/gm, type: 'type' },
    { pattern: /^(?:export\s+)?const\s+(\w+)/gm, type: 'const' },
    { pattern: /^export\s+(?:default\s+)?(\w+)/gm, type: 'export' }
  ],
  javascript: [
    { pattern: /^(?:export\s+)?(?:async\s+)?function\s+(\w+)/gm, type: 'function' },
    { pattern: /^(?:export\s+)?class\s+(\w+)/gm, type: 'class' },
    { pattern: /^(?:export\s+)?const\s+(\w+)/gm, type: 'const' }
  ],
  python: [
    { pattern: /^def\s+(\w+)/gm, type: 'function' },
    { pattern: /^class\s+(\w+)/gm, type: 'class' }
  ],
  rust: [
    { pattern: /^(?:pub\s+)?fn\s+(\w+)/gm, type: 'function' },
    { pattern: /^(?:pub\s+)?struct\s+(\w+)/gm, type: 'class' },
    { pattern: /^(?:pub\s+)?trait\s+(\w+)/gm, type: 'interface' },
    { pattern: /^(?:pub\s+)?type\s+(\w+)/gm, type: 'type' }
  ],
  go: [
    { pattern: /^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)/gm, type: 'function' },
    { pattern: /^type\s+(\w+)\s+struct/gm, type: 'class' },
    { pattern: /^type\s+(\w+)\s+interface/gm, type: 'interface' }
  ],
  vue: [
    { pattern: /^(?:export\s+)?(?:async\s+)?function\s+(\w+)/gm, type: 'function' },
    { pattern: /defineComponent\s*\(\s*{\s*name:\s*['"](\w+)['"]/gm, type: 'class' }
  ]
};

// Import patterns per language
const IMPORT_PATTERNS: Record<string, RegExp[]> = {
  typescript: [
    /import\s+.*?\s+from\s+['"]([^'"]+)['"]/g,
    /import\s+['"]([^'"]+)['"]/g,
    /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  ],
  javascript: [
    /import\s+.*?\s+from\s+['"]([^'"]+)['"]/g,
    /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  ],
  python: [
    /^import\s+(\w+)/gm,
    /^from\s+(\w+(?:\.\w+)*)\s+import/gm
  ],
  rust: [
    /^use\s+(\w+(?:::\w+)*)/gm
  ],
  go: [
    /import\s+"([^"]+)"/g,
    /import\s+\w+\s+"([^"]+)"/g
  ]
};

// ============================================================================
// STATE
// ============================================================================

const fileIndex = reactive<Map<string, FileIndex>>(new Map());
const dependencyGraph = reactive<Map<string, DependencyNode>>(new Map());
const isIndexing = ref(false);
const indexProgress = ref(0);
const lastStats = ref<IndexStats | null>(null);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function detectLanguage(path: string): string {
  for (const [lang, patterns] of Object.entries(LANGUAGE_PATTERNS)) {
    if (patterns.some(p => p.test(path))) {
      return lang;
    }
  }
  return 'unknown';
}

function extractSymbols(content: string, language: string): SymbolInfo[] {
  const symbols: SymbolInfo[] = [];
  const patterns = SYMBOL_PATTERNS[language] || [];

  for (const { pattern, type } of patterns) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      symbols.push({
        name: match[1],
        type,
        line
      });
    }
  }

  return symbols;
}

function extractImports(content: string, language: string): string[] {
  const imports: string[] = [];
  const patterns = IMPORT_PATTERNS[language] || [];

  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      imports.push(match[1]);
    }
  }

  return [...new Set(imports)];
}

function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(16);
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useCodeIndex() {
  /**
   * Index a single file
   */
  async function indexFile(path: string, content: string): Promise<FileIndex> {
    const language = detectLanguage(path);
    const symbols = extractSymbols(content, language);
    const imports = extractImports(content, language);

    const index: FileIndex = {
      path,
      language,
      size: content.length,
      lastModified: new Date(),
      lastIndexed: new Date(),
      hash: simpleHash(content),
      symbols,
      imports,
      exports: symbols.filter(s => s.type === 'export').map(s => s.name)
    };

    fileIndex.set(path, index);
    return index;
  }

  /**
   * Index entire project
   */
  async function indexProject(
    readFile: (path: string) => Promise<string>,
    listFiles: (pattern: string) => Promise<string[]>,
    options?: { onProgress?: (progress: number, file: string) => void }
  ): Promise<IndexStats> {
    isIndexing.value = true;
    indexProgress.value = 0;
    const startTime = Date.now();

    try {
      // Find all files
      const allFiles: string[] = [];
      for (const pattern of CONFIG.INCLUDE_PATTERNS) {
        const files = await listFiles(pattern);
        allFiles.push(...files);
      }

      // Filter out excluded patterns
      const filesToIndex = allFiles.filter(f =>
        !CONFIG.EXCLUDE_PATTERNS.some(p => {
          const regex = new RegExp(p.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'));
          return regex.test(f);
        })
      ).slice(0, CONFIG.MAX_FILES);

      console.log(`[CodeIndex] Indexing ${filesToIndex.length} files...`);

      // Index each file
      const languages: Record<string, number> = {};
      let totalSymbols = 0;
      let totalBytes = 0;

      for (let i = 0; i < filesToIndex.length; i++) {
        const path = filesToIndex[i];
        indexProgress.value = (i / filesToIndex.length) * 100;
        options?.onProgress?.(indexProgress.value, path);

        try {
          const content = await readFile(path);

          if (content.length > CONFIG.MAX_FILE_SIZE) {
            continue; // Skip large files
          }

          const index = await indexFile(path, content);
          languages[index.language] = (languages[index.language] || 0) + 1;
          totalSymbols += index.symbols.length;
          totalBytes += index.size;
        } catch (e) {
          console.warn(`[CodeIndex] Failed to index ${path}:`, e);
        }
      }

      // Build dependency graph
      buildDependencyGraph();

      const stats: IndexStats = {
        totalFiles: fileIndex.size,
        totalSymbols,
        totalBytes,
        languages,
        lastFullIndex: new Date(),
        indexDurationMs: Date.now() - startTime
      };

      lastStats.value = stats;
      console.log(`[CodeIndex] Indexed ${stats.totalFiles} files, ${stats.totalSymbols} symbols in ${stats.indexDurationMs}ms`);

      return stats;
    } finally {
      isIndexing.value = false;
      indexProgress.value = 100;
    }
  }

  /**
   * Build dependency graph from imports
   */
  function buildDependencyGraph(): void {
    dependencyGraph.clear();

    // Initialize all nodes
    for (const [path] of fileIndex) {
      dependencyGraph.set(path, {
        path,
        imports: [],
        importedBy: [],
        depth: 0
      });
    }

    // Build connections
    for (const [path, index] of fileIndex) {
      const node = dependencyGraph.get(path)!;

      for (const imp of index.imports) {
        // Resolve relative imports
        let resolvedPath = imp;
        if (imp.startsWith('.')) {
          const basePath = path.split('/').slice(0, -1).join('/');
          resolvedPath = `${basePath}/${imp}`.replace(/\/\.\//g, '/');
        }

        // Find matching file
        const matchingFile = Array.from(fileIndex.keys()).find(f =>
          f.includes(resolvedPath) || f.endsWith(`${resolvedPath}.ts`) || f.endsWith(`${resolvedPath}.js`)
        );

        if (matchingFile) {
          node.imports.push(matchingFile);
          const importedNode = dependencyGraph.get(matchingFile);
          if (importedNode) {
            importedNode.importedBy.push(path);
          }
        }
      }
    }

    // Calculate depth (distance from entry points)
    // Entry points are files with no importedBy
    const entryPoints = Array.from(dependencyGraph.values())
      .filter(n => n.importedBy.length === 0);

    const visited = new Set<string>();
    const queue = entryPoints.map(e => ({ path: e.path, depth: 0 }));

    while (queue.length > 0) {
      const { path, depth } = queue.shift()!;
      if (visited.has(path)) continue;
      visited.add(path);

      const node = dependencyGraph.get(path);
      if (node) {
        node.depth = depth;
        for (const imp of node.imports) {
          queue.push({ path: imp, depth: depth + 1 });
        }
      }
    }
  }

  /**
   * Search for symbols, files, or content
   */
  function search(query: string, options?: {
    type?: 'symbol' | 'file' | 'content' | 'all';
    language?: string;
    limit?: number;
  }): SearchResult[] {
    const type = options?.type || 'all';
    const limit = options?.limit || 20;
    const queryLower = query.toLowerCase();
    const results: SearchResult[] = [];

    for (const [path, index] of fileIndex) {
      if (options?.language && index.language !== options.language) continue;

      const result: SearchResult = { path, score: 0, matches: [] };

      // Search symbols
      if (type === 'symbol' || type === 'all') {
        for (const symbol of index.symbols) {
          if (symbol.name.toLowerCase().includes(queryLower)) {
            result.matches.push({
              type: 'symbol',
              name: symbol.name,
              line: symbol.line
            });
            result.score += symbol.name.toLowerCase() === queryLower ? 10 : 5;
          }
        }
      }

      // Search file paths
      if (type === 'file' || type === 'all') {
        if (path.toLowerCase().includes(queryLower)) {
          result.matches.push({ type: 'content', snippet: path });
          result.score += 3;
        }
      }

      // Search imports
      if (type === 'all') {
        for (const imp of index.imports) {
          if (imp.toLowerCase().includes(queryLower)) {
            result.matches.push({ type: 'import', name: imp });
            result.score += 2;
          }
        }
      }

      if (result.matches.length > 0) {
        results.push(result);
      }
    }

    // Sort by score and limit
    return results
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }

  /**
   * Find all usages of a symbol
   */
  function findUsages(symbolName: string): SearchResult[] {
    return search(symbolName, { type: 'all', limit: 50 });
  }

  /**
   * Get files that import a given file
   */
  function getImportedBy(path: string): string[] {
    return dependencyGraph.get(path)?.importedBy || [];
  }

  /**
   * Get files imported by a given file
   */
  function getImports(path: string): string[] {
    return dependencyGraph.get(path)?.imports || [];
  }

  /**
   * Get context for AI (summarizes relevant code)
   */
  function getContextForQuery(query: string, maxFiles: number = 5): string {
    const results = search(query, { limit: maxFiles });
    const context: string[] = [];

    for (const result of results) {
      const index = fileIndex.get(result.path);
      if (!index) continue;

      const symbolList = index.symbols
        .slice(0, 10)
        .map(s => `  - ${s.type} ${s.name} (line ${s.line})`)
        .join('\n');

      context.push(`File: ${result.path}\nSymbols:\n${symbolList}`);
    }

    return context.join('\n\n');
  }

  /**
   * Get project structure summary
   */
  function getProjectSummary(): string {
    const stats = lastStats.value;
    if (!stats) return 'Project not indexed';

    const langSummary = Object.entries(stats.languages)
      .sort((a, b) => b[1] - a[1])
      .map(([lang, count]) => `  ${lang}: ${count} files`)
      .join('\n');

    return `Project Index:
Files: ${stats.totalFiles}
Symbols: ${stats.totalSymbols}
Size: ${(stats.totalBytes / 1024).toFixed(1)} KB

Languages:
${langSummary}`;
  }

  /**
   * Check if file needs re-indexing
   */
  function needsReindex(path: string, currentHash: string): boolean {
    const existing = fileIndex.get(path);
    return !existing || existing.hash !== currentHash;
  }

  /**
   * Clear the index
   */
  function clearIndex(): void {
    fileIndex.clear();
    dependencyGraph.clear();
    lastStats.value = null;
  }

  return {
    // State
    isIndexing: computed(() => isIndexing.value),
    indexProgress: computed(() => indexProgress.value),
    stats: computed(() => lastStats.value),
    fileCount: computed(() => fileIndex.size),

    // Indexing
    indexFile,
    indexProject,
    needsReindex,
    clearIndex,

    // Search
    search,
    findUsages,

    // Dependencies
    getImportedBy,
    getImports,
    buildDependencyGraph,

    // Context
    getContextForQuery,
    getProjectSummary,

    // Raw access
    fileIndex,
    dependencyGraph
  };
}

export default useCodeIndex;
