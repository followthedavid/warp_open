/**
 * useUniversalMemory - Deep Context System for Personal Automation Intelligence
 *
 * This is the "super intelligence" core - it knows everything about your work:
 * - Every file you've written (indexed with embeddings)
 * - Every solution pattern (searchable)
 * - Cross-project intelligence ("you built this before in Project X")
 * - Learning from your coding style and preferences
 *
 * Uses Ollama's embedding model (nomic-embed-text) for semantic search.
 */

import { ref, computed, reactive } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

// ============================================================================
// TYPES
// ============================================================================

export interface FileMemory {
  path: string
  relativePath: string
  project: string
  language: string
  lastModified: Date
  lastIndexed: Date
  size: number
  lineCount: number
  embedding?: number[]
  summary?: string
  patterns: string[]
  dependencies: string[]
  exports: string[]
  imports: string[]
}

export interface PatternMemory {
  id: string
  name: string
  description: string
  code: string
  language: string
  files: string[] // Files where this pattern appears
  frequency: number
  embedding?: number[]
  tags: string[]
  createdAt: Date
  lastSeen: Date
}

export interface SolutionMemory {
  id: string
  problem: string
  solution: string
  codeSnippet?: string
  language?: string
  files: string[]
  project: string
  embedding?: number[]
  successCount: number
  createdAt: Date
  lastUsed: Date
}

export interface ProjectMemory {
  path: string
  name: string
  type: 'node' | 'python' | 'rust' | 'go' | 'mixed' | 'unknown'
  framework?: string
  lastAccessed: Date
  fileCount: number
  structure: Record<string, number> // directory -> file count
  summary?: string
  keyFiles: string[]
  dependencies: string[]
}

export interface SearchResult {
  type: 'file' | 'pattern' | 'solution' | 'project'
  score: number
  item: FileMemory | PatternMemory | SolutionMemory | ProjectMemory
  matchContext?: string
}

// ============================================================================
// STORAGE
// ============================================================================

const MEMORY_KEYS = {
  files: 'warp_memory_files',
  patterns: 'warp_memory_patterns',
  solutions: 'warp_memory_solutions',
  projects: 'warp_memory_projects',
  config: 'warp_memory_config'
}

interface MemoryConfig {
  indexedPaths: string[]
  excludePatterns: string[]
  lastFullIndex: Date | null
  embeddingModel: string
}

function loadMemory<T>(key: string): T[] {
  try {
    const stored = localStorage.getItem(key)
    if (stored) {
      const data = JSON.parse(stored)
      // Convert date strings back to Date objects
      return data.map((item: any) => ({
        ...item,
        lastModified: item.lastModified ? new Date(item.lastModified) : undefined,
        lastIndexed: item.lastIndexed ? new Date(item.lastIndexed) : undefined,
        createdAt: item.createdAt ? new Date(item.createdAt) : undefined,
        lastSeen: item.lastSeen ? new Date(item.lastSeen) : undefined,
        lastUsed: item.lastUsed ? new Date(item.lastUsed) : undefined,
        lastAccessed: item.lastAccessed ? new Date(item.lastAccessed) : undefined,
      }))
    }
  } catch {}
  return []
}

function saveMemory<T>(key: string, data: T[]): void {
  try {
    localStorage.setItem(key, JSON.stringify(data))
  } catch (error) {
    console.error(`Failed to save memory ${key}:`, error)
  }
}

function loadConfig(): MemoryConfig {
  try {
    const stored = localStorage.getItem(MEMORY_KEYS.config)
    if (stored) {
      const config = JSON.parse(stored)
      return {
        ...config,
        lastFullIndex: config.lastFullIndex ? new Date(config.lastFullIndex) : null
      }
    }
  } catch {}
  return {
    indexedPaths: ['~/Developer', '~/Projects', '~/Code', '~/repos'],
    excludePatterns: ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'target'],
    lastFullIndex: null,
    embeddingModel: 'nomic-embed-text'
  }
}

function saveConfig(config: MemoryConfig): void {
  localStorage.setItem(MEMORY_KEYS.config, JSON.stringify(config))
}

// ============================================================================
// EMBEDDING UTILITIES
// ============================================================================

async function getEmbedding(text: string, model: string = 'nomic-embed-text'): Promise<number[] | null> {
  try {
    const response = await fetch('http://localhost:11434/api/embeddings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, prompt: text })
    })

    if (!response.ok) return null

    const data = await response.json()
    return data.embedding
  } catch {
    return null
  }
}

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0

  let dotProduct = 0
  let normA = 0
  let normB = 0

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i]
    normA += a[i] * a[i]
    normB += b[i] * b[i]
  }

  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB))
}

// ============================================================================
// LANGUAGE DETECTION
// ============================================================================

function detectLanguage(filepath: string): string {
  const ext = filepath.split('.').pop()?.toLowerCase()
  const langMap: Record<string, string> = {
    ts: 'typescript', tsx: 'typescript',
    js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
    py: 'python',
    rs: 'rust',
    go: 'go',
    java: 'java',
    cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp', h: 'cpp',
    c: 'c',
    vue: 'vue',
    svelte: 'svelte',
    rb: 'ruby',
    php: 'php',
    swift: 'swift',
    kt: 'kotlin',
    scala: 'scala',
    sh: 'bash', bash: 'bash', zsh: 'bash',
    sql: 'sql',
    md: 'markdown',
    json: 'json',
    yaml: 'yaml', yml: 'yaml',
    toml: 'toml',
    css: 'css', scss: 'scss', sass: 'sass', less: 'less',
    html: 'html',
  }
  return langMap[ext || ''] || 'unknown'
}

function detectProjectType(files: string[]): { type: ProjectMemory['type']; framework?: string } {
  const hasPackageJson = files.some(f => f.endsWith('package.json'))
  const hasCargoToml = files.some(f => f.endsWith('Cargo.toml'))
  const hasRequirementsTxt = files.some(f => f.endsWith('requirements.txt'))
  const hasPyprojectToml = files.some(f => f.endsWith('pyproject.toml'))
  const hasGoMod = files.some(f => f.endsWith('go.mod'))

  // Detect framework from files
  let framework: string | undefined
  if (files.some(f => f.includes('next.config'))) framework = 'Next.js'
  else if (files.some(f => f.includes('vite.config'))) framework = 'Vite'
  else if (files.some(f => f.includes('nuxt.config'))) framework = 'Nuxt'
  else if (files.some(f => f.includes('tauri.conf'))) framework = 'Tauri'
  else if (files.some(f => f.includes('django'))) framework = 'Django'
  else if (files.some(f => f.includes('flask'))) framework = 'Flask'
  else if (files.some(f => f.includes('fastapi'))) framework = 'FastAPI'

  if (hasPackageJson && hasCargoToml) return { type: 'mixed', framework: 'Tauri' }
  if (hasPackageJson) return { type: 'node', framework }
  if (hasCargoToml) return { type: 'rust' }
  if (hasRequirementsTxt || hasPyprojectToml) return { type: 'python', framework }
  if (hasGoMod) return { type: 'go' }

  return { type: 'unknown' }
}

// ============================================================================
// PATTERN EXTRACTION
// ============================================================================

function extractPatterns(code: string, language: string): string[] {
  const patterns: string[] = []

  // Common patterns across languages
  if (/async\s+(function|\w+)\s*\(/.test(code)) patterns.push('async-function')
  if (/try\s*{[\s\S]*?catch/.test(code)) patterns.push('try-catch')
  if (/\.map\(/.test(code)) patterns.push('array-map')
  if (/\.filter\(/.test(code)) patterns.push('array-filter')
  if (/\.reduce\(/.test(code)) patterns.push('array-reduce')
  if (/Promise\.all/.test(code)) patterns.push('promise-all')
  if (/new Promise/.test(code)) patterns.push('promise-constructor')
  if (/\bawait\b/.test(code)) patterns.push('await')

  // TypeScript/JavaScript specific
  if (language === 'typescript' || language === 'javascript') {
    if (/interface\s+\w+/.test(code)) patterns.push('interface')
    if (/type\s+\w+\s*=/.test(code)) patterns.push('type-alias')
    if (/class\s+\w+/.test(code)) patterns.push('class')
    if (/extends\s+\w+/.test(code)) patterns.push('class-extends')
    if (/implements\s+\w+/.test(code)) patterns.push('class-implements')
    if (/useState/.test(code)) patterns.push('react-useState')
    if (/useEffect/.test(code)) patterns.push('react-useEffect')
    if (/useMemo/.test(code)) patterns.push('react-useMemo')
    if (/ref\(/.test(code)) patterns.push('vue-ref')
    if (/computed\(/.test(code)) patterns.push('vue-computed')
    if (/onMounted/.test(code)) patterns.push('vue-onMounted')
  }

  // Python specific
  if (language === 'python') {
    if (/def\s+\w+/.test(code)) patterns.push('function-def')
    if (/class\s+\w+/.test(code)) patterns.push('class-def')
    if (/@\w+/.test(code)) patterns.push('decorator')
    if (/async\s+def/.test(code)) patterns.push('async-def')
    if (/with\s+\w+/.test(code)) patterns.push('context-manager')
    if (/\[.*for.*in.*\]/.test(code)) patterns.push('list-comprehension')
  }

  // Rust specific
  if (language === 'rust') {
    if (/impl\s+\w+/.test(code)) patterns.push('impl-block')
    if (/trait\s+\w+/.test(code)) patterns.push('trait')
    if (/enum\s+\w+/.test(code)) patterns.push('enum')
    if (/struct\s+\w+/.test(code)) patterns.push('struct')
    if (/\.unwrap\(\)/.test(code)) patterns.push('unwrap')
    if (/\?/.test(code)) patterns.push('question-mark-operator')
    if (/async\s+fn/.test(code)) patterns.push('async-fn')
  }

  return patterns
}

function extractImportsExports(code: string, language: string): { imports: string[]; exports: string[] } {
  const imports: string[] = []
  const exports: string[] = []

  if (language === 'typescript' || language === 'javascript') {
    // Imports
    const importMatches = code.matchAll(/import\s+(?:{[^}]+}|\*\s+as\s+\w+|\w+)\s+from\s+['"]([^'"]+)['"]/g)
    for (const match of importMatches) {
      imports.push(match[1])
    }

    // Exports
    const exportMatches = code.matchAll(/export\s+(?:default\s+)?(?:function|class|const|let|var|interface|type)\s+(\w+)/g)
    for (const match of exportMatches) {
      exports.push(match[1])
    }
  }

  if (language === 'python') {
    const importMatches = code.matchAll(/(?:from\s+(\S+)\s+)?import\s+(\S+)/g)
    for (const match of importMatches) {
      imports.push(match[1] || match[2])
    }
  }

  if (language === 'rust') {
    const useMatches = code.matchAll(/use\s+([^;]+)/g)
    for (const match of useMatches) {
      imports.push(match[1].trim())
    }

    if (/pub\s+(fn|struct|enum|trait|mod)/.test(code)) {
      const pubMatches = code.matchAll(/pub\s+(?:fn|struct|enum|trait|mod)\s+(\w+)/g)
      for (const match of pubMatches) {
        exports.push(match[1])
      }
    }
  }

  return { imports, exports }
}

// ============================================================================
// COMPOSABLE
// ============================================================================

export function useUniversalMemory() {
  const files = ref<FileMemory[]>(loadMemory<FileMemory>(MEMORY_KEYS.files))
  const patterns = ref<PatternMemory[]>(loadMemory<PatternMemory>(MEMORY_KEYS.patterns))
  const solutions = ref<SolutionMemory[]>(loadMemory<SolutionMemory>(MEMORY_KEYS.solutions))
  const projects = ref<ProjectMemory[]>(loadMemory<ProjectMemory>(MEMORY_KEYS.projects))
  const config = reactive<MemoryConfig>(loadConfig())

  const isIndexing = ref(false)
  const indexProgress = ref({ current: 0, total: 0, currentFile: '' })

  // ========================================================================
  // FILE INDEXING
  // ========================================================================

  /**
   * Index a single file
   */
  async function indexFile(filepath: string, projectPath: string): Promise<FileMemory | null> {
    try {
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: `cat "${filepath}" | head -c 50000`, // Limit to 50KB
        cwd: undefined
      })

      if (result.exit_code !== 0) return null

      const content = result.stdout
      const lines = content.split('\n')
      const language = detectLanguage(filepath)
      const patternsFound = extractPatterns(content, language)
      const { imports, exports } = extractImportsExports(content, language)

      // Get file stats
      const statResult = await invoke<{ stdout: string }>('execute_shell', {
        command: `stat -f '%m' "${filepath}"`,
        cwd: undefined
      })
      const lastModified = new Date(parseInt(statResult.stdout.trim()) * 1000)

      // Generate embedding for semantic search
      const summaryText = `${filepath}\n${content.substring(0, 2000)}`
      const embedding = await getEmbedding(summaryText, config.embeddingModel)

      const memory: FileMemory = {
        path: filepath,
        relativePath: filepath.replace(projectPath, '').replace(/^\//, ''),
        project: projectPath.split('/').pop() || projectPath,
        language,
        lastModified,
        lastIndexed: new Date(),
        size: content.length,
        lineCount: lines.length,
        embedding: embedding || undefined,
        patterns: patternsFound,
        dependencies: imports.filter(i => !i.startsWith('.')),
        exports,
        imports
      }

      // Update or add to files array
      const existingIndex = files.value.findIndex(f => f.path === filepath)
      if (existingIndex >= 0) {
        files.value[existingIndex] = memory
      } else {
        files.value.push(memory)
      }

      saveMemory(MEMORY_KEYS.files, files.value)
      return memory
    } catch (error) {
      console.error(`Failed to index ${filepath}:`, error)
      return null
    }
  }

  /**
   * Index a directory recursively
   */
  async function indexDirectory(dirPath: string): Promise<number> {
    isIndexing.value = true

    try {
      // Find all code files
      const excludeArgs = config.excludePatterns
        .map(p => `-not -path "*/${p}/*"`)
        .join(' ')

      const findResult = await invoke<{ stdout: string }>('execute_shell', {
        command: `find "${dirPath}" -type f \\( -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.rs" -o -name "*.go" -o -name "*.vue" -o -name "*.jsx" -o -name "*.tsx" \\) ${excludeArgs} 2>/dev/null`,
        cwd: undefined
      })

      const filePaths = findResult.stdout.trim().split('\n').filter(Boolean)
      indexProgress.value.total = filePaths.length

      let indexedCount = 0
      for (const filepath of filePaths) {
        indexProgress.value.current = indexedCount
        indexProgress.value.currentFile = filepath.split('/').pop() || filepath

        await indexFile(filepath, dirPath)
        indexedCount++

        // Yield to prevent blocking
        if (indexedCount % 10 === 0) {
          await new Promise(resolve => setTimeout(resolve, 0))
        }
      }

      // Index project
      await indexProject(dirPath, filePaths)

      // Extract patterns
      await extractPatternsFromFiles(filePaths)

      config.lastFullIndex = new Date()
      saveConfig(config)

      return indexedCount
    } finally {
      isIndexing.value = false
    }
  }

  /**
   * Index a project
   */
  async function indexProject(projectPath: string, allFiles: string[]): Promise<ProjectMemory> {
    const { type, framework } = detectProjectType(allFiles)

    // Calculate directory structure
    const structure: Record<string, number> = {}
    for (const file of allFiles) {
      const dir = file.replace(projectPath, '').split('/').slice(0, -1).join('/')
      structure[dir || '/'] = (structure[dir || '/'] || 0) + 1
    }

    // Find key files
    const keyFileNames = ['README.md', 'package.json', 'Cargo.toml', 'requirements.txt', 'main.ts', 'index.ts', 'app.ts', 'main.py', 'app.py', 'main.rs', 'lib.rs']
    const keyFiles = allFiles.filter(f =>
      keyFileNames.some(kf => f.endsWith(kf))
    )

    // Extract dependencies
    const dependencies: string[] = []
    const pkgJsonPath = allFiles.find(f => f.endsWith('package.json'))
    if (pkgJsonPath) {
      try {
        const result = await invoke<{ stdout: string }>('execute_shell', {
          command: `cat "${pkgJsonPath}"`,
          cwd: undefined
        })
        const pkg = JSON.parse(result.stdout)
        dependencies.push(...Object.keys(pkg.dependencies || {}))
        dependencies.push(...Object.keys(pkg.devDependencies || {}))
      } catch {}
    }

    const project: ProjectMemory = {
      path: projectPath,
      name: projectPath.split('/').pop() || projectPath,
      type,
      framework,
      lastAccessed: new Date(),
      fileCount: allFiles.length,
      structure,
      keyFiles,
      dependencies
    }

    const existingIndex = projects.value.findIndex(p => p.path === projectPath)
    if (existingIndex >= 0) {
      projects.value[existingIndex] = project
    } else {
      projects.value.push(project)
    }

    saveMemory(MEMORY_KEYS.projects, projects.value)
    return project
  }

  /**
   * Extract common patterns from indexed files
   */
  async function extractPatternsFromFiles(filePaths: string[]): Promise<void> {
    const patternCounts: Record<string, { files: string[]; code: string }> = {}

    for (const file of files.value) {
      if (!filePaths.includes(file.path)) continue

      for (const pattern of file.patterns) {
        if (!patternCounts[pattern]) {
          patternCounts[pattern] = { files: [], code: '' }
        }
        patternCounts[pattern].files.push(file.path)
      }
    }

    // Save patterns that appear multiple times
    for (const [name, data] of Object.entries(patternCounts)) {
      if (data.files.length >= 2) {
        const existing = patterns.value.find(p => p.name === name)
        if (existing) {
          existing.files = data.files
          existing.frequency = data.files.length
          existing.lastSeen = new Date()
        } else {
          patterns.value.push({
            id: `pattern_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            name,
            description: `Pattern: ${name}`,
            code: data.code,
            language: 'mixed',
            files: data.files,
            frequency: data.files.length,
            tags: [],
            createdAt: new Date(),
            lastSeen: new Date()
          })
        }
      }
    }

    saveMemory(MEMORY_KEYS.patterns, patterns.value)
  }

  // ========================================================================
  // SEARCH
  // ========================================================================

  /**
   * Semantic search across all memory
   */
  async function search(query: string, options: {
    types?: Array<'file' | 'pattern' | 'solution' | 'project'>
    limit?: number
    minScore?: number
    project?: string
    language?: string
  } = {}): Promise<SearchResult[]> {
    const { types = ['file', 'pattern', 'solution', 'project'], limit = 20, minScore = 0.3 } = options

    const queryEmbedding = await getEmbedding(query, config.embeddingModel)
    if (!queryEmbedding) {
      // Fall back to text search
      return textSearch(query, options)
    }

    const results: SearchResult[] = []

    // Search files
    if (types.includes('file')) {
      for (const file of files.value) {
        if (options.project && file.project !== options.project) continue
        if (options.language && file.language !== options.language) continue
        if (!file.embedding) continue

        const score = cosineSimilarity(queryEmbedding, file.embedding)
        if (score >= minScore) {
          results.push({ type: 'file', score, item: file })
        }
      }
    }

    // Search patterns
    if (types.includes('pattern')) {
      for (const pattern of patterns.value) {
        if (pattern.embedding) {
          const score = cosineSimilarity(queryEmbedding, pattern.embedding)
          if (score >= minScore) {
            results.push({ type: 'pattern', score, item: pattern })
          }
        } else if (pattern.name.toLowerCase().includes(query.toLowerCase())) {
          results.push({ type: 'pattern', score: 0.5, item: pattern })
        }
      }
    }

    // Search solutions
    if (types.includes('solution')) {
      for (const solution of solutions.value) {
        if (solution.embedding) {
          const score = cosineSimilarity(queryEmbedding, solution.embedding)
          if (score >= minScore) {
            results.push({ type: 'solution', score, item: solution })
          }
        } else if (solution.problem.toLowerCase().includes(query.toLowerCase())) {
          results.push({ type: 'solution', score: 0.5, item: solution })
        }
      }
    }

    // Search projects
    if (types.includes('project')) {
      for (const project of projects.value) {
        if (project.name.toLowerCase().includes(query.toLowerCase())) {
          results.push({ type: 'project', score: 0.7, item: project })
        }
      }
    }

    // Sort by score and limit
    results.sort((a, b) => b.score - a.score)
    return results.slice(0, limit)
  }

  /**
   * Text-based search fallback
   */
  function textSearch(query: string, options: {
    types?: Array<'file' | 'pattern' | 'solution' | 'project'>
    limit?: number
    project?: string
    language?: string
  } = {}): SearchResult[] {
    const { types = ['file', 'pattern', 'solution', 'project'], limit = 20 } = options
    const queryLower = query.toLowerCase()
    const results: SearchResult[] = []

    if (types.includes('file')) {
      for (const file of files.value) {
        if (options.project && file.project !== options.project) continue
        if (options.language && file.language !== options.language) continue

        if (file.path.toLowerCase().includes(queryLower) ||
            file.exports.some(e => e.toLowerCase().includes(queryLower)) ||
            file.patterns.some(p => p.includes(queryLower))) {
          results.push({ type: 'file', score: 0.5, item: file })
        }
      }
    }

    if (types.includes('solution')) {
      for (const solution of solutions.value) {
        if (solution.problem.toLowerCase().includes(queryLower)) {
          results.push({ type: 'solution', score: 0.7, item: solution })
        }
      }
    }

    return results.slice(0, limit)
  }

  /**
   * Find similar files
   */
  async function findSimilar(filepath: string, limit: number = 5): Promise<SearchResult[]> {
    const file = files.value.find(f => f.path === filepath)
    if (!file || !file.embedding) return []

    const results: SearchResult[] = []
    for (const other of files.value) {
      if (other.path === filepath || !other.embedding) continue

      const score = cosineSimilarity(file.embedding, other.embedding)
      if (score > 0.5) {
        results.push({ type: 'file', score, item: other })
      }
    }

    results.sort((a, b) => b.score - a.score)
    return results.slice(0, limit)
  }

  /**
   * Find where a pattern was used before (cross-project intelligence)
   */
  function findPatternUsage(patternName: string): { file: FileMemory; project: string }[] {
    const results: { file: FileMemory; project: string }[] = []

    for (const file of files.value) {
      if (file.patterns.includes(patternName)) {
        results.push({ file, project: file.project })
      }
    }

    return results
  }

  // ========================================================================
  // SOLUTIONS
  // ========================================================================

  /**
   * Remember a solution for future reference
   */
  async function rememberSolution(
    problem: string,
    solution: string,
    options: {
      codeSnippet?: string
      language?: string
      files?: string[]
      project?: string
    } = {}
  ): Promise<SolutionMemory> {
    const embedding = await getEmbedding(`${problem}\n${solution}`, config.embeddingModel)

    const solutionMemory: SolutionMemory = {
      id: `solution_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      problem,
      solution,
      codeSnippet: options.codeSnippet,
      language: options.language,
      files: options.files || [],
      project: options.project || 'unknown',
      embedding: embedding || undefined,
      successCount: 1,
      createdAt: new Date(),
      lastUsed: new Date()
    }

    solutions.value.push(solutionMemory)
    saveMemory(MEMORY_KEYS.solutions, solutions.value)

    return solutionMemory
  }

  /**
   * Mark a solution as used (increases success count)
   */
  function useSolution(solutionId: string): void {
    const solution = solutions.value.find(s => s.id === solutionId)
    if (solution) {
      solution.successCount++
      solution.lastUsed = new Date()
      saveMemory(MEMORY_KEYS.solutions, solutions.value)
    }
  }

  // ========================================================================
  // STATS & INSIGHTS
  // ========================================================================

  const stats = computed(() => ({
    totalFiles: files.value.length,
    totalProjects: projects.value.length,
    totalPatterns: patterns.value.length,
    totalSolutions: solutions.value.length,
    languageBreakdown: files.value.reduce((acc, f) => {
      acc[f.language] = (acc[f.language] || 0) + 1
      return acc
    }, {} as Record<string, number>),
    topPatterns: patterns.value
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, 10)
      .map(p => ({ name: p.name, frequency: p.frequency })),
    recentProjects: projects.value
      .sort((a, b) => b.lastAccessed.getTime() - a.lastAccessed.getTime())
      .slice(0, 5),
    lastIndexed: config.lastFullIndex
  }))

  /**
   * Get suggestions for the current context
   */
  async function getSuggestions(context: {
    currentFile?: string
    currentProject?: string
    recentPatterns?: string[]
  }): Promise<{
    similarFiles: SearchResult[]
    relatedSolutions: SearchResult[]
    patternSuggestions: PatternMemory[]
  }> {
    const similarFiles = context.currentFile
      ? await findSimilar(context.currentFile)
      : []

    const relatedSolutions = context.currentProject
      ? solutions.value
          .filter(s => s.project === context.currentProject)
          .sort((a, b) => b.lastUsed.getTime() - a.lastUsed.getTime())
          .slice(0, 5)
          .map(s => ({ type: 'solution' as const, score: 1, item: s }))
      : []

    const patternSuggestions = context.recentPatterns
      ? patterns.value.filter(p =>
          context.recentPatterns!.some(rp => p.name.includes(rp))
        ).slice(0, 5)
      : []

    return { similarFiles, relatedSolutions, patternSuggestions }
  }

  return {
    // Indexing
    indexFile,
    indexDirectory,
    isIndexing: computed(() => isIndexing.value),
    indexProgress: computed(() => indexProgress.value),

    // Search
    search,
    findSimilar,
    findPatternUsage,

    // Solutions
    rememberSolution,
    useSolution,

    // Insights
    stats,
    getSuggestions,

    // Configuration
    config,
    saveConfig: () => saveConfig(config),

    // Raw data access
    files: computed(() => files.value),
    patterns: computed(() => patterns.value),
    solutions: computed(() => solutions.value),
    projects: computed(() => projects.value)
  }
}

export type UseUniversalMemoryReturn = ReturnType<typeof useUniversalMemory>
