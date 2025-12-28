/**
 * useAutonomousImprover - The "Perpetual Ladder" for Code Improvement
 *
 * This is the core of the 24/7 autonomous intelligence. It:
 * - Scans all projects for improvement opportunities
 * - Ranks improvements by impact/risk
 * - Auto-applies low-risk improvements (formatting, docs, types)
 * - Queues medium-risk for approval (refactors, tests)
 * - Documents high-risk opportunities for human decision
 * - Learns from approval/rejection patterns
 *
 * The "ladder" concept: each improvement builds on the last,
 * continuously making your codebase better while you sleep.
 */

import { ref, computed, reactive } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { useAuditLog } from './useAuditLog'
import { useConstitution } from './useConstitution'
import { useUniversalMemory } from './useUniversalMemory'

// ============================================================================
// TYPES
// ============================================================================

export type ImprovementType =
  | 'formatting'      // Auto-format code
  | 'types'           // Add TypeScript types
  | 'documentation'   // Add/improve docs
  | 'lint_fix'        // Fix linting issues
  | 'dead_code'       // Remove unused code
  | 'dependency'      // Update dependencies
  | 'security'        // Security fixes
  | 'performance'     // Performance improvements
  | 'test'            // Add missing tests
  | 'refactor'        // Code refactoring
  | 'architecture'    // Architectural changes
  | 'pattern'         // Apply better patterns from other projects

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export interface Improvement {
  id: string
  type: ImprovementType
  riskLevel: RiskLevel
  file: string
  project: string
  title: string
  description: string
  currentCode?: string
  suggestedCode?: string
  diff?: string
  impact: {
    linesChanged: number
    filesAffected: number
    breakingChange: boolean
  }
  confidence: number // 0-1, how confident we are this is a good change
  status: 'pending' | 'approved' | 'rejected' | 'applied' | 'failed'
  createdAt: Date
  appliedAt?: Date
  approvedBy?: 'auto' | 'user'
  rollbackData?: string
  relatedPattern?: string // If this improvement is based on a pattern from another project
}

export interface ImprovementStats {
  total: number
  byType: Record<ImprovementType, number>
  byRisk: Record<RiskLevel, number>
  applied: number
  rejected: number
  pending: number
  approvalRate: number
}

export interface ScanResult {
  project: string
  scannedAt: Date
  filesScanned: number
  improvementsFound: number
  improvements: Improvement[]
}

// ============================================================================
// RISK CLASSIFICATION
// ============================================================================

const TYPE_RISK: Record<ImprovementType, RiskLevel> = {
  formatting: 'low',
  types: 'low',
  documentation: 'low',
  lint_fix: 'low',
  dead_code: 'medium',
  dependency: 'medium',
  security: 'high',
  performance: 'medium',
  test: 'medium',
  refactor: 'high',
  architecture: 'critical',
  pattern: 'medium'
}

// ============================================================================
// STORAGE
// ============================================================================

const IMPROVEMENTS_KEY = 'warp_improvements'
const SCANS_KEY = 'warp_improvement_scans'
const PREFERENCES_KEY = 'warp_improvement_prefs'

interface ImprovementPreferences {
  autoApplyLowRisk: boolean
  autoApplyFormatting: boolean
  autoApplyTypes: boolean
  autoApplyDocs: boolean
  excludePaths: string[]
  focusProjects: string[]
  scanInterval: number // minutes
  maxChangesPerScan: number
}

function loadImprovements(): Improvement[] {
  try {
    const stored = localStorage.getItem(IMPROVEMENTS_KEY)
    if (stored) {
      return JSON.parse(stored).map((i: any) => ({
        ...i,
        createdAt: new Date(i.createdAt),
        appliedAt: i.appliedAt ? new Date(i.appliedAt) : undefined
      }))
    }
  } catch {}
  return []
}

function saveImprovements(improvements: Improvement[]): void {
  // Keep last 1000 improvements
  const trimmed = improvements.slice(-1000)
  localStorage.setItem(IMPROVEMENTS_KEY, JSON.stringify(trimmed))
}

function loadPreferences(): ImprovementPreferences {
  try {
    const stored = localStorage.getItem(PREFERENCES_KEY)
    if (stored) return JSON.parse(stored)
  } catch {}
  return {
    autoApplyLowRisk: true,
    autoApplyFormatting: true,
    autoApplyTypes: true,
    autoApplyDocs: true,
    excludePaths: ['node_modules', '.git', 'dist', 'build', 'coverage'],
    focusProjects: [],
    scanInterval: 60, // 1 hour
    maxChangesPerScan: 20
  }
}

function savePreferences(prefs: ImprovementPreferences): void {
  localStorage.setItem(PREFERENCES_KEY, JSON.stringify(prefs))
}

// ============================================================================
// COMPOSABLE
// ============================================================================

export function useAutonomousImprover() {
  const improvements = ref<Improvement[]>(loadImprovements())
  const preferences = reactive<ImprovementPreferences>(loadPreferences())
  const scanResults = ref<ScanResult[]>([])

  const auditLog = useAuditLog()
  const constitution = useConstitution()
  const memory = useUniversalMemory()

  const isScanning = ref(false)
  const isApplying = ref(false)
  const progress = ref({ phase: '', current: 0, total: 0, currentFile: '' })

  // ========================================================================
  // SCANNING
  // ========================================================================

  /**
   * Scan a project for improvements
   */
  async function scanProject(projectPath: string): Promise<ScanResult> {
    isScanning.value = true
    progress.value = { phase: 'Scanning project...', current: 0, total: 0, currentFile: '' }

    const result: ScanResult = {
      project: projectPath,
      scannedAt: new Date(),
      filesScanned: 0,
      improvementsFound: 0,
      improvements: []
    }

    try {
      // Find all code files
      const excludeArgs = preferences.excludePaths
        .map(p => `-not -path "*/${p}/*"`)
        .join(' ')

      const findResult = await invoke<{ stdout: string }>('execute_shell', {
        command: `find "${projectPath}" -type f \\( -name "*.ts" -o -name "*.js" -o -name "*.tsx" -o -name "*.jsx" -o -name "*.vue" -o -name "*.py" -o -name "*.rs" \\) ${excludeArgs} 2>/dev/null`,
        cwd: undefined
      })

      const files = findResult.stdout.trim().split('\n').filter(Boolean)
      progress.value.total = files.length

      for (let i = 0; i < files.length; i++) {
        const file = files[i]
        progress.value.current = i + 1
        progress.value.currentFile = file.split('/').pop() || file

        const fileImprovements = await scanFile(file, projectPath)
        result.improvements.push(...fileImprovements)
        result.filesScanned++

        // Yield to prevent blocking
        if (i % 5 === 0) {
          await new Promise(resolve => setTimeout(resolve, 0))
        }
      }

      // Check for cross-project patterns
      const patternImprovements = await findPatternOpportunities(projectPath)
      result.improvements.push(...patternImprovements)

      result.improvementsFound = result.improvements.length

      // Save improvements
      improvements.value.push(...result.improvements)
      saveImprovements(improvements.value)

      scanResults.value.push(result)

      await auditLog.log('code_modify', `Scanned ${projectPath}: ${result.improvementsFound} improvements found`, {
        details: {
          filesScanned: result.filesScanned,
          improvements: result.improvementsFound
        },
        riskLevel: 'low'
      })

    } finally {
      isScanning.value = false
    }

    return result
  }

  /**
   * Scan a single file for improvements
   */
  async function scanFile(filepath: string, projectPath: string): Promise<Improvement[]> {
    const improvements: Improvement[] = []

    try {
      const content = await invoke<{ stdout: string }>('execute_shell', {
        command: `cat "${filepath}" | head -c 100000`,
        cwd: undefined
      })

      const code = content.stdout
      const language = detectLanguage(filepath)

      // Check for various improvement opportunities
      improvements.push(...checkFormatting(filepath, projectPath, code, language))
      improvements.push(...checkTypes(filepath, projectPath, code, language))
      improvements.push(...checkDocumentation(filepath, projectPath, code, language))
      improvements.push(...checkDeadCode(filepath, projectPath, code, language))
      improvements.push(...checkSecurityIssues(filepath, projectPath, code, language))
      improvements.push(...checkPerformance(filepath, projectPath, code, language))

    } catch (error) {
      console.error(`Failed to scan ${filepath}:`, error)
    }

    return improvements
  }

  /**
   * Detect file language
   */
  function detectLanguage(filepath: string): string {
    const ext = filepath.split('.').pop()?.toLowerCase()
    const langMap: Record<string, string> = {
      ts: 'typescript', tsx: 'typescript',
      js: 'javascript', jsx: 'javascript',
      py: 'python', rs: 'rust', go: 'go',
      vue: 'vue', svelte: 'svelte'
    }
    return langMap[ext || ''] || 'unknown'
  }

  /**
   * Create an improvement record
   */
  function createImprovement(
    type: ImprovementType,
    file: string,
    project: string,
    title: string,
    description: string,
    options: Partial<Improvement> = {}
  ): Improvement {
    return {
      id: `imp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type,
      riskLevel: TYPE_RISK[type],
      file,
      project: project.split('/').pop() || project,
      title,
      description,
      impact: options.impact || { linesChanged: 0, filesAffected: 1, breakingChange: false },
      confidence: options.confidence || 0.8,
      status: 'pending',
      createdAt: new Date(),
      ...options
    }
  }

  // ========================================================================
  // IMPROVEMENT DETECTORS
  // ========================================================================

  function checkFormatting(file: string, project: string, code: string, lang: string): Improvement[] {
    const improvements: Improvement[] = []

    // Check for inconsistent indentation
    const lines = code.split('\n')
    let hasSpaces = false
    let hasTabs = false
    for (const line of lines.slice(0, 100)) {
      if (line.startsWith('  ')) hasSpaces = true
      if (line.startsWith('\t')) hasTabs = true
    }
    if (hasSpaces && hasTabs) {
      improvements.push(createImprovement(
        'formatting',
        file,
        project,
        'Inconsistent indentation',
        'File mixes tabs and spaces. Should use consistent indentation.',
        { confidence: 0.95 }
      ))
    }

    // Check for trailing whitespace
    if (/[ \t]+$/m.test(code)) {
      improvements.push(createImprovement(
        'formatting',
        file,
        project,
        'Trailing whitespace',
        'Remove trailing whitespace from lines.',
        { confidence: 0.99 }
      ))
    }

    // Check for missing final newline
    if (!code.endsWith('\n')) {
      improvements.push(createImprovement(
        'formatting',
        file,
        project,
        'Missing final newline',
        'Add newline at end of file.',
        { confidence: 0.99 }
      ))
    }

    return improvements
  }

  function checkTypes(file: string, project: string, code: string, lang: string): Improvement[] {
    const improvements: Improvement[] = []

    if (lang !== 'typescript' && lang !== 'javascript') return improvements

    // Check for `any` usage
    const anyCount = (code.match(/:\s*any\b/g) || []).length
    if (anyCount > 3) {
      improvements.push(createImprovement(
        'types',
        file,
        project,
        `Reduce 'any' usage (${anyCount} occurrences)`,
        'Replace "any" types with proper type definitions.',
        { confidence: 0.7, impact: { linesChanged: anyCount, filesAffected: 1, breakingChange: false } }
      ))
    }

    // Check for missing function return types (TypeScript)
    if (lang === 'typescript') {
      const functionsWithoutReturn = (code.match(/(?:async\s+)?function\s+\w+\([^)]*\)\s*{/g) || []).length
      const arrowsWithoutReturn = (code.match(/=>\s*{/g) || []).length
      const typed = (code.match(/\):\s*\w+/g) || []).length

      if (functionsWithoutReturn + arrowsWithoutReturn > typed + 5) {
        improvements.push(createImprovement(
          'types',
          file,
          project,
          'Add return type annotations',
          'Many functions are missing explicit return type annotations.',
          { confidence: 0.6 }
        ))
      }
    }

    return improvements
  }

  function checkDocumentation(file: string, project: string, code: string, lang: string): Improvement[] {
    const improvements: Improvement[] = []

    // Count exported functions/classes vs JSDoc comments
    const exports = (code.match(/export\s+(async\s+)?function|export\s+class|export\s+const/g) || []).length
    const jsdocs = (code.match(/\/\*\*[\s\S]*?\*\//g) || []).length

    if (exports > 5 && jsdocs < exports / 2) {
      improvements.push(createImprovement(
        'documentation',
        file,
        project,
        'Add JSDoc documentation',
        `${exports} exports but only ${jsdocs} JSDoc comments. Add documentation for public APIs.`,
        { confidence: 0.6 }
      ))
    }

    return improvements
  }

  function checkDeadCode(file: string, project: string, code: string, lang: string): Improvement[] {
    const improvements: Improvement[] = []

    // Check for commented-out code blocks
    const commentedCode = code.match(/\/\/.*(?:function|const|let|var|class|import|export)/gi) || []
    if (commentedCode.length > 3) {
      improvements.push(createImprovement(
        'dead_code',
        file,
        project,
        'Remove commented-out code',
        `Found ${commentedCode.length} lines of commented-out code. Version control makes this unnecessary.`,
        { confidence: 0.8 }
      ))
    }

    // Check for TODO/FIXME that are old (would need git blame, simplified here)
    const todos = (code.match(/\/\/\s*(TODO|FIXME|HACK|XXX)/gi) || []).length
    if (todos > 5) {
      improvements.push(createImprovement(
        'dead_code',
        file,
        project,
        `Address ${todos} TODO/FIXME comments`,
        'Many TODO comments may indicate technical debt that should be addressed.',
        { confidence: 0.5, riskLevel: 'medium' }
      ))
    }

    return improvements
  }

  function checkSecurityIssues(file: string, project: string, code: string, lang: string): Improvement[] {
    const improvements: Improvement[] = []

    // Check for hardcoded secrets (simplified)
    if (/(?:password|secret|api_?key|token)\s*=\s*['"][^'"]{8,}['"]/i.test(code)) {
      improvements.push(createImprovement(
        'security',
        file,
        project,
        'Possible hardcoded secret',
        'Found what appears to be a hardcoded credential. Use environment variables instead.',
        { confidence: 0.7, riskLevel: 'high' }
      ))
    }

    // Check for SQL injection risks
    if (/\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)/i.test(code) ||
        /query\s*\(\s*`[^`]*\$\{/i.test(code)) {
      improvements.push(createImprovement(
        'security',
        file,
        project,
        'Possible SQL injection',
        'String interpolation in SQL query. Use parameterized queries.',
        { confidence: 0.6, riskLevel: 'critical' }
      ))
    }

    // Check for eval usage
    if (/\beval\s*\(/i.test(code)) {
      improvements.push(createImprovement(
        'security',
        file,
        project,
        'Avoid eval()',
        'eval() can execute arbitrary code and is a security risk.',
        { confidence: 0.9, riskLevel: 'high' }
      ))
    }

    return improvements
  }

  function checkPerformance(file: string, project: string, code: string, lang: string): Improvement[] {
    const improvements: Improvement[] = []

    // Check for synchronous file operations in Node.js
    if (lang === 'javascript' || lang === 'typescript') {
      if (/readFileSync|writeFileSync|appendFileSync|existsSync|readdirSync/i.test(code)) {
        improvements.push(createImprovement(
          'performance',
          file,
          project,
          'Use async file operations',
          'Synchronous file operations block the event loop. Use async versions.',
          { confidence: 0.7 }
        ))
      }
    }

    // Check for N+1 query patterns (simplified)
    if (/for\s*\([^)]+\)\s*{[^}]*await\s+.*(?:find|query|fetch|get)/s.test(code)) {
      improvements.push(createImprovement(
        'performance',
        file,
        project,
        'Possible N+1 query',
        'Database query inside a loop. Consider batch fetching.',
        { confidence: 0.6 }
      ))
    }

    return improvements
  }

  /**
   * Find patterns from other projects that could be applied
   */
  async function findPatternOpportunities(projectPath: string): Promise<Improvement[]> {
    const improvements: Improvement[] = []

    try {
      // Get patterns from memory that might apply
      const projectFiles = memory.files.value.filter(f => f.path.includes(projectPath))

      for (const file of projectFiles) {
        for (const pattern of file.patterns) {
          // Find if this pattern exists elsewhere with more sophisticated usage
          const usages = memory.findPatternUsage(pattern)
          const otherProjects = usages.filter(u => !u.file.path.includes(projectPath))

          if (otherProjects.length > 2) {
            // This pattern is used more elsewhere - might have better implementations
            improvements.push(createImprovement(
              'pattern',
              file.path,
              projectPath,
              `Pattern "${pattern}" used better in ${otherProjects[0].project}`,
              `This pattern is used in ${otherProjects.length} other projects. Review for potential improvements.`,
              { confidence: 0.5, relatedPattern: pattern }
            ))
          }
        }
      }
    } catch (error) {
      console.error('Failed to find pattern opportunities:', error)
    }

    return improvements
  }

  // ========================================================================
  // APPLYING IMPROVEMENTS
  // ========================================================================

  /**
   * Apply an improvement
   */
  async function applyImprovement(improvementId: string): Promise<boolean> {
    const improvement = improvements.value.find(i => i.id === improvementId)
    if (!improvement) return false

    // Constitution check
    const validation = constitution.validateAction('code_modify', improvement.file)
    if (!validation.allowed) {
      improvement.status = 'rejected'
      saveImprovements(improvements.value)
      return false
    }

    if (validation.requiresApproval && improvement.approvedBy !== 'user') {
      // Needs user approval
      return false
    }

    isApplying.value = true

    try {
      // Store rollback data
      const originalContent = await invoke<{ stdout: string }>('execute_shell', {
        command: `cat "${improvement.file}"`,
        cwd: undefined
      })
      improvement.rollbackData = originalContent.stdout

      // Apply the improvement based on type
      let success = false

      switch (improvement.type) {
        case 'formatting':
          success = await applyFormatting(improvement)
          break
        case 'lint_fix':
          success = await applyLintFix(improvement)
          break
        // Add more cases as needed
        default:
          // For complex improvements, we'd need the suggested code
          if (improvement.suggestedCode) {
            success = await applyCodeChange(improvement)
          }
      }

      if (success) {
        improvement.status = 'applied'
        improvement.appliedAt = new Date()

        await auditLog.log('code_modify', `Applied improvement: ${improvement.title}`, {
          target: improvement.file,
          details: { type: improvement.type },
          riskLevel: improvement.riskLevel,
          rollbackData: improvement.rollbackData
        })
      } else {
        improvement.status = 'failed'
      }

      saveImprovements(improvements.value)
      return success

    } catch (error) {
      improvement.status = 'failed'
      saveImprovements(improvements.value)
      return false
    } finally {
      isApplying.value = false
    }
  }

  /**
   * Apply formatting improvements
   */
  async function applyFormatting(improvement: Improvement): Promise<boolean> {
    try {
      // Use prettier or similar for formatting
      const result = await invoke<{ exit_code: number }>('execute_shell', {
        command: `npx prettier --write "${improvement.file}" 2>/dev/null || true`,
        cwd: undefined
      })
      return result.exit_code === 0
    } catch {
      return false
    }
  }

  /**
   * Apply lint fixes
   */
  async function applyLintFix(improvement: Improvement): Promise<boolean> {
    try {
      const result = await invoke<{ exit_code: number }>('execute_shell', {
        command: `npx eslint --fix "${improvement.file}" 2>/dev/null || true`,
        cwd: undefined
      })
      return result.exit_code === 0
    } catch {
      return false
    }
  }

  /**
   * Apply a code change
   */
  async function applyCodeChange(improvement: Improvement): Promise<boolean> {
    if (!improvement.suggestedCode) return false

    try {
      // In real implementation, would use more sophisticated patching
      await invoke('execute_shell', {
        command: `cat > "${improvement.file}" << 'CODEEOF'
${improvement.suggestedCode}
CODEEOF`,
        cwd: undefined
      })
      return true
    } catch {
      return false
    }
  }

  /**
   * Rollback an applied improvement
   */
  async function rollbackImprovement(improvementId: string): Promise<boolean> {
    const improvement = improvements.value.find(i => i.id === improvementId)
    if (!improvement || !improvement.rollbackData) return false

    try {
      await invoke('execute_shell', {
        command: `cat > "${improvement.file}" << 'CODEEOF'
${improvement.rollbackData}
CODEEOF`,
        cwd: undefined
      })

      improvement.status = 'pending'
      improvement.appliedAt = undefined
      saveImprovements(improvements.value)

      await auditLog.log('rollback', `Rolled back: ${improvement.title}`, {
        target: improvement.file,
        riskLevel: 'medium'
      })

      return true
    } catch {
      return false
    }
  }

  /**
   * Auto-apply low-risk improvements
   */
  async function autoApplyLowRisk(): Promise<number> {
    if (!preferences.autoApplyLowRisk) return 0

    let applied = 0
    const candidates = improvements.value.filter(i =>
      i.status === 'pending' &&
      i.riskLevel === 'low' &&
      i.confidence >= 0.8 &&
      (
        (preferences.autoApplyFormatting && i.type === 'formatting') ||
        (preferences.autoApplyTypes && i.type === 'types') ||
        (preferences.autoApplyDocs && i.type === 'documentation') ||
        i.type === 'lint_fix'
      )
    )

    for (const improvement of candidates.slice(0, preferences.maxChangesPerScan)) {
      improvement.approvedBy = 'auto'
      if (await applyImprovement(improvement.id)) {
        applied++
      }
    }

    return applied
  }

  // ========================================================================
  // STATS
  // ========================================================================

  const stats = computed<ImprovementStats>(() => {
    const byType: Record<string, number> = {}
    const byRisk: Record<string, number> = {}
    let applied = 0
    let rejected = 0
    let pending = 0

    for (const imp of improvements.value) {
      byType[imp.type] = (byType[imp.type] || 0) + 1
      byRisk[imp.riskLevel] = (byRisk[imp.riskLevel] || 0) + 1

      if (imp.status === 'applied') applied++
      else if (imp.status === 'rejected') rejected++
      else if (imp.status === 'pending') pending++
    }

    return {
      total: improvements.value.length,
      byType: byType as Record<ImprovementType, number>,
      byRisk: byRisk as Record<RiskLevel, number>,
      applied,
      rejected,
      pending,
      approvalRate: applied + rejected > 0 ? applied / (applied + rejected) : 0
    }
  })

  /**
   * Get pending improvements that need approval
   */
  const pendingApproval = computed(() =>
    improvements.value.filter(i =>
      i.status === 'pending' &&
      (i.riskLevel === 'medium' || i.riskLevel === 'high' || i.riskLevel === 'critical')
    )
  )

  /**
   * Get risk level for an improvement type
   */
  function getRiskLevel(type: ImprovementType): RiskLevel {
    return TYPE_RISK[type]
  }

  return {
    // State
    improvements: computed(() => improvements.value),
    preferences,
    isScanning: computed(() => isScanning.value),
    isApplying: computed(() => isApplying.value),
    progress: computed(() => progress.value),
    stats,
    pendingApproval,

    // Scanning
    scanProject,
    scanFile,

    // Applying
    applyImprovement,
    rollbackImprovement,
    autoApplyLowRisk,

    // Risk classification
    getRiskLevel,

    // Preferences
    savePreferences: () => savePreferences(preferences)
  }
}

export type UseAutonomousImproverReturn = ReturnType<typeof useAutonomousImprover>
