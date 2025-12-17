#!/usr/bin/env npx ts-node
/**
 * GitHub Issue Auto-Tagger
 *
 * Automatically labels GitHub issues based on content analysis.
 * Uses keyword matching and pattern detection to suggest/apply labels.
 *
 * Usage:
 *   npx ts-node scripts/maintainer/auto-tagger.ts
 *
 * Environment Variables:
 *   GITHUB_TOKEN - GitHub Personal Access Token (with repo scope)
 *   GITHUB_REPO - Repository in format "owner/repo"
 *   DRY_RUN - Set to "true" to only log without applying labels
 */

import * as https from 'https'
import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Configuration
const CONFIG = {
  github: {
    token: process.env.GITHUB_TOKEN || '',
    repo: process.env.GITHUB_REPO || 'warp_open/warp_open',
  },
  dryRun: process.env.DRY_RUN === 'true',
  stateFile: path.join(__dirname, '.auto-tagger-state.json'),
}

// Label definitions with keywords and patterns
interface LabelRule {
  name: string
  color: string
  description: string
  keywords: string[]
  titlePatterns?: RegExp[]
  bodyPatterns?: RegExp[]
  priority: number
  autoApply: boolean // Whether to auto-apply or just suggest
}

const LABEL_RULES: LabelRule[] = [
  // Bug-related labels
  {
    name: 'bug',
    color: 'd73a4a',
    description: 'Something is not working',
    keywords: ['bug', 'broken', 'crash', 'error', 'fail', 'doesn\'t work', 'not working', 'issue'],
    titlePatterns: [/\bcrash(es|ed|ing)?\b/i, /\bbug\b/i, /\berror\b/i],
    priority: 1,
    autoApply: true,
  },
  {
    name: 'crash',
    color: 'b60205',
    description: 'Application crash',
    keywords: ['crash', 'panic', 'segfault', 'abort', 'SIGSEGV'],
    bodyPatterns: [/panic/i, /stack trace/i, /backtrace/i],
    priority: 1,
    autoApply: true,
  },

  // Feature requests
  {
    name: 'enhancement',
    color: 'a2eeef',
    description: 'New feature or request',
    keywords: ['feature', 'enhancement', 'request', 'suggestion', 'would be nice', 'could you add'],
    titlePatterns: [/\bfeature\b/i, /\brequest\b/i, /^add\b/i],
    priority: 2,
    autoApply: true,
  },
  {
    name: 'plugin-request',
    color: '7057ff',
    description: 'Plugin idea or request',
    keywords: ['plugin', 'extension', 'addon'],
    titlePatterns: [/plugin/i],
    priority: 2,
    autoApply: true,
  },

  // Area labels
  {
    name: 'area:terminal',
    color: '0e8a16',
    description: 'Terminal/PTY related',
    keywords: ['terminal', 'pty', 'shell', 'bash', 'zsh', 'escape sequence', 'ansi'],
    priority: 3,
    autoApply: false,
  },
  {
    name: 'area:ai',
    color: '1d76db',
    description: 'AI/LLM features',
    keywords: ['ai', 'llm', 'ollama', 'assistant', 'chat', 'generate', 'model'],
    priority: 3,
    autoApply: false,
  },
  {
    name: 'area:ui',
    color: 'd4c5f9',
    description: 'User interface',
    keywords: ['ui', 'display', 'theme', 'font', 'style', 'layout', 'render'],
    priority: 3,
    autoApply: false,
  },
  {
    name: 'area:plugins',
    color: 'fbca04',
    description: 'Plugin system',
    keywords: ['plugin', 'api', 'extension', 'hook'],
    priority: 3,
    autoApply: false,
  },
  {
    name: 'area:performance',
    color: 'f9d0c4',
    description: 'Performance related',
    keywords: ['slow', 'performance', 'memory', 'cpu', 'lag', 'freeze', 'hang'],
    priority: 3,
    autoApply: false,
  },

  // Platform labels
  {
    name: 'platform:macos',
    color: '000000',
    description: 'macOS specific',
    keywords: ['macos', 'mac os', 'darwin', 'apple', 'macbook', 'imac'],
    priority: 4,
    autoApply: true,
  },
  {
    name: 'platform:linux',
    color: 'fcc624',
    description: 'Linux specific',
    keywords: ['linux', 'ubuntu', 'debian', 'fedora', 'arch', 'x11', 'wayland'],
    priority: 4,
    autoApply: true,
  },
  {
    name: 'platform:windows',
    color: '0078d4',
    description: 'Windows specific',
    keywords: ['windows', 'win10', 'win11', 'powershell', 'cmd', 'conpty'],
    priority: 4,
    autoApply: true,
  },

  // Priority labels
  {
    name: 'priority:critical',
    color: 'e11d48',
    description: 'Critical issue',
    keywords: ['critical', 'urgent', 'severe', 'blocking', 'data loss'],
    priority: 0,
    autoApply: false, // Manual review for priority
  },

  // Metadata labels
  {
    name: 'good-first-issue',
    color: '7057ff',
    description: 'Good for newcomers',
    keywords: [],
    titlePatterns: [],
    priority: 5,
    autoApply: false, // Always manual
  },
  {
    name: 'help-wanted',
    color: '008672',
    description: 'Extra attention is needed',
    keywords: [],
    priority: 5,
    autoApply: false,
  },
  {
    name: 'documentation',
    color: '0075ca',
    description: 'Documentation improvements',
    keywords: ['docs', 'documentation', 'readme', 'guide', 'tutorial', 'typo'],
    priority: 3,
    autoApply: true,
  },
  {
    name: 'duplicate',
    color: 'cfd3d7',
    description: 'Duplicate issue',
    keywords: [],
    priority: 5,
    autoApply: false,
  },
  {
    name: 'wontfix',
    color: 'ffffff',
    description: 'Will not be fixed',
    keywords: [],
    priority: 5,
    autoApply: false,
  },
  {
    name: 'question',
    color: 'd876e3',
    description: 'Further information requested',
    keywords: ['question', 'how do i', 'how to', 'help me', 'can i', 'is it possible'],
    titlePatterns: [/\?$/],
    priority: 2,
    autoApply: true,
  },
]

// State tracking
interface TaggerState {
  processedIssues: number[]
  labeledCount: number
  lastRun: number
}

function loadState(): TaggerState {
  try {
    if (fs.existsSync(CONFIG.stateFile)) {
      return JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf-8'))
    }
  } catch (e) {
    console.error('[State] Failed to load:', e)
  }
  return { processedIssues: [], labeledCount: 0, lastRun: 0 }
}

function saveState(state: TaggerState): void {
  try {
    fs.writeFileSync(CONFIG.stateFile, JSON.stringify(state, null, 2))
  } catch (e) {
    console.error('[State] Failed to save:', e)
  }
}

// HTTP helpers
function githubRequest(
  method: string,
  endpoint: string,
  body?: object
): Promise<any> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: endpoint,
      method,
      headers: {
        'User-Agent': 'Warp_Open-Auto-Tagger/1.0',
        'Authorization': `token ${CONFIG.github.token}`,
        'Accept': 'application/vnd.github.v3+json',
        ...(body && { 'Content-Type': 'application/json' }),
      },
    }

    const req = https.request(options, (res) => {
      let data = ''
      res.on('data', (chunk) => data += chunk)
      res.on('end', () => {
        try {
          resolve(JSON.parse(data))
        } catch {
          resolve(data)
        }
      })
    })
    req.on('error', reject)
    if (body) req.write(JSON.stringify(body))
    req.end()
  })
}

// Analyze issue and determine labels
function analyzeIssue(issue: any): { suggested: string[]; autoApply: string[] } {
  const title = (issue.title || '').toLowerCase()
  const body = (issue.body || '').toLowerCase()
  const combined = `${title} ${body}`

  const suggested: Set<string> = new Set()
  const autoApply: Set<string> = new Set()

  for (const rule of LABEL_RULES) {
    let matched = false

    // Check keywords
    if (rule.keywords.some(kw => combined.includes(kw.toLowerCase()))) {
      matched = true
    }

    // Check title patterns
    if (rule.titlePatterns?.some(p => p.test(issue.title || ''))) {
      matched = true
    }

    // Check body patterns
    if (rule.bodyPatterns?.some(p => p.test(issue.body || ''))) {
      matched = true
    }

    if (matched) {
      if (rule.autoApply) {
        autoApply.add(rule.name)
      } else {
        suggested.add(rule.name)
      }
    }
  }

  return {
    suggested: Array.from(suggested),
    autoApply: Array.from(autoApply),
  }
}

// Ensure labels exist in repo
async function ensureLabelsExist(): Promise<void> {
  console.log('[Labels] Ensuring labels exist...')

  const existingLabels = await githubRequest(
    'GET',
    `/repos/${CONFIG.github.repo}/labels?per_page=100`
  )

  const existingNames = new Set(
    (existingLabels || []).map((l: any) => l.name.toLowerCase())
  )

  for (const rule of LABEL_RULES) {
    if (!existingNames.has(rule.name.toLowerCase())) {
      console.log(`[Labels] Creating: ${rule.name}`)
      if (!CONFIG.dryRun) {
        await githubRequest('POST', `/repos/${CONFIG.github.repo}/labels`, {
          name: rule.name,
          color: rule.color,
          description: rule.description,
        })
      }
    }
  }
}

// Apply labels to an issue
async function applyLabels(issueNumber: number, labels: string[]): Promise<void> {
  if (labels.length === 0) return

  console.log(`[Issue #${issueNumber}] Applying labels: ${labels.join(', ')}`)

  if (!CONFIG.dryRun) {
    await githubRequest(
      'POST',
      `/repos/${CONFIG.github.repo}/issues/${issueNumber}/labels`,
      { labels }
    )
  }
}

// Add suggestion comment
async function addSuggestionComment(
  issueNumber: number,
  suggested: string[],
  autoApplied: string[]
): Promise<void> {
  if (suggested.length === 0 && autoApplied.length === 0) return

  let comment = '🏷️ **Auto-Tagger Analysis**\n\n'

  if (autoApplied.length > 0) {
    comment += `Applied labels: ${autoApplied.map(l => `\`${l}\``).join(', ')}\n\n`
  }

  if (suggested.length > 0) {
    comment += `Suggested labels for maintainer review: ${suggested.map(l => `\`${l}\``).join(', ')}\n\n`
  }

  comment += '_This is an automated analysis. Maintainers may adjust labels as needed._'

  console.log(`[Issue #${issueNumber}] Adding comment`)

  if (!CONFIG.dryRun) {
    await githubRequest(
      'POST',
      `/repos/${CONFIG.github.repo}/issues/${issueNumber}/comments`,
      { body: comment }
    )
  }
}

// Process new issues
async function processNewIssues(state: TaggerState): Promise<void> {
  console.log('[Issues] Fetching open issues...')

  const issues = await githubRequest(
    'GET',
    `/repos/${CONFIG.github.repo}/issues?state=open&sort=created&direction=desc&per_page=20`
  )

  if (!Array.isArray(issues)) {
    console.error('[Issues] Unexpected response:', issues)
    return
  }

  for (const issue of issues) {
    // Skip PRs (GitHub API returns PRs in issues endpoint)
    if (issue.pull_request) continue

    // Skip already processed
    if (state.processedIssues.includes(issue.number)) continue

    // Skip issues that already have labels
    if (issue.labels && issue.labels.length > 0) {
      console.log(`[Issue #${issue.number}] Already labeled, skipping`)
      state.processedIssues.push(issue.number)
      continue
    }

    console.log(`\n[Issue #${issue.number}] ${issue.title}`)

    const analysis = analyzeIssue(issue)

    if (analysis.autoApply.length > 0 || analysis.suggested.length > 0) {
      // Apply auto labels
      await applyLabels(issue.number, analysis.autoApply)

      // Add comment with analysis
      await addSuggestionComment(issue.number, analysis.suggested, analysis.autoApply)

      state.labeledCount++
    } else {
      console.log(`[Issue #${issue.number}] No labels matched`)
    }

    state.processedIssues.push(issue.number)

    // Rate limiting
    await new Promise(resolve => setTimeout(resolve, 500))
  }

  // Keep only last 500 processed issue numbers
  state.processedIssues = state.processedIssues.slice(-500)
}

// Main entry point
async function main(): Promise<void> {
  console.log('╔════════════════════════════════════════════╗')
  console.log('║      Warp_Open GitHub Issue Auto-Tagger    ║')
  console.log('╚════════════════════════════════════════════╝')
  console.log('')

  if (!CONFIG.github.token) {
    console.error('Error: GITHUB_TOKEN environment variable required')
    process.exit(1)
  }

  console.log('Configuration:')
  console.log(`  Repository: ${CONFIG.github.repo}`)
  console.log(`  Dry Run: ${CONFIG.dryRun}`)
  console.log(`  Rules: ${LABEL_RULES.length}`)
  console.log('')

  const state = loadState()

  // Ensure all labels exist
  await ensureLabelsExist()

  // Process issues
  await processNewIssues(state)

  state.lastRun = Date.now()
  saveState(state)

  console.log('')
  console.log(`Done! Labeled ${state.labeledCount} issues total.`)
}

main().catch(console.error)
