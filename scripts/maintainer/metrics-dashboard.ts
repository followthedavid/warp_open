#!/usr/bin/env npx ts-node
/**
 * Metrics Dashboard
 *
 * Collects and displays key metrics for Warp_Open across platforms.
 * Generates reports for tracking launch success.
 *
 * Usage:
 *   npx ts-node scripts/maintainer/metrics-dashboard.ts
 *   npx ts-node scripts/maintainer/metrics-dashboard.ts --json
 *   npx ts-node scripts/maintainer/metrics-dashboard.ts --markdown
 *
 * Environment Variables:
 *   GITHUB_TOKEN - GitHub Personal Access Token
 *   GITHUB_REPO - Repository in format "owner/repo"
 *   HN_STORY_ID - Hacker News story ID
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
  hn: {
    storyId: process.env.HN_STORY_ID || '',
  },
  outputDir: path.join(__dirname, '../../launch/metrics'),
}

// Metrics data structure
interface Metrics {
  timestamp: number
  github: {
    stars: number
    forks: number
    watchers: number
    openIssues: number
    closedIssues: number
    openPRs: number
    mergedPRs: number
    contributors: number
    releases: number
    totalDownloads: number
    topContributors: Array<{ login: string; contributions: number }>
    recentIssues: Array<{ number: number; title: string; labels: string[] }>
    recentPRs: Array<{ number: number; title: string; author: string }>
  }
  hn?: {
    score: number
    comments: number
    position?: number
  }
  trends: {
    starsToday: number
    issuesOpened: number
    issuesClosed: number
    prsOpened: number
    prsMerged: number
  }
}

// HTTP request helper
function httpGet(url: string, headers: Record<string, string> = {}): Promise<any> {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url)
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Warp_Open-Metrics-Dashboard/1.0',
        ...headers,
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
    req.end()
  })
}

// GitHub API helper
function githubRequest(endpoint: string): Promise<any> {
  return httpGet(`https://api.github.com${endpoint}`, {
    'Authorization': `token ${CONFIG.github.token}`,
    'Accept': 'application/vnd.github.v3+json',
  })
}

// Collect GitHub metrics
async function collectGitHubMetrics(): Promise<Metrics['github']> {
  const [owner, repo] = CONFIG.github.repo.split('/')

  // Get repo info
  const repoData = await githubRequest(`/repos/${CONFIG.github.repo}`)

  // Get issues
  const openIssues = await githubRequest(
    `/repos/${CONFIG.github.repo}/issues?state=open&per_page=100`
  )
  const closedIssues = await githubRequest(
    `/repos/${CONFIG.github.repo}/issues?state=closed&per_page=100`
  )

  // Filter actual issues (not PRs)
  const actualOpenIssues = openIssues.filter((i: any) => !i.pull_request)
  const actualClosedIssues = closedIssues.filter((i: any) => !i.pull_request)

  // Get PRs
  const openPRs = await githubRequest(
    `/repos/${CONFIG.github.repo}/pulls?state=open`
  )
  const closedPRs = await githubRequest(
    `/repos/${CONFIG.github.repo}/pulls?state=closed&per_page=50`
  )
  const mergedPRs = closedPRs.filter((p: any) => p.merged_at)

  // Get contributors
  const contributors = await githubRequest(
    `/repos/${CONFIG.github.repo}/contributors?per_page=10`
  )

  // Get releases
  const releases = await githubRequest(
    `/repos/${CONFIG.github.repo}/releases`
  )

  // Calculate total downloads from releases
  let totalDownloads = 0
  for (const release of releases || []) {
    for (const asset of release.assets || []) {
      totalDownloads += asset.download_count || 0
    }
  }

  return {
    stars: repoData.stargazers_count || 0,
    forks: repoData.forks_count || 0,
    watchers: repoData.subscribers_count || 0,
    openIssues: actualOpenIssues.length,
    closedIssues: actualClosedIssues.length,
    openPRs: openPRs.length,
    mergedPRs: mergedPRs.length,
    contributors: contributors?.length || 0,
    releases: releases?.length || 0,
    totalDownloads,
    topContributors: (contributors || []).slice(0, 5).map((c: any) => ({
      login: c.login,
      contributions: c.contributions,
    })),
    recentIssues: actualOpenIssues.slice(0, 5).map((i: any) => ({
      number: i.number,
      title: i.title,
      labels: (i.labels || []).map((l: any) => l.name),
    })),
    recentPRs: openPRs.slice(0, 5).map((p: any) => ({
      number: p.number,
      title: p.title,
      author: p.user?.login || 'unknown',
    })),
  }
}

// Collect Hacker News metrics
async function collectHNMetrics(): Promise<Metrics['hn'] | undefined> {
  if (!CONFIG.hn.storyId) return undefined

  try {
    const story = await httpGet(
      `https://hacker-news.firebaseio.com/v0/item/${CONFIG.hn.storyId}.json`
    )

    if (!story) return undefined

    return {
      score: story.score || 0,
      comments: story.descendants || 0,
    }
  } catch (e) {
    console.error('[HN] Error fetching metrics:', e)
    return undefined
  }
}

// Load previous metrics for trend calculation
function loadPreviousMetrics(): Metrics | null {
  const historyFile = path.join(CONFIG.outputDir, 'history.json')
  try {
    if (fs.existsSync(historyFile)) {
      const history = JSON.parse(fs.readFileSync(historyFile, 'utf-8'))
      // Get yesterday's metrics
      const yesterday = Date.now() - 24 * 60 * 60 * 1000
      const recent = history.filter((m: Metrics) => m.timestamp > yesterday)
      return recent[0] || null
    }
  } catch (e) {
    console.error('[History] Error loading:', e)
  }
  return null
}

// Save metrics to history
function saveMetrics(metrics: Metrics): void {
  if (!fs.existsSync(CONFIG.outputDir)) {
    fs.mkdirSync(CONFIG.outputDir, { recursive: true })
  }

  const historyFile = path.join(CONFIG.outputDir, 'history.json')
  let history: Metrics[] = []

  try {
    if (fs.existsSync(historyFile)) {
      history = JSON.parse(fs.readFileSync(historyFile, 'utf-8'))
    }
  } catch (e) {
    // Start fresh
  }

  history.unshift(metrics)
  // Keep 30 days of history
  history = history.slice(0, 720) // ~30 days at hourly collection

  fs.writeFileSync(historyFile, JSON.stringify(history, null, 2))

  // Also save latest
  fs.writeFileSync(
    path.join(CONFIG.outputDir, 'latest.json'),
    JSON.stringify(metrics, null, 2)
  )
}

// Format for terminal display
function formatTerminalDisplay(metrics: Metrics): string {
  const lines: string[] = []

  lines.push('')
  lines.push('╔═══════════════════════════════════════════════════════════════╗')
  lines.push('║               WARP_OPEN METRICS DASHBOARD                     ║')
  lines.push('║           ' + new Date(metrics.timestamp).toISOString().slice(0, 19).replace('T', ' ') + '                        ║')
  lines.push('╠═══════════════════════════════════════════════════════════════╣')

  // GitHub stats
  lines.push('║  📊 GITHUB                                                     ║')
  lines.push('╠═══════════════════════════════════════════════════════════════╣')
  lines.push(`║  ⭐ Stars:        ${padRight(metrics.github.stars, 8)} ${trend(metrics.trends.starsToday)}`)
  lines.push(`║  🍴 Forks:        ${padRight(metrics.github.forks, 8)}                               ║`)
  lines.push(`║  👀 Watchers:     ${padRight(metrics.github.watchers, 8)}                               ║`)
  lines.push(`║  📦 Downloads:    ${padRight(metrics.github.totalDownloads, 8)}                               ║`)

  lines.push('║                                                                ║')
  lines.push(`║  📋 Issues Open:  ${padRight(metrics.github.openIssues, 8)} (${metrics.trends.issuesOpened} new, ${metrics.trends.issuesClosed} closed)`)
  lines.push(`║  🔀 PRs Open:     ${padRight(metrics.github.openPRs, 8)} (${metrics.trends.prsOpened} new, ${metrics.trends.prsMerged} merged)`)
  lines.push(`║  👥 Contributors: ${padRight(metrics.github.contributors, 8)}                               ║`)
  lines.push(`║  📦 Releases:     ${padRight(metrics.github.releases, 8)}                               ║`)

  // HN stats
  if (metrics.hn) {
    lines.push('╠═══════════════════════════════════════════════════════════════╣')
    lines.push('║  🔥 HACKER NEWS                                                ║')
    lines.push('╠═══════════════════════════════════════════════════════════════╣')
    lines.push(`║  📈 Score:        ${padRight(metrics.hn.score, 8)}                               ║`)
    lines.push(`║  💬 Comments:     ${padRight(metrics.hn.comments, 8)}                               ║`)
  }

  // Recent activity
  if (metrics.github.recentIssues.length > 0) {
    lines.push('╠═══════════════════════════════════════════════════════════════╣')
    lines.push('║  📋 RECENT ISSUES                                              ║')
    lines.push('╠═══════════════════════════════════════════════════════════════╣')
    for (const issue of metrics.github.recentIssues.slice(0, 3)) {
      const labels = issue.labels.length > 0 ? ` [${issue.labels.slice(0, 2).join(', ')}]` : ''
      lines.push(`║  #${issue.number}: ${truncate(issue.title, 40)}${truncate(labels, 15)}`)
    }
  }

  // Top contributors
  if (metrics.github.topContributors.length > 0) {
    lines.push('╠═══════════════════════════════════════════════════════════════╣')
    lines.push('║  👥 TOP CONTRIBUTORS                                           ║')
    lines.push('╠═══════════════════════════════════════════════════════════════╣')
    for (const contrib of metrics.github.topContributors.slice(0, 3)) {
      lines.push(`║  @${padRight(contrib.login, 20)} ${contrib.contributions} commits                ║`)
    }
  }

  lines.push('╚═══════════════════════════════════════════════════════════════╝')
  lines.push('')

  return lines.join('\n')
}

// Format as Markdown report
function formatMarkdownReport(metrics: Metrics): string {
  const date = new Date(metrics.timestamp).toISOString().slice(0, 10)
  let md = `# Warp_Open Metrics Report\n\n`
  md += `**Generated:** ${new Date(metrics.timestamp).toISOString()}\n\n`

  md += `## GitHub Statistics\n\n`
  md += `| Metric | Value | Trend |\n`
  md += `|--------|-------|-------|\n`
  md += `| Stars | ${metrics.github.stars} | ${trendEmoji(metrics.trends.starsToday)} |\n`
  md += `| Forks | ${metrics.github.forks} | - |\n`
  md += `| Watchers | ${metrics.github.watchers} | - |\n`
  md += `| Downloads | ${metrics.github.totalDownloads} | - |\n`
  md += `| Open Issues | ${metrics.github.openIssues} | +${metrics.trends.issuesOpened}/-${metrics.trends.issuesClosed} |\n`
  md += `| Open PRs | ${metrics.github.openPRs} | +${metrics.trends.prsOpened} |\n`
  md += `| Contributors | ${metrics.github.contributors} | - |\n`
  md += `| Releases | ${metrics.github.releases} | - |\n\n`

  if (metrics.hn) {
    md += `## Hacker News\n\n`
    md += `| Metric | Value |\n`
    md += `|--------|-------|\n`
    md += `| Score | ${metrics.hn.score} |\n`
    md += `| Comments | ${metrics.hn.comments} |\n\n`
  }

  if (metrics.github.recentIssues.length > 0) {
    md += `## Recent Issues\n\n`
    for (const issue of metrics.github.recentIssues) {
      const labels = issue.labels.length > 0 ? ` \`${issue.labels.join('` `')}\`` : ''
      md += `- **#${issue.number}**: ${issue.title}${labels}\n`
    }
    md += '\n'
  }

  if (metrics.github.topContributors.length > 0) {
    md += `## Top Contributors\n\n`
    for (const contrib of metrics.github.topContributors) {
      md += `- @${contrib.login} (${contrib.contributions} commits)\n`
    }
    md += '\n'
  }

  return md
}

// Helpers
function padRight(value: any, width: number): string {
  const str = String(value)
  return str + ' '.repeat(Math.max(0, width - str.length))
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text + ' '.repeat(maxLen - text.length) + '║'
  return text.slice(0, maxLen - 3) + '...║'
}

function trend(value: number): string {
  if (value > 0) return `(+${value} today)                      ║`
  if (value < 0) return `(${value} today)                       ║`
  return `                                        ║`
}

function trendEmoji(value: number): string {
  if (value > 10) return `🚀 +${value}`
  if (value > 0) return `📈 +${value}`
  if (value < 0) return `📉 ${value}`
  return '-'
}

// Main collection function
async function collectMetrics(): Promise<Metrics> {
  console.log('Collecting metrics...\n')

  const previousMetrics = loadPreviousMetrics()

  const [github, hn] = await Promise.all([
    collectGitHubMetrics(),
    collectHNMetrics(),
  ])

  // Calculate trends
  const trends = {
    starsToday: previousMetrics ? github.stars - previousMetrics.github.stars : 0,
    issuesOpened: 0, // Would need more complex calculation
    issuesClosed: 0,
    prsOpened: 0,
    prsMerged: 0,
  }

  const metrics: Metrics = {
    timestamp: Date.now(),
    github,
    hn,
    trends,
  }

  return metrics
}

// Main entry point
async function main(): Promise<void> {
  if (!CONFIG.github.token) {
    console.error('Error: GITHUB_TOKEN environment variable required')
    process.exit(1)
  }

  const args = process.argv.slice(2)

  try {
    const metrics = await collectMetrics()

    // Save metrics
    saveMetrics(metrics)

    // Output based on format
    if (args.includes('--json')) {
      console.log(JSON.stringify(metrics, null, 2))
    } else if (args.includes('--markdown')) {
      const report = formatMarkdownReport(metrics)
      console.log(report)

      // Also save to file
      const reportFile = path.join(CONFIG.outputDir, `report-${new Date().toISOString().slice(0, 10)}.md`)
      fs.writeFileSync(reportFile, report)
      console.log(`\nSaved to: ${reportFile}`)
    } else {
      console.log(formatTerminalDisplay(metrics))
    }

  } catch (e) {
    console.error('Error collecting metrics:', e)
    process.exit(1)
  }
}

main().catch(console.error)
