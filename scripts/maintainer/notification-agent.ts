#!/usr/bin/env npx ts-node
/**
 * Maintainer Notification Agent
 *
 * Monitors GitHub, Hacker News, and Reddit for activity on Warp_Open.
 * Sends notifications via desktop alerts and optional Discord/Slack webhooks.
 *
 * Usage:
 *   npx ts-node scripts/maintainer/notification-agent.ts
 *
 * Environment Variables:
 *   GITHUB_TOKEN - GitHub Personal Access Token
 *   GITHUB_REPO - Repository in format "owner/repo"
 *   HN_STORY_ID - Hacker News story ID (from Show HN post)
 *   REDDIT_CLIENT_ID - Reddit app client ID
 *   REDDIT_CLIENT_SECRET - Reddit app client secret
 *   DISCORD_WEBHOOK_URL - Discord webhook for notifications
 *   SLACK_WEBHOOK_URL - Slack webhook for notifications
 */

import * as https from 'https'
import * as fs from 'fs'
import * as path from 'path'
import { exec } from 'child_process'
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
  reddit: {
    clientId: process.env.REDDIT_CLIENT_ID || '',
    clientSecret: process.env.REDDIT_CLIENT_SECRET || '',
    subreddits: ['commandline', 'rust', 'selfhosted', 'vuejs'],
  },
  webhooks: {
    discord: process.env.DISCORD_WEBHOOK_URL || '',
    slack: process.env.SLACK_WEBHOOK_URL || '',
  },
  pollInterval: 60000, // 1 minute
  stateFile: path.join(__dirname, '.notification-state.json'),
}

// State tracking
interface NotificationState {
  github: {
    lastIssueId: number
    lastStars: number
    lastPRId: number
    lastCommentId: number
  }
  hn: {
    lastCommentCount: number
    lastScore: number
    seenCommentIds: string[]
  }
  reddit: {
    seenPostIds: string[]
    seenCommentIds: string[]
  }
  lastChecked: number
}

const defaultState: NotificationState = {
  github: {
    lastIssueId: 0,
    lastStars: 0,
    lastPRId: 0,
    lastCommentId: 0,
  },
  hn: {
    lastCommentCount: 0,
    lastScore: 0,
    seenCommentIds: [],
  },
  reddit: {
    seenPostIds: [],
    seenCommentIds: [],
  },
  lastChecked: Date.now(),
}

// Load/save state
function loadState(): NotificationState {
  try {
    if (fs.existsSync(CONFIG.stateFile)) {
      return JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf-8'))
    }
  } catch (e) {
    console.error('[State] Failed to load state:', e)
  }
  return { ...defaultState }
}

function saveState(state: NotificationState): void {
  try {
    fs.writeFileSync(CONFIG.stateFile, JSON.stringify(state, null, 2))
  } catch (e) {
    console.error('[State] Failed to save state:', e)
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
        'User-Agent': 'Warp_Open-Notification-Agent/1.0',
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

function httpPost(url: string, body: object, headers: Record<string, string> = {}): Promise<any> {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url)
    const postData = JSON.stringify(body)
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'User-Agent': 'Warp_Open-Notification-Agent/1.0',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        ...headers,
      },
    }

    const req = https.request(options, (res) => {
      let data = ''
      res.on('data', (chunk) => data += chunk)
      res.on('end', () => resolve(data))
    })
    req.on('error', reject)
    req.write(postData)
    req.end()
  })
}

// Desktop notification
function sendDesktopNotification(title: string, message: string): void {
  if (process.platform === 'darwin') {
    exec(`osascript -e 'display notification "${message}" with title "${title}"'`)
  } else if (process.platform === 'linux') {
    exec(`notify-send "${title}" "${message}"`)
  }
  console.log(`[NOTIFY] ${title}: ${message}`)
}

// Webhook notifications
async function sendDiscordNotification(title: string, message: string, url?: string): Promise<void> {
  if (!CONFIG.webhooks.discord) return

  const embed = {
    title,
    description: message,
    color: 0x6366f1, // Indigo
    timestamp: new Date().toISOString(),
    ...(url && { url }),
  }

  try {
    await httpPost(CONFIG.webhooks.discord, { embeds: [embed] })
  } catch (e) {
    console.error('[Discord] Failed to send notification:', e)
  }
}

async function sendSlackNotification(title: string, message: string, url?: string): Promise<void> {
  if (!CONFIG.webhooks.slack) return

  const blocks = [
    {
      type: 'header',
      text: { type: 'plain_text', text: title },
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: message },
    },
    ...(url ? [{
      type: 'section',
      text: { type: 'mrkdwn', text: `<${url}|View on platform>` },
    }] : []),
  ]

  try {
    await httpPost(CONFIG.webhooks.slack, { blocks })
  } catch (e) {
    console.error('[Slack] Failed to send notification:', e)
  }
}

async function notify(title: string, message: string, url?: string): Promise<void> {
  sendDesktopNotification(title, message)
  await Promise.all([
    sendDiscordNotification(title, message, url),
    sendSlackNotification(title, message, url),
  ])
}

// GitHub monitoring
async function checkGitHub(state: NotificationState): Promise<void> {
  if (!CONFIG.github.token) {
    console.log('[GitHub] No token configured, skipping')
    return
  }

  const headers = {
    'Authorization': `token ${CONFIG.github.token}`,
    'Accept': 'application/vnd.github.v3+json',
  }

  try {
    // Check stars
    const repo = await httpGet(
      `https://api.github.com/repos/${CONFIG.github.repo}`,
      headers
    )

    if (repo.stargazers_count > state.github.lastStars) {
      const newStars = repo.stargazers_count - state.github.lastStars
      if (state.github.lastStars > 0) {
        await notify(
          '⭐ New GitHub Stars',
          `+${newStars} stars! Total: ${repo.stargazers_count}`,
          `https://github.com/${CONFIG.github.repo}`
        )
      }
      state.github.lastStars = repo.stargazers_count
    }

    // Check new issues
    const issues = await httpGet(
      `https://api.github.com/repos/${CONFIG.github.repo}/issues?state=open&sort=created&direction=desc`,
      headers
    )

    for (const issue of issues) {
      if (issue.id > state.github.lastIssueId && !issue.pull_request) {
        await notify(
          '📋 New Issue',
          `#${issue.number}: ${issue.title}`,
          issue.html_url
        )
      }
    }
    if (issues.length > 0) {
      state.github.lastIssueId = Math.max(state.github.lastIssueId, issues[0]?.id || 0)
    }

    // Check new PRs
    const prs = await httpGet(
      `https://api.github.com/repos/${CONFIG.github.repo}/pulls?state=open&sort=created&direction=desc`,
      headers
    )

    for (const pr of prs) {
      if (pr.id > state.github.lastPRId) {
        await notify(
          '🔀 New Pull Request',
          `#${pr.number}: ${pr.title}`,
          pr.html_url
        )
      }
    }
    if (prs.length > 0) {
      state.github.lastPRId = Math.max(state.github.lastPRId, prs[0]?.id || 0)
    }

    console.log(`[GitHub] Stars: ${repo.stargazers_count}, Issues: ${issues.length}, PRs: ${prs.length}`)

  } catch (e) {
    console.error('[GitHub] Error checking:', e)
  }
}

// Hacker News monitoring
async function checkHackerNews(state: NotificationState): Promise<void> {
  if (!CONFIG.hn.storyId) {
    console.log('[HN] No story ID configured, skipping')
    return
  }

  try {
    const story = await httpGet(
      `https://hacker-news.firebaseio.com/v0/item/${CONFIG.hn.storyId}.json`
    )

    if (!story) {
      console.log('[HN] Story not found')
      return
    }

    // Check score increase
    if (story.score > state.hn.lastScore) {
      const increase = story.score - state.hn.lastScore
      if (state.hn.lastScore > 0 && increase >= 10) {
        await notify(
          '🔥 HN Points Milestone',
          `+${increase} points! Total: ${story.score}`,
          `https://news.ycombinator.com/item?id=${CONFIG.hn.storyId}`
        )
      }
      state.hn.lastScore = story.score
    }

    // Check new comments
    const commentCount = story.descendants || 0
    if (commentCount > state.hn.lastCommentCount) {
      const newComments = commentCount - state.hn.lastCommentCount
      if (state.hn.lastCommentCount > 0) {
        await notify(
          '💬 New HN Comments',
          `+${newComments} comments! Total: ${commentCount}`,
          `https://news.ycombinator.com/item?id=${CONFIG.hn.storyId}`
        )
      }
      state.hn.lastCommentCount = commentCount
    }

    // Check for new top-level comments (kids)
    if (story.kids) {
      for (const kidId of story.kids.slice(0, 5)) {
        if (!state.hn.seenCommentIds.includes(String(kidId))) {
          const comment = await httpGet(
            `https://hacker-news.firebaseio.com/v0/item/${kidId}.json`
          )
          if (comment && comment.text) {
            const preview = comment.text.replace(/<[^>]*>/g, '').slice(0, 100)
            await notify(
              '💬 New HN Comment',
              `by ${comment.by}: ${preview}...`,
              `https://news.ycombinator.com/item?id=${kidId}`
            )
          }
          state.hn.seenCommentIds.push(String(kidId))
        }
      }
      // Keep only last 100 seen comments
      state.hn.seenCommentIds = state.hn.seenCommentIds.slice(-100)
    }

    console.log(`[HN] Score: ${story.score}, Comments: ${commentCount}`)

  } catch (e) {
    console.error('[HN] Error checking:', e)
  }
}

// Reddit monitoring (simplified without OAuth for now)
async function checkReddit(state: NotificationState): Promise<void> {
  const searchTerm = 'warp_open OR "warp open source"'

  try {
    // Search for mentions
    const searchUrl = `https://www.reddit.com/search.json?q=${encodeURIComponent(searchTerm)}&sort=new&limit=10`
    const results = await httpGet(searchUrl)

    if (results?.data?.children) {
      for (const post of results.data.children) {
        const data = post.data
        if (!state.reddit.seenPostIds.includes(data.id)) {
          await notify(
            `📢 Reddit: r/${data.subreddit}`,
            data.title.slice(0, 80),
            `https://reddit.com${data.permalink}`
          )
          state.reddit.seenPostIds.push(data.id)
        }
      }
      // Keep only last 100 seen posts
      state.reddit.seenPostIds = state.reddit.seenPostIds.slice(-100)
    }

    console.log('[Reddit] Checked for mentions')

  } catch (e) {
    console.error('[Reddit] Error checking:', e)
  }
}

// Main polling loop
async function poll(): Promise<void> {
  const state = loadState()

  console.log(`\n[${new Date().toISOString()}] Polling...`)

  await checkGitHub(state)
  await checkHackerNews(state)
  await checkReddit(state)

  state.lastChecked = Date.now()
  saveState(state)
}

// Entry point
async function main(): Promise<void> {
  console.log('╔════════════════════════════════════════════╗')
  console.log('║   Warp_Open Maintainer Notification Agent  ║')
  console.log('╚════════════════════════════════════════════╝')
  console.log('')
  console.log('Configuration:')
  console.log(`  GitHub: ${CONFIG.github.token ? '✓' : '✗'} ${CONFIG.github.repo}`)
  console.log(`  HN Story: ${CONFIG.hn.storyId || 'Not configured'}`)
  console.log(`  Discord: ${CONFIG.webhooks.discord ? '✓' : '✗'}`)
  console.log(`  Slack: ${CONFIG.webhooks.slack ? '✓' : '✗'}`)
  console.log(`  Poll Interval: ${CONFIG.pollInterval / 1000}s`)
  console.log('')

  // Initial poll
  await poll()

  // Set up interval
  setInterval(poll, CONFIG.pollInterval)

  console.log('Notification agent running. Press Ctrl+C to stop.')
}

main().catch(console.error)
