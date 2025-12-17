#!/usr/bin/env npx ts-node
/**
 * Response Suggester
 *
 * Analyzes GitHub issues and suggests appropriate response templates.
 * Uses pattern matching to identify question types and recommend responses.
 *
 * Usage:
 *   npx ts-node scripts/maintainer/response-suggester.ts [issue-number]
 *   npx ts-node scripts/maintainer/response-suggester.ts --all
 *
 * Environment Variables:
 *   GITHUB_TOKEN - GitHub Personal Access Token
 *   GITHUB_REPO - Repository in format "owner/repo"
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
  responsesFile: path.join(__dirname, '../../launch/RESPONSES.md'),
}

// Response template definitions
interface ResponseTemplate {
  id: string
  title: string
  triggers: {
    keywords: string[]
    patterns?: RegExp[]
  }
  template: string
  priority: number
}

const RESPONSE_TEMPLATES: ResponseTemplate[] = [
  {
    id: 'why-not-contribute-warp',
    title: 'Why not contribute to Warp instead?',
    triggers: {
      keywords: ['contribute', 'why not', 'warp', 'proprietary'],
      patterns: [/why.*not.*contribute/i, /warp.*open.*source/i],
    },
    template: `Great question! Warp is proprietary software, so contributing directly isn't possible. More importantly, my goals are different:

1. **Local-first** - I wanted no cloud dependencies whatsoever
2. **Open AI** - Using Ollama means any model, no API keys, works offline
3. **Extensible** - The Plugin API v2 lets anyone extend the terminal

Think of Warp_Open as "what if Warp was open source and local-first from day one."`,
    priority: 1,
  },
  {
    id: 'production-ready',
    title: 'Is this production ready?',
    triggers: {
      keywords: ['production', 'stable', 'ready', 'daily use', 'reliable'],
      patterns: [/production.*ready/i, /stable.*enough/i, /daily.*driver/i],
    },
    template: `v1.0.0 is stable for daily use. I've been using it as my primary terminal.

**What's solid:**
- Core terminal functionality (PTY, tabs, splits)
- Session persistence and recovery
- AI features with Ollama

**Caveats:**
- Windows support is experimental
- No SSH integration yet (v2 roadmap)
- New project, fewer battle-tested edge cases than iTerm2

If you hit issues, please file them! We have crash logging and 53 tests.`,
    priority: 1,
  },
  {
    id: 'windows-support',
    title: 'Windows support?',
    triggers: {
      keywords: ['windows', 'win10', 'win11', 'powershell'],
      patterns: [/windows.*support/i, /run.*on.*windows/i],
    },
    template: `Windows is supported but experimental. Known issues:

- ConPTY behavior differs from Unix PTY
- Some keyboard shortcuts conflict with Windows defaults
- Performance may be lower than macOS/Linux

We'd love Windows contributors to help improve this. See the [contributing guide](./CONTRIBUTING.md).`,
    priority: 2,
  },
  {
    id: 'why-local-ai',
    title: 'Why local AI only?',
    triggers: {
      keywords: ['openai', 'anthropic', 'api key', 'cloud ai', 'gpt', 'claude'],
      patterns: [/why.*local.*ai/i, /use.*openai/i, /cloud.*api/i],
    },
    template: `Intentional design choice. Local-first means:

1. **Privacy** - Your terminal data never leaves your machine
2. **No cost** - No API keys, no usage fees
3. **Offline** - Works without internet
4. **Control** - Use any model you want via Ollama

That said, the architecture could support external APIs. If there's demand, we could add it as an opt-in feature with clear privacy warnings.`,
    priority: 2,
  },
  {
    id: 'compare-terminals',
    title: 'How does this compare to iTerm2/Alacritty/Kitty?',
    triggers: {
      keywords: ['compare', 'iterm', 'alacritty', 'kitty', 'terminal emulator', 'vs'],
      patterns: [/compare.*to/i, /vs.*iterm/i, /better.*than/i],
    },
    template: `Different goals:

| Feature | Warp_Open | iTerm2 | Alacritty |
|---------|-----------|--------|-----------|
| Command Blocks | ✅ | ❌ | ❌ |
| AI Assistant | ✅ (local) | ❌ | ❌ |
| Notebooks | ✅ | ❌ | ❌ |
| Plugins | ✅ (v2 API) | Scripts | ❌ |
| GPU Rendering | ✅ (WebGL) | ❌ | ✅ |

If you want a fast, minimal terminal → Alacritty
If you want mature macOS features → iTerm2
If you want Warp's UX + local AI → Warp_Open`,
    priority: 2,
  },
  {
    id: 'why-tauri',
    title: 'Why Tauri instead of Electron?',
    triggers: {
      keywords: ['tauri', 'electron', 'rust', 'webview'],
      patterns: [/why.*tauri/i, /not.*electron/i],
    },
    template: `Performance and security:

1. **Smaller binary** - Tauri apps are ~10MB vs Electron's ~150MB+
2. **Lower memory** - No bundled Chromium
3. **Native performance** - Rust backend
4. **Security** - Explicit permission system

Trade-off: Slightly less cross-platform consistency (WebView varies by OS).`,
    priority: 3,
  },
  {
    id: 'tmux-support',
    title: 'Can I use this with tmux/screen?',
    triggers: {
      keywords: ['tmux', 'screen', 'multiplexer'],
      patterns: [/tmux.*work/i, /use.*with.*tmux/i],
    },
    template: `Yes! Warp_Open is a terminal emulator, so tmux/screen work normally inside it.

However, some Warp-style features (command blocks) rely on shell integration. If you're inside tmux, the OSC 133 sequences may not pass through correctly.

For best results, use Warp_Open's built-in tabs/splits instead of tmux.`,
    priority: 3,
  },
  {
    id: 'install-ollama',
    title: 'How do I install Ollama?',
    triggers: {
      keywords: ['install', 'ollama', 'setup', 'model', 'llm'],
      patterns: [/install.*ollama/i, /setup.*ai/i, /get.*started/i],
    },
    template: `\`\`\`bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Then start Ollama
ollama serve

# Pull a coding model
ollama pull qwen2.5-coder:7b
\`\`\`

See [ollama.ai](https://ollama.ai) for more models and options.`,
    priority: 2,
  },
  {
    id: 'plugin-idea',
    title: 'Plugin idea',
    triggers: {
      keywords: ['plugin idea', 'plugin suggestion', 'add plugin', 'build plugin'],
      patterns: [/plugin.*idea/i, /would.*nice.*plugin/i],
    },
    template: `Thanks for the suggestion! Please open an issue using the [Plugin Idea template](.github/ISSUE_TEMPLATE/plugin_idea.md).

If you're interested in building it yourself, check out:
- [PLUGINS.md](./PLUGINS.md) for API documentation
- \`src/plugins/demos/\` for examples
- The "Good First Plugin Ideas" issue for inspiration`,
    priority: 2,
  },
  {
    id: 'found-bug',
    title: 'Found a bug',
    triggers: {
      keywords: ['bug', 'crash', 'error', 'broken', 'issue', 'problem'],
      patterns: [/found.*bug/i, /report.*issue/i],
    },
    template: `Thanks for reporting! To help us investigate, please provide:

1. Steps to reproduce
2. Expected vs actual behavior
3. OS and Warp_Open version
4. Any logs from \`~/.warp_open/crash.log\`

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md).`,
    priority: 1,
  },
  {
    id: 'how-contribute',
    title: 'How can I contribute?',
    triggers: {
      keywords: ['contribute', 'help', 'pr', 'pull request'],
      patterns: [/how.*contribute/i, /want.*to.*help/i],
    },
    template: `Awesome! Here's how to get started:

1. Read [CONTRIBUTING.md](./CONTRIBUTING.md)
2. Check issues labeled \`good-first-issue\` or \`help-wanted\`
3. Look at the "Good First Plugin Ideas" issue
4. Join discussions for bigger features

Priority areas: Windows fixes, plugins, performance, docs.`,
    priority: 2,
  },
  {
    id: 'cloud-feature',
    title: 'Will you add [cloud feature]?',
    triggers: {
      keywords: ['cloud', 'sync', 'account', 'login', 'telemetry'],
      patterns: [/add.*cloud/i, /sync.*feature/i],
    },
    template: `Warp_Open is intentionally local-first. We won't add features that require:

- User accounts
- Cloud storage
- External telemetry

However, we may add **opt-in** cloud features in the future with:
- Clear privacy disclosures
- Self-hosted options
- Easy disable

The core will always work 100% offline.`,
    priority: 2,
  },
  {
    id: 'positive-feedback',
    title: 'Positive feedback',
    triggers: {
      keywords: ['love', 'great', 'awesome', 'amazing', 'thank you', 'fantastic'],
      patterns: [/love.*this/i, /great.*project/i, /keep.*up/i],
    },
    template: `Thank you! Really appreciate the kind words. If you find it useful, starring the repo helps others discover it. And if you have ideas for improvements, issues and PRs are welcome!`,
    priority: 3,
  },
  {
    id: 'constructive-criticism',
    title: 'Constructive criticism',
    triggers: {
      keywords: ['but', 'however', 'improve', 'better', 'wish', 'missing'],
      patterns: [/could.*be.*better/i, /needs.*improvement/i],
    },
    template: `Thanks for the feedback! This is helpful. [Acknowledge the specific point]. I've noted this for consideration. If you'd like to discuss further or have specific suggestions, feel free to open an issue or discussion.`,
    priority: 3,
  },
]

// GitHub API helper
function githubRequest(endpoint: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: endpoint,
      method: 'GET',
      headers: {
        'User-Agent': 'Warp_Open-Response-Suggester/1.0',
        'Authorization': `token ${CONFIG.github.token}`,
        'Accept': 'application/vnd.github.v3+json',
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

// Analyze issue and find matching templates
function analyzeIssue(issue: any): ResponseTemplate[] {
  const title = (issue.title || '').toLowerCase()
  const body = (issue.body || '').toLowerCase()
  const combined = `${title} ${body}`

  const matches: Array<{ template: ResponseTemplate; score: number }> = []

  for (const template of RESPONSE_TEMPLATES) {
    let score = 0

    // Check keywords
    for (const keyword of template.triggers.keywords) {
      if (combined.includes(keyword.toLowerCase())) {
        score += 10
      }
    }

    // Check patterns
    if (template.triggers.patterns) {
      for (const pattern of template.triggers.patterns) {
        if (pattern.test(combined)) {
          score += 20
        }
      }
    }

    // Adjust by priority (lower priority = higher score)
    score += (5 - template.priority) * 5

    if (score > 0) {
      matches.push({ template, score })
    }
  }

  // Sort by score descending
  matches.sort((a, b) => b.score - a.score)

  return matches.slice(0, 3).map(m => m.template)
}

// Format suggestion output
function formatSuggestion(issue: any, templates: ResponseTemplate[]): string {
  let output = ''
  output += `\n${'═'.repeat(60)}\n`
  output += `Issue #${issue.number}: ${issue.title}\n`
  output += `${'─'.repeat(60)}\n`
  output += `URL: ${issue.html_url}\n`
  output += `Author: ${issue.user?.login || 'unknown'}\n`
  output += `Labels: ${issue.labels?.map((l: any) => l.name).join(', ') || 'none'}\n`
  output += `${'─'.repeat(60)}\n`

  if (issue.body) {
    output += `\nBody Preview:\n${issue.body.slice(0, 200)}${issue.body.length > 200 ? '...' : ''}\n`
  }

  if (templates.length === 0) {
    output += `\n⚠️  No matching response templates found.\n`
    output += `    Consider creating a custom response.\n`
  } else {
    output += `\n📝 Suggested Responses (${templates.length}):\n\n`

    for (let i = 0; i < templates.length; i++) {
      const t = templates[i]
      output += `${i + 1}. ${t.title}\n`
      output += `${'─'.repeat(40)}\n`
      output += `${t.template}\n\n`
    }
  }

  output += `${'═'.repeat(60)}\n`
  return output
}

// Process single issue
async function processIssue(issueNumber: number): Promise<void> {
  console.log(`Fetching issue #${issueNumber}...`)

  const issue = await githubRequest(
    `/repos/${CONFIG.github.repo}/issues/${issueNumber}`
  )

  if (!issue || issue.message) {
    console.error(`Issue not found: ${issue?.message || 'unknown error'}`)
    return
  }

  const templates = analyzeIssue(issue)
  console.log(formatSuggestion(issue, templates))
}

// Process all open issues
async function processAllIssues(): Promise<void> {
  console.log('Fetching open issues...\n')

  const issues = await githubRequest(
    `/repos/${CONFIG.github.repo}/issues?state=open&sort=created&direction=desc&per_page=20`
  )

  if (!Array.isArray(issues)) {
    console.error('Failed to fetch issues:', issues)
    return
  }

  // Filter to actual issues (not PRs) without responses
  const unreplied = issues.filter((i: any) => {
    if (i.pull_request) return false
    // Could also check comment count, but skipping for now
    return true
  })

  console.log(`Found ${unreplied.length} open issues\n`)

  for (const issue of unreplied) {
    const templates = analyzeIssue(issue)
    console.log(formatSuggestion(issue, templates))
  }
}

// Interactive CLI
async function interactiveMode(): Promise<void> {
  const readline = await import('readline')
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  })

  const ask = (q: string): Promise<string> =>
    new Promise((resolve) => rl.question(q, resolve))

  console.log('╔════════════════════════════════════════════╗')
  console.log('║      Warp_Open Response Suggester          ║')
  console.log('╚════════════════════════════════════════════╝')
  console.log('')
  console.log('Commands:')
  console.log('  <number>  - Analyze specific issue')
  console.log('  all       - Analyze all open issues')
  console.log('  list      - List available templates')
  console.log('  exit      - Exit')
  console.log('')

  while (true) {
    const input = await ask('> ')
    const cmd = input.trim().toLowerCase()

    if (cmd === 'exit' || cmd === 'quit' || cmd === 'q') {
      break
    }

    if (cmd === 'all') {
      await processAllIssues()
    } else if (cmd === 'list') {
      console.log('\nAvailable Templates:\n')
      for (const t of RESPONSE_TEMPLATES) {
        console.log(`  • ${t.title} (priority: ${t.priority})`)
        console.log(`    Keywords: ${t.triggers.keywords.slice(0, 3).join(', ')}...`)
        console.log('')
      }
    } else if (/^\d+$/.test(cmd)) {
      await processIssue(parseInt(cmd))
    } else {
      console.log('Unknown command. Type "exit" to quit.')
    }
  }

  rl.close()
}

// Main entry point
async function main(): Promise<void> {
  if (!CONFIG.github.token) {
    console.error('Error: GITHUB_TOKEN environment variable required')
    process.exit(1)
  }

  const args = process.argv.slice(2)

  if (args.length === 0) {
    await interactiveMode()
  } else if (args[0] === '--all' || args[0] === '-a') {
    await processAllIssues()
  } else if (/^\d+$/.test(args[0])) {
    await processIssue(parseInt(args[0]))
  } else {
    console.log('Usage:')
    console.log('  npx ts-node response-suggester.ts          # Interactive mode')
    console.log('  npx ts-node response-suggester.ts 123      # Analyze issue #123')
    console.log('  npx ts-node response-suggester.ts --all    # Analyze all open issues')
  }
}

main().catch(console.error)
