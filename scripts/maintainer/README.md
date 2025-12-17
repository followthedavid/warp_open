# Maintainer Automation Tools

A suite of scripts to help maintain Warp_Open during and after the public launch.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in this directory:
```bash
# GitHub
GITHUB_TOKEN=your_github_personal_access_token
GITHUB_REPO=owner/warp_open

# Hacker News (optional, set after posting Show HN)
HN_STORY_ID=12345678

# Webhooks (optional)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

3. Run scripts with:
```bash
npx ts-node scripts/maintainer/<script-name>.ts
```

---

## Available Tools

### 1. Notification Agent (`notification-agent.ts`)

Monitors GitHub, Hacker News, and Reddit for Warp_Open activity. Sends desktop notifications and optional Discord/Slack alerts.

**Usage:**
```bash
# Run in terminal (keeps running)
npx ts-node scripts/maintainer/notification-agent.ts

# Run as background process
nohup npx ts-node scripts/maintainer/notification-agent.ts &
```

**What it monitors:**
- ⭐ New GitHub stars
- 📋 New issues opened
- 🔀 New pull requests
- 🔥 HN score increases
- 💬 New HN comments
- 📢 Reddit mentions

**Notification outputs:**
- macOS/Linux desktop notifications
- Discord webhook (if configured)
- Slack webhook (if configured)
- Console logging

---

### 2. Auto-Tagger (`auto-tagger.ts`)

Automatically labels GitHub issues based on content analysis. Adds appropriate labels like `bug`, `enhancement`, `platform:macos`, etc.

**Usage:**
```bash
# Run once
npx ts-node scripts/maintainer/auto-tagger.ts

# Dry run (no changes)
DRY_RUN=true npx ts-node scripts/maintainer/auto-tagger.ts
```

**Labels applied automatically:**
- `bug` - When crash/error keywords detected
- `enhancement` - Feature requests
- `question` - Help requests (titles ending with ?)
- `platform:macos/linux/windows` - Platform mentions
- `documentation` - Docs-related issues

**Labels suggested (not auto-applied):**
- `priority:critical` - Needs manual review
- `area:*` - Component areas
- `good-first-issue` - Always manual

---

### 3. Response Suggester (`response-suggester.ts`)

Analyzes issues and suggests appropriate response templates based on content patterns.

**Usage:**
```bash
# Interactive mode
npx ts-node scripts/maintainer/response-suggester.ts

# Analyze specific issue
npx ts-node scripts/maintainer/response-suggester.ts 123

# Analyze all open issues
npx ts-node scripts/maintainer/response-suggester.ts --all
```

**Template categories:**
- Why not contribute to Warp?
- Is this production ready?
- Windows support?
- Why local AI only?
- How to install Ollama?
- Found a bug
- How can I contribute?
- And more...

Templates are based on `launch/RESPONSES.md`.

---

### 4. Metrics Dashboard (`metrics-dashboard.ts`)

Collects and displays key metrics across platforms. Tracks launch progress.

**Usage:**
```bash
# Terminal display
npx ts-node scripts/maintainer/metrics-dashboard.ts

# JSON output
npx ts-node scripts/maintainer/metrics-dashboard.ts --json

# Markdown report
npx ts-node scripts/maintainer/metrics-dashboard.ts --markdown
```

**Metrics tracked:**
- GitHub: stars, forks, watchers, issues, PRs, downloads, contributors
- Hacker News: score, comments
- Trends: daily changes

**Output:**
- Terminal ASCII dashboard
- `launch/metrics/latest.json` - Latest snapshot
- `launch/metrics/history.json` - Historical data
- `launch/metrics/report-YYYY-MM-DD.md` - Daily reports

---

## Automation Schedule

For best results during launch, run these on a schedule:

```bash
# crontab example

# Every minute - notifications
* * * * * cd /path/to/warp_open && npx ts-node scripts/maintainer/notification-agent.ts

# Every 15 minutes - auto-tagging
*/15 * * * * cd /path/to/warp_open && npx ts-node scripts/maintainer/auto-tagger.ts

# Every hour - metrics
0 * * * * cd /path/to/warp_open && npx ts-node scripts/maintainer/metrics-dashboard.ts --markdown
```

Or use a process manager like PM2:
```bash
pm2 start scripts/maintainer/notification-agent.ts --name warp-notifications
```

---

## Launch Day Checklist

### Before Launch
- [ ] Set up `.env` with GitHub token
- [ ] Test notification agent with mock data
- [ ] Verify labels exist in GitHub repo
- [ ] Review response templates

### After Posting
- [ ] Update `HN_STORY_ID` in `.env`
- [ ] Start notification agent
- [ ] Run initial metrics collection
- [ ] Schedule auto-tagger runs

### During Launch
- [ ] Monitor notifications
- [ ] Respond to HN comments quickly
- [ ] Review auto-tagged issues
- [ ] Use response suggester for common questions
- [ ] Take metrics snapshots

### Post-Launch
- [ ] Generate metrics report
- [ ] Update `launch/LAUNCH_TRACKING.md`
- [ ] Compile FAQ from common questions
- [ ] Identify top feature requests

---

## Customization

### Adding Auto-Tagger Rules

Edit `auto-tagger.ts` and add to `LABEL_RULES`:

```typescript
{
  name: 'my-label',
  color: 'ff0000',
  description: 'My custom label',
  keywords: ['keyword1', 'keyword2'],
  titlePatterns: [/pattern/i],
  priority: 2,
  autoApply: true, // false = suggestion only
}
```

### Adding Response Templates

Edit `response-suggester.ts` and add to `RESPONSE_TEMPLATES`:

```typescript
{
  id: 'my-template',
  title: 'My Response',
  triggers: {
    keywords: ['trigger1', 'trigger2'],
    patterns: [/regex/i],
  },
  template: `Your response text here`,
  priority: 2,
}
```

---

## Troubleshooting

### "Rate limit exceeded"
GitHub API has rate limits. Ensure you're using a token and reduce polling frequency.

### Notifications not showing
- macOS: Check System Preferences > Notifications
- Linux: Ensure `notify-send` is installed

### Auto-tagger missing issues
Check the `.auto-tagger-state.json` file. Delete to reprocess all issues.

### Wrong labels applied
Set `DRY_RUN=true` to preview changes before applying.
