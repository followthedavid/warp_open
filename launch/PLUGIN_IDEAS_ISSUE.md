# Good First Plugin Ideas

**This issue tracks plugin ideas for the Warp_Open ecosystem. If you're looking to contribute, building a plugin is a great way to start!**

## Official Reference Plugins (Planned)

These will be built as examples for the Plugin API v2:

### 1. Git Insights Plugin
- Show current branch, status, ahead/behind
- Quick diff view in side panel
- Branch switching shortcuts
- Permissions: `read-output`, `read-commands`, `render-panel`

### 2. System Monitor Plugin
- CPU, memory, disk usage
- Network activity
- Process list for current shell
- Permissions: `render-panel`, `read-session`

### 3. Command Linter Plugin
- Warn before destructive commands (`rm -rf`, `sudo rm`, etc.)
- Suggest safer alternatives
- Customizable rules
- Permissions: `read-commands`, `render-panel`

### 4. Session Annotator Plugin
- Add notes to commands
- Tag important commands
- Export annotated sessions
- Permissions: `read-commands`, `read-session`, `render-panel`

### 5. AI Refactor Helper Plugin
- Suggest command improvements
- Explain complex pipelines
- Offline with local LLM
- Permissions: `read-commands`, `read-output`, `render-panel`

---

## Community Plugin Ideas

### Easy (Good First Plugin)

- [ ] **Command Timer** - Show execution time for each command
- [ ] **Working Directory Breadcrumbs** - Visual path navigation
- [ ] **Command Frequency Chart** - Visualize most-used commands (demo exists)
- [ ] **Clipboard History** - Track copied content
- [ ] **Custom Aliases Panel** - Quick access to shell aliases

### Medium Complexity

- [ ] **Docker Dashboard** - Container status, logs, controls
- [ ] **SSH Connection Manager** - Save and quick-connect to hosts
- [ ] **Environment Variable Viewer** - Browse and search env vars
- [ ] **Terminal Themes Gallery** - Preview and apply themes
- [ ] **Command Bookmarks** - Save and organize useful commands

### Advanced

- [ ] **Language Server Bridge** - LSP diagnostics in terminal
- [ ] **Remote File Browser** - SFTP/SCP file management
- [ ] **CI/CD Status** - GitHub Actions, GitLab CI status
- [ ] **Kubernetes Dashboard** - Pod status, logs, exec
- [ ] **Database Explorer** - SQL query interface

---

## How to Build a Plugin

1. Read [PLUGINS.md](./PLUGINS.md) for API documentation
2. Look at `src/plugins/demos/CommandFrequencyPlugin.ts` for an example
3. Use the Plugin API v2 types from `src/plugins/types.ts`
4. Test with the Plugin Dev Console

## Plugin Template

```typescript
import type { WarpPlugin, PluginContext } from '../types'

export const MyPlugin: WarpPlugin = {
  name: 'My Plugin',
  version: '1.0.0',
  apiVersion: '2.0',

  init(context: PluginContext) {
    context.log.info('Plugin initialized')

    context.subscribe('command', (event) => {
      // Handle command events
    })
  },

  render(container, state) {
    container.innerHTML = '<div>My Plugin UI</div>'
  },

  destroy() {
    console.log('Plugin destroyed')
  }
}
```

---

## Claiming a Plugin Idea

1. Comment on this issue with which plugin you want to build
2. Create a new issue with the `[PLUGIN]` template
3. Submit a PR when ready

**Questions?** Open a discussion or comment here!
