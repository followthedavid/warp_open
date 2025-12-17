# Components Reference

Complete documentation for all Vue components in the project.

## Table of Contents

1. [Core Layout](#core-layout)
2. [Terminal Components](#terminal-components)
3. [Block Components](#block-components)
4. [Notebook Components](#notebook-components)
5. [AI Components](#ai-components)
6. [Workflow Components](#workflow-components)
7. [UI Components](#ui-components)

---

## Core Layout

### App.vue

Root application component.

```vue
<template>
  <div id="app" :class="[themeClass, { 'dark-mode': isDark }]">
    <TitleBar />
    <div class="main-container">
      <Sidebar v-if="showSidebar" />
      <div class="content">
        <TabBar />
        <SplitPaneContainer />
      </div>
    </div>
    <StatusBar />
    <ToastContainer />
    <CommandPalette v-if="showCommandPalette" />
  </div>
</template>
```

**Props:** None (root component)

**State:**
- Theme from `useTheme()`
- Sidebar visibility
- Command palette visibility

---

### TitleBar.vue

macOS-style window title bar with traffic lights.

```vue
<template>
  <div class="title-bar" @dblclick="toggleMaximize">
    <div class="traffic-lights">
      <button class="close" @click="closeWindow" />
      <button class="minimize" @click="minimizeWindow" />
      <button class="maximize" @click="toggleMaximize" />
    </div>
    <div class="title">{{ activeTab?.title || 'Warp Terminal' }}</div>
    <div class="spacer" />
  </div>
</template>
```

**Events:**
- Window control (close, minimize, maximize)
- Double-click to maximize

---

### TabBar.vue

Tab strip for managing terminal sessions.

```vue
<template>
  <div class="tab-bar">
    <draggable v-model="tabs" item-key="id" @end="onReorder">
      <template #item="{ element }">
        <Tab
          :tab="element"
          :isActive="element.id === activeTabId"
          @click="activateTab(element.id)"
          @close="closeTab(element.id)"
          @rename="renameTab"
        />
      </template>
    </draggable>
    <button class="new-tab-btn" @click="createTab">+</button>
  </div>
</template>
```

**Features:**
- Drag-and-drop reordering (vuedraggable)
- Tab close buttons
- New tab button
- Tab context menu

---

### SplitPaneContainer.vue

Container for split terminal panes.

```vue
<template>
  <div class="split-container" :class="splitDirection">
    <template v-for="(pane, index) in panes" :key="pane.id">
      <div
        class="pane"
        :style="{ flexBasis: pane.size + '%' }"
        :class="{ active: pane.id === activePaneId }"
      >
        <component
          :is="getPaneComponent(pane.type)"
          :paneId="pane.id"
          @split="splitPane"
          @close="closePane"
        />
      </div>
      <div
        v-if="index < panes.length - 1"
        class="resizer"
        @mousedown="startResize(index, $event)"
      />
    </template>
  </div>
</template>
```

**Pane Types:**
- `terminal` → TerminalPane
- `editor` → EditorPane
- `notebook` → NotebookPanel
- `agent` → AgentPanel

---

## Terminal Components

### TerminalPane.vue

Main terminal display with xterm.js integration.

```vue
<template>
  <div class="terminal-pane" ref="terminalRef">
    <div class="terminal-header">
      <span class="cwd">{{ currentCwd }}</span>
      <div class="pane-actions">
        <button @click="splitHorizontal">─</button>
        <button @click="splitVertical">│</button>
        <button @click="showBlocks = !showBlocks">▤</button>
      </div>
    </div>
    <div class="terminal-container" ref="xtermContainer" />
    <BlockList v-if="showBlocks" :blocks="blocks" />
    <AutocompleteDropdown
      v-if="showAutocomplete"
      :suggestions="suggestions"
      @select="insertSuggestion"
    />
    <AICommandSearch
      v-if="showAISearch"
      @insert-command="insertCommand"
    />
  </div>
</template>

<script setup lang="ts">
import { Terminal } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { WebLinksAddon } from 'xterm-addon-web-links'

const props = defineProps<{
  paneId: string
}>()

// xterm.js setup
const terminal = new Terminal({
  cursorBlink: true,
  fontSize: 14,
  fontFamily: "'SF Mono', Monaco, monospace",
  theme: {
    background: '#1a1a2e',
    foreground: '#e0e0e0',
    cursor: '#6366f1',
    // ... ANSI colors
  }
})

// PTY connection
const { create, write, resize, onData } = usePty({ paneId: props.paneId })

onMounted(async () => {
  terminal.open(xtermContainer.value)
  fitAddon.fit()
  await create()
  onData((data) => terminal.write(data))
  terminal.onData((data) => write(data))
})
</script>
```

**Features:**
- xterm.js terminal emulation
- Auto-fit to container
- Clickable links
- Block mode toggle
- Autocomplete integration
- AI command search (Ctrl+K)

**Keyboard Shortcuts:**
| Key | Action |
|-----|--------|
| Ctrl+K | Open AI command search |
| Tab | Accept autocomplete |
| Up/Down | Navigate autocomplete |
| Ctrl+Shift+V | Split vertical |
| Ctrl+Shift+H | Split horizontal |

---

### AutocompleteDropdown.vue

Dropdown for command suggestions.

```vue
<template>
  <div class="autocomplete-dropdown" :style="position">
    <div
      v-for="(suggestion, index) in suggestions"
      :key="suggestion.id"
      :class="['suggestion', { selected: index === selectedIndex }]"
      @click="$emit('select', suggestion)"
      @mouseenter="selectedIndex = index"
    >
      <span :class="['type-badge', suggestion.type]">
        {{ getTypeIcon(suggestion.type) }}
      </span>
      <span class="text">{{ suggestion.text }}</span>
      <span class="description">{{ suggestion.description }}</span>
      <span class="score">{{ Math.round(suggestion.score) }}</span>
    </div>
  </div>
</template>
```

**Props:**
```typescript
interface Props {
  suggestions: Suggestion[]
  position?: { top: number; left: number }
}
```

**Type Icons:**
- command: `>`
- path: `📁`
- flag: `--`
- git: ``
- env: `$`
- history: `🕐`
- snippet: `✂️`

---

## Block Components

### BlockList.vue

List of command blocks with toolbar.

```vue
<template>
  <div class="block-list">
    <div class="block-toolbar">
      <button @click="collapseAll">Collapse All</button>
      <button @click="expandAll">Expand All</button>
      <button @click="clearBlocks">Clear</button>
      <button @click="exportToNotebook">Export to Notebook</button>
    </div>
    <div class="blocks-container">
      <CommandBlock
        v-for="block in blocks"
        :key="block.id"
        :block="block"
        @toggle="toggleCollapse"
        @delete="deleteBlock"
        @copy="copyOutput"
        @rerun="rerunCommand"
      />
    </div>
  </div>
</template>
```

---

### CommandBlock.vue

Single command block with collapsible output.

```vue
<template>
  <div :class="['command-block', { collapsed: block.collapsed, running: block.isRunning }]">
    <BlockHeader
      :command="block.command"
      :exitCode="block.exitCode"
      :duration="duration"
      :collapsed="block.collapsed"
      @toggle="$emit('toggle', block.id)"
    />
    <BlockBody
      v-if="!block.collapsed"
      :output="block.output"
      :outputType="block.outputType"
      :error="block.error"
    />
  </div>
</template>
```

**Props:**
```typescript
interface Props {
  block: Block
}
```

**Visual States:**
- Default: Gray border
- Running: Animated border (pulse)
- Success (exit 0): Green indicator
- Error (exit != 0): Red indicator
- Collapsed: Minimized height

---

### BlockHeader.vue

Header for command block showing command and status.

```vue
<template>
  <div class="block-header" @click="$emit('toggle')">
    <span class="chevron">{{ collapsed ? '▶' : '▼' }}</span>
    <code class="command">{{ command }}</code>
    <span class="spacer" />
    <span v-if="duration" class="duration">{{ formatDuration(duration) }}</span>
    <span :class="['exit-code', exitCodeClass]">
      {{ exitCode === 0 ? '✓' : `✗ ${exitCode}` }}
    </span>
  </div>
</template>
```

---

### BlockBody.vue

Body content for command block with rich rendering.

```vue
<template>
  <div class="block-body">
    <!-- Error output -->
    <div v-if="error" class="error-output">
      <pre>{{ error }}</pre>
    </div>

    <!-- Rich rendering based on output type -->
    <div v-if="outputType === 'json'" class="json-output">
      <pre><code v-html="highlightedJson"></code></pre>
    </div>
    <div v-else-if="outputType === 'diff'" class="diff-output">
      <div v-for="line in diffLines" :key="line.num" :class="line.type">
        {{ line.text }}
      </div>
    </div>
    <div v-else-if="outputType === 'table'" class="table-output">
      <table>
        <tr v-for="(row, i) in tableRows" :key="i">
          <td v-for="(cell, j) in row" :key="j">{{ cell }}</td>
        </tr>
      </table>
    </div>
    <div v-else class="text-output">
      <pre>{{ output }}</pre>
    </div>
  </div>
</template>
```

**Output Type Detection:**
```typescript
function detectOutputType(output: string): OutputType {
  if (output.trim().startsWith('{') || output.trim().startsWith('[')) return 'json'
  if (output.includes('@@') && output.match(/^[+-]/m)) return 'diff'
  if (output.includes('error') || output.includes('Error')) return 'error'
  if (output.split('\n').every(line => line.includes('\t'))) return 'table'
  return 'text'
}
```

---

## Notebook Components

### NotebookPanel.vue

Main notebook interface with tabs.

```vue
<template>
  <div class="notebook-panel">
    <div class="notebook-header">
      <div class="notebook-tabs">
        <button
          v-for="nb in notebooks"
          :key="nb.id"
          :class="['tab', { active: activeNotebook?.id === nb.id }]"
          @click="openNotebook(nb.id)"
        >
          {{ nb.name }}
          <button class="close" @click.stop="confirmDelete(nb.id)">×</button>
        </button>
        <button class="new-tab" @click="createNew">+ New</button>
      </div>
      <div class="notebook-actions">
        <button @click="executeAll">▶▶ Run All</button>
        <button @click="clearOutputs">Clear Outputs</button>
        <div class="export-dropdown">
          <button>Export ▾</button>
          <div class="dropdown-menu">
            <button @click="exportAs('json')">JSON</button>
            <button @click="exportAs('markdown')">Markdown</button>
            <button @click="exportAs('script')">Shell Script</button>
          </div>
        </div>
      </div>
    </div>

    <div v-if="activeNotebook" class="notebook-content">
      <NotebookCell
        v-for="cell in activeNotebook.cells"
        :key="cell.id"
        :cell="cell"
        :isActive="activeCellId === cell.id"
        :isExecuting="isExecuting && activeCellId === cell.id"
        @select="selectCell"
        @execute="executeCell"
        @update="handleUpdate"
        @delete="deleteCell"
        @move="moveCell"
      />
      <div class="add-cell-buttons">
        <button @click="addCell('code')">+ Code</button>
        <button @click="addCell('markdown')">+ Markdown</button>
      </div>
    </div>

    <div v-else class="empty-state">
      <div class="empty-icon">📓</div>
      <h3>No Notebook Open</h3>
      <button @click="createNew">Create Notebook</button>
    </div>
  </div>
</template>
```

---

### NotebookCell.vue

Individual notebook cell (code or markdown).

```vue
<template>
  <div :class="['notebook-cell', cell.type, { active: isActive }]">
    <div class="cell-gutter">
      <span v-if="cell.type === 'code'" class="execution-count">
        [{{ cell.executionCount || ' ' }}]
      </span>
    </div>

    <div class="cell-content">
      <div class="cell-actions">
        <button v-if="cell.type === 'code'" @click="$emit('execute', cell.id)">
          {{ isExecuting ? '⏳' : '▶' }}
        </button>
        <button @click="$emit('toggle-collapse', cell.id)">
          {{ cell.collapsed ? '▼' : '▲' }}
        </button>
        <button @click="$emit('move', cell.id, 'up')">↑</button>
        <button @click="$emit('move', cell.id, 'down')">↓</button>
        <button @click="$emit('delete', cell.id)">×</button>
      </div>

      <div v-show="!cell.collapsed" class="cell-body">
        <!-- Editor for active cell -->
        <textarea
          v-if="isActive"
          v-model="editContent"
          @input="onInput"
          @keydown="onKeydown"
          class="cell-editor"
        />
        <!-- Display for inactive cell -->
        <div v-else class="cell-display">
          <pre v-if="cell.type === 'code'"><code>{{ cell.content }}</code></pre>
          <div v-else v-html="renderedMarkdown" />
        </div>

        <!-- Output for code cells -->
        <div v-if="cell.type === 'code' && cell.output" class="cell-output">
          <pre>{{ cell.output }}</pre>
        </div>
        <div v-if="cell.error" class="cell-error">
          <pre>{{ cell.error }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>
```

**Props:**
```typescript
interface Props {
  cell: NotebookCell
  isActive: boolean
  isExecuting: boolean
}
```

**Keyboard Shortcuts:**
| Key | Action |
|-----|--------|
| Shift+Enter | Execute cell |
| Cmd+B | Add code cell below |
| Cmd+M | Add markdown cell below |

---

## AI Components

### AgentPanel.vue

AI assistant chat interface.

```vue
<template>
  <div class="agent-panel">
    <div class="agent-header">
      <span class="agent-icon">🤖</span>
      <h3>AI Assistant</h3>
      <span :class="['status', { processing: isProcessing }]">
        {{ isProcessing ? 'Thinking...' : 'Ready' }}
      </span>
      <select v-model="selectedModel">
        <option value="qwen2.5-coder:7b">Qwen2.5 Coder 7B</option>
        <option value="codellama:7b">CodeLlama 7B</option>
        <option value="deepseek-coder:6.7b">DeepSeek Coder 6.7B</option>
      </select>
    </div>

    <div class="messages-container">
      <div v-if="messages.length === 0" class="welcome">
        <h4>Welcome to AI Assistant</h4>
        <p>I can help you with files, commands, and code.</p>
        <div class="suggestions">
          <button @click="sendSuggestion('List files')">List files</button>
          <button @click="sendSuggestion('Read package.json')">Read package.json</button>
        </div>
      </div>

      <div v-for="msg in messages" :key="msg.id" :class="['message', msg.role]">
        <div class="message-header">
          <span>{{ getRoleIcon(msg.role) }}</span>
          <span>{{ getRoleName(msg.role) }}</span>
        </div>
        <div class="message-content">
          <div v-if="msg.toolCall" class="tool-call">
            <span class="tool-name">{{ msg.toolCall.tool }}</span>
            <div class="tool-params">
              <code v-for="(v, k) in msg.toolCall.params" :key="k">
                {{ k }}: {{ v }}
              </code>
            </div>
            <div v-if="msg.toolCall.result" class="tool-result">
              <pre>{{ msg.toolCall.result.output }}</pre>
            </div>
          </div>
          <pre v-else>{{ msg.content }}</pre>
        </div>
      </div>
    </div>

    <div class="input-container">
      <textarea
        v-model="inputText"
        @keydown.enter.prevent="sendMessage"
        placeholder="Ask me anything..."
      />
      <button @click="sendMessage" :disabled="!inputText.trim()">
        ➤
      </button>
    </div>
  </div>
</template>
```

**Message Roles:**
- `user` - 👤 User input
- `assistant` - 🤖 AI response
- `tool` - 🔧 Tool execution result
- `system` - ⚙️ System message

---

### AICommandSearch.vue

Natural language command search overlay.

```vue
<template>
  <div class="ai-command-search" :class="{ expanded: isExpanded }">
    <div class="search-header">
      <span class="search-icon">🔮</span>
      <input
        v-model="searchQuery"
        @input="onInput"
        @keydown="onKeydown"
        @focus="isExpanded = true"
        placeholder="Describe what you want to do..."
      />
      <span v-if="isSearching" class="spinner" />
    </div>

    <div v-if="isExpanded" class="search-body">
      <div v-if="suggestions.length > 0" class="suggestions">
        <div
          v-for="(s, i) in suggestions"
          :key="s.id"
          :class="['suggestion', { selected: selectedIndex === i }]"
          @click="selectSuggestion(s)"
        >
          <code class="command">{{ s.command }}</code>
          <span v-if="s.dangerous" class="danger-badge">⚠️ Caution</span>
          <p class="description">{{ s.description }}</p>
          <p class="explanation">{{ s.explanation }}</p>
          <div class="actions">
            <button @click.stop="copyCommand(s.command)">📋 Copy</button>
            <button @click.stop="insertCommand(s.command)">➤ Insert</button>
          </div>
        </div>
      </div>

      <div v-else-if="!searchQuery" class="hints">
        <h4>Try asking:</h4>
        <button v-for="hint in hints" :key="hint" @click="searchFor(hint)">
          {{ hint }}
        </button>
      </div>
    </div>
  </div>
</template>
```

**Props:**
```typescript
// No props - self-contained component
```

**Events:**
```typescript
interface Emits {
  'insert-command': [command: string]
  'execute-command': [command: string]
}
```

---

## Workflow Components

### WorkflowPanel.vue

Workflow library and management.

```vue
<template>
  <div class="workflow-panel">
    <div class="panel-header">
      <h3>Workflows</h3>
      <button @click="createWorkflow">+ New</button>
    </div>

    <div class="search-bar">
      <input v-model="searchQuery" placeholder="Search workflows..." />
    </div>

    <div class="category-tabs">
      <button
        v-for="cat in categories"
        :key="cat"
        :class="{ active: activeCategory === cat }"
        @click="activeCategory = cat"
      >
        {{ cat }}
      </button>
    </div>

    <div class="workflows-grid">
      <WorkflowCard
        v-for="workflow in filteredWorkflows"
        :key="workflow.id"
        :workflow="workflow"
        @execute="executeWorkflow"
        @toggle-favorite="toggleFavorite"
        @edit="editWorkflow"
        @delete="deleteWorkflow"
      />
    </div>

    <!-- Workflow editor modal -->
    <WorkflowEditor
      v-if="editingWorkflow"
      :workflow="editingWorkflow"
      @save="saveWorkflow"
      @cancel="editingWorkflow = null"
    />
  </div>
</template>
```

---

### WorkflowCard.vue

Individual workflow card with actions.

```vue
<template>
  <div class="workflow-card" @click="$emit('execute', workflow)">
    <div class="card-header">
      <span class="icon">{{ workflow.icon || getDefaultIcon() }}</span>
      <div class="info">
        <h4>{{ workflow.name }}</h4>
        <p>{{ workflow.description }}</p>
      </div>
      <div class="actions" @click.stop>
        <button @click="$emit('toggle-favorite', workflow.id)">
          {{ workflow.isFavorite ? '⭐' : '☆' }}
        </button>
        <button v-if="!workflow.isBuiltin" @click="$emit('edit', workflow)">✏️</button>
        <button v-if="!workflow.isBuiltin" @click="$emit('delete', workflow)">🗑️</button>
      </div>
    </div>
    <code class="command-preview">{{ truncate(workflow.command) }}</code>
    <div class="card-footer">
      <div class="tags">
        <span v-for="tag in workflow.tags.slice(0, 3)" :key="tag">{{ tag }}</span>
      </div>
      <span class="usage">{{ workflow.usageCount }} uses</span>
    </div>
  </div>
</template>
```

**Props:**
```typescript
interface Props {
  workflow: Workflow
}
```

**Events:**
```typescript
interface Emits {
  execute: [workflow: Workflow]
  'toggle-favorite': [id: string]
  edit: [workflow: Workflow]
  delete: [workflow: Workflow]
}
```

---

## UI Components

### ToastContainer.vue

Container for toast notifications.

```vue
<template>
  <div class="toast-container">
    <transition-group name="toast">
      <Toast
        v-for="toast in toasts"
        :key="toast.id"
        :toast="toast"
        @dismiss="dismiss(toast.id)"
      />
    </transition-group>
  </div>
</template>
```

---

### CommandPalette.vue

Fuzzy command search overlay (Cmd+P).

```vue
<template>
  <div class="command-palette-overlay" @click="close">
    <div class="command-palette" @click.stop>
      <input
        v-model="query"
        @input="search"
        @keydown="handleKeydown"
        placeholder="Type a command..."
        autofocus
      />
      <div class="results">
        <div
          v-for="(result, i) in results"
          :key="result.id"
          :class="['result', { selected: selectedIndex === i }]"
          @click="execute(result)"
        >
          <span class="icon">{{ result.icon }}</span>
          <span class="label">{{ result.label }}</span>
          <span class="shortcut">{{ result.shortcut }}</span>
        </div>
      </div>
    </div>
  </div>
</template>
```

**Commands:**
- New Tab
- Close Tab
- Split Horizontal
- Split Vertical
- Toggle Sidebar
- Open Settings
- Toggle Theme
- Open AI Chat
- etc.

---

### StatusBar.vue

Bottom status bar with session info.

```vue
<template>
  <div class="status-bar">
    <div class="left">
      <span class="shell">{{ shellName }}</span>
      <span class="cwd">{{ currentCwd }}</span>
    </div>
    <div class="right">
      <span class="git-branch" v-if="gitBranch"> {{ gitBranch }}</span>
      <span class="pane-count">{{ paneCount }} panes</span>
      <span class="time">{{ currentTime }}</span>
    </div>
  </div>
</template>
```
