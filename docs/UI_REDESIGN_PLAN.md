# Warp_Open UI Redesign Plan

## Goal
Transform Warp_Open from a "generic IDE look" to a **distinctive Warp Terminal-inspired design** while maintaining our own identity.

---

## Phase 1: Foundation - Color & Typography System

### 1.1 New Color Palette
Replace current flat dark blues with a rich, layered system:

```css
:root {
  /* Background Layers (darkest to lightest) */
  --warp-bg-base: #0a0a0f;      /* Deepest background */
  --warp-bg-surface: #12121a;    /* Card/panel backgrounds */
  --warp-bg-elevated: #1a1a24;   /* Elevated surfaces */
  --warp-bg-hover: #222230;      /* Hover states */

  /* Accent Colors */
  --warp-accent-primary: #7c3aed;    /* Primary purple */
  --warp-accent-secondary: #3b82f6;  /* Blue */
  --warp-accent-gradient: linear-gradient(135deg, #7c3aed 0%, #3b82f6 100%);

  /* Text Hierarchy */
  --warp-text-primary: #f4f4f5;      /* Primary text - near white */
  --warp-text-secondary: #a1a1aa;    /* Secondary - muted */
  --warp-text-tertiary: #71717a;     /* Tertiary - dimmed */

  /* Semantic Colors */
  --warp-success: #22c55e;
  --warp-error: #ef4444;
  --warp-warning: #f59e0b;
  --warp-info: #3b82f6;

  /* Border & Dividers */
  --warp-border: rgba(255, 255, 255, 0.08);
  --warp-border-subtle: rgba(255, 255, 255, 0.04);
}
```

### 1.2 Typography System
```css
:root {
  /* Font Families */
  --warp-font-ui: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --warp-font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', monospace;

  /* Font Sizes */
  --warp-text-xs: 11px;
  --warp-text-sm: 12px;
  --warp-text-base: 13px;
  --warp-text-lg: 14px;
  --warp-text-xl: 16px;

  /* Font Weights */
  --warp-weight-normal: 400;
  --warp-weight-medium: 500;
  --warp-weight-semibold: 600;
}
```

### 1.3 Add Inter & JetBrains Mono Fonts
- Load from Google Fonts or bundle locally
- Use Inter for UI, JetBrains Mono for terminal

---

## Phase 2: Layout Restructure

### 2.1 New App Shell Structure
```
┌─────────────────────────────────────────────────────────┐
│ ▸ Minimal Header (logo, title, window controls)         │
├───────────┬─────────────────────────────────────────────┤
│           │  ┌─────────────────────────────────────┐    │
│  Sidebar  │  │     Tab Bar (minimal, subtle)       │    │
│  (hidden  │  ├─────────────────────────────────────┤    │
│   by      │  │                                     │    │
│  default) │  │     Terminal Content Area           │    │
│           │  │     (Command Blocks)                │    │
│           │  │                                     │    │
│           │  ├─────────────────────────────────────┤    │
│           │  │  ▸ Prompt Input Area (prominent)    │    │
│           │  └─────────────────────────────────────┘    │
├───────────┴─────────────────────────────────────────────┤
│ Status Bar: branch, cwd, ai status, notifications       │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Key Layout Changes
1. **Hide sidebar by default** - Terminal-first experience
2. **Minimal header** - Just logo + essential controls
3. **Prominent input area** - Fixed at bottom, styled
4. **Status bar** - Git branch, path, AI status
5. **Cleaner tab bar** - Subtle, no clutter

---

## Phase 3: Command Blocks Redesign

### 3.1 Block Structure
```
┌──────────────────────────────────────────────────────┐
│ ⏵  echo "Hello World"                      ✓ 0.12s │
├──────────────────────────────────────────────────────┤
│ Hello World                                          │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### 3.2 Block Styling
```css
.command-block {
  background: var(--warp-bg-surface);
  border-radius: 8px;
  margin: 8px 16px;
  overflow: hidden;
  border: 1px solid var(--warp-border);
}

.block-header {
  display: flex;
  align-items: center;
  padding: 8px 12px;
  background: var(--warp-bg-elevated);
  border-bottom: 1px solid var(--warp-border-subtle);
}

.block-prompt-icon {
  color: var(--warp-accent-primary);
  margin-right: 8px;
}

.block-command {
  font-family: var(--warp-font-mono);
  color: var(--warp-text-primary);
  flex: 1;
}

.block-status-success {
  color: var(--warp-success);
}

.block-status-error {
  color: var(--warp-error);
}

.block-output {
  padding: 12px;
  font-family: var(--warp-font-mono);
  font-size: var(--warp-text-sm);
  color: var(--warp-text-secondary);
  max-height: 300px;
  overflow-y: auto;
}
```

---

## Phase 4: Input Area Redesign

### 4.1 Prominent Input
```css
.input-area {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  background: var(--warp-bg-surface);
  border-top: 1px solid var(--warp-border);
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.prompt-display {
  font-family: var(--warp-font-mono);
  font-size: var(--warp-text-sm);
  color: var(--warp-text-tertiary);
}

.prompt-path {
  color: var(--warp-accent-primary);
}

.prompt-input {
  flex: 1;
  background: var(--warp-bg-elevated);
  border: 1px solid var(--warp-border);
  border-radius: 6px;
  padding: 10px 14px;
  font-family: var(--warp-font-mono);
  font-size: var(--warp-text-base);
  color: var(--warp-text-primary);
}

.prompt-input:focus {
  border-color: var(--warp-accent-primary);
  box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.2);
}
```

---

## Phase 5: Header & Status Bar

### 5.1 Minimal Header
```css
.header {
  height: 38px;
  display: flex;
  align-items: center;
  padding: 0 12px;
  background: var(--warp-bg-base);
  border-bottom: 1px solid var(--warp-border-subtle);
  -webkit-app-region: drag; /* Draggable on macOS */
}

.header-logo {
  width: 20px;
  height: 20px;
  margin-right: 12px;
}

.header-title {
  font-size: var(--warp-text-sm);
  font-weight: var(--warp-weight-medium);
  color: var(--warp-text-secondary);
}

.header-controls {
  margin-left: auto;
  display: flex;
  gap: 4px;
  -webkit-app-region: no-drag;
}
```

### 5.2 Status Bar
```css
.status-bar {
  height: 24px;
  display: flex;
  align-items: center;
  padding: 0 12px;
  background: var(--warp-bg-surface);
  border-top: 1px solid var(--warp-border-subtle);
  font-size: var(--warp-text-xs);
  color: var(--warp-text-tertiary);
  gap: 16px;
}

.status-item {
  display: flex;
  align-items: center;
  gap: 4px;
}

.status-git-branch {
  color: var(--warp-accent-secondary);
}

.status-ai-active {
  color: var(--warp-success);
}
```

---

## Phase 6: Tab Bar Redesign

### 6.1 Minimal Tabs
```css
.tab-bar {
  display: flex;
  align-items: center;
  height: 36px;
  padding: 0 8px;
  background: var(--warp-bg-base);
  border-bottom: 1px solid var(--warp-border-subtle);
  gap: 2px;
}

.tab {
  display: flex;
  align-items: center;
  height: 28px;
  padding: 0 12px;
  border-radius: 6px;
  font-size: var(--warp-text-sm);
  color: var(--warp-text-tertiary);
  background: transparent;
  border: none;
  cursor: pointer;
  transition: all 0.15s ease;
}

.tab:hover {
  background: var(--warp-bg-hover);
  color: var(--warp-text-secondary);
}

.tab.active {
  background: var(--warp-bg-surface);
  color: var(--warp-text-primary);
}

.tab-icon {
  width: 14px;
  height: 14px;
  margin-right: 6px;
  opacity: 0.7;
}

.tab-close {
  margin-left: 6px;
  opacity: 0;
  transition: opacity 0.15s;
}

.tab:hover .tab-close {
  opacity: 0.5;
}

.tab-close:hover {
  opacity: 1;
}
```

---

## Phase 7: Icons & Assets

### 7.1 Replace Emojis with SVG Icons
Create an icon system using Lucide or custom SVGs:

| Current | New |
|---------|-----|
| 📝 | `<FileIcon />` |
| 🤖 | `<BotIcon />` |
| ⌘ | `<TerminalIcon />` |
| 🛠 | `<SettingsIcon />` |
| ⚡ | `<ZapIcon />` |
| 🔒 | `<LockIcon />` |

### 7.2 Add Logo
Create a distinctive Warp_Open logo (stylized "W" or terminal icon)

---

## Phase 8: Animations & Polish

### 8.1 Micro-interactions
```css
/* Smooth state transitions */
* {
  transition-property: background-color, border-color, color, opacity;
  transition-duration: 0.15s;
  transition-timing-function: ease;
}

/* Block expand/collapse */
.block-output {
  transition: max-height 0.2s ease, opacity 0.2s ease;
}

/* Tab switch */
.tab-content-enter-active,
.tab-content-leave-active {
  transition: opacity 0.1s ease;
}

/* Command execution pulse */
@keyframes executingPulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.block-executing .block-header {
  animation: executingPulse 1.5s ease infinite;
}
```

### 8.2 Focus States
```css
/* Global focus ring */
:focus-visible {
  outline: 2px solid var(--warp-accent-primary);
  outline-offset: 2px;
}

/* Remove default focus for mouse users */
:focus:not(:focus-visible) {
  outline: none;
}
```

---

## Phase 9: Theme System

### 9.1 Warp-style Themes
Create themes that match Warp's offerings:

1. **Default Dark** - Our signature look
2. **Light Mode** - For daylight users
3. **Dracula** - Popular dark theme
4. **Solarized Dark** - Classic
5. **Gruvbox** - Warm tones
6. **Cyber Wave** - Gradient background
7. **Custom** - User-defined

### 9.2 Theme Backgrounds
Support for:
- Solid colors
- Gradients
- Blur effects (glass morphism)
- Image backgrounds (with overlay)

---

## Implementation Order

| Priority | Task | Effort |
|----------|------|--------|
| 1 | Color palette CSS variables | Small |
| 2 | Typography system | Small |
| 3 | Command blocks redesign | Medium |
| 4 | Input area redesign | Medium |
| 5 | Header simplification | Small |
| 6 | Status bar addition | Small |
| 7 | Tab bar redesign | Medium |
| 8 | Icon system (Lucide) | Medium |
| 9 | Animation polish | Small |
| 10 | Theme system | Large |

---

## Files to Modify

### High Priority
1. `src/style.css` - Global CSS variables
2. `src/App.vue` - Layout restructure
3. `src/components/TerminalPane.vue` - Command blocks
4. `src/components/TabManager.vue` - Tab bar

### Medium Priority
5. `src/components/CommandBlock.vue` - New component
6. `src/components/InputArea.vue` - New component
7. `src/components/StatusBar.vue` - New component
8. `src/components/Header.vue` - Simplified header

### Assets
9. `src/assets/icons/` - SVG icon components
10. `src/assets/logo.svg` - App logo

---

## Success Metrics

After implementation, Warp_Open should:
1. ✅ Have a distinctive, modern appearance
2. ✅ Feel like a premium terminal application
3. ✅ Have clear visual hierarchy
4. ✅ Use consistent spacing and typography
5. ✅ Support multiple themes
6. ✅ Have smooth, polished animations
7. ✅ Look recognizably "Warp-inspired" but unique

---

## References

- [Warp Terminal](https://www.warp.dev)
- [Warp Themes Documentation](https://docs.warp.dev/terminal/appearance/themes)
- [Inter Font](https://rsms.me/inter/)
- [JetBrains Mono](https://www.jetbrains.com/lp/mono/)
- [Lucide Icons](https://lucide.dev)
