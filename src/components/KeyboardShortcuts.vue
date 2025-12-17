<template>
  <Teleport to="body">
    <div v-if="isVisible" class="shortcuts-overlay" @click="$emit('close')">
      <div class="shortcuts-modal" @click.stop>
        <div class="modal-header">
          <h2>Keyboard Shortcuts</h2>
          <button class="close-btn" @click="$emit('close')">×</button>
        </div>
        <div class="shortcuts-content">
          <div class="shortcut-section" v-for="section in sections" :key="section.title">
            <h3>{{ section.title }}</h3>
            <div class="shortcut-list">
              <div class="shortcut-item" v-for="shortcut in section.shortcuts" :key="shortcut.keys">
                <span class="shortcut-desc">{{ shortcut.description }}</span>
                <span class="shortcut-keys">
                  <kbd v-for="(key, i) in shortcut.keys.split('+')" :key="i">{{ key }}</kbd>
                </span>
              </div>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <span class="tip">Tip: Press <kbd>⌘</kbd><kbd>⇧</kbd><kbd>P</kbd> to open the Command Palette</span>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
defineProps<{
  isVisible: boolean
}>()

defineEmits<{
  (e: 'close'): void
}>()

const sections = [
  {
    title: 'Tabs',
    shortcuts: [
      { keys: '⌘+T', description: 'New Terminal Tab' },
      { keys: '⌘+W', description: 'Close Current Tab' },
      { keys: '⌘+⇧+[', description: 'Previous Tab' },
      { keys: '⌘+⇧+]', description: 'Next Tab' },
      { keys: '⌘+1-9', description: 'Jump to Tab 1-9' },
    ]
  },
  {
    title: 'Panes',
    shortcuts: [
      { keys: '⌘+⇧+D', description: 'Split Pane Vertically' },
      { keys: '⌘+⇧+E', description: 'Split Pane Horizontally' },
      { keys: '⌥+←', description: 'Navigate Pane Left' },
      { keys: '⌥+→', description: 'Navigate Pane Right' },
      { keys: '⌥+↑', description: 'Navigate Pane Up' },
      { keys: '⌥+↓', description: 'Navigate Pane Down' },
      { keys: '⌘+⌥+←', description: 'Resize Pane Left' },
      { keys: '⌘+⌥+→', description: 'Resize Pane Right' },
      { keys: '⌘+⌥+↑', description: 'Resize Pane Up' },
      { keys: '⌘+⌥+↓', description: 'Resize Pane Down' },
    ]
  },
  {
    title: 'AI',
    shortcuts: [
      { keys: '⌘+⇧+A', description: 'Toggle AI Overlay' },
      { keys: 'Esc', description: 'Close AI Overlay' },
    ]
  },
  {
    title: 'General',
    shortcuts: [
      { keys: '⌘+⇧+P', description: 'Command Palette' },
      { keys: '⌘+⇧+F', description: 'Global Search' },
      { keys: '⌘+⇧+A', description: 'Analytics Dashboard' },
      { keys: '⌘+/', description: 'Show Shortcuts (this dialog)' },
      { keys: '⌘+,', description: 'Open Preferences' },
      { keys: '⌘+B', description: 'Toggle Sidebar' },
      { keys: '⌘+O', description: 'Open Folder' },
    ]
  },
  {
    title: 'Terminal',
    shortcuts: [
      { keys: '⌘+V', description: 'Paste from Clipboard' },
      { keys: '⌘+C', description: 'Copy Selection' },
      { keys: '⌘+K', description: 'Clear Terminal' },
    ]
  },
  {
    title: 'Recording',
    shortcuts: [
      { keys: '⌘+⇧+R', description: 'Start/Stop Recording' },
      { keys: '⌘+⇧+U', description: 'Pause/Resume Recording' },
    ]
  },
]
</script>

<style scoped>
.shortcuts-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(2px);
}

.shortcuts-modal {
  width: 640px;
  max-width: 90vw;
  max-height: 80vh;
  background: #1a1f2e;
  border: 1px solid #334155;
  border-radius: 12px;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid #334155;
  background: #0f172a;
}

.modal-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: #e2e8f0;
}

.close-btn {
  width: 32px;
  height: 32px;
  border: none;
  background: transparent;
  color: #64748b;
  cursor: pointer;
  border-radius: 6px;
  font-size: 20px;
  line-height: 1;
}

.close-btn:hover {
  background: #334155;
  color: #e2e8f0;
}

.shortcuts-content {
  flex: 1;
  overflow-y: auto;
  padding: 16px 20px;
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 24px;
}

.shortcut-section h3 {
  margin: 0 0 12px 0;
  font-size: 13px;
  font-weight: 600;
  color: #3b82f6;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.shortcut-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.shortcut-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 0;
}

.shortcut-desc {
  font-size: 13px;
  color: #cbd5e1;
}

.shortcut-keys {
  display: flex;
  gap: 4px;
}

.shortcut-keys kbd {
  display: inline-block;
  padding: 3px 8px;
  background: #0f172a;
  border: 1px solid #334155;
  border-radius: 4px;
  font-family: 'SF Mono', Monaco, monospace;
  font-size: 12px;
  color: #94a3b8;
  min-width: 24px;
  text-align: center;
}

.modal-footer {
  padding: 12px 20px;
  border-top: 1px solid #334155;
  background: #0f172a;
}

.tip {
  font-size: 12px;
  color: #64748b;
}

.tip kbd {
  display: inline-block;
  padding: 2px 6px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 4px;
  font-family: inherit;
  font-size: 11px;
  margin: 0 2px;
}

/* Scrollbar */
.shortcuts-content::-webkit-scrollbar {
  width: 8px;
}

.shortcuts-content::-webkit-scrollbar-track {
  background: transparent;
}

.shortcuts-content::-webkit-scrollbar-thumb {
  background: #334155;
  border-radius: 4px;
}
</style>
