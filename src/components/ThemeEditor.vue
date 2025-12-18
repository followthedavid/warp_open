<template>
  <div class="theme-editor">
    <!-- Header -->
    <div class="theme-editor__header">
      <h3 class="theme-editor__title">Theme Editor</h3>
      <div class="theme-editor__controls">
        <button class="theme-editor__btn" @click="exportTheme">Export</button>
        <button class="theme-editor__btn" @click="importTheme">Import</button>
        <button class="theme-editor__btn" @click="resetTheme">Reset</button>
        <button class="theme-editor__btn" @click="emit('close')">×</button>
      </div>
    </div>

    <!-- Theme selector -->
    <div class="theme-editor__selector">
      <label>Base Theme</label>
      <select v-model="selectedPreset" @change="applyPreset" class="theme-editor__select">
        <option v-for="preset in presets" :key="preset.name" :value="preset.name">
          {{ preset.label }}
        </option>
      </select>
    </div>

    <!-- Preview -->
    <div class="theme-editor__preview" :style="previewStyle">
      <div class="theme-editor__preview-header">
        <span class="theme-editor__preview-title">Preview</span>
        <span class="theme-editor__preview-branch">⎇ main</span>
      </div>
      <div class="theme-editor__preview-content">
        <div class="theme-editor__preview-prompt">
          <span class="theme-editor__preview-user">user</span>
          <span class="theme-editor__preview-sep">@</span>
          <span class="theme-editor__preview-host">terminal</span>
          <span class="theme-editor__preview-dir">~/project</span>
          <span class="theme-editor__preview-symbol">$</span>
        </div>
        <div class="theme-editor__preview-command">ls -la</div>
        <div class="theme-editor__preview-output">
          <span style="color: var(--preview-blue)">drwxr-xr-x</span>
          <span style="color: var(--preview-green)"> user</span>
          <span> 4096 </span>
          <span style="color: var(--preview-cyan)">src/</span>
        </div>
        <div class="theme-editor__preview-ai">
          <span class="theme-editor__preview-ai-label">AI:</span>
          <span>Here's what I found...</span>
        </div>
        <div class="theme-editor__preview-error">Error: file not found</div>
        <div class="theme-editor__preview-success">✓ Operation completed</div>
      </div>
    </div>

    <!-- Color sections -->
    <div class="theme-editor__sections">
      <!-- Background colors -->
      <div class="theme-editor__section">
        <h4 class="theme-editor__section-title" @click="toggleSection('background')">
          <span class="theme-editor__section-icon">{{ expandedSections.background ? '▼' : '▶' }}</span>
          Background
        </h4>
        <div v-if="expandedSections.background" class="theme-editor__colors">
          <ColorInput v-model="theme.background" label="Terminal Background" />
          <ColorInput v-model="theme.backgroundAlt" label="Panel Background" />
          <ColorInput v-model="theme.backgroundHover" label="Hover Background" />
          <ColorInput v-model="theme.backgroundSelected" label="Selected Background" />
        </div>
      </div>

      <!-- Foreground colors -->
      <div class="theme-editor__section">
        <h4 class="theme-editor__section-title" @click="toggleSection('foreground')">
          <span class="theme-editor__section-icon">{{ expandedSections.foreground ? '▼' : '▶' }}</span>
          Foreground
        </h4>
        <div v-if="expandedSections.foreground" class="theme-editor__colors">
          <ColorInput v-model="theme.foreground" label="Main Text" />
          <ColorInput v-model="theme.foregroundMuted" label="Muted Text" />
          <ColorInput v-model="theme.foregroundAccent" label="Accent Text" />
        </div>
      </div>

      <!-- Accent colors -->
      <div class="theme-editor__section">
        <h4 class="theme-editor__section-title" @click="toggleSection('accent')">
          <span class="theme-editor__section-icon">{{ expandedSections.accent ? '▼' : '▶' }}</span>
          Accent Colors
        </h4>
        <div v-if="expandedSections.accent" class="theme-editor__colors">
          <ColorInput v-model="theme.accent" label="Primary Accent" />
          <ColorInput v-model="theme.accentHover" label="Accent Hover" />
          <ColorInput v-model="theme.success" label="Success" />
          <ColorInput v-model="theme.warning" label="Warning" />
          <ColorInput v-model="theme.error" label="Error" />
          <ColorInput v-model="theme.info" label="Info" />
        </div>
      </div>

      <!-- Terminal colors (ANSI) -->
      <div class="theme-editor__section">
        <h4 class="theme-editor__section-title" @click="toggleSection('ansi')">
          <span class="theme-editor__section-icon">{{ expandedSections.ansi ? '▼' : '▶' }}</span>
          Terminal Colors (ANSI)
        </h4>
        <div v-if="expandedSections.ansi" class="theme-editor__colors theme-editor__colors--grid">
          <ColorInput v-model="theme.ansiBlack" label="Black" />
          <ColorInput v-model="theme.ansiRed" label="Red" />
          <ColorInput v-model="theme.ansiGreen" label="Green" />
          <ColorInput v-model="theme.ansiYellow" label="Yellow" />
          <ColorInput v-model="theme.ansiBlue" label="Blue" />
          <ColorInput v-model="theme.ansiMagenta" label="Magenta" />
          <ColorInput v-model="theme.ansiCyan" label="Cyan" />
          <ColorInput v-model="theme.ansiWhite" label="White" />
          <ColorInput v-model="theme.ansiBrightBlack" label="Bright Black" />
          <ColorInput v-model="theme.ansiBrightRed" label="Bright Red" />
          <ColorInput v-model="theme.ansiBrightGreen" label="Bright Green" />
          <ColorInput v-model="theme.ansiBrightYellow" label="Bright Yellow" />
          <ColorInput v-model="theme.ansiBrightBlue" label="Bright Blue" />
          <ColorInput v-model="theme.ansiBrightMagenta" label="Bright Magenta" />
          <ColorInput v-model="theme.ansiBrightCyan" label="Bright Cyan" />
          <ColorInput v-model="theme.ansiBrightWhite" label="Bright White" />
        </div>
      </div>

      <!-- UI elements -->
      <div class="theme-editor__section">
        <h4 class="theme-editor__section-title" @click="toggleSection('ui')">
          <span class="theme-editor__section-icon">{{ expandedSections.ui ? '▼' : '▶' }}</span>
          UI Elements
        </h4>
        <div v-if="expandedSections.ui" class="theme-editor__colors">
          <ColorInput v-model="theme.border" label="Border" />
          <ColorInput v-model="theme.scrollbar" label="Scrollbar" />
          <ColorInput v-model="theme.scrollbarHover" label="Scrollbar Hover" />
          <ColorInput v-model="theme.cursor" label="Cursor" />
          <ColorInput v-model="theme.selection" label="Selection" />
        </div>
      </div>

      <!-- Typography -->
      <div class="theme-editor__section">
        <h4 class="theme-editor__section-title" @click="toggleSection('typography')">
          <span class="theme-editor__section-icon">{{ expandedSections.typography ? '▼' : '▶' }}</span>
          Typography
        </h4>
        <div v-if="expandedSections.typography" class="theme-editor__typography">
          <div class="theme-editor__field">
            <label>Font Family</label>
            <select v-model="theme.fontFamily" class="theme-editor__select">
              <option value="'JetBrains Mono', monospace">JetBrains Mono</option>
              <option value="'Fira Code', monospace">Fira Code</option>
              <option value="'Source Code Pro', monospace">Source Code Pro</option>
              <option value="'SF Mono', monospace">SF Mono</option>
              <option value="Menlo, monospace">Menlo</option>
              <option value="Consolas, monospace">Consolas</option>
            </select>
          </div>
          <div class="theme-editor__field">
            <label>Font Size</label>
            <input
              type="range"
              v-model.number="theme.fontSize"
              min="10"
              max="20"
              class="theme-editor__range"
            />
            <span class="theme-editor__range-value">{{ theme.fontSize }}px</span>
          </div>
          <div class="theme-editor__field">
            <label>Line Height</label>
            <input
              type="range"
              v-model.number="theme.lineHeight"
              min="1"
              max="2"
              step="0.1"
              class="theme-editor__range"
            />
            <span class="theme-editor__range-value">{{ theme.lineHeight }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Apply button -->
    <div class="theme-editor__footer">
      <button class="theme-editor__btn theme-editor__btn--primary" @click="applyTheme">
        Apply Theme
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, defineComponent, h } from 'vue';

// Emits
const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'apply', theme: Theme): void;
}>();

// Types
interface Theme {
  name: string;
  background: string;
  backgroundAlt: string;
  backgroundHover: string;
  backgroundSelected: string;
  foreground: string;
  foregroundMuted: string;
  foregroundAccent: string;
  accent: string;
  accentHover: string;
  success: string;
  warning: string;
  error: string;
  info: string;
  border: string;
  scrollbar: string;
  scrollbarHover: string;
  cursor: string;
  selection: string;
  ansiBlack: string;
  ansiRed: string;
  ansiGreen: string;
  ansiYellow: string;
  ansiBlue: string;
  ansiMagenta: string;
  ansiCyan: string;
  ansiWhite: string;
  ansiBrightBlack: string;
  ansiBrightRed: string;
  ansiBrightGreen: string;
  ansiBrightYellow: string;
  ansiBrightBlue: string;
  ansiBrightMagenta: string;
  ansiBrightCyan: string;
  ansiBrightWhite: string;
  fontFamily: string;
  fontSize: number;
  lineHeight: number;
}

// Presets
const presets: Array<{ name: string; label: string; theme: Theme }> = [
  {
    name: 'catppuccin-mocha',
    label: 'Catppuccin Mocha',
    theme: {
      name: 'catppuccin-mocha',
      background: '#1e1e2e',
      backgroundAlt: '#181825',
      backgroundHover: '#313244',
      backgroundSelected: '#45475a',
      foreground: '#cdd6f4',
      foregroundMuted: '#6c7086',
      foregroundAccent: '#89b4fa',
      accent: '#89b4fa',
      accentHover: '#b4befe',
      success: '#a6e3a1',
      warning: '#f9e2af',
      error: '#f38ba8',
      info: '#89dceb',
      border: '#313244',
      scrollbar: '#45475a',
      scrollbarHover: '#585b70',
      cursor: '#f5e0dc',
      selection: '#45475a80',
      ansiBlack: '#45475a',
      ansiRed: '#f38ba8',
      ansiGreen: '#a6e3a1',
      ansiYellow: '#f9e2af',
      ansiBlue: '#89b4fa',
      ansiMagenta: '#f5c2e7',
      ansiCyan: '#94e2d5',
      ansiWhite: '#bac2de',
      ansiBrightBlack: '#585b70',
      ansiBrightRed: '#f38ba8',
      ansiBrightGreen: '#a6e3a1',
      ansiBrightYellow: '#f9e2af',
      ansiBrightBlue: '#89b4fa',
      ansiBrightMagenta: '#f5c2e7',
      ansiBrightCyan: '#94e2d5',
      ansiBrightWhite: '#a6adc8',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 14,
      lineHeight: 1.5,
    },
  },
  {
    name: 'dracula',
    label: 'Dracula',
    theme: {
      name: 'dracula',
      background: '#282a36',
      backgroundAlt: '#21222c',
      backgroundHover: '#44475a',
      backgroundSelected: '#6272a4',
      foreground: '#f8f8f2',
      foregroundMuted: '#6272a4',
      foregroundAccent: '#bd93f9',
      accent: '#bd93f9',
      accentHover: '#ff79c6',
      success: '#50fa7b',
      warning: '#f1fa8c',
      error: '#ff5555',
      info: '#8be9fd',
      border: '#44475a',
      scrollbar: '#44475a',
      scrollbarHover: '#6272a4',
      cursor: '#f8f8f2',
      selection: '#44475a80',
      ansiBlack: '#21222c',
      ansiRed: '#ff5555',
      ansiGreen: '#50fa7b',
      ansiYellow: '#f1fa8c',
      ansiBlue: '#bd93f9',
      ansiMagenta: '#ff79c6',
      ansiCyan: '#8be9fd',
      ansiWhite: '#f8f8f2',
      ansiBrightBlack: '#6272a4',
      ansiBrightRed: '#ff6e6e',
      ansiBrightGreen: '#69ff94',
      ansiBrightYellow: '#ffffa5',
      ansiBrightBlue: '#d6acff',
      ansiBrightMagenta: '#ff92df',
      ansiBrightCyan: '#a4ffff',
      ansiBrightWhite: '#ffffff',
      fontFamily: "'Fira Code', monospace",
      fontSize: 14,
      lineHeight: 1.5,
    },
  },
  {
    name: 'nord',
    label: 'Nord',
    theme: {
      name: 'nord',
      background: '#2e3440',
      backgroundAlt: '#3b4252',
      backgroundHover: '#434c5e',
      backgroundSelected: '#4c566a',
      foreground: '#eceff4',
      foregroundMuted: '#4c566a',
      foregroundAccent: '#88c0d0',
      accent: '#88c0d0',
      accentHover: '#81a1c1',
      success: '#a3be8c',
      warning: '#ebcb8b',
      error: '#bf616a',
      info: '#5e81ac',
      border: '#4c566a',
      scrollbar: '#4c566a',
      scrollbarHover: '#5e81ac',
      cursor: '#d8dee9',
      selection: '#4c566a80',
      ansiBlack: '#3b4252',
      ansiRed: '#bf616a',
      ansiGreen: '#a3be8c',
      ansiYellow: '#ebcb8b',
      ansiBlue: '#81a1c1',
      ansiMagenta: '#b48ead',
      ansiCyan: '#88c0d0',
      ansiWhite: '#e5e9f0',
      ansiBrightBlack: '#4c566a',
      ansiBrightRed: '#bf616a',
      ansiBrightGreen: '#a3be8c',
      ansiBrightYellow: '#ebcb8b',
      ansiBrightBlue: '#81a1c1',
      ansiBrightMagenta: '#b48ead',
      ansiBrightCyan: '#8fbcbb',
      ansiBrightWhite: '#eceff4',
      fontFamily: "'Source Code Pro', monospace",
      fontSize: 14,
      lineHeight: 1.5,
    },
  },
  {
    name: 'tokyo-night',
    label: 'Tokyo Night',
    theme: {
      name: 'tokyo-night',
      background: '#1a1b26',
      backgroundAlt: '#16161e',
      backgroundHover: '#292e42',
      backgroundSelected: '#33467c',
      foreground: '#c0caf5',
      foregroundMuted: '#565f89',
      foregroundAccent: '#7aa2f7',
      accent: '#7aa2f7',
      accentHover: '#bb9af7',
      success: '#9ece6a',
      warning: '#e0af68',
      error: '#f7768e',
      info: '#7dcfff',
      border: '#292e42',
      scrollbar: '#292e42',
      scrollbarHover: '#414868',
      cursor: '#c0caf5',
      selection: '#33467c80',
      ansiBlack: '#414868',
      ansiRed: '#f7768e',
      ansiGreen: '#9ece6a',
      ansiYellow: '#e0af68',
      ansiBlue: '#7aa2f7',
      ansiMagenta: '#bb9af7',
      ansiCyan: '#7dcfff',
      ansiWhite: '#c0caf5',
      ansiBrightBlack: '#414868',
      ansiBrightRed: '#f7768e',
      ansiBrightGreen: '#9ece6a',
      ansiBrightYellow: '#e0af68',
      ansiBrightBlue: '#7aa2f7',
      ansiBrightMagenta: '#bb9af7',
      ansiBrightCyan: '#7dcfff',
      ansiBrightWhite: '#c0caf5',
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 14,
      lineHeight: 1.5,
    },
  },
];

// State
const selectedPreset = ref('catppuccin-mocha');
const theme = ref<Theme>({ ...presets[0].theme });
const expandedSections = ref({
  background: true,
  foreground: false,
  accent: false,
  ansi: false,
  ui: false,
  typography: false,
});

// Computed
const previewStyle = computed(() => ({
  '--preview-bg': theme.value.background,
  '--preview-fg': theme.value.foreground,
  '--preview-muted': theme.value.foregroundMuted,
  '--preview-accent': theme.value.accent,
  '--preview-success': theme.value.success,
  '--preview-error': theme.value.error,
  '--preview-blue': theme.value.ansiBlue,
  '--preview-green': theme.value.ansiGreen,
  '--preview-cyan': theme.value.ansiCyan,
  '--preview-border': theme.value.border,
  '--preview-font': theme.value.fontFamily,
  '--preview-font-size': `${theme.value.fontSize}px`,
}));

// Methods
function toggleSection(section: keyof typeof expandedSections.value) {
  expandedSections.value[section] = !expandedSections.value[section];
}

function applyPreset() {
  const preset = presets.find(p => p.name === selectedPreset.value);
  if (preset) {
    theme.value = { ...preset.theme };
  }
}

function applyTheme() {
  // Apply CSS variables to document
  const root = document.documentElement;

  root.style.setProperty('--terminal-bg', theme.value.background);
  root.style.setProperty('--terminal-fg', theme.value.foreground);
  root.style.setProperty('--panel-bg', theme.value.backgroundAlt);
  root.style.setProperty('--panel-fg', theme.value.foreground);
  root.style.setProperty('--border-color', theme.value.border);
  root.style.setProperty('--accent-color', theme.value.accent);
  root.style.setProperty('--success-color', theme.value.success);
  root.style.setProperty('--warning-color', theme.value.warning);
  root.style.setProperty('--error-color', theme.value.error);
  root.style.setProperty('--muted-color', theme.value.foregroundMuted);

  // Save to localStorage
  localStorage.setItem('warp_open_theme', JSON.stringify(theme.value));

  emit('apply', theme.value);
}

function resetTheme() {
  selectedPreset.value = 'catppuccin-mocha';
  applyPreset();
}

function exportTheme() {
  const data = JSON.stringify(theme.value, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `${theme.value.name || 'custom'}-theme.json`;
  a.click();

  URL.revokeObjectURL(url);
}

function importTheme() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';

  input.onchange = (e) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const imported = JSON.parse(e.target?.result as string);
        theme.value = { ...theme.value, ...imported };
        selectedPreset.value = 'custom';
      } catch (err) {
        console.error('[ThemeEditor] Error importing theme:', err);
      }
    };
    reader.readAsText(file);
  };

  input.click();
}

// Load saved theme
onMounted(() => {
  const saved = localStorage.getItem('warp_open_theme');
  if (saved) {
    try {
      theme.value = { ...theme.value, ...JSON.parse(saved) };
      // Find matching preset
      const match = presets.find(p => p.theme.background === theme.value.background);
      if (match) {
        selectedPreset.value = match.name;
      }
    } catch {
      // Use default
    }
  }
});

// ColorInput sub-component
const ColorInput = defineComponent({
  props: {
    modelValue: { type: String, required: true },
    label: { type: String, required: true },
  },
  emits: ['update:modelValue'],
  setup(props, { emit }) {
    return () =>
      h('div', { class: 'theme-editor__color-input' }, [
        h('label', { class: 'theme-editor__color-label' }, props.label),
        h('div', { class: 'theme-editor__color-wrapper' }, [
          h('input', {
            type: 'color',
            value: props.modelValue,
            class: 'theme-editor__color-picker',
            onInput: (e: Event) => emit('update:modelValue', (e.target as HTMLInputElement).value),
          }),
          h('input', {
            type: 'text',
            value: props.modelValue,
            class: 'theme-editor__color-text',
            onInput: (e: Event) => emit('update:modelValue', (e.target as HTMLInputElement).value),
          }),
        ]),
      ]);
  },
});
</script>

<style scoped>
.theme-editor {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--panel-bg, #1e1e2e);
  color: var(--panel-fg, #cdd6f4);
  font-size: 13px;
}

.theme-editor__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
}

.theme-editor__title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}

.theme-editor__controls {
  display: flex;
  gap: 8px;
}

.theme-editor__btn {
  padding: 4px 10px;
  background: var(--button-bg, #45475a);
  border: none;
  border-radius: 4px;
  color: inherit;
  cursor: pointer;
  font-size: 12px;
}

.theme-editor__btn:hover {
  background: var(--button-hover, #585b70);
}

.theme-editor__btn--primary {
  background: var(--accent-color, #89b4fa);
  color: var(--panel-bg, #1e1e2e);
}

.theme-editor__selector {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color, #313244);
}

.theme-editor__selector label {
  display: block;
  margin-bottom: 4px;
  font-size: 11px;
  color: var(--muted-color, #6c7086);
}

.theme-editor__select {
  width: 100%;
  padding: 8px;
  background: var(--input-bg, #313244);
  border: 1px solid var(--border-color, #45475a);
  border-radius: 4px;
  color: inherit;
  font-size: 13px;
}

.theme-editor__preview {
  margin: 16px;
  border-radius: 8px;
  overflow: hidden;
  background: var(--preview-bg);
  border: 1px solid var(--preview-border);
  font-family: var(--preview-font);
  font-size: var(--preview-font-size);
}

.theme-editor__preview-header {
  display: flex;
  justify-content: space-between;
  padding: 8px 12px;
  background: rgba(255, 255, 255, 0.05);
  border-bottom: 1px solid var(--preview-border);
  color: var(--preview-muted);
  font-size: 11px;
}

.theme-editor__preview-content {
  padding: 12px;
  color: var(--preview-fg);
}

.theme-editor__preview-prompt {
  margin-bottom: 4px;
}

.theme-editor__preview-user { color: var(--preview-accent); }
.theme-editor__preview-sep { color: var(--preview-muted); }
.theme-editor__preview-host { color: var(--preview-success); }
.theme-editor__preview-dir { color: var(--preview-cyan); font-weight: 500; }
.theme-editor__preview-symbol { color: var(--preview-muted); margin-left: 4px; }

.theme-editor__preview-command {
  color: var(--preview-fg);
  margin-bottom: 8px;
}

.theme-editor__preview-output {
  margin-bottom: 8px;
}

.theme-editor__preview-ai {
  padding: 8px;
  background: rgba(137, 180, 250, 0.1);
  border-radius: 4px;
  margin-bottom: 8px;
}

.theme-editor__preview-ai-label {
  color: var(--preview-accent);
  font-weight: 600;
  margin-right: 8px;
}

.theme-editor__preview-error {
  color: var(--preview-error);
  margin-bottom: 4px;
}

.theme-editor__preview-success {
  color: var(--preview-success);
}

.theme-editor__sections {
  flex: 1;
  overflow: auto;
}

.theme-editor__section {
  border-bottom: 1px solid var(--border-color, #313244);
}

.theme-editor__section-title {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0;
  padding: 12px 16px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  user-select: none;
}

.theme-editor__section-title:hover {
  background: var(--hover-bg, #313244);
}

.theme-editor__section-icon {
  font-size: 10px;
  color: var(--muted-color, #6c7086);
}

.theme-editor__colors {
  padding: 0 16px 16px;
}

.theme-editor__colors--grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
}

.theme-editor__color-input {
  margin-bottom: 12px;
}

.theme-editor__color-label {
  display: block;
  margin-bottom: 4px;
  font-size: 11px;
  color: var(--muted-color, #6c7086);
}

.theme-editor__color-wrapper {
  display: flex;
  gap: 8px;
}

.theme-editor__color-picker {
  width: 40px;
  height: 32px;
  padding: 0;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.theme-editor__color-text {
  flex: 1;
  padding: 4px 8px;
  background: var(--input-bg, #313244);
  border: 1px solid var(--border-color, #45475a);
  border-radius: 4px;
  color: inherit;
  font-family: monospace;
  font-size: 12px;
}

.theme-editor__typography {
  padding: 0 16px 16px;
}

.theme-editor__field {
  margin-bottom: 12px;
}

.theme-editor__field label {
  display: block;
  margin-bottom: 4px;
  font-size: 11px;
  color: var(--muted-color, #6c7086);
}

.theme-editor__range {
  width: calc(100% - 50px);
  vertical-align: middle;
}

.theme-editor__range-value {
  display: inline-block;
  width: 40px;
  text-align: right;
  font-family: monospace;
  font-size: 12px;
}

.theme-editor__footer {
  padding: 12px 16px;
  border-top: 1px solid var(--border-color, #313244);
  text-align: right;
}
</style>
