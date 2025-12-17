import { ref, watch } from 'vue'

// Available themes
export const themes = {
  dark: {
    name: 'Dark',
    terminal: {
      background: '#1e1e1e',
      foreground: '#d4d4d4',
      cursor: '#d4d4d4',
      black: '#000000',
      red: '#cd3131',
      green: '#0dbc79',
      yellow: '#e5e510',
      blue: '#2472c8',
      magenta: '#bc3fbc',
      cyan: '#11a8cd',
      white: '#e5e5e5',
      brightBlack: '#666666',
      brightRed: '#f14c4c',
      brightGreen: '#23d18b',
      brightYellow: '#f5f543',
      brightBlue: '#3b8eea',
      brightMagenta: '#d670d6',
      brightCyan: '#29b8db',
      brightWhite: '#e5e5e5'
    },
    ui: {
      background: '#1e1e1e',
      tabBar: '#2d2d2d',
      border: '#404040',
      activeTab: '#007acc',
      text: '#d4d4d4'
    }
  },
  light: {
    name: 'Light',
    terminal: {
      background: '#ffffff',
      foreground: '#333333',
      cursor: '#333333',
      black: '#000000',
      red: '#cd3131',
      green: '#00bc00',
      yellow: '#949800',
      blue: '#0451a5',
      magenta: '#bc05bc',
      cyan: '#0598bc',
      white: '#555555',
      brightBlack: '#666666',
      brightRed: '#cd3131',
      brightGreen: '#14ce14',
      brightYellow: '#b5ba00',
      brightBlue: '#0451a5',
      brightMagenta: '#bc05bc',
      brightCyan: '#0598bc',
      brightWhite: '#a5a5a5'
    },
    ui: {
      background: '#ffffff',
      tabBar: '#f3f3f3',
      border: '#e0e0e0',
      activeTab: '#007acc',
      text: '#333333'
    }
  },
  dracula: {
    name: 'Dracula',
    terminal: {
      background: '#282a36',
      foreground: '#f8f8f2',
      cursor: '#f8f8f2',
      black: '#21222c',
      red: '#ff5555',
      green: '#50fa7b',
      yellow: '#f1fa8c',
      blue: '#bd93f9',
      magenta: '#ff79c6',
      cyan: '#8be9fd',
      white: '#f8f8f2',
      brightBlack: '#6272a4',
      brightRed: '#ff6e6e',
      brightGreen: '#69ff94',
      brightYellow: '#ffffa5',
      brightBlue: '#d6acff',
      brightMagenta: '#ff92df',
      brightCyan: '#a4ffff',
      brightWhite: '#ffffff'
    },
    ui: {
      background: '#282a36',
      tabBar: '#21222c',
      border: '#44475a',
      activeTab: '#bd93f9',
      text: '#f8f8f2'
    }
  }
}

// Current theme (reactive)
const currentTheme = ref(localStorage.getItem('warp-theme') || 'dark')

// Watch for theme changes and save to localStorage
watch(currentTheme, (newTheme) => {
  localStorage.setItem('warp-theme', newTheme)
  applyTheme(newTheme)
})

// Apply theme to document
function applyTheme(themeName) {
  const theme = themes[themeName]
  if (!theme) return

  const root = document.documentElement
  
  // Apply UI colors
  root.style.setProperty('--bg-color', theme.ui.background)
  root.style.setProperty('--tab-bar-bg', theme.ui.tabBar)
  root.style.setProperty('--border-color', theme.ui.border)
  root.style.setProperty('--active-tab-color', theme.ui.activeTab)
  root.style.setProperty('--text-color', theme.ui.text)
}

export function useTheme() {
  // Apply theme on initial load
  if (typeof window !== 'undefined') {
    applyTheme(currentTheme.value)
  }

  const setTheme = (themeName) => {
    if (themes[themeName]) {
      currentTheme.value = themeName
    }
  }

  const getTheme = () => {
    return themes[currentTheme.value]
  }

  const getThemeNames = () => {
    return Object.keys(themes)
  }

  return {
    currentTheme,
    setTheme,
    getTheme,
    getThemeNames,
    themes
  }
}
