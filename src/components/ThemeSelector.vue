<template>
  <div class="theme-selector">
    <select v-model="currentTheme" @change="handleThemeChange" class="theme-select">
      <option v-for="themeName in themeNames" :key="themeName" :value="themeName">
        {{ themes[themeName].name }}
      </option>
    </select>
  </div>
</template>

<script setup>
import { useTheme } from '../composables/useTheme'

const { currentTheme, setTheme, themes, getThemeNames } = useTheme()
const themeNames = getThemeNames()

function handleThemeChange() {
  setTheme(currentTheme.value)
  // Emit event to notify parent (e.g., to update terminal themes)
  emit('theme-changed', currentTheme.value)
}

const emit = defineEmits(['theme-changed'])
</script>

<style scoped>
.theme-selector {
  display: flex;
  align-items: center;
  padding: 0 12px;
}

.theme-select {
  background: var(--bg-color, #1e1e1e);
  color: var(--text-color, #d4d4d4);
  border: 1px solid var(--border-color, #404040);
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
  outline: none;
  transition: all 0.2s;
}

.theme-select:hover {
  border-color: var(--active-tab-color, #007acc);
}

.theme-select:focus {
  border-color: var(--active-tab-color, #007acc);
  box-shadow: 0 0 0 2px rgba(0, 122, 204, 0.2);
}

.theme-select option {
  background: var(--bg-color, #1e1e1e);
  color: var(--text-color, #d4d4d4);
}
</style>
