<template>
  <div class="tab-bar" ref="tabBar">
    <!-- Left scroll indicator -->
    <button
      v-if="canScrollLeft"
      class="scroll-btn scroll-left"
      @click="scrollLeft"
      title="Scroll tabs left"
    >
      ‹
    </button>

    <div class="tabs" ref="tabsContainer" @scroll="updateScrollState">
      <div
        v-for="(tab, index) in tabs"
        :key="tab.id"
        :ref="el => { if (tab.id === activeTabId) activeTabEl = el }"
        :class="['tab', { active: tab.id === activeTabId }]"
        @click="$emit('switch-tab', tab.id)"
        data-testid="tab-item"
      >
        <span class="tab-kind">{{ kindIcon(tab.kind) }}</span>
        <span class="tab-name" @dblclick.stop="handleRename(tab.id, tab.name)">{{ tab.name }}</span>
        <button
          class="close-btn"
          @click.stop="$emit('close-tab', tab.id)"
          v-if="tabs.length > 1"
          title="Close tab"
        >
          ✕
        </button>
        <button
          v-if="index > 0"
          class="reorder-btn"
          @click.stop="$emit('reorder-tab', index, index - 1)"
          title="Move left"
        >
          ←
        </button>
        <button
          v-if="index < tabs.length - 1"
          class="reorder-btn"
          @click.stop="$emit('reorder-tab', index, index + 1)"
          title="Move right"
        >
          →
        </button>
      </div>
      <button class="new-tab-btn" @click="$emit('new-tab')" title="New Terminal">
        +
      </button>
    </div>

    <!-- Right scroll indicator -->
    <button
      v-if="canScrollRight"
      class="scroll-btn scroll-right"
      @click="scrollRight"
      title="Scroll tabs right"
    >
      ›
    </button>

    <!-- Tab count indicator when overflowing -->
    <div v-if="isOverflowing" class="tab-count">
      {{ tabs.length }} tabs
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted, nextTick } from 'vue'
import type { PropType } from 'vue'
import type { Tab } from '../composables/useTabs'

const props = defineProps({
  tabs: {
    type: Array as PropType<Tab[]>,
    required: true
  },
  activeTabId: {
    type: String as PropType<string | null>,
    default: null
  }
})

const emit = defineEmits(['new-tab', 'close-tab', 'switch-tab', 'rename-tab', 'reorder-tab'])

const tabsContainer = ref<HTMLElement | null>(null)
const activeTabEl = ref<HTMLElement | null>(null)
const canScrollLeft = ref(false)
const canScrollRight = ref(false)
const isOverflowing = ref(false)

function updateScrollState() {
  if (!tabsContainer.value) return

  const { scrollLeft, scrollWidth, clientWidth } = tabsContainer.value
  const tolerance = 5 // pixels tolerance for edge detection

  canScrollLeft.value = scrollLeft > tolerance
  canScrollRight.value = scrollLeft < scrollWidth - clientWidth - tolerance
  isOverflowing.value = scrollWidth > clientWidth + tolerance
}

function scrollLeft() {
  if (!tabsContainer.value) return
  tabsContainer.value.scrollBy({ left: -150, behavior: 'smooth' })
}

function scrollRight() {
  if (!tabsContainer.value) return
  tabsContainer.value.scrollBy({ left: 150, behavior: 'smooth' })
}

function scrollActiveTabIntoView() {
  nextTick(() => {
    if (activeTabEl.value && tabsContainer.value) {
      const container = tabsContainer.value
      const tab = activeTabEl.value
      const tabRect = tab.getBoundingClientRect()
      const containerRect = container.getBoundingClientRect()

      // Check if tab is out of view
      if (tabRect.left < containerRect.left) {
        // Tab is to the left of visible area
        container.scrollBy({
          left: tabRect.left - containerRect.left - 10,
          behavior: 'smooth'
        })
      } else if (tabRect.right > containerRect.right) {
        // Tab is to the right of visible area
        container.scrollBy({
          left: tabRect.right - containerRect.right + 10,
          behavior: 'smooth'
        })
      }
    }
  })
}

function handleRename(tabId: string, currentName: string) {
  const newName = prompt('Rename tab:', currentName)
  if (newName && newName !== currentName) {
    emit('rename-tab', tabId, newName)
  }
}

function kindIcon(kind: Tab['kind']) {
  switch (kind) {
    case 'editor':
      return '📝'
    case 'terminal':
      return '⌘'
    case 'ai':
      return '🤖'
    case 'developer':
      return '🛠'
    default:
      return '•'
  }
}

// Handle window resize
let resizeObserver: ResizeObserver | null = null

onMounted(() => {
  updateScrollState()

  // Watch for container size changes
  if (tabsContainer.value) {
    resizeObserver = new ResizeObserver(() => {
      updateScrollState()
    })
    resizeObserver.observe(tabsContainer.value)
  }
})

onUnmounted(() => {
  if (resizeObserver) {
    resizeObserver.disconnect()
  }
})

// Watch for active tab changes to scroll into view
watch(() => props.activeTabId, () => {
  scrollActiveTabIntoView()
  nextTick(updateScrollState)
})

// Watch for tab count changes
watch(() => props.tabs.length, () => {
  nextTick(updateScrollState)
})
</script>

<style scoped>
.tab-bar {
  background-color: var(--tab-bar-bg);
  border-bottom: 1px solid var(--border-color);
  display: flex;
  align-items: center;
  flex: 1;
  height: 36px;
  user-select: none;
  position: relative;
}

.tabs {
  display: flex;
  align-items: center;
  height: 100%;
  overflow-x: auto;
  flex: 1;
  scroll-behavior: smooth;
  scrollbar-width: none; /* Firefox */
  -ms-overflow-style: none; /* IE/Edge */
}

.tabs::-webkit-scrollbar {
  display: none; /* Chrome, Safari, Opera */
}

.tab {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 12px;
  height: 100%;
  background-color: var(--bg-color);
  border-right: 1px solid var(--border-color);
  cursor: pointer;
  transition: background-color 0.2s;
  min-width: 120px;
  max-width: 200px;
  color: var(--text-color);
  flex-shrink: 0;
}

.tab:hover {
  background-color: color-mix(in srgb, var(--bg-color) 80%, white 20%);
}

.tab.active {
  background-color: var(--bg-color);
  border-bottom: 2px solid var(--active-tab-color);
}

.tab-kind {
  font-size: 12px;
}

.tab-name {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
}

.close-btn {
  background: none;
  border: none;
  color: #888;
  cursor: pointer;
  padding: 0;
  width: 16px;
  height: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 3px;
  font-size: 14px;
  transition: all 0.2s;
}

.close-btn:hover {
  background-color: var(--border-color);
  color: var(--text-color);
}

.reorder-btn {
  background: none;
  border: none;
  color: #888;
  cursor: pointer;
  padding: 0 4px;
  width: 20px;
  height: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 3px;
  font-size: 12px;
  transition: all 0.2s;
}

.reorder-btn:hover {
  background-color: var(--border-color);
  color: var(--text-color);
}

.new-tab-btn {
  background: none;
  border: none;
  color: #888;
  cursor: pointer;
  padding: 0 12px;
  height: 100%;
  font-size: 18px;
  transition: all 0.2s;
  flex-shrink: 0;
}

.new-tab-btn:hover {
  background-color: color-mix(in srgb, var(--bg-color) 80%, white 20%);
  color: var(--text-color);
}

/* Scroll buttons */
.scroll-btn {
  background: linear-gradient(to right, var(--tab-bar-bg), transparent);
  border: none;
  color: #94a3b8;
  cursor: pointer;
  padding: 0 8px;
  height: 100%;
  font-size: 20px;
  font-weight: bold;
  transition: all 0.2s;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
}

.scroll-btn.scroll-left {
  background: linear-gradient(to right, var(--tab-bar-bg) 60%, transparent);
}

.scroll-btn.scroll-right {
  background: linear-gradient(to left, var(--tab-bar-bg) 60%, transparent);
}

.scroll-btn:hover {
  color: var(--text-color);
  background: var(--tab-bar-bg);
}

/* Tab count indicator */
.tab-count {
  padding: 0 12px;
  font-size: 11px;
  color: #64748b;
  white-space: nowrap;
  flex-shrink: 0;
}
</style>
