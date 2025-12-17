<template>
  <div
    v-if="node.type === 'leaf'"
    class="pane-leaf"
    :class="{ 'pane-active': node.paneId === activePaneId }"
    @click="$emit('pane-focus', node.paneId)"
  >
    <TerminalPane
      :paneId="node.paneId"
      :ptyId="node.ptyId"
      :isActive="node.paneId === activePaneId"
      @cwd-change="$emit('cwd-change', $event)"
      @title-change="$emit('title-change', $event)"
      @output-change="$emit('output-change', $event)"
      @command-executed="$emit('command-executed', $event)"
    />
  </div>
  <div
    v-else
    class="pane-split"
    :class="node.direction"
    ref="splitContainer"
  >
    <div class="split-first" :style="firstStyle">
      <LayoutRenderer
        :node="node.first"
        :activePaneId="activePaneId"
        @pane-focus="$emit('pane-focus', $event)"
        @cwd-change="$emit('cwd-change', $event)"
        @title-change="$emit('title-change', $event)"
        @output-change="$emit('output-change', $event)"
        @command-executed="$emit('command-executed', $event)"
        @resize="$emit('resize', $event)"
      />
    </div>
    <div
      class="split-divider"
      :class="[node.direction, { dragging: isDragging }]"
      @mousedown="startResize"
      @dblclick="resetRatio"
      :title="ratioTooltip + ' (Double-click to reset)'"
    >
      <div class="divider-handle"></div>
      <div v-if="isDragging || showRatioHint" class="ratio-indicator" :class="{ transient: showRatioHint && !isDragging }">
        {{ ratioPercent }}%
      </div>
    </div>
    <div class="split-second" :style="secondStyle">
      <LayoutRenderer
        :node="node.second"
        :activePaneId="activePaneId"
        @pane-focus="$emit('pane-focus', $event)"
        @cwd-change="$emit('cwd-change', $event)"
        @title-change="$emit('title-change', $event)"
        @output-change="$emit('output-change', $event)"
        @command-executed="$emit('command-executed', $event)"
        @resize="$emit('resize', $event)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onUnmounted } from 'vue'
import TerminalPane from './TerminalPane.vue'
import type { LayoutNode, SplitNode } from '../composables/useTabs'

const MIN_PANE_SIZE = 0.1 // 10% minimum
const MAX_PANE_SIZE = 0.9 // 90% maximum

const props = defineProps<{
  node: LayoutNode
  activePaneId: string | undefined
}>()

const emit = defineEmits(['pane-focus', 'cwd-change', 'title-change', 'output-change', 'command-executed', 'resize'])

const splitContainer = ref<HTMLElement | null>(null)
const isDragging = ref(false)
const showRatioHint = ref(false)
let ratioHintTimer: ReturnType<typeof setTimeout> | null = null
const currentRatio = ref(props.node.type === 'split' ? (props.node as SplitNode).ratio : 0.5)

// Watch for external ratio changes
const firstStyle = computed(() => {
  if (props.node.type !== 'split') return {}
  const ratio = isDragging.value ? currentRatio.value : (props.node as SplitNode).ratio
  const percent = ratio * 100
  return props.node.direction === 'horizontal'
    ? { width: `calc(${percent}% - 3px)` }
    : { height: `calc(${percent}% - 3px)` }
})

const secondStyle = computed(() => {
  if (props.node.type !== 'split') return {}
  const ratio = isDragging.value ? currentRatio.value : (props.node as SplitNode).ratio
  const percent = (1 - ratio) * 100
  return props.node.direction === 'horizontal'
    ? { width: `calc(${percent}% - 3px)` }
    : { height: `calc(${percent}% - 3px)` }
})

// Ratio display for indicator and tooltip
const ratioPercent = computed(() => {
  const ratio = isDragging.value ? currentRatio.value : (props.node.type === 'split' ? (props.node as SplitNode).ratio : 0.5)
  return Math.round(ratio * 100)
})

const ratioTooltip = computed(() => {
  return `Drag to resize (${ratioPercent.value}% / ${100 - ratioPercent.value}%)`
})

function startResize(e: MouseEvent) {
  if (props.node.type !== 'split') return

  e.preventDefault()
  isDragging.value = true
  currentRatio.value = (props.node as SplitNode).ratio

  const container = splitContainer.value
  if (!container) return

  const rect = container.getBoundingClientRect()
  const isHorizontal = props.node.direction === 'horizontal'

  function onMouseMove(e: MouseEvent) {
    if (!isDragging.value) return

    let ratio: number
    if (isHorizontal) {
      ratio = (e.clientX - rect.left) / rect.width
    } else {
      ratio = (e.clientY - rect.top) / rect.height
    }

    // Clamp to min/max
    ratio = Math.max(MIN_PANE_SIZE, Math.min(MAX_PANE_SIZE, ratio))
    currentRatio.value = ratio
  }

  function onMouseUp() {
    if (isDragging.value && props.node.type === 'split') {
      // Emit the new ratio to parent for persistence
      emit('resize', {
        nodeId: getNodeId(props.node),
        ratio: currentRatio.value
      })
    }
    isDragging.value = false
    document.removeEventListener('mousemove', onMouseMove)
    document.removeEventListener('mouseup', onMouseUp)
    document.body.style.cursor = ''
    document.body.style.userSelect = ''
  }

  document.addEventListener('mousemove', onMouseMove)
  document.addEventListener('mouseup', onMouseUp)
  document.body.style.cursor = isHorizontal ? 'col-resize' : 'row-resize'
  document.body.style.userSelect = 'none'
}

// Generate a unique ID for this split node based on its children
function getNodeId(node: LayoutNode): string {
  if (node.type === 'leaf') {
    return node.paneId
  }
  return `split-${getNodeId(node.first)}-${getNodeId(node.second)}`
}

// Reset ratio to 50% on double-click
function resetRatio() {
  if (props.node.type !== 'split') return

  currentRatio.value = 0.5
  showRatioHint.value = true

  // Clear any existing timer
  if (ratioHintTimer) {
    clearTimeout(ratioHintTimer)
  }

  // Hide the hint after a short delay
  ratioHintTimer = setTimeout(() => {
    showRatioHint.value = false
    ratioHintTimer = null
  }, 1000)

  // Emit the new ratio
  emit('resize', {
    nodeId: getNodeId(props.node),
    ratio: 0.5
  })
}

onUnmounted(() => {
  // Cleanup any lingering event listeners
  isDragging.value = false
  if (ratioHintTimer) {
    clearTimeout(ratioHintTimer)
  }
})
</script>

<style scoped>
.pane-leaf {
  width: 100%;
  height: 100%;
  position: relative;
}

.pane-active {
  /* Active pane indicator handled by border */
}

.pane-active::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: #3b82f6;
  z-index: 10;
}

.pane-split {
  width: 100%;
  height: 100%;
  display: flex;
}

.pane-split.horizontal {
  flex-direction: row;
}

.pane-split.vertical {
  flex-direction: column;
}

.split-first,
.split-second {
  overflow: hidden;
  min-width: 50px;
  min-height: 50px;
}

.split-divider {
  flex-shrink: 0;
  background: #1e293b;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.15s ease;
  z-index: 5;
}

.split-divider:hover,
.split-divider.dragging {
  background: #3b82f6;
}

.split-divider.horizontal {
  width: 6px;
  cursor: col-resize;
}

.split-divider.vertical {
  height: 6px;
  cursor: row-resize;
}

.divider-handle {
  background: #475569;
  border-radius: 2px;
  transition: background 0.15s ease;
}

.split-divider:hover .divider-handle,
.split-divider.dragging .divider-handle {
  background: white;
}

.split-divider.horizontal .divider-handle {
  width: 2px;
  height: 32px;
}

.split-divider.vertical .divider-handle {
  width: 32px;
  height: 2px;
}

/* Ratio indicator shown during drag */
.ratio-indicator {
  position: absolute;
  background: #1e293b;
  color: #e2e8f0;
  font-size: 11px;
  font-weight: 600;
  padding: 4px 8px;
  border-radius: 4px;
  border: 1px solid #3b82f6;
  white-space: nowrap;
  pointer-events: none;
  z-index: 100;
}

.split-divider.horizontal .ratio-indicator {
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%) translateX(20px);
}

.split-divider.vertical .ratio-indicator {
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%) translateY(20px);
}

/* Transient ratio hint (after double-click reset) */
.ratio-indicator.transient {
  animation: fadeInOut 1s ease-out;
  background: #10b981;
  border-color: #10b981;
}

@keyframes fadeInOut {
  0% { opacity: 0; transform: translate(-50%, -50%) scale(0.8); }
  20% { opacity: 1; transform: translate(-50%, -50%) scale(1); }
  80% { opacity: 1; }
  100% { opacity: 0; }
}

/* Add transition to panes for smooth resize after double-click */
.split-first,
.split-second {
  transition: none;
}

/* During non-drag resize (like double-click), use transition */
.pane-split:not(:has(.dragging)) .split-first,
.pane-split:not(:has(.dragging)) .split-second {
  transition: width 0.2s ease-out, height 0.2s ease-out;
}
</style>
