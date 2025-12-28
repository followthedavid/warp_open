/**
 * Performance Optimizations
 * Handle 10+ panes and 1M+ lines without degradation
 *
 * Features:
 * - Per-pane render throttling
 * - Lazy pane initialization
 * - Memory pooling for buffers
 * - Offscreen pane suspension
 * - Virtual scrolling for large output
 * - Background processing
 * - Memory pressure handling
 * - Startup time optimization
 */

import { ref, computed, reactive, shallowRef, watch, onUnmounted } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export interface PerformanceConfig {
  // Rendering
  targetFPS: number;
  renderThrottleMs: number;
  offscreenSuspendDelay: number;  // ms before suspending offscreen pane

  // Memory
  maxBufferLines: number;         // Max lines to keep in memory per pane
  memoryPressureThresholdMB: number;
  enableMemoryPooling: boolean;

  // Virtual scrolling
  virtualScrollBuffer: number;    // Lines to render above/below viewport
  lineHeightPx: number;

  // Background processing
  backgroundChunkSize: number;    // Lines to process per frame
  idleCallbackTimeout: number;

  // Large output
  largeOutputThreshold: number;   // Lines that trigger "large output" mode
  compressOldOutput: boolean;     // Compress output beyond threshold
}

export interface PanePerformanceState {
  paneId: string;
  isVisible: boolean;
  isSuspended: boolean;
  totalLines: number;
  renderedLines: number;
  memoryUsageMB: number;
  lastRenderTime: number;
  fps: number;
}

export interface PerformanceMetrics {
  currentFPS: number;
  averageFPS: number;
  memoryUsageMB: number;
  heapUsageMB: number;
  activePanes: number;
  suspendedPanes: number;
  totalBufferedLines: number;
  renderTime: number;
  gcPressure: 'low' | 'medium' | 'high';
}

export interface BufferPool<T> {
  acquire(): T;
  release(item: T): void;
  clear(): void;
  size: number;
  available: number;
}

// ============================================================================
// DEFAULT CONFIGURATION
// ============================================================================

const DEFAULT_CONFIG: PerformanceConfig = {
  targetFPS: 60,
  renderThrottleMs: 16,           // ~60fps
  offscreenSuspendDelay: 5000,    // 5 seconds

  maxBufferLines: 50000,          // 50k lines per pane
  memoryPressureThresholdMB: 500,
  enableMemoryPooling: true,

  virtualScrollBuffer: 50,
  lineHeightPx: 20,

  backgroundChunkSize: 1000,
  idleCallbackTimeout: 50,

  largeOutputThreshold: 10000,
  compressOldOutput: true
};

// ============================================================================
// STATE
// ============================================================================

const config = reactive<PerformanceConfig>({ ...DEFAULT_CONFIG });
const paneStates = reactive<Map<string, PanePerformanceState>>(new Map());
const metrics = reactive<PerformanceMetrics>({
  currentFPS: 60,
  averageFPS: 60,
  memoryUsageMB: 0,
  heapUsageMB: 0,
  activePanes: 0,
  suspendedPanes: 0,
  totalBufferedLines: 0,
  renderTime: 0,
  gcPressure: 'low'
});

// FPS tracking
let frameCount = 0;
let lastFPSUpdate = performance.now();
let fpsHistory: number[] = [];
const FPS_HISTORY_SIZE = 60;

// Render scheduling
let pendingRenders = new Set<string>();
let rafId: number | null = null;
let lastFrameTime = 0;

// Suspension timers
const suspensionTimers = new Map<string, number>();

// Memory pools
const lineBufferPool = createBufferPool<string[]>(() => [], 10);
const objectPool = createBufferPool<Record<string, unknown>>(() => ({}), 50);

// ============================================================================
// BUFFER POOL
// ============================================================================

function createBufferPool<T>(factory: () => T, maxSize: number): BufferPool<T> {
  const available: T[] = [];
  let totalCreated = 0;

  return {
    acquire(): T {
      if (available.length > 0) {
        return available.pop()!;
      }
      totalCreated++;
      return factory();
    },

    release(item: T): void {
      if (available.length < maxSize) {
        // Reset if array
        if (Array.isArray(item)) {
          item.length = 0;
        }
        available.push(item);
      }
    },

    clear(): void {
      available.length = 0;
    },

    get size() {
      return totalCreated;
    },

    get available() {
      return available.length;
    }
  };
}

// ============================================================================
// VIRTUAL SCROLL
// ============================================================================

export interface VirtualScrollState {
  totalLines: number;
  viewportHeight: number;
  scrollTop: number;
  visibleStartIndex: number;
  visibleEndIndex: number;
  offsetY: number;
  totalHeight: number;
}

function calculateVirtualScroll(
  totalLines: number,
  viewportHeight: number,
  scrollTop: number,
  lineHeight: number,
  bufferLines: number
): VirtualScrollState {
  const visibleLines = Math.ceil(viewportHeight / lineHeight);
  const scrolledLines = Math.floor(scrollTop / lineHeight);

  const startIndex = Math.max(0, scrolledLines - bufferLines);
  const endIndex = Math.min(totalLines, scrolledLines + visibleLines + bufferLines);

  return {
    totalLines,
    viewportHeight,
    scrollTop,
    visibleStartIndex: startIndex,
    visibleEndIndex: endIndex,
    offsetY: startIndex * lineHeight,
    totalHeight: totalLines * lineHeight
  };
}

// ============================================================================
// RENDER SCHEDULING
// ============================================================================

function scheduleRender(paneId: string): void {
  pendingRenders.add(paneId);

  if (rafId === null) {
    rafId = requestAnimationFrame(processRenderQueue);
  }
}

function processRenderQueue(timestamp: number): void {
  // Calculate delta
  const delta = timestamp - lastFrameTime;
  lastFrameTime = timestamp;

  // Track FPS
  frameCount++;
  if (timestamp - lastFPSUpdate >= 1000) {
    metrics.currentFPS = frameCount;
    fpsHistory.push(frameCount);
    if (fpsHistory.length > FPS_HISTORY_SIZE) {
      fpsHistory.shift();
    }
    metrics.averageFPS = fpsHistory.reduce((a, b) => a + b, 0) / fpsHistory.length;
    frameCount = 0;
    lastFPSUpdate = timestamp;
  }

  // Throttle if below target FPS
  const frameTime = 1000 / config.targetFPS;
  if (delta < frameTime * 0.5) {
    // We're ahead, can process more
  }

  const startTime = performance.now();

  // Process pending renders
  for (const paneId of pendingRenders) {
    const state = paneStates.get(paneId);
    if (!state || state.isSuspended) continue;

    // Emit render event
    window.dispatchEvent(new CustomEvent('perf:render', {
      detail: { paneId, timestamp }
    }));

    state.lastRenderTime = performance.now();
  }

  pendingRenders.clear();
  metrics.renderTime = performance.now() - startTime;

  rafId = null;
}

// ============================================================================
// PANE MANAGEMENT
// ============================================================================

function registerPane(paneId: string): PanePerformanceState {
  const state: PanePerformanceState = {
    paneId,
    isVisible: true,
    isSuspended: false,
    totalLines: 0,
    renderedLines: 0,
    memoryUsageMB: 0,
    lastRenderTime: 0,
    fps: 60
  };

  paneStates.set(paneId, state);
  updateMetrics();

  return state;
}

function unregisterPane(paneId: string): void {
  paneStates.delete(paneId);

  const timer = suspensionTimers.get(paneId);
  if (timer) {
    clearTimeout(timer);
    suspensionTimers.delete(paneId);
  }

  updateMetrics();
}

function setPaneVisible(paneId: string, visible: boolean): void {
  const state = paneStates.get(paneId);
  if (!state) return;

  state.isVisible = visible;

  if (visible) {
    // Cancel suspension timer
    const timer = suspensionTimers.get(paneId);
    if (timer) {
      clearTimeout(timer);
      suspensionTimers.delete(paneId);
    }

    // Resume if suspended
    if (state.isSuspended) {
      resumePane(paneId);
    }
  } else {
    // Start suspension timer
    const timer = window.setTimeout(() => {
      suspendPane(paneId);
    }, config.offscreenSuspendDelay);

    suspensionTimers.set(paneId, timer);
  }
}

function suspendPane(paneId: string): void {
  const state = paneStates.get(paneId);
  if (!state || state.isSuspended) return;

  state.isSuspended = true;
  metrics.suspendedPanes++;
  metrics.activePanes--;

  // Emit event for pane to free resources
  window.dispatchEvent(new CustomEvent('perf:suspend', {
    detail: { paneId }
  }));

  console.log(`[Perf] Suspended pane ${paneId}`);
}

function resumePane(paneId: string): void {
  const state = paneStates.get(paneId);
  if (!state || !state.isSuspended) return;

  state.isSuspended = false;
  metrics.suspendedPanes--;
  metrics.activePanes++;

  // Emit event for pane to restore
  window.dispatchEvent(new CustomEvent('perf:resume', {
    detail: { paneId }
  }));

  console.log(`[Perf] Resumed pane ${paneId}`);
}

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

function updateMemoryMetrics(): void {
  if ('memory' in performance) {
    const memory = (performance as unknown as { memory: { usedJSHeapSize: number; totalJSHeapSize: number } }).memory;
    metrics.memoryUsageMB = memory.usedJSHeapSize / (1024 * 1024);
    metrics.heapUsageMB = memory.totalJSHeapSize / (1024 * 1024);

    // Determine GC pressure
    const usage = memory.usedJSHeapSize / memory.totalJSHeapSize;
    if (usage > 0.9) {
      metrics.gcPressure = 'high';
    } else if (usage > 0.7) {
      metrics.gcPressure = 'medium';
    } else {
      metrics.gcPressure = 'low';
    }
  }
}

function checkMemoryPressure(): boolean {
  updateMemoryMetrics();

  if (metrics.memoryUsageMB > config.memoryPressureThresholdMB) {
    console.warn('[Perf] Memory pressure detected, triggering cleanup');
    handleMemoryPressure();
    return true;
  }

  return false;
}

function handleMemoryPressure(): void {
  // Clear buffer pools
  lineBufferPool.clear();
  objectPool.clear();

  // Trim large pane buffers
  for (const state of paneStates.values()) {
    if (state.totalLines > config.maxBufferLines) {
      window.dispatchEvent(new CustomEvent('perf:trim_buffer', {
        detail: {
          paneId: state.paneId,
          keepLines: config.maxBufferLines / 2
        }
      }));
    }
  }

  // Suspend non-visible panes immediately
  for (const state of paneStates.values()) {
    if (!state.isVisible && !state.isSuspended) {
      suspendPane(state.paneId);
    }
  }
}

// ============================================================================
// LARGE OUTPUT HANDLING
// ============================================================================

export interface LargeOutputProcessor {
  processChunk(lines: string[]): void;
  getVisibleLines(start: number, end: number): string[];
  getTotalLines(): number;
  clear(): void;
}

function createLargeOutputProcessor(paneId: string): LargeOutputProcessor {
  // Use chunks for memory efficiency
  const CHUNK_SIZE = 10000;
  const chunks: string[][] = [];
  let totalLines = 0;

  return {
    processChunk(lines: string[]): void {
      // Process in background
      if ('requestIdleCallback' in window) {
        requestIdleCallback(() => {
          for (const line of lines) {
            if (chunks.length === 0 || chunks[chunks.length - 1].length >= CHUNK_SIZE) {
              chunks.push([]);
            }
            chunks[chunks.length - 1].push(line);
            totalLines++;
          }

          // Update pane state
          const state = paneStates.get(paneId);
          if (state) {
            state.totalLines = totalLines;
          }
        }, { timeout: config.idleCallbackTimeout });
      } else {
        // Fallback for browsers without requestIdleCallback
        for (const line of lines) {
          if (chunks.length === 0 || chunks[chunks.length - 1].length >= CHUNK_SIZE) {
            chunks.push([]);
          }
          chunks[chunks.length - 1].push(line);
          totalLines++;
        }
      }
    },

    getVisibleLines(start: number, end: number): string[] {
      const result: string[] = [];

      const startChunk = Math.floor(start / CHUNK_SIZE);
      const endChunk = Math.floor(end / CHUNK_SIZE);

      for (let c = startChunk; c <= endChunk && c < chunks.length; c++) {
        const chunk = chunks[c];
        const chunkStart = c * CHUNK_SIZE;

        for (let i = 0; i < chunk.length; i++) {
          const lineIndex = chunkStart + i;
          if (lineIndex >= start && lineIndex < end) {
            result.push(chunk[i]);
          }
        }
      }

      return result;
    },

    getTotalLines(): number {
      return totalLines;
    },

    clear(): void {
      chunks.length = 0;
      totalLines = 0;
    }
  };
}

// ============================================================================
// DEBOUNCE / THROTTLE
// ============================================================================

function throttle<T extends (...args: Parameters<T>) => void>(
  fn: T,
  limit: number
): T {
  let lastRun = 0;
  let timeout: number | null = null;

  return ((...args: Parameters<T>) => {
    const now = Date.now();

    if (now - lastRun >= limit) {
      fn(...args);
      lastRun = now;
    } else if (!timeout) {
      timeout = window.setTimeout(() => {
        fn(...args);
        lastRun = Date.now();
        timeout = null;
      }, limit - (now - lastRun));
    }
  }) as T;
}

function debounce<T extends (...args: Parameters<T>) => void>(
  fn: T,
  delay: number
): T {
  let timeout: number | null = null;

  return ((...args: Parameters<T>) => {
    if (timeout) clearTimeout(timeout);
    timeout = window.setTimeout(() => fn(...args), delay);
  }) as T;
}

// ============================================================================
// METRICS
// ============================================================================

function updateMetrics(): void {
  let totalLines = 0;
  let active = 0;
  let suspended = 0;

  for (const state of paneStates.values()) {
    totalLines += state.totalLines;
    if (state.isSuspended) {
      suspended++;
    } else {
      active++;
    }
  }

  metrics.totalBufferedLines = totalLines;
  metrics.activePanes = active;
  metrics.suspendedPanes = suspended;

  updateMemoryMetrics();
}

// Start periodic metrics update
let metricsInterval: number | null = null;

function startMetricsCollection(): void {
  if (metricsInterval) return;

  metricsInterval = window.setInterval(() => {
    updateMetrics();
  }, 1000);
}

function stopMetricsCollection(): void {
  if (metricsInterval) {
    clearInterval(metricsInterval);
    metricsInterval = null;
  }
}

// ============================================================================
// STARTUP OPTIMIZATION
// ============================================================================

interface DeferredTask {
  id: string;
  priority: number;
  task: () => void | Promise<void>;
}

const deferredTasks: DeferredTask[] = [];
let isProcessingDeferred = false;

function deferTask(id: string, task: () => void | Promise<void>, priority = 0): void {
  deferredTasks.push({ id, priority, task });
  deferredTasks.sort((a, b) => b.priority - a.priority);

  if (!isProcessingDeferred) {
    processDeferredTasks();
  }
}

async function processDeferredTasks(): Promise<void> {
  if (isProcessingDeferred) return;
  isProcessingDeferred = true;

  while (deferredTasks.length > 0) {
    // Wait for idle
    await new Promise<void>(resolve => {
      if ('requestIdleCallback' in window) {
        requestIdleCallback(() => resolve(), { timeout: 100 });
      } else {
        setTimeout(resolve, 16);
      }
    });

    const task = deferredTasks.shift();
    if (task) {
      try {
        await task.task();
      } catch (e) {
        console.error(`[Perf] Deferred task ${task.id} failed:`, e);
      }
    }
  }

  isProcessingDeferred = false;
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function usePerformance() {
  /**
   * Initialize performance monitoring
   */
  function initialize(): void {
    startMetricsCollection();

    // Start memory pressure checks
    setInterval(checkMemoryPressure, 30000);

    console.log('[Perf] Performance monitoring initialized');
  }

  /**
   * Shutdown
   */
  function shutdown(): void {
    stopMetricsCollection();

    if (rafId) {
      cancelAnimationFrame(rafId);
    }

    for (const timer of suspensionTimers.values()) {
      clearTimeout(timer);
    }
    suspensionTimers.clear();
  }

  /**
   * Update configuration
   */
  function updateConfig(newConfig: Partial<PerformanceConfig>): void {
    Object.assign(config, newConfig);
  }

  /**
   * Get pane state
   */
  function getPaneState(paneId: string): PanePerformanceState | undefined {
    return paneStates.get(paneId);
  }

  /**
   * Update pane line count
   */
  function updatePaneLines(paneId: string, totalLines: number, renderedLines?: number): void {
    const state = paneStates.get(paneId);
    if (state) {
      state.totalLines = totalLines;
      if (renderedLines !== undefined) {
        state.renderedLines = renderedLines;
      }
    }
    updateMetrics();
  }

  return {
    // Config
    config: computed(() => config),
    updateConfig,

    // Metrics
    metrics: computed(() => ({ ...metrics })),

    // Lifecycle
    initialize,
    shutdown,

    // Pane management
    registerPane,
    unregisterPane,
    setPaneVisible,
    suspendPane,
    resumePane,
    getPaneState,
    updatePaneLines,

    // Rendering
    scheduleRender,

    // Virtual scrolling
    calculateVirtualScroll: (totalLines: number, viewportHeight: number, scrollTop: number) =>
      calculateVirtualScroll(
        totalLines,
        viewportHeight,
        scrollTop,
        config.lineHeightPx,
        config.virtualScrollBuffer
      ),

    // Large output
    createLargeOutputProcessor,

    // Memory
    checkMemoryPressure,

    // Buffer pools
    lineBufferPool,
    objectPool,

    // Utilities
    throttle,
    debounce,
    deferTask
  };
}

export default usePerformance;
