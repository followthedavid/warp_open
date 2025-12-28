<template>
  <div class="test-runner-panel">
    <div class="panel-header">
      <div class="header-left">
        <span class="panel-icon">🧪</span>
        <span class="panel-title">Test Runner</span>
      </div>
      <div class="header-right">
        <button class="btn-icon" @click="runTests" :disabled="isRunning">
          {{ isRunning ? '⏳' : '▶' }}
        </button>
        <button class="btn-icon" @click="clearResults" :disabled="!results.length">
          🗑
        </button>
      </div>
    </div>

    <div class="test-summary" v-if="summary">
      <div class="summary-item passed">
        <span class="count">{{ summary.passed }}</span>
        <span class="label">passed</span>
      </div>
      <div class="summary-item failed" v-if="summary.failed">
        <span class="count">{{ summary.failed }}</span>
        <span class="label">failed</span>
      </div>
      <div class="summary-item skipped" v-if="summary.skipped">
        <span class="count">{{ summary.skipped }}</span>
        <span class="label">skipped</span>
      </div>
      <div class="summary-duration" v-if="summary.duration">
        {{ formatDuration(summary.duration) }}
      </div>
    </div>

    <div class="test-results" v-if="results.length">
      <div
        v-for="(result, index) in results"
        :key="index"
        class="test-item"
        :class="result.status"
        @click="toggleExpanded(index)"
      >
        <span class="test-status">
          {{ result.status === 'passed' ? '✓' : result.status === 'failed' ? '✗' : '○' }}
        </span>
        <span class="test-name">{{ result.name }}</span>
        <span class="test-duration" v-if="result.duration">{{ result.duration }}ms</span>

        <div class="test-details" v-if="expandedTests.has(index) && result.error">
          <pre class="error-output">{{ result.error }}</pre>
          <div class="error-location" v-if="result.file">
            <a @click.stop="openFile(result.file, result.line)">
              {{ result.file }}{{ result.line ? ':' + result.line : '' }}
            </a>
          </div>
        </div>
      </div>
    </div>

    <div class="empty-state" v-else-if="!isRunning">
      <p>No test results</p>
      <p class="hint">Run tests with ▶ or use <code>npm test</code></p>
    </div>

    <div class="running-state" v-if="isRunning">
      <div class="spinner">⟳</div>
      <span>Running tests...</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

interface TestResult {
  name: string
  status: 'passed' | 'failed' | 'skipped' | 'error'
  duration?: number
  error?: string
  file?: string
  line?: number
}

interface TestSummary {
  passed: number
  failed: number
  skipped: number
  total: number
  duration?: number
}

const props = defineProps<{
  testCommand?: string
  cwd?: string
}>()

const emit = defineEmits<{
  (e: 'openFile', file: string, line?: number): void
}>()

const results = ref<TestResult[]>([])
const isRunning = ref(false)
const expandedTests = ref<Set<number>>(new Set())

const summary = computed<TestSummary | null>(() => {
  if (!results.value.length) return null

  return {
    passed: results.value.filter(r => r.status === 'passed').length,
    failed: results.value.filter(r => r.status === 'failed').length,
    skipped: results.value.filter(r => r.status === 'skipped').length,
    total: results.value.length,
    duration: results.value.reduce((sum, r) => sum + (r.duration || 0), 0)
  }
})

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

function toggleExpanded(index: number) {
  if (expandedTests.value.has(index)) {
    expandedTests.value.delete(index)
  } else {
    expandedTests.value.add(index)
  }
  expandedTests.value = new Set(expandedTests.value)
}

function openFile(file: string, line?: number) {
  emit('openFile', file, line)
}

async function runTests() {
  isRunning.value = true
  results.value = []
  expandedTests.value = new Set()

  const command = props.testCommand || 'npm test -- --reporter=json 2>&1'

  try {
    const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command,
      cwd: props.cwd || undefined
    })

    const output = result.stdout + result.stderr
    results.value = parseTestOutput(output)
  } catch (error) {
    results.value = [{
      name: 'Test execution failed',
      status: 'error',
      error: String(error)
    }]
  } finally {
    isRunning.value = false
  }
}

function parseTestOutput(output: string): TestResult[] {
  const parsed: TestResult[] = []

  // Try to parse as JSON (Jest, Vitest with --reporter=json)
  try {
    const json = JSON.parse(output)
    if (json.testResults) {
      // Jest format
      for (const file of json.testResults) {
        for (const test of file.assertionResults || []) {
          parsed.push({
            name: test.fullName || test.title,
            status: test.status === 'passed' ? 'passed' : 'failed',
            duration: test.duration,
            error: test.failureMessages?.join('\n'),
            file: file.name
          })
        }
      }
      return parsed
    }
  } catch {}

  // Parse line-by-line for common formats
  const lines = output.split('\n')

  // Jest/Vitest pattern: ✓ test name (123 ms)
  const passPattern = /^\s*[✓✔]\s+(.+?)(?:\s+\((\d+)\s*m?s\))?$/
  const failPattern = /^\s*[✗✘×]\s+(.+?)(?:\s+\((\d+)\s*m?s\))?$/

  // Cargo test pattern: test name ... ok/FAILED
  const cargoPassPattern = /^test\s+(.+?)\s+\.\.\.\s+ok$/
  const cargoFailPattern = /^test\s+(.+?)\s+\.\.\.\s+FAILED$/

  // Pytest pattern: test_name PASSED/FAILED
  const pytestPassPattern = /^(.+?)\s+PASSED/
  const pytestFailPattern = /^(.+?)\s+FAILED/

  for (const line of lines) {
    let match

    if ((match = line.match(passPattern))) {
      parsed.push({
        name: match[1].trim(),
        status: 'passed',
        duration: match[2] ? parseInt(match[2]) : undefined
      })
    } else if ((match = line.match(failPattern))) {
      parsed.push({
        name: match[1].trim(),
        status: 'failed',
        duration: match[2] ? parseInt(match[2]) : undefined
      })
    } else if ((match = line.match(cargoPassPattern))) {
      parsed.push({
        name: match[1].trim(),
        status: 'passed'
      })
    } else if ((match = line.match(cargoFailPattern))) {
      parsed.push({
        name: match[1].trim(),
        status: 'failed'
      })
    } else if ((match = line.match(pytestPassPattern))) {
      parsed.push({
        name: match[1].trim(),
        status: 'passed'
      })
    } else if ((match = line.match(pytestFailPattern))) {
      parsed.push({
        name: match[1].trim(),
        status: 'failed'
      })
    }
  }

  // If no tests found, create a single result from the output
  if (parsed.length === 0 && output.trim()) {
    parsed.push({
      name: 'Test output',
      status: output.toLowerCase().includes('fail') || output.toLowerCase().includes('error') ? 'failed' : 'passed',
      error: output
    })
  }

  return parsed
}

function clearResults() {
  results.value = []
  expandedTests.value = new Set()
}

defineExpose({
  runTests,
  clearResults,
  results,
  summary
})
</script>

<style scoped>
.test-runner-panel {
  background: var(--bg-primary, #1a1a2e);
  border: 1px solid var(--border-color, #333);
  border-radius: 8px;
  overflow: hidden;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 13px;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  background: var(--bg-secondary, #252540);
  border-bottom: 1px solid var(--border-color, #333);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.panel-icon {
  font-size: 14px;
}

.panel-title {
  font-weight: 600;
  color: var(--text-primary, #fff);
}

.header-right {
  display: flex;
  gap: 4px;
}

.btn-icon {
  background: none;
  border: none;
  padding: 4px 8px;
  cursor: pointer;
  border-radius: 4px;
  font-size: 14px;
}

.btn-icon:hover:not(:disabled) {
  background: var(--bg-hover, rgba(255,255,255,0.1));
}

.btn-icon:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.test-summary {
  display: flex;
  gap: 16px;
  padding: 12px;
  background: var(--bg-tertiary, rgba(255,255,255,0.02));
  border-bottom: 1px solid var(--border-color, #333);
}

.summary-item {
  display: flex;
  align-items: baseline;
  gap: 4px;
}

.summary-item .count {
  font-size: 18px;
  font-weight: 600;
}

.summary-item .label {
  font-size: 11px;
  color: var(--text-muted, #888);
}

.summary-item.passed .count {
  color: var(--success-color, #4ade80);
}

.summary-item.failed .count {
  color: var(--error-color, #f87171);
}

.summary-item.skipped .count {
  color: var(--warning-color, #fbbf24);
}

.summary-duration {
  margin-left: auto;
  color: var(--text-muted, #888);
  font-size: 12px;
}

.test-results {
  max-height: 400px;
  overflow-y: auto;
}

.test-item {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  cursor: pointer;
  border-bottom: 1px solid var(--border-color, #222);
}

.test-item:hover {
  background: var(--bg-hover, rgba(255,255,255,0.03));
}

.test-status {
  width: 16px;
  text-align: center;
}

.test-item.passed .test-status {
  color: var(--success-color, #4ade80);
}

.test-item.failed .test-status {
  color: var(--error-color, #f87171);
}

.test-item.skipped .test-status {
  color: var(--warning-color, #fbbf24);
}

.test-name {
  flex: 1;
  color: var(--text-primary, #ddd);
}

.test-duration {
  font-size: 11px;
  color: var(--text-muted, #666);
}

.test-details {
  width: 100%;
  margin-top: 8px;
  padding: 8px;
  background: var(--bg-primary, #0d0d1a);
  border-radius: 4px;
}

.error-output {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 11px;
  color: var(--error-color, #f87171);
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}

.error-location {
  margin-top: 8px;
}

.error-location a {
  color: var(--accent-color, #60a5fa);
  text-decoration: underline;
  cursor: pointer;
  font-size: 11px;
}

.empty-state,
.running-state {
  padding: 24px;
  text-align: center;
  color: var(--text-muted, #888);
}

.hint {
  font-size: 12px;
  margin-top: 8px;
}

.hint code {
  background: var(--bg-tertiary, rgba(255,255,255,0.1));
  padding: 2px 6px;
  border-radius: 4px;
}

.running-state {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.spinner {
  animation: spin 1s linear infinite;
  display: inline-block;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>
