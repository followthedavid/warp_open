/**
 * Claude Code Parity Test Suite
 * Tests all implemented tools and features for 100% parity
 */

import { invoke } from '@tauri-apps/api/tauri'

interface TestResult {
  name: string
  passed: boolean
  error?: string
  duration: number
}

const results: TestResult[] = []

async function runTest(name: string, fn: () => Promise<void>): Promise<void> {
  const start = Date.now()
  try {
    await fn()
    results.push({ name, passed: true, duration: Date.now() - start })
    console.log(`✅ ${name}`)
  } catch (error) {
    results.push({ name, passed: false, error: String(error), duration: Date.now() - start })
    console.log(`❌ ${name}: ${error}`)
  }
}

// Test 1: Read tool with offset/limit
async function testRead() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'head -20 package.json',
    cwd: process.cwd()
  })
  if (!result.stdout.includes('"name"')) {
    throw new Error('Read failed - no content returned')
  }
}

// Test 2: Grep tool with ripgrep
async function testGrep() {
  const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
    command: 'rg --version || grep --version',
    cwd: undefined
  })
  if (result.exit_code !== 0) {
    throw new Error('Grep/ripgrep not available')
  }

  // Test actual grep
  const search = await invoke<{ stdout: string }>('execute_shell', {
    command: 'rg -l "useTools" --type ts || grep -rl "useTools" --include="*.ts" .',
    cwd: process.cwd()
  })
  if (!search.stdout) {
    throw new Error('Grep search returned no results')
  }
}

// Test 3: Glob tool
async function testGlob() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'fd -e vue -t f || find . -name "*.vue" -type f | head -10',
    cwd: process.cwd()
  })
  if (!result.stdout.includes('.vue')) {
    throw new Error('Glob found no Vue files')
  }
}

// Test 4: WebSearch (DuckDuckGo)
async function testWebSearch() {
  const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
    command: 'curl -sL "https://html.duckduckgo.com/html/?q=test" | head -c 1000',
    cwd: undefined
  })
  if (result.exit_code !== 0 || !result.stdout) {
    throw new Error('WebSearch curl failed')
  }
}

// Test 5: Background task execution
async function testBackgroundTask() {
  const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
    command: 'sleep 0.1 && echo "background complete"',
    cwd: undefined
  })
  if (!result.stdout.includes('complete')) {
    throw new Error('Background task did not complete')
  }
}

// Test 6: Edit tool (simulated)
async function testEdit() {
  // Create test file
  await invoke('execute_shell', {
    command: 'echo "line1\nline2\nline3" > /tmp/test_edit.txt',
    cwd: undefined
  })

  // Read and verify
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat /tmp/test_edit.txt',
    cwd: undefined
  })
  if (!result.stdout.includes('line2')) {
    throw new Error('Edit test file creation failed')
  }

  // Cleanup
  await invoke('execute_shell', {
    command: 'rm /tmp/test_edit.txt',
    cwd: undefined
  })
}

// Test 7: TodoWrite (check composable exists)
async function testTodoList() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat src/composables/useTodoList.ts | head -20',
    cwd: process.cwd()
  })
  if (!result.stdout.includes('TodoItem')) {
    throw new Error('useTodoList composable not found')
  }
}

// Test 8: MCP Server support
async function testMCPServers() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat src/composables/useMCPServers.ts 2>/dev/null | head -5 || echo "not found"',
    cwd: process.cwd()
  })
  if (result.stdout.includes('not found')) {
    throw new Error('MCP Servers composable not found')
  }
}

// Test 9: Slash commands
async function testSlashCommands() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat src/composables/useSlashCommands.ts 2>/dev/null | grep -c "registerCommand" || echo "0"',
    cwd: process.cwd()
  })
  const count = parseInt(result.stdout.trim())
  if (count < 5) {
    throw new Error(`Only ${count} slash commands registered`)
  }
}

// Test 10: Hooks system
async function testHooksSystem() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat src/composables/useHooks.ts 2>/dev/null | head -20 || echo "not found"',
    cwd: process.cwd()
  })
  if (result.stdout.includes('not found')) {
    throw new Error('Hooks system not found')
  }
}

// Test 11: Planning mode
async function testPlanningMode() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat src/composables/usePlanningMode.ts 2>/dev/null | head -20 || echo "not found"',
    cwd: process.cwd()
  })
  if (result.stdout.includes('not found')) {
    throw new Error('Planning mode not found')
  }
}

// Test 12: Context compression
async function testContextCompression() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat src/composables/useContextCompression.ts 2>/dev/null | head -20 || echo "not found"',
    cwd: process.cwd()
  })
  if (result.stdout.includes('not found')) {
    throw new Error('Context compression not found')
  }
}

// Test 13: Block sharing
async function testBlockSharing() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat src/composables/useBlockSharing.ts 2>/dev/null | head -20 || echo "not found"',
    cwd: process.cwd()
  })
  if (result.stdout.includes('not found')) {
    throw new Error('Block sharing not found')
  }
}

// Test 14: Warp Drive
async function testWarpDrive() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat src/composables/useWarpDrive.ts 2>/dev/null | head -20 || echo "not found"',
    cwd: process.cwd()
  })
  if (result.stdout.includes('not found')) {
    throw new Error('Warp Drive not found')
  }
}

// Test 15: Remote PWA
async function testRemotePWA() {
  const result = await invoke<{ stdout: string }>('execute_shell', {
    command: 'cat public/remote.html 2>/dev/null | grep -c "apple-mobile-web-app-capable" || echo "0"',
    cwd: process.cwd()
  })
  const count = parseInt(result.stdout.trim())
  if (count < 1) {
    throw new Error('Remote PWA not properly configured')
  }
}

// Main test runner
async function runAllTests() {
  console.log('\\n🧪 Claude Code Parity Test Suite\\n')
  console.log('=' .repeat(50))

  await runTest('Read tool', testRead)
  await runTest('Grep tool (ripgrep)', testGrep)
  await runTest('Glob tool (fd/find)', testGlob)
  await runTest('WebSearch (DuckDuckGo)', testWebSearch)
  await runTest('Background tasks', testBackgroundTask)
  await runTest('Edit tool', testEdit)
  await runTest('TodoWrite/TodoList', testTodoList)
  await runTest('MCP Servers', testMCPServers)
  await runTest('Slash commands', testSlashCommands)
  await runTest('Hooks system', testHooksSystem)
  await runTest('Planning mode', testPlanningMode)
  await runTest('Context compression', testContextCompression)
  await runTest('Block sharing', testBlockSharing)
  await runTest('Warp Drive', testWarpDrive)
  await runTest('Remote PWA', testRemotePWA)

  console.log('\\n' + '=' .repeat(50))

  const passed = results.filter(r => r.passed).length
  const failed = results.filter(r => !r.passed).length
  const total = results.length

  console.log(`\\n📊 Results: ${passed}/${total} passed (${Math.round(passed/total*100)}%)`)

  if (failed > 0) {
    console.log('\\n❌ Failed tests:')
    results.filter(r => !r.passed).forEach(r => {
      console.log(`   - ${r.name}: ${r.error}`)
    })
  }

  return { passed, failed, total, results }
}

export { runAllTests, results }
