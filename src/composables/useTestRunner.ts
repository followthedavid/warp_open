/**
 * Test Runner System
 * Run tests, detect failures, and let AI fix them
 */

import { ref, computed } from 'vue';
import { executeCommand } from '../utils/commandOps';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

export interface TestResult {
  name: string;
  status: 'passed' | 'failed' | 'skipped' | 'error';
  duration?: number;
  error?: string;
  file?: string;
  line?: number;
}

export interface TestRun {
  id: string;
  command: string;
  timestamp: Date;
  duration: number;
  results: TestResult[];
  passed: number;
  failed: number;
  skipped: number;
  output: string;
}

export interface TestFramework {
  name: string;
  detectFiles: string[];
  command: string;
  parseOutput: (output: string) => TestResult[];
}

// Supported test frameworks
const TEST_FRAMEWORKS: TestFramework[] = [
  {
    name: 'cargo',
    detectFiles: ['Cargo.toml'],
    command: 'cargo test',
    parseOutput: parseCargoTestOutput,
  },
  {
    name: 'jest',
    detectFiles: ['jest.config.js', 'jest.config.ts', 'package.json'],
    command: 'npm test',
    parseOutput: parseJestOutput,
  },
  {
    name: 'vitest',
    detectFiles: ['vitest.config.ts', 'vitest.config.js'],
    command: 'npm run test',
    parseOutput: parseVitestOutput,
  },
  {
    name: 'pytest',
    detectFiles: ['pytest.ini', 'pyproject.toml', 'setup.py'],
    command: 'pytest -v',
    parseOutput: parsePytestOutput,
  },
  {
    name: 'go',
    detectFiles: ['go.mod'],
    command: 'go test ./...',
    parseOutput: parseGoTestOutput,
  },
];

const isRunning = ref(false);
const currentRun = ref<TestRun | null>(null);
const runHistory = ref<TestRun[]>([]);
const MAX_HISTORY = 20;

export function useTestRunner() {
  /**
   * Detect test framework in a directory
   */
  async function detectFramework(directory: string): Promise<TestFramework | null> {
    for (const framework of TEST_FRAMEWORKS) {
      for (const file of framework.detectFiles) {
        try {
          if (isTauri && invoke) {
            await invoke<string>('read_file', { path: `${directory}/${file}` });
            return framework;
          }
        } catch {
          // File doesn't exist, try next
        }
      }
    }
    return null;
  }

  /**
   * Run tests in a directory
   */
  async function runTests(
    directory: string,
    command?: string,
    filter?: string
  ): Promise<TestRun> {
    isRunning.value = true;
    const startTime = Date.now();

    try {
      // Detect framework if no command provided
      let testCommand = command;
      let framework: TestFramework | null = null;

      if (!testCommand) {
        framework = await detectFramework(directory);
        if (framework) {
          testCommand = framework.command;
        } else {
          throw new Error('Could not detect test framework');
        }
      }

      // Add filter if provided
      if (filter) {
        testCommand += ` ${filter}`;
      }

      // Run tests
      const result = await executeCommand(testCommand, directory);
      const output = result.stdout + '\n' + result.stderr;
      const duration = Date.now() - startTime;

      // Parse results
      let results: TestResult[] = [];
      if (framework) {
        results = framework.parseOutput(output);
      } else {
        results = parseGenericOutput(output);
      }

      const run: TestRun = {
        id: generateId(),
        command: testCommand,
        timestamp: new Date(),
        duration,
        results,
        passed: results.filter(r => r.status === 'passed').length,
        failed: results.filter(r => r.status === 'failed').length,
        skipped: results.filter(r => r.status === 'skipped').length,
        output,
      };

      currentRun.value = run;
      runHistory.value.unshift(run);

      if (runHistory.value.length > MAX_HISTORY) {
        runHistory.value.pop();
      }

      return run;
    } catch (e) {
      const run: TestRun = {
        id: generateId(),
        command: command || 'unknown',
        timestamp: new Date(),
        duration: Date.now() - startTime,
        results: [],
        passed: 0,
        failed: 0,
        skipped: 0,
        output: String(e),
      };

      currentRun.value = run;
      return run;
    } finally {
      isRunning.value = false;
    }
  }

  /**
   * Run tests and have AI fix failures
   */
  async function runAndFix(
    directory: string,
    maxIterations: number = 3,
    model: string = 'qwen2.5-coder:1.5b',
    onProgress?: (message: string) => void
  ): Promise<{ success: boolean; iterations: number; finalRun: TestRun }> {
    let iteration = 0;
    let lastRun: TestRun;

    while (iteration < maxIterations) {
      iteration++;
      onProgress?.(`Running tests (iteration ${iteration}/${maxIterations})...`);

      // Run tests
      lastRun = await runTests(directory);

      if (lastRun.failed === 0) {
        onProgress?.(`All tests passed!`);
        return { success: true, iterations: iteration, finalRun: lastRun };
      }

      onProgress?.(`${lastRun.failed} test(s) failed. Analyzing...`);

      // Get failed tests
      const failedTests = lastRun.results.filter(r => r.status === 'failed');

      // Ask AI to fix each failure
      for (const test of failedTests) {
        onProgress?.(`Attempting to fix: ${test.name}`);

        const fixed = await attemptFix(test, lastRun.output, directory, model);
        if (!fixed) {
          onProgress?.(`Could not fix: ${test.name}`);
        }
      }
    }

    onProgress?.(`Max iterations reached. ${lastRun!.failed} test(s) still failing.`);
    return { success: false, iterations: iteration, finalRun: lastRun! };
  }

  /**
   * Attempt to fix a failing test
   */
  async function attemptFix(
    test: TestResult,
    output: string,
    directory: string,
    model: string
  ): Promise<boolean> {
    // Build prompt
    const prompt = `A test is failing. Analyze the error and suggest a fix.

Test: ${test.name}
File: ${test.file || 'unknown'}
Error: ${test.error || 'See output below'}

Test Output:
${output.substring(0, 2000)}

Instructions:
1. Identify the root cause of the failure
2. Determine if it's a code bug or test issue
3. Provide a fix using the edit_file tool

If you need to fix code, respond with:
{"tool":"edit_file","args":{"path":"file/path","old_string":"old code","new_string":"fixed code"}}

If the test itself is wrong, explain why.`;

    try {
      let response: string;

      if (isTauri && invoke) {
        response = await invoke<string>('query_ollama', { prompt, model });
      } else {
        const res = await fetch('http://localhost:11434/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, prompt, stream: false }),
        });
        const data = await res.json();
        response = data.response;
      }

      // Check for tool call
      const toolMatch = response.match(/\{[\s\S]*"tool"[\s\S]*"edit_file"[\s\S]*\}/);
      if (toolMatch) {
        const toolCall = JSON.parse(toolMatch[0]);
        if (toolCall.args?.path && toolCall.args?.old_string && toolCall.args?.new_string) {
          // Apply the fix
          if (isTauri && invoke) {
            await invoke('edit_file', {
              path: toolCall.args.path.startsWith('/')
                ? toolCall.args.path
                : `${directory}/${toolCall.args.path}`,
              oldString: toolCall.args.old_string,
              newString: toolCall.args.new_string,
            });
            return true;
          }
        }
      }

      return false;
    } catch (e) {
      console.error('[TestRunner] Error attempting fix:', e);
      return false;
    }
  }

  /**
   * Watch for file changes and re-run tests
   */
  async function watchTests(
    directory: string,
    command?: string,
    onChange?: (run: TestRun) => void
  ) {
    // For now, just provide manual re-run
    // In future, could use fs watcher
    console.log('[TestRunner] Watch mode not yet implemented');
  }

  /**
   * Get test summary
   */
  function getSummary(): { total: number; passed: number; failed: number; skipped: number } {
    if (!currentRun.value) {
      return { total: 0, passed: 0, failed: 0, skipped: 0 };
    }
    return {
      total: currentRun.value.results.length,
      passed: currentRun.value.passed,
      failed: currentRun.value.failed,
      skipped: currentRun.value.skipped,
    };
  }

  /**
   * Generate unique ID
   */
  function generateId(): string {
    return `run-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  return {
    isRunning: computed(() => isRunning.value),
    currentRun: computed(() => currentRun.value),
    runHistory: computed(() => runHistory.value),
    frameworks: TEST_FRAMEWORKS,
    detectFramework,
    runTests,
    runAndFix,
    watchTests,
    getSummary,
  };
}

// Parser functions for different test frameworks

function parseCargoTestOutput(output: string): TestResult[] {
  const results: TestResult[] = [];
  const testRegex = /test\s+(\S+)\s+\.\.\.\s+(ok|FAILED|ignored)/g;

  let match;
  while ((match = testRegex.exec(output)) !== null) {
    results.push({
      name: match[1],
      status: match[2] === 'ok' ? 'passed' : match[2] === 'FAILED' ? 'failed' : 'skipped',
    });
  }

  // Extract error messages for failed tests
  const failedRegex = /---- (\S+) stdout ----\n([\s\S]*?)(?=----|\z)/g;
  while ((match = failedRegex.exec(output)) !== null) {
    const result = results.find(r => r.name === match[1]);
    if (result) {
      result.error = match[2].trim();
    }
  }

  return results;
}

function parseJestOutput(output: string): TestResult[] {
  const results: TestResult[] = [];
  const testRegex = /(✓|✕|○)\s+(.+?)\s*(?:\((\d+)\s*ms\))?$/gm;

  let match;
  while ((match = testRegex.exec(output)) !== null) {
    results.push({
      name: match[2].trim(),
      status: match[1] === '✓' ? 'passed' : match[1] === '✕' ? 'failed' : 'skipped',
      duration: match[3] ? parseInt(match[3]) : undefined,
    });
  }

  return results;
}

function parseVitestOutput(output: string): TestResult[] {
  // Similar to Jest
  return parseJestOutput(output);
}

function parsePytestOutput(output: string): TestResult[] {
  const results: TestResult[] = [];
  const testRegex = /(PASSED|FAILED|SKIPPED)\s+(\S+)/g;

  let match;
  while ((match = testRegex.exec(output)) !== null) {
    results.push({
      name: match[2],
      status: match[1].toLowerCase() as 'passed' | 'failed' | 'skipped',
    });
  }

  return results;
}

function parseGoTestOutput(output: string): TestResult[] {
  const results: TestResult[] = [];
  const testRegex = /---\s+(PASS|FAIL|SKIP):\s+(\S+)\s+\((\d+\.\d+)s\)/g;

  let match;
  while ((match = testRegex.exec(output)) !== null) {
    results.push({
      name: match[2],
      status: match[1] === 'PASS' ? 'passed' : match[1] === 'FAIL' ? 'failed' : 'skipped',
      duration: parseFloat(match[3]) * 1000,
    });
  }

  return results;
}

function parseGenericOutput(output: string): TestResult[] {
  const results: TestResult[] = [];

  // Try to detect passed/failed counts
  const summaryMatch = output.match(/(\d+)\s+pass(?:ed)?.*?(\d+)\s+fail(?:ed)?/i);
  if (summaryMatch) {
    const passed = parseInt(summaryMatch[1]);
    const failed = parseInt(summaryMatch[2]);

    for (let i = 0; i < passed; i++) {
      results.push({ name: `Test ${i + 1}`, status: 'passed' });
    }
    for (let i = 0; i < failed; i++) {
      results.push({ name: `Failed Test ${i + 1}`, status: 'failed' });
    }
  }

  return results;
}
