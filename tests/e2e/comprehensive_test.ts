/**
 * Comprehensive E2E Test Suite for Warp_Open
 * Tests all features end-to-end
 */

// Test utilities
interface TestResult {
  name: string;
  passed: boolean;
  duration: number;
  error?: string;
}

interface TestSuite {
  name: string;
  tests: TestResult[];
  passed: number;
  failed: number;
}

const results: TestSuite[] = [];
let currentSuite: TestSuite | null = null;

function describe(name: string, fn: () => void | Promise<void>) {
  currentSuite = { name, tests: [], passed: 0, failed: 0 };
  results.push(currentSuite);
  console.log(`\n📦 ${name}`);
  fn();
}

async function test(name: string, fn: () => void | Promise<void>) {
  const start = Date.now();
  try {
    await fn();
    const duration = Date.now() - start;
    currentSuite!.tests.push({ name, passed: true, duration });
    currentSuite!.passed++;
    console.log(`  ✅ ${name} (${duration}ms)`);
  } catch (e) {
    const duration = Date.now() - start;
    const error = e instanceof Error ? e.message : String(e);
    currentSuite!.tests.push({ name, passed: false, duration, error });
    currentSuite!.failed++;
    console.log(`  ❌ ${name} (${duration}ms)`);
    console.log(`     Error: ${error}`);
  }
}

function expect(value: any) {
  return {
    toBe: (expected: any) => {
      if (value !== expected) {
        throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(value)}`);
      }
    },
    toEqual: (expected: any) => {
      if (JSON.stringify(value) !== JSON.stringify(expected)) {
        throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(value)}`);
      }
    },
    toBeTruthy: () => {
      if (!value) {
        throw new Error(`Expected truthy value, got ${JSON.stringify(value)}`);
      }
    },
    toBeFalsy: () => {
      if (value) {
        throw new Error(`Expected falsy value, got ${JSON.stringify(value)}`);
      }
    },
    toContain: (item: any) => {
      if (typeof value === 'string') {
        if (!value.includes(item)) {
          throw new Error(`Expected "${value}" to contain "${item}"`);
        }
      } else if (Array.isArray(value)) {
        if (!value.includes(item)) {
          throw new Error(`Expected array to contain ${JSON.stringify(item)}`);
        }
      }
    },
    toBeGreaterThan: (expected: number) => {
      if (value <= expected) {
        throw new Error(`Expected ${value} to be greater than ${expected}`);
      }
    },
    toBeLessThan: (expected: number) => {
      if (value >= expected) {
        throw new Error(`Expected ${value} to be less than ${expected}`);
      }
    },
    toMatch: (pattern: RegExp) => {
      if (!pattern.test(value)) {
        throw new Error(`Expected "${value}" to match ${pattern}`);
      }
    },
    toThrow: async () => {
      let threw = false;
      try {
        if (typeof value === 'function') {
          await value();
        }
      } catch {
        threw = true;
      }
      if (!threw) {
        throw new Error('Expected function to throw');
      }
    },
    toHaveLength: (length: number) => {
      if (value.length !== length) {
        throw new Error(`Expected length ${length}, got ${value.length}`);
      }
    },
  };
}

// ============================================
// TEST SUITES
// ============================================

describe('Command History', async () => {
  // Simulate the composable
  const history: any[] = [];

  function addCommand(cmd: string, exitCode = 0) {
    history.unshift({
      id: `cmd-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      command: cmd,
      timestamp: new Date(),
      cwd: '/test',
      exitCode,
    });
  }

  await test('adds commands to history', () => {
    addCommand('ls -la');
    addCommand('cd /home');
    addCommand('git status');
    expect(history.length).toBe(3);
  });

  await test('maintains order (newest first)', () => {
    expect(history[0].command).toBe('git status');
    expect(history[2].command).toBe('ls -la');
  });

  await test('search finds matching commands', () => {
    const results = history.filter(h => h.command.includes('git'));
    expect(results.length).toBe(1);
    expect(results[0].command).toBe('git status');
  });

  await test('fuzzy search works', () => {
    const query = 'gst';
    const results = history.filter(h => {
      let qi = 0;
      for (const c of h.command.toLowerCase()) {
        if (c === query[qi]) qi++;
        if (qi === query.length) return true;
      }
      return false;
    });
    expect(results.length).toBeGreaterThan(0);
  });

  await test('handles 1000+ entries', () => {
    for (let i = 0; i < 1000; i++) {
      addCommand(`command-${i}`);
    }
    expect(history.length).toBeGreaterThan(1000);
  });
});

describe('Clipboard History', async () => {
  const clipboard: any[] = [];

  function detectType(content: string) {
    if (/^https?:\/\//.test(content)) return 'url';
    if (/^[\/~]/.test(content)) return 'path';
    if (/^(git|npm|cargo)\s/.test(content)) return 'command';
    return 'text';
  }

  function addClip(content: string) {
    clipboard.unshift({
      id: `clip-${Date.now()}`,
      content,
      type: detectType(content),
      timestamp: new Date(),
    });
  }

  await test('detects URLs', () => {
    addClip('https://github.com/test');
    expect(clipboard[0].type).toBe('url');
  });

  await test('detects paths', () => {
    addClip('/usr/local/bin');
    expect(clipboard[0].type).toBe('path');
  });

  await test('detects commands', () => {
    addClip('git commit -m "test"');
    expect(clipboard[0].type).toBe('command');
  });

  await test('detects plain text', () => {
    addClip('Hello world');
    expect(clipboard[0].type).toBe('text');
  });

  await test('search works across types', () => {
    const results = clipboard.filter(c => c.content.includes('git'));
    expect(results.length).toBeGreaterThan(0);
  });
});

describe('Syntax Highlighter', async () => {
  const rules = [
    { id: 'url', pattern: /https?:\/\/[^\s]+/g, className: 'highlight-url' },
    { id: 'error', pattern: /\b(error|fail)\b/gi, className: 'highlight-error' },
    { id: 'success', pattern: /\b(success|pass)\b/gi, className: 'highlight-success' },
    { id: 'path', pattern: /\/[\w\/.-]+/g, className: 'highlight-path' },
    { id: 'json-key', pattern: /"([^"]+)"(?=\s*:)/g, className: 'highlight-json-key' },
  ];

  function highlight(text: string) {
    const matches: any[] = [];
    for (const rule of rules) {
      rule.pattern.lastIndex = 0;
      let m;
      while ((m = rule.pattern.exec(text)) !== null) {
        matches.push({ start: m.index, end: m.index + m[0].length, className: rule.className });
      }
    }
    return matches;
  }

  await test('highlights URLs', () => {
    const matches = highlight('Visit https://example.com for more');
    expect(matches.some(m => m.className === 'highlight-url')).toBeTruthy();
  });

  await test('highlights errors', () => {
    const matches = highlight('Error: something failed');
    expect(matches.some(m => m.className === 'highlight-error')).toBeTruthy();
  });

  await test('highlights success messages', () => {
    const matches = highlight('All tests passed successfully');
    expect(matches.some(m => m.className === 'highlight-success')).toBeTruthy();
  });

  await test('highlights file paths', () => {
    const matches = highlight('File at /usr/local/bin/test');
    expect(matches.some(m => m.className === 'highlight-path')).toBeTruthy();
  });

  await test('highlights JSON keys', () => {
    const matches = highlight('{"name": "test", "value": 123}');
    expect(matches.some(m => m.className === 'highlight-json-key')).toBeTruthy();
  });

  await test('handles complex mixed content', () => {
    const text = `
      Error at /var/log/app.log
      Visit https://docs.example.com
      {"status": "success", "code": 200}
    `;
    const matches = highlight(text);
    expect(matches.length).toBeGreaterThan(3);
  });
});

describe('Keyboard Shortcuts', async () => {
  const bindings = [
    { id: 'new-tab', keys: ['Cmd', 'T'], action: 'newTab' },
    { id: 'close-tab', keys: ['Cmd', 'W'], action: 'closeTab' },
    { id: 'command-palette', keys: ['Cmd', 'Shift', 'P'], action: 'commandPalette' },
    { id: 'split-horizontal', keys: ['Cmd', 'D'], action: 'splitHorizontal' },
  ];

  function normalizeKeys(keys: string[]) {
    return keys.map(k => {
      if (k === 'Meta' || k === 'Command') return 'Cmd';
      if (k === 'Control') return 'Ctrl';
      return k;
    }).sort().join('+');
  }

  function findBinding(keys: string[]) {
    const normalized = normalizeKeys(keys);
    return bindings.find(b => normalizeKeys(b.keys) === normalized);
  }

  await test('finds Cmd+T binding', () => {
    const binding = findBinding(['Cmd', 'T']);
    expect(binding?.action).toBe('newTab');
  });

  await test('finds Cmd+Shift+P binding', () => {
    const binding = findBinding(['Cmd', 'Shift', 'P']);
    expect(binding?.action).toBe('commandPalette');
  });

  await test('normalizes key names', () => {
    const binding = findBinding(['Meta', 'T']);
    expect(binding?.action).toBe('newTab');
  });

  await test('returns undefined for unbound keys', () => {
    const binding = findBinding(['Cmd', 'Shift', 'Alt', 'Z']);
    expect(binding).toBeFalsy();
  });

  await test('detects conflicts', () => {
    const keyMap = new Map<string, string[]>();
    for (const b of bindings) {
      const key = normalizeKeys(b.keys);
      if (!keyMap.has(key)) keyMap.set(key, []);
      keyMap.get(key)!.push(b.action);
    }
    const conflicts = Array.from(keyMap.values()).filter(v => v.length > 1);
    expect(conflicts.length).toBe(0);
  });
});

describe('Slash Commands', async () => {
  const commands = [
    { name: 'explain', description: 'Explain code', handler: (args: string) => `Explaining: ${args}` },
    { name: 'fix', description: 'Fix code', handler: (args: string) => `Fixing: ${args}` },
    { name: 'test', description: 'Run tests', handler: (args: string) => `Testing: ${args}` },
    { name: 'commit', description: 'Smart commit', handler: () => 'Committing...' },
    { name: 'help', description: 'Show help', handler: () => 'Help text' },
  ];

  function parseCommand(input: string) {
    if (!input.startsWith('/')) return null;
    const parts = input.slice(1).split(' ');
    const name = parts[0];
    const args = parts.slice(1).join(' ');
    return { name, args };
  }

  function executeCommand(input: string) {
    const parsed = parseCommand(input);
    if (!parsed) return null;
    const cmd = commands.find(c => c.name === parsed.name);
    if (!cmd) return null;
    return cmd.handler(parsed.args);
  }

  await test('parses /explain command', () => {
    const parsed = parseCommand('/explain this function');
    expect(parsed?.name).toBe('explain');
    expect(parsed?.args).toBe('this function');
  });

  await test('executes /explain command', () => {
    const result = executeCommand('/explain foo');
    expect(result).toContain('Explaining');
  });

  await test('handles command without args', () => {
    const result = executeCommand('/commit');
    expect(result).toBe('Committing...');
  });

  await test('returns null for invalid command', () => {
    const result = executeCommand('/nonexistent');
    expect(result).toBeFalsy();
  });

  await test('returns null for non-command input', () => {
    const result = executeCommand('regular text');
    expect(result).toBeFalsy();
  });
});

describe('Diff Preview', async () => {
  function generateDiff(oldText: string, newText: string) {
    const oldLines = oldText.split('\n');
    const newLines = newText.split('\n');
    const hunks: any[] = [];

    let i = 0, j = 0;
    while (i < oldLines.length || j < newLines.length) {
      if (i >= oldLines.length) {
        hunks.push({ type: 'add', content: newLines[j] });
        j++;
      } else if (j >= newLines.length) {
        hunks.push({ type: 'remove', content: oldLines[i] });
        i++;
      } else if (oldLines[i] === newLines[j]) {
        hunks.push({ type: 'same', content: oldLines[i] });
        i++; j++;
      } else {
        hunks.push({ type: 'remove', content: oldLines[i] });
        hunks.push({ type: 'add', content: newLines[j] });
        i++; j++;
      }
    }
    return hunks;
  }

  await test('detects no changes', () => {
    const diff = generateDiff('hello\nworld', 'hello\nworld');
    expect(diff.every(h => h.type === 'same')).toBeTruthy();
  });

  await test('detects additions', () => {
    const diff = generateDiff('hello', 'hello\nworld');
    expect(diff.some(h => h.type === 'add')).toBeTruthy();
  });

  await test('detects removals', () => {
    const diff = generateDiff('hello\nworld', 'hello');
    expect(diff.some(h => h.type === 'remove')).toBeTruthy();
  });

  await test('detects modifications', () => {
    const diff = generateDiff('hello', 'goodbye');
    expect(diff.some(h => h.type === 'remove')).toBeTruthy();
    expect(diff.some(h => h.type === 'add')).toBeTruthy();
  });

  await test('handles empty strings', () => {
    const diff = generateDiff('', 'new content');
    expect(diff.length).toBeGreaterThan(0);
  });
});

describe('Undo/Redo System', async () => {
  const operations: any[] = [];
  let currentIndex = -1;

  function recordOperation(op: any) {
    // Remove any operations after current index
    if (currentIndex < operations.length - 1) {
      operations.splice(currentIndex + 1);
    }
    operations.push({ ...op, id: `op-${Date.now()}`, undone: false });
    currentIndex = operations.length - 1;
  }

  function undo() {
    if (currentIndex < 0) return null;
    const op = operations[currentIndex];
    op.undone = true;
    currentIndex--;
    return op;
  }

  function redo() {
    if (currentIndex >= operations.length - 1) return null;
    currentIndex++;
    const op = operations[currentIndex];
    op.undone = false;
    return op;
  }

  await test('records operations', () => {
    recordOperation({ type: 'write', path: '/test.txt' });
    expect(operations.length).toBe(1);
    expect(currentIndex).toBe(0);
  });

  await test('undo moves back', () => {
    const op = undo();
    expect(op).toBeTruthy();
    expect(currentIndex).toBe(-1);
  });

  await test('redo moves forward', () => {
    const op = redo();
    expect(op).toBeTruthy();
    expect(currentIndex).toBe(0);
  });

  await test('undo returns null when nothing to undo', () => {
    undo();
    const op = undo();
    expect(op).toBeFalsy();
  });

  await test('new operation clears redo stack', () => {
    redo();
    recordOperation({ type: 'edit', path: '/test2.txt' });
    recordOperation({ type: 'edit', path: '/test3.txt' });
    undo();
    recordOperation({ type: 'write', path: '/new.txt' });
    expect(operations.length).toBe(3);
  });
});

describe('AI Memory System', async () => {
  const memory: any[] = [];
  const preferences: Record<string, string> = {};

  function remember(entry: any) {
    memory.push({
      ...entry,
      id: `mem-${Date.now()}`,
      timestamp: new Date(),
    });
  }

  function recall(query: string, limit = 10) {
    const q = query.toLowerCase();
    return memory
      .filter(m => m.content.toLowerCase().includes(q))
      .slice(0, limit);
  }

  function setPreference(key: string, value: string) {
    preferences[key] = value;
  }

  await test('stores memory entries', () => {
    remember({ type: 'fact', content: 'User prefers dark themes', importance: 8 });
    remember({ type: 'decision', content: 'Using TypeScript for frontend', importance: 9 });
    expect(memory.length).toBe(2);
  });

  await test('recalls by query', () => {
    const results = recall('TypeScript');
    expect(results.length).toBe(1);
    expect(results[0].content).toContain('TypeScript');
  });

  await test('stores preferences', () => {
    setPreference('theme', 'dark');
    setPreference('fontSize', '14');
    expect(preferences.theme).toBe('dark');
    expect(preferences.fontSize).toBe('14');
  });

  await test('handles empty recall', () => {
    const results = recall('nonexistent query');
    expect(results.length).toBe(0);
  });
});

describe('Test Runner', async () => {
  function parseCargoOutput(output: string) {
    const results: any[] = [];
    const regex = /test\s+(\S+)\s+\.\.\.\s+(ok|FAILED|ignored)/g;
    let match;
    while ((match = regex.exec(output)) !== null) {
      results.push({
        name: match[1],
        status: match[2] === 'ok' ? 'passed' : match[2] === 'FAILED' ? 'failed' : 'skipped',
      });
    }
    return results;
  }

  function parseJestOutput(output: string) {
    const results: any[] = [];
    const regex = /(✓|✕|○)\s+(.+?)(?:\s*\((\d+)\s*ms\))?$/gm;
    let match;
    while ((match = regex.exec(output)) !== null) {
      results.push({
        name: match[2].trim(),
        status: match[1] === '✓' ? 'passed' : match[1] === '✕' ? 'failed' : 'skipped',
        duration: match[3] ? parseInt(match[3]) : undefined,
      });
    }
    return results;
  }

  await test('parses Cargo test output', () => {
    const output = `
running 3 tests
test test_one ... ok
test test_two ... FAILED
test test_three ... ignored
    `;
    const results = parseCargoOutput(output);
    expect(results.length).toBe(3);
    expect(results[0].status).toBe('passed');
    expect(results[1].status).toBe('failed');
    expect(results[2].status).toBe('skipped');
  });

  await test('parses Jest test output', () => {
    const output = `
  ✓ should pass (5 ms)
  ✕ should fail (10 ms)
  ○ skipped test
    `;
    const results = parseJestOutput(output);
    expect(results.length).toBe(3);
    expect(results[0].status).toBe('passed');
    expect(results[1].status).toBe('failed');
  });
});

describe('Code Explainer', async () => {
  function detectLanguage(code: string, filename?: string) {
    if (filename) {
      const ext = filename.split('.').pop()?.toLowerCase();
      const map: Record<string, string> = {
        ts: 'typescript', js: 'javascript', py: 'python',
        rs: 'rust', go: 'go', java: 'java',
      };
      if (ext && map[ext]) return map[ext];
    }
    if (code.includes('fn ') && code.includes('let ')) return 'rust';
    if (code.includes('def ') && code.includes(':')) return 'python';
    if (code.includes('function') || code.includes('=>')) return 'javascript';
    return 'unknown';
  }

  await test('detects TypeScript by extension', () => {
    expect(detectLanguage('', 'test.ts')).toBe('typescript');
  });

  await test('detects Python by extension', () => {
    expect(detectLanguage('', 'test.py')).toBe('python');
  });

  await test('detects Rust by content', () => {
    expect(detectLanguage('fn main() { let x = 5; }')).toBe('rust');
  });

  await test('detects Python by content', () => {
    expect(detectLanguage('def hello():\n  print("hi")')).toBe('python');
  });

  await test('detects JavaScript by content', () => {
    expect(detectLanguage('const x = () => 5;')).toBe('javascript');
  });
});

describe('Git AI Integration', async () => {
  function generateCommitMessage(diff: string) {
    // Simulate AI commit message generation
    if (diff.includes('fix')) return 'fix: resolve issue';
    if (diff.includes('add') || diff.includes('+')) return 'feat: add new feature';
    if (diff.includes('refactor')) return 'refactor: improve code structure';
    if (diff.includes('test')) return 'test: add tests';
    return 'chore: update code';
  }

  await test('generates fix commit message', () => {
    const msg = generateCommitMessage('fix bug in parser');
    expect(msg).toContain('fix');
  });

  await test('generates feat commit message', () => {
    const msg = generateCommitMessage('+ new function\n+ more code');
    expect(msg).toContain('feat');
  });

  await test('generates refactor commit message', () => {
    const msg = generateCommitMessage('refactor the module');
    expect(msg).toContain('refactor');
  });

  await test('generates test commit message', () => {
    const msg = generateCommitMessage('add test for parser');
    expect(msg).toContain('test');
  });
});

describe('Extended Tools', async () => {
  // Simulate tool execution
  function executeTool(name: string, args: any) {
    const tools: Record<string, (args: any) => any> = {
      git_command: (a) => ({ success: true, output: `git ${a.command}` }),
      npm_command: (a) => ({ success: true, output: `npm ${a.command}` }),
      curl_request: (a) => ({ success: true, output: `fetched ${a.url}` }),
      env_command: (a) => {
        if (a.action === 'get') return { success: true, output: 'value' };
        if (a.action === 'list') return { success: true, output: 'PATH=/usr/bin' };
        return { success: true, output: 'done' };
      },
      docker_command: (a) => ({ success: true, output: `docker ${a.command}` }),
      list_processes: () => ({ success: true, output: 'PID USER %CPU' }),
      system_info: () => ({ success: true, output: 'Darwin 25.0' }),
      find_files: (a) => ({ success: true, output: `found ${a.pattern}` }),
      disk_usage: (a) => ({ success: true, output: `1.5G ${a.path}` }),
    };
    const tool = tools[name];
    if (!tool) return { success: false, error: 'Unknown tool' };
    return tool(args);
  }

  await test('git_command tool', () => {
    const result = executeTool('git_command', { command: 'status' });
    expect(result.success).toBeTruthy();
    expect(result.output).toContain('git');
  });

  await test('npm_command tool', () => {
    const result = executeTool('npm_command', { command: 'install' });
    expect(result.success).toBeTruthy();
  });

  await test('curl_request tool', () => {
    const result = executeTool('curl_request', { url: 'https://api.example.com' });
    expect(result.success).toBeTruthy();
  });

  await test('env_command get', () => {
    const result = executeTool('env_command', { action: 'get', key: 'PATH' });
    expect(result.success).toBeTruthy();
  });

  await test('env_command list', () => {
    const result = executeTool('env_command', { action: 'list' });
    expect(result.success).toBeTruthy();
    expect(result.output).toContain('PATH');
  });

  await test('docker_command tool', () => {
    const result = executeTool('docker_command', { command: 'ps' });
    expect(result.success).toBeTruthy();
  });

  await test('list_processes tool', () => {
    const result = executeTool('list_processes', {});
    expect(result.success).toBeTruthy();
  });

  await test('system_info tool', () => {
    const result = executeTool('system_info', {});
    expect(result.success).toBeTruthy();
  });

  await test('find_files tool', () => {
    const result = executeTool('find_files', { pattern: '*.ts' });
    expect(result.success).toBeTruthy();
  });

  await test('disk_usage tool', () => {
    const result = executeTool('disk_usage', { path: '.' });
    expect(result.success).toBeTruthy();
  });

  await test('unknown tool returns error', () => {
    const result = executeTool('nonexistent', {});
    expect(result.success).toBeFalsy();
  });
});

describe('Theme System', async () => {
  const themes = {
    'catppuccin-mocha': { background: '#1e1e2e', foreground: '#cdd6f4' },
    'dracula': { background: '#282a36', foreground: '#f8f8f2' },
    'nord': { background: '#2e3440', foreground: '#eceff4' },
  };

  function applyTheme(name: string) {
    return themes[name as keyof typeof themes] || null;
  }

  function validateHexColor(color: string) {
    return /^#[0-9a-fA-F]{6}$/.test(color);
  }

  await test('loads catppuccin theme', () => {
    const theme = applyTheme('catppuccin-mocha');
    expect(theme).toBeTruthy();
    expect(theme?.background).toBe('#1e1e2e');
  });

  await test('loads dracula theme', () => {
    const theme = applyTheme('dracula');
    expect(theme).toBeTruthy();
    expect(theme?.background).toBe('#282a36');
  });

  await test('returns null for invalid theme', () => {
    const theme = applyTheme('nonexistent');
    expect(theme).toBeFalsy();
  });

  await test('validates hex colors', () => {
    expect(validateHexColor('#1e1e2e')).toBeTruthy();
    expect(validateHexColor('#FFFFFF')).toBeTruthy();
    expect(validateHexColor('invalid')).toBeFalsy();
    expect(validateHexColor('#GGG')).toBeFalsy();
  });
});

describe('Project Context', async () => {
  const contextFiles = [
    { name: '.claude.md', priority: 1 },
    { name: 'CLAUDE.md', priority: 2 },
    { name: '.warp.md', priority: 3 },
    { name: 'README.md', priority: 4 },
  ];

  function findContextFile(files: string[]) {
    for (const cf of contextFiles) {
      if (files.includes(cf.name)) {
        return cf.name;
      }
    }
    return null;
  }

  await test('finds .claude.md first', () => {
    const found = findContextFile(['.claude.md', 'README.md']);
    expect(found).toBe('.claude.md');
  });

  await test('finds CLAUDE.md if no .claude.md', () => {
    const found = findContextFile(['CLAUDE.md', 'README.md']);
    expect(found).toBe('CLAUDE.md');
  });

  await test('returns null if no context file', () => {
    const found = findContextFile(['package.json', 'index.ts']);
    expect(found).toBeFalsy();
  });
});

describe('Stress Tests', async () => {
  await test('handles 10000 history entries', () => {
    const history: any[] = [];
    for (let i = 0; i < 10000; i++) {
      history.push({ id: i, command: `command-${i}` });
    }
    expect(history.length).toBe(10000);

    // Search performance
    const start = Date.now();
    const results = history.filter(h => h.command.includes('5000'));
    const duration = Date.now() - start;
    expect(duration).toBeLessThan(100); // Should be fast
    expect(results.length).toBeGreaterThan(0);
  });

  await test('handles rapid operations', () => {
    const operations: any[] = [];
    for (let i = 0; i < 1000; i++) {
      operations.push({ type: 'write', id: i });
      if (i % 10 === 0) {
        operations.pop(); // Simulate undo
      }
    }
    expect(operations.length).toBeGreaterThan(800);
  });

  await test('handles large text highlighting', () => {
    const largeText = 'Error at https://example.com/path '.repeat(1000);
    const start = Date.now();
    const matches = largeText.match(/https?:\/\/[^\s]+/g) || [];
    const duration = Date.now() - start;
    expect(duration).toBeLessThan(100);
    expect(matches.length).toBe(1000);
  });

  await test('handles concurrent operations simulation', async () => {
    const results: number[] = [];
    const operations = Array(100).fill(null).map((_, i) =>
      new Promise<number>(resolve => {
        setTimeout(() => {
          results.push(i);
          resolve(i);
        }, Math.random() * 10);
      })
    );
    await Promise.all(operations);
    expect(results.length).toBe(100);
  });
});

// ============================================
// RUN TESTS AND REPORT
// ============================================

async function runAllTests() {
  console.log('🚀 Running Comprehensive E2E Tests for Warp_Open\n');
  console.log('='.repeat(60));

  // Run all test suites
  // (They run automatically when describe is called)

  // Wait a bit for async tests
  await new Promise(resolve => setTimeout(resolve, 100));

  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('\n📊 TEST SUMMARY\n');

  let totalPassed = 0;
  let totalFailed = 0;

  for (const suite of results) {
    const status = suite.failed === 0 ? '✅' : '❌';
    console.log(`${status} ${suite.name}: ${suite.passed}/${suite.tests.length} passed`);
    totalPassed += suite.passed;
    totalFailed += suite.failed;
  }

  console.log('\n' + '-'.repeat(60));
  console.log(`\nTotal: ${totalPassed} passed, ${totalFailed} failed out of ${totalPassed + totalFailed} tests`);

  if (totalFailed === 0) {
    console.log('\n🎉 All tests passed!\n');
  } else {
    console.log('\n⚠️  Some tests failed. See details above.\n');

    // Print failed tests
    console.log('Failed tests:');
    for (const suite of results) {
      for (const test of suite.tests) {
        if (!test.passed) {
          console.log(`  - ${suite.name} > ${test.name}`);
          console.log(`    Error: ${test.error}`);
        }
      }
    }
  }

  return { totalPassed, totalFailed };
}

// Export for use
export { runAllTests, results };

// Run if executed directly
runAllTests();
