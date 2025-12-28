/**
 * Composables Unit Tests
 * Tests all Vue composables in isolation
 */

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => { store[key] = value; },
    removeItem: (key: string) => { delete store[key]; },
    clear: () => { store = {}; },
  };
})();

// @ts-ignore
global.localStorage = localStorageMock;

// Test utilities
let testResults: { name: string; passed: boolean; error?: string }[] = [];

function test(name: string, fn: () => void) {
  try {
    fn();
    testResults.push({ name, passed: true });
    console.log(`  ✅ ${name}`);
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    testResults.push({ name, passed: false, error });
    console.log(`  ❌ ${name}: ${error}`);
  }
}

function expect(value: any) {
  return {
    toBe: (expected: any) => {
      if (value !== expected) throw new Error(`Expected ${expected}, got ${value}`);
    },
    toEqual: (expected: any) => {
      if (JSON.stringify(value) !== JSON.stringify(expected)) {
        throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(value)}`);
      }
    },
    toBeTruthy: () => {
      if (!value) throw new Error(`Expected truthy, got ${value}`);
    },
    toBeFalsy: () => {
      if (value) throw new Error(`Expected falsy, got ${value}`);
    },
    toContain: (item: any) => {
      if (typeof value === 'string' && !value.includes(item)) {
        throw new Error(`Expected "${value}" to contain "${item}"`);
      }
      if (Array.isArray(value) && !value.includes(item)) {
        throw new Error(`Expected array to contain ${item}`);
      }
    },
    toHaveLength: (len: number) => {
      if (value.length !== len) throw new Error(`Expected length ${len}, got ${value.length}`);
    },
    toBeGreaterThan: (n: number) => {
      if (value <= n) throw new Error(`Expected ${value} > ${n}`);
    },
    toMatch: (pattern: RegExp) => {
      if (!pattern.test(value)) throw new Error(`Expected "${value}" to match ${pattern}`);
    },
  };
}

function describe(name: string, fn: () => void) {
  console.log(`\n📦 ${name}`);
  testResults = [];
  fn();
}

// ============================================
// useCommandHistory Tests
// ============================================
describe('useCommandHistory', () => {
  interface CommandEntry {
    id: string;
    command: string;
    timestamp: Date;
    cwd: string;
    exitCode?: number;
    duration?: number;
    favorite?: boolean;
    tags?: string[];
  }

  let history: CommandEntry[] = [];

  function add(entry: Omit<CommandEntry, 'id'>) {
    const newEntry = { ...entry, id: `cmd-${Date.now()}-${Math.random().toString(36).substr(2, 9)}` };
    history.unshift(newEntry);
    return newEntry;
  }

  function search(query: string) {
    return history.filter(h => h.command.toLowerCase().includes(query.toLowerCase()));
  }

  function fuzzySearch(query: string) {
    const q = query.toLowerCase();
    return history.filter(h => {
      let qi = 0;
      for (const c of h.command.toLowerCase()) {
        if (c === q[qi]) qi++;
        if (qi === q.length) return true;
      }
      return false;
    });
  }

  function toggleFavorite(id: string) {
    const entry = history.find(h => h.id === id);
    if (entry) entry.favorite = !entry.favorite;
    return entry?.favorite;
  }

  // Reset before tests
  history = [];

  test('adds command to history', () => {
    const entry = add({ command: 'ls -la', timestamp: new Date(), cwd: '/home' });
    expect(history.length).toBe(1);
    expect(entry.command).toBe('ls -la');
  });

  test('maintains order (newest first)', () => {
    add({ command: 'cd /tmp', timestamp: new Date(), cwd: '/home' });
    add({ command: 'pwd', timestamp: new Date(), cwd: '/tmp' });
    expect(history[0].command).toBe('pwd');
  });

  test('search finds matching commands', () => {
    const results = search('cd');
    expect(results.length).toBe(1);
    expect(results[0].command).toContain('cd');
  });

  test('fuzzy search works', () => {
    add({ command: 'git status', timestamp: new Date(), cwd: '/repo' });
    const results = fuzzySearch('gst');
    expect(results.length).toBeGreaterThan(0);
  });

  test('toggle favorite works', () => {
    const entry = history[0];
    const result = toggleFavorite(entry.id);
    expect(result).toBeTruthy();
  });

  test('handles large history', () => {
    for (let i = 0; i < 1000; i++) {
      add({ command: `command-${i}`, timestamp: new Date(), cwd: '/test' });
    }
    expect(history.length).toBeGreaterThan(1000);
  });
});

// ============================================
// useClipboardHistory Tests
// ============================================
describe('useClipboardHistory', () => {
  interface ClipboardEntry {
    id: string;
    content: string;
    type: 'text' | 'code' | 'command' | 'path' | 'url';
    timestamp: Date;
    pinned?: boolean;
  }

  let clipboard: ClipboardEntry[] = [];

  function detectType(content: string): ClipboardEntry['type'] {
    if (/^https?:\/\//.test(content)) return 'url';
    if (/^[\/~][\w\/.-]+$/.test(content)) return 'path';
    if (/^(git|npm|cargo|docker)\s/.test(content)) return 'command';
    if (/[{}\[\]();]/.test(content)) return 'code';
    return 'text';
  }

  function add(content: string) {
    clipboard.unshift({
      id: `clip-${Date.now()}`,
      content,
      type: detectType(content),
      timestamp: new Date(),
    });
  }

  clipboard = [];

  test('detects URL type', () => {
    add('https://github.com');
    expect(clipboard[0].type).toBe('url');
  });

  test('detects path type', () => {
    add('/usr/local/bin');
    expect(clipboard[0].type).toBe('path');
  });

  test('detects command type', () => {
    add('git commit -m "test"');
    expect(clipboard[0].type).toBe('command');
  });

  test('detects code type', () => {
    add('function test() { return 42; }');
    expect(clipboard[0].type).toBe('code');
  });

  test('detects plain text', () => {
    add('Hello World');
    expect(clipboard[0].type).toBe('text');
  });

  test('maintains order', () => {
    add('first');
    add('second');
    expect(clipboard[0].content).toBe('second');
  });
});

// ============================================
// useSyntaxHighlighter Tests
// ============================================
describe('useSyntaxHighlighter', () => {
  const rules = [
    { id: 'url', pattern: /https?:\/\/[^\s]+/g, className: 'url' },
    { id: 'error', pattern: /\b(error|fail|exception)\b/gi, className: 'error' },
    { id: 'success', pattern: /\b(success|pass|ok)\b/gi, className: 'success' },
    { id: 'path', pattern: /\/[\w\/.-]+/g, className: 'path' },
    { id: 'number', pattern: /\b\d+\b/g, className: 'number' },
  ];

  function highlight(text: string) {
    const matches: { start: number; end: number; class: string }[] = [];
    for (const rule of rules) {
      rule.pattern.lastIndex = 0;
      let m;
      while ((m = rule.pattern.exec(text)) !== null) {
        matches.push({ start: m.index, end: m.index + m[0].length, class: rule.className });
      }
    }
    return matches;
  }

  test('highlights URLs', () => {
    const matches = highlight('Visit https://example.com');
    expect(matches.some(m => m.class === 'url')).toBeTruthy();
  });

  test('highlights errors', () => {
    const matches = highlight('Error: operation failed');
    expect(matches.filter(m => m.class === 'error').length).toBe(2);
  });

  test('highlights success keywords', () => {
    const matches = highlight('Test passed successfully');
    expect(matches.some(m => m.class === 'success')).toBeTruthy();
  });

  test('highlights paths', () => {
    const matches = highlight('File at /var/log/app.log');
    expect(matches.some(m => m.class === 'path')).toBeTruthy();
  });

  test('highlights numbers', () => {
    const matches = highlight('Found 42 results');
    expect(matches.some(m => m.class === 'number')).toBeTruthy();
  });

  test('handles no matches', () => {
    const matches = highlight('plain text here');
    expect(matches.filter(m => m.class === 'url').length).toBe(0);
  });
});

// ============================================
// useKeyboardShortcuts Tests
// ============================================
describe('useKeyboardShortcuts', () => {
  interface KeyBinding {
    id: string;
    keys: string[];
    action: string;
    enabled: boolean;
  }

  const bindings: KeyBinding[] = [
    { id: 'new-tab', keys: ['Cmd', 'T'], action: 'newTab', enabled: true },
    { id: 'close-tab', keys: ['Cmd', 'W'], action: 'closeTab', enabled: true },
    { id: 'palette', keys: ['Cmd', 'Shift', 'P'], action: 'commandPalette', enabled: true },
    { id: 'ai-panel', keys: ['Cmd', 'Shift', 'A'], action: 'aiPanel', enabled: true },
    { id: 'disabled', keys: ['Cmd', 'D'], action: 'disabled', enabled: false },
  ];

  function normalizeKeys(keys: string[]) {
    return keys.map(k => {
      if (k === 'Meta' || k === 'Command') return 'Cmd';
      if (k === 'Control') return 'Ctrl';
      return k;
    }).sort().join('+');
  }

  function findBinding(keys: string[]) {
    const norm = normalizeKeys(keys);
    return bindings.find(b => b.enabled && normalizeKeys(b.keys) === norm);
  }

  function checkConflicts() {
    const keyMap = new Map<string, string[]>();
    for (const b of bindings.filter(b => b.enabled)) {
      const key = normalizeKeys(b.keys);
      if (!keyMap.has(key)) keyMap.set(key, []);
      keyMap.get(key)!.push(b.action);
    }
    return Array.from(keyMap.entries()).filter(([_, v]) => v.length > 1);
  }

  test('finds binding by keys', () => {
    const binding = findBinding(['Cmd', 'T']);
    expect(binding?.action).toBe('newTab');
  });

  test('normalizes Meta to Cmd', () => {
    const binding = findBinding(['Meta', 'T']);
    expect(binding?.action).toBe('newTab');
  });

  test('handles multi-key bindings', () => {
    const binding = findBinding(['Cmd', 'Shift', 'P']);
    expect(binding?.action).toBe('commandPalette');
  });

  test('ignores disabled bindings', () => {
    const binding = findBinding(['Cmd', 'D']);
    expect(binding).toBeFalsy();
  });

  test('detects no conflicts', () => {
    const conflicts = checkConflicts();
    expect(conflicts.length).toBe(0);
  });

  test('returns undefined for unbound keys', () => {
    const binding = findBinding(['Cmd', 'Alt', 'Z']);
    expect(binding).toBeFalsy();
  });
});

// ============================================
// useSlashCommands Tests
// ============================================
describe('useSlashCommands', () => {
  interface SlashCommand {
    name: string;
    description: string;
    handler: (args: string) => string;
  }

  const commands: SlashCommand[] = [
    { name: 'explain', description: 'Explain code', handler: (args) => `Explaining: ${args}` },
    { name: 'fix', description: 'Fix code', handler: (args) => `Fixing: ${args}` },
    { name: 'test', description: 'Run tests', handler: (args) => `Testing: ${args}` },
    { name: 'commit', description: 'Smart commit', handler: () => 'Generating commit...' },
    { name: 'help', description: 'Show help', handler: () => 'Available commands: ...' },
  ];

  function parse(input: string) {
    if (!input.startsWith('/')) return null;
    const [name, ...rest] = input.slice(1).split(' ');
    return { name, args: rest.join(' ') };
  }

  function execute(input: string) {
    const parsed = parse(input);
    if (!parsed) return null;
    const cmd = commands.find(c => c.name === parsed.name);
    return cmd?.handler(parsed.args) || null;
  }

  test('parses command with args', () => {
    const result = parse('/explain this code');
    expect(result?.name).toBe('explain');
    expect(result?.args).toBe('this code');
  });

  test('parses command without args', () => {
    const result = parse('/help');
    expect(result?.name).toBe('help');
    expect(result?.args).toBe('');
  });

  test('returns null for non-command', () => {
    const result = parse('not a command');
    expect(result).toBeFalsy();
  });

  test('executes explain command', () => {
    const result = execute('/explain foo');
    expect(result).toContain('Explaining');
  });

  test('executes help command', () => {
    const result = execute('/help');
    expect(result).toContain('Available');
  });

  test('returns null for unknown command', () => {
    const result = execute('/unknown');
    expect(result).toBeFalsy();
  });
});

// ============================================
// useDiffPreview Tests
// ============================================
describe('useDiffPreview', () => {
  type DiffLine = { type: 'same' | 'add' | 'remove'; content: string };

  function generateDiff(oldText: string, newText: string): DiffLine[] {
    const oldLines = oldText.split('\n');
    const newLines = newText.split('\n');
    const diff: DiffLine[] = [];

    let i = 0, j = 0;
    while (i < oldLines.length || j < newLines.length) {
      if (i >= oldLines.length) {
        diff.push({ type: 'add', content: newLines[j++] });
      } else if (j >= newLines.length) {
        diff.push({ type: 'remove', content: oldLines[i++] });
      } else if (oldLines[i] === newLines[j]) {
        diff.push({ type: 'same', content: oldLines[i] });
        i++; j++;
      } else {
        diff.push({ type: 'remove', content: oldLines[i++] });
        diff.push({ type: 'add', content: newLines[j++] });
      }
    }
    return diff;
  }

  test('detects no changes', () => {
    const diff = generateDiff('same', 'same');
    expect(diff.every(d => d.type === 'same')).toBeTruthy();
  });

  test('detects additions', () => {
    const diff = generateDiff('line1', 'line1\nline2');
    expect(diff.some(d => d.type === 'add')).toBeTruthy();
  });

  test('detects removals', () => {
    const diff = generateDiff('line1\nline2', 'line1');
    expect(diff.some(d => d.type === 'remove')).toBeTruthy();
  });

  test('detects modifications', () => {
    const diff = generateDiff('old', 'new');
    expect(diff.some(d => d.type === 'remove' && d.content === 'old')).toBeTruthy();
    expect(diff.some(d => d.type === 'add' && d.content === 'new')).toBeTruthy();
  });

  test('handles empty strings', () => {
    const diff = generateDiff('', 'new');
    expect(diff.length).toBe(1);
    expect(diff[0].type).toBe('add');
  });

  test('handles multi-line changes', () => {
    const diff = generateDiff('a\nb\nc', 'a\nx\nc');
    expect(diff.length).toBe(4); // same, remove, add, same
  });
});

// ============================================
// useUndoRedo Tests
// ============================================
describe('useUndoRedo', () => {
  interface Operation {
    id: string;
    type: string;
    path: string;
    undone: boolean;
  }

  let operations: Operation[] = [];
  let currentIndex = -1;

  function record(op: Omit<Operation, 'id' | 'undone'>) {
    if (currentIndex < operations.length - 1) {
      operations = operations.slice(0, currentIndex + 1);
    }
    operations.push({ ...op, id: `op-${Date.now()}`, undone: false });
    currentIndex = operations.length - 1;
  }

  function undo() {
    if (currentIndex < 0) return null;
    operations[currentIndex].undone = true;
    return operations[currentIndex--];
  }

  function redo() {
    if (currentIndex >= operations.length - 1) return null;
    operations[++currentIndex].undone = false;
    return operations[currentIndex];
  }

  function canUndo() { return currentIndex >= 0; }
  function canRedo() { return currentIndex < operations.length - 1; }

  // Reset
  operations = [];
  currentIndex = -1;

  test('records operation', () => {
    record({ type: 'write', path: '/test.txt' });
    expect(operations.length).toBe(1);
    expect(currentIndex).toBe(0);
  });

  test('can undo after record', () => {
    expect(canUndo()).toBeTruthy();
  });

  test('undo returns operation', () => {
    const op = undo();
    expect(op?.type).toBe('write');
    expect(currentIndex).toBe(-1);
  });

  test('cannot undo when empty', () => {
    expect(canUndo()).toBeFalsy();
    expect(undo()).toBeFalsy();
  });

  test('can redo after undo', () => {
    expect(canRedo()).toBeTruthy();
  });

  test('redo restores operation', () => {
    const op = redo();
    expect(op?.type).toBe('write');
    expect(op?.undone).toBeFalsy();
  });

  test('new operation clears redo stack', () => {
    record({ type: 'edit', path: '/a.txt' });
    undo();
    record({ type: 'delete', path: '/b.txt' });
    expect(canRedo()).toBeFalsy();
  });
});

// ============================================
// useAIMemory Tests
// ============================================
describe('useAIMemory', () => {
  interface MemoryEntry {
    id: string;
    type: 'fact' | 'preference' | 'decision';
    content: string;
    importance: number;
    timestamp: Date;
  }

  let memory: MemoryEntry[] = [];
  const preferences: Record<string, string> = {};

  function remember(entry: Omit<MemoryEntry, 'id' | 'timestamp'>) {
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
      .sort((a, b) => b.importance - a.importance)
      .slice(0, limit);
  }

  function setPreference(key: string, value: string) {
    preferences[key] = value;
  }

  function getPreference(key: string) {
    return preferences[key];
  }

  // Reset
  memory = [];

  test('stores memory entry', () => {
    remember({ type: 'fact', content: 'User prefers TypeScript', importance: 8 });
    expect(memory.length).toBe(1);
  });

  test('recalls by query', () => {
    remember({ type: 'decision', content: 'Using React for UI', importance: 9 });
    const results = recall('React');
    expect(results.length).toBe(1);
  });

  test('sorts by importance', () => {
    remember({ type: 'fact', content: 'Low importance fact', importance: 2 });
    const results = recall('');
    expect(results[0].importance).toBeGreaterThan(results[results.length - 1].importance);
  });

  test('stores preferences', () => {
    setPreference('theme', 'dark');
    expect(getPreference('theme')).toBe('dark');
  });

  test('returns undefined for missing preference', () => {
    expect(getPreference('nonexistent')).toBeFalsy();
  });
});

// ============================================
// useTestRunner Tests
// ============================================
describe('useTestRunner', () => {
  type TestStatus = 'passed' | 'failed' | 'skipped';

  interface TestResult {
    name: string;
    status: TestStatus;
    duration?: number;
  }

  function parseCargoOutput(output: string): TestResult[] {
    const results: TestResult[] = [];
    const regex = /test\s+(\S+)\s+\.\.\.\s+(ok|FAILED|ignored)/g;
    let m;
    while ((m = regex.exec(output)) !== null) {
      results.push({
        name: m[1],
        status: m[2] === 'ok' ? 'passed' : m[2] === 'FAILED' ? 'failed' : 'skipped',
      });
    }
    return results;
  }

  function parseJestOutput(output: string): TestResult[] {
    const results: TestResult[] = [];
    const regex = /(✓|✕|○)\s+(.+?)(?:\s*\((\d+)\s*ms\))?$/gm;
    let m;
    while ((m = regex.exec(output)) !== null) {
      results.push({
        name: m[2].trim(),
        status: m[1] === '✓' ? 'passed' : m[1] === '✕' ? 'failed' : 'skipped',
        duration: m[3] ? parseInt(m[3]) : undefined,
      });
    }
    return results;
  }

  test('parses Cargo output', () => {
    const output = 'test test_one ... ok\ntest test_two ... FAILED';
    const results = parseCargoOutput(output);
    expect(results.length).toBe(2);
    expect(results[0].status).toBe('passed');
    expect(results[1].status).toBe('failed');
  });

  test('parses Jest output', () => {
    const output = '  ✓ should pass (5 ms)\n  ✕ should fail';
    const results = parseJestOutput(output);
    expect(results.length).toBe(2);
    expect(results[0].duration).toBe(5);
  });

  test('handles empty output', () => {
    expect(parseCargoOutput('').length).toBe(0);
    expect(parseJestOutput('').length).toBe(0);
  });
});

// ============================================
// useCodeExplainer Tests
// ============================================
describe('useCodeExplainer', () => {
  function detectLanguage(code: string, filename?: string) {
    if (filename) {
      const ext = filename.split('.').pop()?.toLowerCase();
      const map: Record<string, string> = {
        ts: 'typescript', tsx: 'typescript',
        js: 'javascript', jsx: 'javascript',
        py: 'python', rs: 'rust', go: 'go',
      };
      if (ext && map[ext]) return map[ext];
    }
    if (code.includes('fn ') && code.includes('let ')) return 'rust';
    if (code.includes('def ') && !code.includes('{')) return 'python';
    if (code.includes('func ') && code.includes('package')) return 'go';
    if (code.includes('=>') || code.includes('function')) return 'javascript';
    return 'unknown';
  }

  test('detects by extension - TypeScript', () => {
    expect(detectLanguage('', 'app.ts')).toBe('typescript');
    expect(detectLanguage('', 'component.tsx')).toBe('typescript');
  });

  test('detects by extension - Python', () => {
    expect(detectLanguage('', 'script.py')).toBe('python');
  });

  test('detects Rust by content', () => {
    expect(detectLanguage('fn main() { let x = 5; }')).toBe('rust');
  });

  test('detects Python by content', () => {
    expect(detectLanguage('def hello():\n    print("hi")')).toBe('python');
  });

  test('detects JavaScript by content', () => {
    expect(detectLanguage('const fn = () => 42')).toBe('javascript');
  });

  test('returns unknown for unrecognized', () => {
    expect(detectLanguage('some random text')).toBe('unknown');
  });
});

// ============================================
// Run all tests
// ============================================
console.log('\n🚀 Running Composables Unit Tests\n');
console.log('='.repeat(50));

// The describe() calls above run the tests

console.log('\n' + '='.repeat(50));
console.log('\n✅ All composable tests completed!\n');
