/**
 * PatternCache - Cache successful patterns for reuse
 *
 * Reduces LLM calls by:
 * - Storing successful code patterns
 * - Matching similar tasks to cached patterns
 * - Template-based code generation
 * - Learning from user corrections
 */

import { invoke } from '@tauri-apps/api/tauri';

export interface CodePattern {
  id: string;
  name: string;
  description: string;
  template: string;
  variables: string[];
  language: string;
  tags: string[];
  examples: PatternExample[];
  successCount: number;
  failureCount: number;
  createdAt: number;
  updatedAt: number;
}

export interface PatternExample {
  input: Record<string, string>;
  output: string;
  wasAccepted: boolean;
}

export interface PatternMatch {
  pattern: CodePattern;
  confidence: number;
  extractedVars: Record<string, string>;
}

export class PatternCache {
  private patterns: Map<string, CodePattern>;
  private storageKey: string;
  private maxPatterns: number;

  constructor(options: {
    storageKey?: string;
    maxPatterns?: number;
  } = {}) {
    this.patterns = new Map();
    this.storageKey = options.storageKey ?? 'warp_open_patterns';
    this.maxPatterns = options.maxPatterns ?? 100;

    // Initialize with built-in patterns
    this.loadBuiltinPatterns();
  }

  /**
   * Load built-in common patterns
   */
  private loadBuiltinPatterns(): void {
    // Express route pattern
    this.addPattern({
      name: 'express_route',
      description: 'Add an Express.js route handler',
      template: `app.{{method}}('{{path}}', async (req, res) => {
  try {
    {{body}}
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});`,
      variables: ['method', 'path', 'body'],
      language: 'javascript',
      tags: ['express', 'route', 'api', 'endpoint']
    });

    // React functional component
    this.addPattern({
      name: 'react_component',
      description: 'Create a React functional component',
      template: `import React from 'react';

interface {{name}}Props {
  {{props}}
}

export function {{name}}({ {{destructuredProps}} }: {{name}}Props) {
  return (
    <div className="{{className}}">
      {{children}}
    </div>
  );
}`,
      variables: ['name', 'props', 'destructuredProps', 'className', 'children'],
      language: 'typescript',
      tags: ['react', 'component', 'frontend']
    });

    // Vue composable
    this.addPattern({
      name: 'vue_composable',
      description: 'Create a Vue 3 composable',
      template: `import { ref, computed } from 'vue';

export function use{{Name}}() {
  const {{state}} = ref({{initialValue}});

  const {{computed}} = computed(() => {
    return {{computedBody}};
  });

  function {{method}}({{params}}) {
    {{methodBody}}
  }

  return {
    {{state}},
    {{computed}},
    {{method}}
  };
}`,
      variables: ['Name', 'state', 'initialValue', 'computed', 'computedBody', 'method', 'params', 'methodBody'],
      language: 'typescript',
      tags: ['vue', 'composable', 'composition-api']
    });

    // Python function with type hints
    this.addPattern({
      name: 'python_function',
      description: 'Create a Python function with type hints',
      template: `def {{name}}({{params}}) -> {{returnType}}:
    """{{docstring}}"""
    {{body}}
    return {{returnValue}}`,
      variables: ['name', 'params', 'returnType', 'docstring', 'body', 'returnValue'],
      language: 'python',
      tags: ['python', 'function']
    });

    // Rust struct with impl
    this.addPattern({
      name: 'rust_struct',
      description: 'Create a Rust struct with implementation',
      template: `#[derive(Debug, Clone)]
pub struct {{Name}} {
    {{fields}}
}

impl {{Name}} {
    pub fn new({{params}}) -> Self {
        Self {
            {{fieldInit}}
        }
    }

    {{methods}}
}`,
      variables: ['Name', 'fields', 'params', 'fieldInit', 'methods'],
      language: 'rust',
      tags: ['rust', 'struct']
    });

    // SQL CRUD operations
    this.addPattern({
      name: 'sql_crud',
      description: 'SQL CRUD operations for a table',
      template: `-- Create
INSERT INTO {{table}} ({{columns}}) VALUES ({{values}});

-- Read
SELECT {{selectColumns}} FROM {{table}} WHERE {{whereClause}};

-- Update
UPDATE {{table}} SET {{setClause}} WHERE {{whereClause}};

-- Delete
DELETE FROM {{table}} WHERE {{whereClause}};`,
      variables: ['table', 'columns', 'values', 'selectColumns', 'setClause', 'whereClause'],
      language: 'sql',
      tags: ['sql', 'crud', 'database']
    });

    // Error handling wrapper
    this.addPattern({
      name: 'error_handler',
      description: 'Wrap code with error handling',
      template: `try {
  {{code}}
} catch (error) {
  console.error('{{errorContext}}:', error);
  {{errorHandler}}
}`,
      variables: ['code', 'errorContext', 'errorHandler'],
      language: 'javascript',
      tags: ['error', 'try-catch', 'exception']
    });

    // Test case template
    this.addPattern({
      name: 'test_case',
      description: 'Create a test case',
      template: `describe('{{suiteName}}', () => {
  {{beforeSetup}}

  it('{{testDescription}}', async () => {
    // Arrange
    {{arrange}}

    // Act
    {{act}}

    // Assert
    {{assert}}
  });
});`,
      variables: ['suiteName', 'beforeSetup', 'testDescription', 'arrange', 'act', 'assert'],
      language: 'typescript',
      tags: ['test', 'jest', 'vitest']
    });
  }

  /**
   * Add a new pattern
   */
  addPattern(options: {
    name: string;
    description: string;
    template: string;
    variables: string[];
    language: string;
    tags: string[];
  }): CodePattern {
    const pattern: CodePattern = {
      id: `pattern_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      ...options,
      examples: [],
      successCount: 0,
      failureCount: 0,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    this.patterns.set(pattern.id, pattern);
    return pattern;
  }

  /**
   * Find matching patterns for a task
   */
  findMatches(description: string, language?: string): PatternMatch[] {
    const words = description.toLowerCase().split(/\s+/);
    const matches: PatternMatch[] = [];

    for (const pattern of this.patterns.values()) {
      // Filter by language if specified
      if (language && pattern.language !== language) continue;

      // Calculate match score
      let score = 0;

      // Tag matches
      for (const tag of pattern.tags) {
        if (words.some(w => w.includes(tag) || tag.includes(w))) {
          score += 2;
        }
      }

      // Description word matches
      const patternWords = pattern.description.toLowerCase().split(/\s+/);
      for (const word of words) {
        if (patternWords.some(pw => pw === word)) {
          score += 1;
        }
      }

      // Boost by success rate
      const totalUses = pattern.successCount + pattern.failureCount;
      if (totalUses > 0) {
        const successRate = pattern.successCount / totalUses;
        score *= (0.5 + successRate * 0.5);
      }

      if (score > 0) {
        matches.push({
          pattern,
          confidence: Math.min(score / 10, 1),
          extractedVars: this.extractVariables(description, pattern)
        });
      }
    }

    return matches.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * Try to extract variable values from description
   */
  private extractVariables(description: string, pattern: CodePattern): Record<string, string> {
    const vars: Record<string, string> = {};

    for (const varName of pattern.variables) {
      // Try common patterns
      const patterns = [
        new RegExp(`${varName}[:\\s]+['""]?([^'""\\s,]+)`, 'i'),
        new RegExp(`called\\s+['""]?([^'""\\s,]+)`, 'i'),
        new RegExp(`named\\s+['""]?([^'""\\s,]+)`, 'i'),
      ];

      for (const regex of patterns) {
        const match = description.match(regex);
        if (match) {
          vars[varName] = match[1];
          break;
        }
      }
    }

    return vars;
  }

  /**
   * Fill a pattern template with variables
   */
  fillTemplate(pattern: CodePattern, vars: Record<string, string>): string {
    let result = pattern.template;

    for (const [key, value] of Object.entries(vars)) {
      result = result.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), value);
    }

    // Mark unfilled variables
    result = result.replace(/\{\{(\w+)\}\}/g, '/* TODO: $1 */');

    return result;
  }

  /**
   * Record pattern usage outcome
   */
  recordUsage(patternId: string, success: boolean, example?: PatternExample): void {
    const pattern = this.patterns.get(patternId);
    if (!pattern) return;

    if (success) {
      pattern.successCount++;
    } else {
      pattern.failureCount++;
    }

    if (example) {
      pattern.examples.push(example);
      // Keep only last 10 examples
      if (pattern.examples.length > 10) {
        pattern.examples.shift();
      }
    }

    pattern.updatedAt = Date.now();
  }

  /**
   * Learn a new pattern from successful code
   */
  learnPattern(
    code: string,
    description: string,
    language: string,
    tags: string[]
  ): CodePattern | null {
    // Detect variables (simple heuristic: quoted strings, identifiers after keywords)
    const variables: string[] = [];
    const template = code
      .replace(/(['"])([^'"]+)\1/g, (match, quote, value) => {
        const varName = `var_${variables.length}`;
        variables.push(varName);
        return `{{${varName}}}`;
      })
      .replace(/\b(const|let|var|function|class)\s+(\w+)/g, (match, keyword, name) => {
        if (!variables.includes('name')) {
          variables.push('name');
        }
        return `${keyword} {{name}}`;
      });

    // Only learn if we found some variables
    if (variables.length === 0) return null;

    return this.addPattern({
      name: `learned_${Date.now()}`,
      description,
      template,
      variables,
      language,
      tags
    });
  }

  /**
   * Get pattern by ID
   */
  getPattern(id: string): CodePattern | undefined {
    return this.patterns.get(id);
  }

  /**
   * Get all patterns for a language
   */
  getPatternsByLanguage(language: string): CodePattern[] {
    return Array.from(this.patterns.values()).filter(p => p.language === language);
  }

  /**
   * Get top patterns by success rate
   */
  getTopPatterns(count: number = 10): CodePattern[] {
    return Array.from(this.patterns.values())
      .filter(p => p.successCount + p.failureCount > 0)
      .sort((a, b) => {
        const aRate = a.successCount / (a.successCount + a.failureCount);
        const bRate = b.successCount / (b.successCount + b.failureCount);
        return bRate - aRate;
      })
      .slice(0, count);
  }

  /**
   * Save patterns to storage
   */
  async save(): Promise<void> {
    const data = Array.from(this.patterns.values());
    try {
      const path = `~/.warp_open/${this.storageKey}.json`;
      await invoke<void>('write_file', {
        path,
        content: JSON.stringify(data, null, 2)
      });
    } catch (e) {
      console.error('Failed to save patterns:', e);
    }
  }

  /**
   * Load patterns from storage
   */
  async load(): Promise<void> {
    try {
      const path = `~/.warp_open/${this.storageKey}.json`;
      const content = await invoke<string>('read_file', { path });
      const data = JSON.parse(content) as CodePattern[];

      for (const pattern of data) {
        this.patterns.set(pattern.id, pattern);
      }
    } catch (e) {
      // No saved patterns, use defaults
    }
  }

  /**
   * Get statistics
   */
  getStats(): {
    totalPatterns: number;
    totalUsage: number;
    overallSuccessRate: number;
    byLanguage: Record<string, number>;
  } {
    let totalUsage = 0;
    let totalSuccess = 0;
    const byLanguage: Record<string, number> = {};

    for (const pattern of this.patterns.values()) {
      const usage = pattern.successCount + pattern.failureCount;
      totalUsage += usage;
      totalSuccess += pattern.successCount;
      byLanguage[pattern.language] = (byLanguage[pattern.language] || 0) + 1;
    }

    return {
      totalPatterns: this.patterns.size,
      totalUsage,
      overallSuccessRate: totalUsage > 0 ? totalSuccess / totalUsage : 0,
      byLanguage
    };
  }
}

export default PatternCache;
