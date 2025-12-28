/**
 * Tests for the Scaffolded Agent System
 *
 * Run with: npx vitest run src/agents/__tests__/scaffolding.test.ts
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'

// Mock Tauri invoke
vi.mock('@tauri-apps/api/tauri', () => ({
  invoke: vi.fn()
}))

import { invoke } from '@tauri-apps/api/tauri'
import { ContextManager } from '../ContextManager'
import { ConstrainedOutput, type AgentAction } from '../ConstrainedOutput'
import { Verifier } from '../Verifier'
import { RecoveryHandler } from '../RecoveryHandler'
import { ModelRouter } from '../ModelRouter'
import { PatternCache } from '../PatternCache'

describe('ContextManager', () => {
  let ctx: ContextManager

  beforeEach(() => {
    ctx = new ContextManager({ maxShortTermMessages: 4 })
  })

  it('should build prompts with context', () => {
    ctx.setTask('Create a hello world function')
    const prompt = ctx.buildPrompt('Write the code')

    expect(prompt).toContain('Create a hello world function')
    expect(prompt).toContain('Write the code')
    expect(prompt).toContain('JSON')
  })

  it('should track completed steps', () => {
    ctx.setTask('Build an API')
    ctx.completeStep('Created routes')
    ctx.completeStep('Added handlers')

    const prompt = ctx.buildPrompt('Continue')
    expect(prompt).toContain('Created routes')
    expect(prompt).toContain('Added handlers')
  })

  it('should track errors', () => {
    ctx.addError('Syntax error on line 5')
    const prompt = ctx.buildPrompt('Fix it')

    expect(prompt).toContain('Syntax error on line 5')
    expect(prompt).toContain('avoid')
  })

  it('should estimate tokens', () => {
    ctx.setTask('A simple task')
    const tokens = ctx.estimateTokens()

    expect(tokens).toBeGreaterThan(0)
    expect(tokens).toBeLessThan(1000)
  })

  it('should save and restore state', () => {
    ctx.setTask('Original task')
    ctx.completeStep('Step 1')

    const state = ctx.getState()
    ctx.clear()
    ctx.restoreState(state)

    expect(ctx.getState().currentTask).toBe('Original task')
    expect(ctx.getState().completedSteps).toContain('Step 1')
  })
})

describe('ConstrainedOutput', () => {
  let co: ConstrainedOutput

  beforeEach(() => {
    co = new ConstrainedOutput()
  })

  it('should extract JSON from clean output', () => {
    const json = co.extractJSON('{"action": "read", "path": "/test"}')
    expect(json).toBe('{"action": "read", "path": "/test"}')
  })

  it('should extract JSON from markdown code blocks', () => {
    const output = 'Here is the action:\n```json\n{"action": "write", "path": "test.txt", "content": "hello"}\n```'
    const json = co.extractJSON(output)

    expect(json).toContain('"action": "write"')
  })

  it('should validate read action', () => {
    const result = co.parse('{"action": "read", "path": "/test.txt"}')

    expect(result.valid).toBe(true)
    expect(result.action?.action).toBe('read')
    expect(result.action?.path).toBe('/test.txt')
  })

  it('should validate write action', () => {
    const result = co.parse('{"action": "write", "path": "file.js", "content": "code"}')

    expect(result.valid).toBe(true)
    expect(result.action?.action).toBe('write')
  })

  it('should reject missing required fields', () => {
    const result = co.parse('{"action": "write", "path": "test.txt"}')

    expect(result.valid).toBe(false)
    expect(result.error).toContain('content')
  })

  it('should reject invalid action types', () => {
    const result = co.parse('{"action": "delete", "path": "test.txt"}')

    expect(result.valid).toBe(false)
    expect(result.error).toContain('Invalid action')
  })
})

describe('Verifier', () => {
  let verifier: Verifier

  beforeEach(() => {
    verifier = new Verifier()
  })

  it('should pass safe bash commands', () => {
    const action: AgentAction = { action: 'bash', command: 'ls -la' }
    const result = verifier.quickSafetyCheck(action)

    expect(result.safe).toBe(true)
  })

  it('should block dangerous rm commands', () => {
    const action: AgentAction = { action: 'bash', command: 'rm -rf /' }
    const result = verifier.quickSafetyCheck(action)

    expect(result.safe).toBe(false)
  })

  it('should block fork bombs', () => {
    const action: AgentAction = { action: 'bash', command: ':(){ :|:& };:' }
    const result = verifier.quickSafetyCheck(action)

    expect(result.safe).toBe(false)
  })

  it('should warn about protected paths', () => {
    const action: AgentAction = { action: 'write', path: '/etc/passwd', content: 'test' }
    const result = verifier.quickSafetyCheck(action)

    expect(result.safe).toBe(false)
  })

  it('should allow normal file writes', () => {
    const action: AgentAction = { action: 'write', path: 'src/test.ts', content: 'code' }
    const result = verifier.quickSafetyCheck(action)

    expect(result.safe).toBe(true)
  })
})

describe('ModelRouter', () => {
  let router: ModelRouter

  beforeEach(() => {
    router = new ModelRouter()
  })

  it('should classify code generation tasks', () => {
    const taskType = router.classifyTask('Write a function to sort an array')
    expect(taskType).toBe('code_generation')
  })

  it('should classify debugging tasks', () => {
    const taskType = router.classifyTask('Fix the bug in the login function')
    expect(taskType).toBe('debugging')
  })

  it('should classify code explanation tasks', () => {
    const taskType = router.classifyTask('Explain how this function works')
    expect(taskType).toBe('code_explanation')
  })

  it('should classify refactoring tasks', () => {
    const taskType = router.classifyTask('Refactor the user module')
    expect(taskType).toBe('refactoring')
  })

  it('should estimate complexity', () => {
    const simple = router.estimateComplexity('Add a button')
    const complex = router.estimateComplexity('Implement a distributed caching system with Redis and also add authentication using OAuth2 and JWT tokens plus create a dashboard to monitor performance')

    expect(simple).toBeLessThan(complex)
  })

  it('should route to appropriate model', async () => {
    const result = await router.route('Write a hello world function', { preferLocal: true })

    expect(result.model).toBeDefined()
    expect(result.reason).toContain('code_generation')
  })

  it('should provide fallback chain', () => {
    const chain = router.getFallbackChain('qwen2.5-coder:1.5b', 'code_generation')

    expect(Array.isArray(chain)).toBe(true)
    expect(chain.length).toBeGreaterThan(0)
  })
})

describe('PatternCache', () => {
  let cache: PatternCache

  beforeEach(() => {
    cache = new PatternCache()
  })

  it('should have builtin patterns', () => {
    const stats = cache.getStats()
    expect(stats.totalPatterns).toBeGreaterThan(0)
  })

  it('should find matching patterns', () => {
    const matches = cache.findMatches('add an express route for users', 'javascript')

    expect(matches.length).toBeGreaterThan(0)
    expect(matches[0].pattern.tags).toContain('express')
  })

  it('should fill templates', () => {
    const patterns = cache.findMatches('express route', 'javascript')
    if (patterns.length > 0) {
      const filled = cache.fillTemplate(patterns[0].pattern, {
        method: 'get',
        path: '/users',
        body: 'return users'
      })

      expect(filled).toContain('/users')
      expect(filled).toContain('get')
    }
  })

  it('should track pattern usage', () => {
    const patterns = cache.findMatches('express route', 'javascript')
    if (patterns.length > 0) {
      cache.recordUsage(patterns[0].pattern.id, true)
      cache.recordUsage(patterns[0].pattern.id, true)
      cache.recordUsage(patterns[0].pattern.id, false)

      const pattern = cache.getPattern(patterns[0].pattern.id)
      expect(pattern?.successCount).toBe(2)
      expect(pattern?.failureCount).toBe(1)
    }
  })

  it('should add new patterns', () => {
    const pattern = cache.addPattern({
      name: 'test_pattern',
      description: 'A test pattern',
      template: 'function {{name}}() { return {{value}}; }',
      variables: ['name', 'value'],
      language: 'javascript',
      tags: ['test']
    })

    expect(pattern.id).toBeDefined()
    expect(cache.getPattern(pattern.id)).toBeDefined()
  })
})

describe('RecoveryHandler', () => {
  let recovery: RecoveryHandler

  beforeEach(() => {
    recovery = new RecoveryHandler()
  })

  it('should create checkpoints', async () => {
    const contextState = {
      shortTerm: [],
      summary: '',
      relevantFiles: [],
      currentTask: 'test',
      completedSteps: [],
      errors: []
    }

    const id = await recovery.createCheckpoint(contextState, 'test checkpoint')
    expect(id).toContain('cp_')
  })

  it('should record actions', () => {
    const action: AgentAction = { action: 'read', path: '/test.txt' }
    recovery.recordAction(action, 'success', 'file contents')

    const history = recovery.getHistory()
    expect(history.length).toBe(1)
    expect(history[0].action.action).toBe('read')
    expect(history[0].result).toBe('success')
  })

  it('should track stats', () => {
    const action: AgentAction = { action: 'bash', command: 'ls' }
    recovery.recordAction(action, 'success')
    recovery.recordAction(action, 'success')
    recovery.recordAction(action, 'failed', undefined, 'error')

    const stats = recovery.getStats()
    expect(stats.historyLength).toBe(3)
    expect(stats.successRate).toBeCloseTo(0.67, 1)
  })
})

describe('Integration', () => {
  it('should have all exports available', async () => {
    const exports = await import('../index')

    expect(exports.ContextManager).toBeDefined()
    expect(exports.ConstrainedOutput).toBeDefined()
    expect(exports.Verifier).toBeDefined()
    expect(exports.RecoveryHandler).toBeDefined()
    expect(exports.Orchestrator).toBeDefined()
    expect(exports.ModelRouter).toBeDefined()
    expect(exports.PatternCache).toBeDefined()
    expect(exports.ScaffoldedAgent).toBeDefined()
    expect(exports.useScaffoldedAgent).toBeDefined()
  })
})
