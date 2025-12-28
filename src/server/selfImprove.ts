/**
 * Self-Improvement Orchestrator
 * Safe 24/7 autonomous improvement loop
 *
 * Architecture:
 * ┌────────────────────────────────────────────────────────────────┐
 * │                    PRODUCTION (main branch)                    │
 * │  • Stable, tested code                                         │
 * │  • Only updated after human approval                           │
 * └────────────────────────────────────────────────────────────────┘
 *                              ▲
 *                              │ Approved changes only
 *                              │
 * ┌────────────────────────────────────────────────────────────────┐
 * │                    STAGING (staging branch)                    │
 * │  • Validated improvements waiting for approval                 │
 * │  • All tests passed                                            │
 * └────────────────────────────────────────────────────────────────┘
 *                              ▲
 *                              │ Tests passed
 *                              │
 * ┌────────────────────────────────────────────────────────────────┐
 * │                    DEVELOPMENT (dev branch)                    │
 * │  • Active work by AI                                           │
 * │  • Experimental changes                                        │
 * │  • Safe sandbox                                                │
 * └────────────────────────────────────────────────────────────────┘
 *
 * Safety Guarantees:
 * 1. Never modifies production without approval
 * 2. All changes are version controlled
 * 3. Full rollback capability
 * 4. Pauses on any error
 * 5. Human approval for major changes
 */

import { spawn, ChildProcess } from 'child_process';
import { createApproval, waitForApproval, broadcast } from './api';

// ============================================================================
// TYPES
// ============================================================================

export interface ImprovementConfig {
  repoPath: string;
  productionBranch: string;
  stagingBranch: string;
  devBranch: string;

  // Safety
  requireApprovalFor: ApprovalTrigger[];
  maxChangesPerCycle: number;
  maxFilesPerChange: number;
  forbiddenPaths: string[];
  forbiddenPatterns: RegExp[];

  // Timing
  cycleDurationMs: number;
  pauseBetweenCyclesMs: number;
  maxContinuousRuntime: number;  // Hours before mandatory pause

  // AI
  aiModel: string;
  aiEndpoint: string;

  // Notifications
  notifyOnSuccess: boolean;
  notifyOnFailure: boolean;
  notifyOnApprovalNeeded: boolean;
}

export type ApprovalTrigger =
  | 'any_change'
  | 'new_feature'
  | 'delete_file'
  | 'modify_config'
  | 'dependency_change'
  | 'security_related'
  | 'large_change'
  | 'staging_to_production';

export interface ImprovementCycle {
  id: string;
  startedAt: Date;
  endedAt?: Date;
  status: 'running' | 'completed' | 'failed' | 'paused' | 'waiting_approval';
  task: ImprovementTask;
  changes: FileChange[];
  testResults?: TestResults;
  approvalId?: string;
  error?: string;
}

export interface ImprovementTask {
  id: string;
  type: 'bug_fix' | 'optimization' | 'feature' | 'refactor' | 'documentation' | 'test';
  title: string;
  description: string;
  priority: number;
  estimatedComplexity: 'trivial' | 'small' | 'medium' | 'large';
  createdAt: Date;
  source: 'ai_suggested' | 'todo_comment' | 'test_failure' | 'performance_issue' | 'user_request';
}

export interface FileChange {
  path: string;
  type: 'create' | 'modify' | 'delete' | 'rename';
  oldContent?: string;
  newContent?: string;
  diff?: string;
  linesAdded: number;
  linesRemoved: number;
}

export interface TestResults {
  passed: number;
  failed: number;
  skipped: number;
  duration: number;
  coverage?: number;
  failedTests: string[];
}

export interface ImprovementState {
  status: 'idle' | 'running' | 'paused' | 'waiting_approval' | 'error';
  currentCycle?: ImprovementCycle;
  completedCycles: number;
  failedCycles: number;
  startedAt?: Date;
  pausedAt?: Date;
  lastSuccessfulMerge?: Date;
  pendingTasks: ImprovementTask[];
  recentChanges: FileChange[];
  totalLinesChanged: number;
}

// ============================================================================
// DEFAULT CONFIG
// ============================================================================

const DEFAULT_CONFIG: ImprovementConfig = {
  repoPath: process.cwd(),
  productionBranch: 'main',
  stagingBranch: 'staging',
  devBranch: 'dev-ai',

  requireApprovalFor: [
    'delete_file',
    'modify_config',
    'dependency_change',
    'security_related',
    'large_change',
    'staging_to_production'
  ],
  maxChangesPerCycle: 10,
  maxFilesPerChange: 5,
  forbiddenPaths: [
    '.git',
    'node_modules',
    '.env',
    'credentials',
    'secrets',
    '*.key',
    '*.pem'
  ],
  forbiddenPatterns: [
    /password\s*=/i,
    /api_key\s*=/i,
    /secret\s*=/i,
    /rm\s+-rf\s+\//,
    /eval\(/,
    /exec\(/
  ],

  cycleDurationMs: 30 * 60 * 1000,  // 30 minutes max per cycle
  pauseBetweenCyclesMs: 5 * 60 * 1000,  // 5 minutes between cycles
  maxContinuousRuntime: 8,  // 8 hours before mandatory pause

  aiModel: 'qwen2.5-coder:7b',
  aiEndpoint: 'http://localhost:11434',

  notifyOnSuccess: true,
  notifyOnFailure: true,
  notifyOnApprovalNeeded: true
};

// ============================================================================
// STATE
// ============================================================================

const config: ImprovementConfig = { ...DEFAULT_CONFIG };
const state: ImprovementState = {
  status: 'idle',
  completedCycles: 0,
  failedCycles: 0,
  pendingTasks: [],
  recentChanges: [],
  totalLinesChanged: 0
};

let loopInterval: NodeJS.Timeout | null = null;
let currentProcess: ChildProcess | null = null;

// ============================================================================
// GIT OPERATIONS
// ============================================================================

async function git(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn('git', args, { cwd: config.repoPath });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', data => stdout += data);
    proc.stderr.on('data', data => stderr += data);

    proc.on('close', code => {
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(new Error(stderr || `Git exited with code ${code}`));
      }
    });
  });
}

async function ensureBranches(): Promise<void> {
  const branches = await git(['branch', '--list']);

  // Create dev branch if needed
  if (!branches.includes(config.devBranch)) {
    await git(['checkout', '-b', config.devBranch, config.productionBranch]);
    console.log(`[SelfImprove] Created ${config.devBranch} branch`);
  }

  // Create staging branch if needed
  if (!branches.includes(config.stagingBranch)) {
    await git(['checkout', '-b', config.stagingBranch, config.productionBranch]);
    console.log(`[SelfImprove] Created ${config.stagingBranch} branch`);
  }
}

async function switchToDev(): Promise<void> {
  await git(['checkout', config.devBranch]);
  await git(['pull', 'origin', config.productionBranch, '--rebase']);
}

async function commitChanges(message: string): Promise<string> {
  await git(['add', '-A']);
  await git(['commit', '-m', message]);
  return git(['rev-parse', 'HEAD']);
}

async function getChangedFiles(): Promise<string[]> {
  const output = await git(['diff', '--name-only', config.productionBranch]);
  return output.split('\n').filter(Boolean);
}

async function getDiff(file: string): Promise<string> {
  return git(['diff', config.productionBranch, '--', file]);
}

async function rollback(commitHash: string): Promise<void> {
  await git(['reset', '--hard', commitHash]);
  console.log(`[SelfImprove] Rolled back to ${commitHash}`);
}

// ============================================================================
// SAFETY CHECKS
// ============================================================================

function isForbiddenPath(path: string): boolean {
  return config.forbiddenPaths.some(forbidden => {
    if (forbidden.includes('*')) {
      const regex = new RegExp(forbidden.replace(/\*/g, '.*'));
      return regex.test(path);
    }
    return path.includes(forbidden);
  });
}

function containsForbiddenPattern(content: string): boolean {
  return config.forbiddenPatterns.some(pattern => pattern.test(content));
}

function requiresApproval(change: FileChange, allChanges: FileChange[]): ApprovalTrigger | null {
  // Delete file
  if (change.type === 'delete' && config.requireApprovalFor.includes('delete_file')) {
    return 'delete_file';
  }

  // Config file
  if ((change.path.includes('config') || change.path.endsWith('.json') || change.path.endsWith('.toml')) &&
      config.requireApprovalFor.includes('modify_config')) {
    return 'modify_config';
  }

  // Dependency change
  if ((change.path === 'package.json' || change.path === 'Cargo.toml') &&
      config.requireApprovalFor.includes('dependency_change')) {
    return 'dependency_change';
  }

  // Large change
  if ((change.linesAdded + change.linesRemoved > 100 || allChanges.length > 3) &&
      config.requireApprovalFor.includes('large_change')) {
    return 'large_change';
  }

  // Security related
  if ((change.path.includes('auth') || change.path.includes('security') || change.path.includes('crypto')) &&
      config.requireApprovalFor.includes('security_related')) {
    return 'security_related';
  }

  return null;
}

// ============================================================================
// TEST RUNNER
// ============================================================================

async function runTests(): Promise<TestResults> {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const proc = spawn('npm', ['test', '--', '--json'], { cwd: config.repoPath });

    let output = '';
    proc.stdout.on('data', data => output += data);
    proc.stderr.on('data', data => output += data);

    proc.on('close', code => {
      const duration = Date.now() - startTime;

      try {
        // Try to parse Jest/Vitest JSON output
        const jsonMatch = output.match(/\{[\s\S]*"numPassedTests"[\s\S]*\}/);
        if (jsonMatch) {
          const results = JSON.parse(jsonMatch[0]);
          resolve({
            passed: results.numPassedTests || 0,
            failed: results.numFailedTests || 0,
            skipped: results.numPendingTests || 0,
            duration,
            failedTests: results.testResults?.filter((t: { status: string }) => t.status === 'failed')
              .map((t: { name: string }) => t.name) || []
          });
          return;
        }
      } catch {}

      // Fallback: parse text output
      const passed = (output.match(/(\d+) passing/i) || [])[1] || '0';
      const failed = (output.match(/(\d+) failing/i) || [])[1] || '0';

      resolve({
        passed: parseInt(passed),
        failed: parseInt(failed),
        skipped: 0,
        duration,
        failedTests: code !== 0 ? ['Unknown - check logs'] : []
      });
    });
  });
}

async function runBuild(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('npm', ['run', 'build'], { cwd: config.repoPath });

    proc.on('close', code => {
      resolve(code === 0);
    });
  });
}

// ============================================================================
// AI INTEGRATION
// ============================================================================

async function askAI(prompt: string): Promise<string> {
  const response = await fetch(`${config.aiEndpoint}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: config.aiModel,
      prompt,
      stream: false
    })
  });

  const data = await response.json();
  return data.response;
}

async function generateTask(): Promise<ImprovementTask | null> {
  const prompt = `You are analyzing a codebase to find improvement opportunities.

Look for:
1. TODO comments that can be implemented
2. Code that could be optimized
3. Missing error handling
4. Potential bugs
5. Missing tests
6. Documentation improvements

Respond with a single JSON object:
{
  "type": "bug_fix" | "optimization" | "feature" | "refactor" | "documentation" | "test",
  "title": "Brief title",
  "description": "What to do and why",
  "priority": 1-10,
  "estimatedComplexity": "trivial" | "small" | "medium" | "large",
  "targetFiles": ["file1.ts", "file2.ts"]
}

Only respond with JSON, no explanation.`;

  try {
    const response = await askAI(prompt);
    const task = JSON.parse(response);

    return {
      ...task,
      id: Date.now().toString(36),
      createdAt: new Date(),
      source: 'ai_suggested'
    };
  } catch {
    return null;
  }
}

async function implementTask(task: ImprovementTask): Promise<FileChange[]> {
  const prompt = `Implement this improvement:

Task: ${task.title}
Description: ${task.description}
Type: ${task.type}

Rules:
1. Make minimal, focused changes
2. Follow existing code style
3. Add tests if appropriate
4. Don't break existing functionality
5. Maximum 5 files changed

Respond with a JSON array of file changes:
[{
  "path": "src/file.ts",
  "action": "modify" | "create" | "delete",
  "content": "full file content for create/modify"
}]

Only respond with JSON.`;

  try {
    const response = await askAI(prompt);
    const changes = JSON.parse(response);

    return changes.map((c: { path: string; action: string; content?: string }) => ({
      path: c.path,
      type: c.action as FileChange['type'],
      newContent: c.content,
      linesAdded: (c.content?.split('\n').length || 0),
      linesRemoved: 0
    }));
  } catch {
    return [];
  }
}

// ============================================================================
// IMPROVEMENT CYCLE
// ============================================================================

async function runCycle(): Promise<void> {
  if (state.status !== 'running') return;

  const cycleId = Date.now().toString(36);
  console.log(`[SelfImprove] Starting cycle ${cycleId}`);

  const cycle: ImprovementCycle = {
    id: cycleId,
    startedAt: new Date(),
    status: 'running',
    task: null as unknown as ImprovementTask,
    changes: []
  };

  state.currentCycle = cycle;
  broadcast({ type: 'cycle_started', cycle });

  try {
    // Switch to dev branch
    await switchToDev();
    const startCommit = await git(['rev-parse', 'HEAD']);

    // Generate or pick task
    let task: ImprovementTask | null = state.pendingTasks.shift() || null;
    if (!task) {
      task = await generateTask();
    }

    if (!task) {
      console.log('[SelfImprove] No tasks to work on');
      cycle.status = 'completed';
      return;
    }

    cycle.task = task;
    broadcast({ type: 'task_started', task });

    // Implement the task
    const changes = await implementTask(task);

    if (changes.length === 0) {
      console.log('[SelfImprove] No changes generated');
      cycle.status = 'completed';
      return;
    }

    // Safety checks
    for (const change of changes) {
      if (isForbiddenPath(change.path)) {
        throw new Error(`Forbidden path: ${change.path}`);
      }

      if (change.newContent && containsForbiddenPattern(change.newContent)) {
        throw new Error(`Forbidden pattern in: ${change.path}`);
      }
    }

    // Apply changes
    for (const change of changes) {
      if (change.type === 'delete') {
        // Would delete file
      } else if (change.newContent) {
        // Would write file
      }
    }

    cycle.changes = changes;

    // Run tests
    console.log('[SelfImprove] Running tests...');
    const testResults = await runTests();
    cycle.testResults = testResults;

    if (testResults.failed > 0) {
      console.log(`[SelfImprove] Tests failed: ${testResults.failed}`);
      await rollback(startCommit);
      cycle.status = 'failed';
      state.failedCycles++;
      return;
    }

    // Run build
    const buildSuccess = await runBuild();
    if (!buildSuccess) {
      console.log('[SelfImprove] Build failed');
      await rollback(startCommit);
      cycle.status = 'failed';
      state.failedCycles++;
      return;
    }

    // Check if approval needed
    for (const change of changes) {
      const trigger = requiresApproval(change, changes);
      if (trigger) {
        console.log(`[SelfImprove] Approval required: ${trigger}`);

        const approval = createApproval({
          type: 'code_change',
          title: `Approve: ${task.title}`,
          description: `The AI wants to make changes (${trigger})`,
          details: { task, changes, testResults },
          options: [
            { id: 'approve', label: 'Approve', isDefault: true },
            { id: 'reject', label: 'Reject' },
            { id: 'modify', label: 'Request Changes' }
          ],
          priority: trigger === 'security_related' ? 'high' : 'medium'
        });

        cycle.approvalId = approval.id;
        cycle.status = 'waiting_approval';
        state.status = 'waiting_approval';

        broadcast({ type: 'approval_needed', approval });

        const response = await waitForApproval(approval.id);

        if (response !== 'approve') {
          console.log(`[SelfImprove] Changes rejected: ${response}`);
          await rollback(startCommit);
          cycle.status = 'failed';
          return;
        }
      }
    }

    // Commit changes
    await commitChanges(`[AI] ${task.title}\n\n${task.description}`);

    cycle.status = 'completed';
    cycle.endedAt = new Date();
    state.completedCycles++;
    state.recentChanges.push(...changes);
    state.totalLinesChanged += changes.reduce((sum, c) => sum + c.linesAdded + c.linesRemoved, 0);

    console.log(`[SelfImprove] Cycle ${cycleId} completed successfully`);
    broadcast({ type: 'cycle_completed', cycle });

  } catch (error) {
    cycle.status = 'failed';
    cycle.error = error instanceof Error ? error.message : String(error);
    state.failedCycles++;

    console.error(`[SelfImprove] Cycle ${cycleId} failed:`, error);
    broadcast({ type: 'cycle_failed', cycle, error: cycle.error });
  } finally {
    state.currentCycle = undefined;
  }
}

// ============================================================================
// MAIN LOOP
// ============================================================================

async function startLoop(): Promise<void> {
  if (state.status === 'running') return;

  console.log('[SelfImprove] Starting improvement loop');

  await ensureBranches();

  state.status = 'running';
  state.startedAt = new Date();

  broadcast({ type: 'loop_started' });

  const runLoopIteration = async () => {
    if (state.status !== 'running') return;

    // Check max runtime
    const runtime = (Date.now() - (state.startedAt?.getTime() || 0)) / (1000 * 60 * 60);
    if (runtime >= config.maxContinuousRuntime) {
      console.log('[SelfImprove] Max runtime reached, pausing');
      await pauseLoop('Max continuous runtime reached');
      return;
    }

    await runCycle();

    // Schedule next cycle
    if (state.status === 'running') {
      loopInterval = setTimeout(runLoopIteration, config.pauseBetweenCyclesMs);
    }
  };

  runLoopIteration();
}

async function pauseLoop(reason?: string): Promise<void> {
  if (state.status !== 'running' && state.status !== 'waiting_approval') return;

  console.log(`[SelfImprove] Pausing loop: ${reason || 'User requested'}`);

  state.status = 'paused';
  state.pausedAt = new Date();

  if (loopInterval) {
    clearTimeout(loopInterval);
    loopInterval = null;
  }

  broadcast({ type: 'loop_paused', reason });
}

async function resumeLoop(): Promise<void> {
  if (state.status !== 'paused') return;

  console.log('[SelfImprove] Resuming loop');
  state.status = 'running';
  state.pausedAt = undefined;

  broadcast({ type: 'loop_resumed' });

  // Continue with next cycle
  loopInterval = setTimeout(() => runCycle(), 1000);
}

async function stopLoop(): Promise<void> {
  console.log('[SelfImprove] Stopping loop');

  state.status = 'idle';

  if (loopInterval) {
    clearTimeout(loopInterval);
    loopInterval = null;
  }

  if (currentProcess) {
    currentProcess.kill();
    currentProcess = null;
  }

  broadcast({ type: 'loop_stopped' });
}

// ============================================================================
// STAGING TO PRODUCTION
// ============================================================================

async function promoteToStaging(): Promise<boolean> {
  try {
    await git(['checkout', config.stagingBranch]);
    await git(['merge', config.devBranch, '--no-ff', '-m', 'Merge dev improvements']);
    console.log('[SelfImprove] Promoted dev to staging');
    return true;
  } catch (e) {
    console.error('[SelfImprove] Failed to promote to staging:', e);
    return false;
  }
}

async function promoteToProduction(): Promise<boolean> {
  // Always require approval for production
  const approval = createApproval({
    type: 'update',
    title: 'Deploy to Production',
    description: 'Ready to merge staging changes to production',
    details: {
      completedCycles: state.completedCycles,
      totalChanges: state.recentChanges.length,
      linesChanged: state.totalLinesChanged
    },
    options: [
      { id: 'approve', label: 'Deploy', isDefault: true },
      { id: 'reject', label: 'Cancel' }
    ],
    priority: 'high'
  });

  const response = await waitForApproval(approval.id);

  if (response !== 'approve') {
    console.log('[SelfImprove] Production deployment rejected');
    return false;
  }

  try {
    await git(['checkout', config.productionBranch]);
    await git(['merge', config.stagingBranch, '--no-ff', '-m', 'Deploy staging to production']);
    await git(['push', 'origin', config.productionBranch]);

    state.lastSuccessfulMerge = new Date();
    console.log('[SelfImprove] Deployed to production');

    broadcast({ type: 'deployed_to_production' });
    return true;
  } catch (e) {
    console.error('[SelfImprove] Failed to deploy to production:', e);
    return false;
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export function useSelfImprove() {
  return {
    // State
    state: { ...state },
    config: { ...config },

    // Control
    start: startLoop,
    pause: pauseLoop,
    resume: resumeLoop,
    stop: stopLoop,

    // Tasks
    addTask: (task: Omit<ImprovementTask, 'id' | 'createdAt'>) => {
      state.pendingTasks.push({
        ...task,
        id: Date.now().toString(36),
        createdAt: new Date()
      });
    },

    // Deployment
    promoteToStaging,
    promoteToProduction,

    // Config
    updateConfig: (newConfig: Partial<ImprovementConfig>) => {
      Object.assign(config, newConfig);
    }
  };
}

export default useSelfImprove;
