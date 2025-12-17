#!/usr/bin/env node
/**
 * Claude Task Runner
 *
 * Watches task_queue.json and invokes Claude Code to implement pending tasks.
 * Works in tandem with autonomous_loop.cjs which handles ChatGPT communication.
 *
 * Flow:
 * 1. Pick next pending task
 * 2. Move to inProgress
 * 3. Run Claude Code with task prompt
 * 4. Move to completed (or failed)
 * 5. Repeat
 *
 * Usage:
 *   node claude_task_runner.cjs
 *   node claude_task_runner.cjs --once    # Run one task and exit
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const CONFIG = {
  taskQueuePath: path.join(__dirname, 'task_queue.json'),
  workingDir: __dirname,

  // How often to check for new tasks (ms)
  pollInterval: 5000,

  // Claude Code command
  claudeCommand: 'claude',

  // Project context to include in every prompt
  projectContext: `
You are working on the Warp Terminal Clone project - a Tauri + Vue 3 terminal emulator.

Key files:
- src/App.vue - Main app component
- src/components/ - Vue components (TerminalPane, TabBar, etc.)
- src/composables/ - Vue composables (useTabs, useSnapshots, useToast, useAI)
- src-tauri/src/main.rs - Tauri entry point
- src-tauri/src/commands.rs - Rust PTY commands

After completing the task, update task_queue.json to mark the task as completed with a brief result summary.
`.trim(),
};

// Load task queue
function loadTaskQueue() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG.taskQueuePath, 'utf8'));
  } catch (e) {
    console.error('Failed to load task queue:', e.message);
    return null;
  }
}

// Save task queue
function saveTaskQueue(queue) {
  fs.writeFileSync(CONFIG.taskQueuePath, JSON.stringify(queue, null, 2));
}

// Get next pending task (highest priority first)
function getNextTask() {
  const queue = loadTaskQueue();
  if (!queue || queue.pending.length === 0) {
    return null;
  }

  // Sort by priority: high > medium > low
  const priorityOrder = { high: 0, medium: 1, low: 2 };
  const sorted = [...queue.pending].sort((a, b) => {
    return (priorityOrder[a.priority] || 1) - (priorityOrder[b.priority] || 1);
  });

  return sorted[0];
}

// Move task to inProgress
function startTask(taskId) {
  const queue = loadTaskQueue();
  const taskIndex = queue.pending.findIndex(t => t.id === taskId);

  if (taskIndex === -1) {
    console.error(`Task ${taskId} not found in pending`);
    return null;
  }

  const task = queue.pending.splice(taskIndex, 1)[0];
  task.startedAt = new Date().toISOString();
  queue.inProgress.push(task);

  saveTaskQueue(queue);
  return task;
}

// Mark task as completed
function completeTask(taskId, result) {
  const queue = loadTaskQueue();
  const taskIndex = queue.inProgress.findIndex(t => t.id === taskId);

  if (taskIndex === -1) {
    // Maybe already completed by Claude itself
    console.log(`Task ${taskId} not in inProgress (may have been updated by Claude)`);
    return;
  }

  const task = queue.inProgress.splice(taskIndex, 1)[0];
  task.completedAt = new Date().toISOString();
  task.result = result;
  queue.completed.push(task);

  saveTaskQueue(queue);
}

// Mark task as failed
function failTask(taskId, error) {
  const queue = loadTaskQueue();
  const taskIndex = queue.inProgress.findIndex(t => t.id === taskId);

  if (taskIndex === -1) {
    console.error(`Task ${taskId} not found in inProgress`);
    return;
  }

  const task = queue.inProgress.splice(taskIndex, 1)[0];
  task.failedAt = new Date().toISOString();
  task.error = error;
  queue.failed.push(task);

  saveTaskQueue(queue);
}

// Build prompt for Claude
function buildPrompt(task) {
  return `
${CONFIG.projectContext}

---

## Current Task

**ID:** ${task.id}
**Priority:** ${task.priority}
**Title:** ${task.title}
${task.description ? `**Description:** ${task.description}` : ''}

Please implement this task. When done:
1. Test that your changes work (run build if needed)
2. Update task_queue.json to mark task ${task.id} as completed

Begin implementation now.
`.trim();
}

// Run Claude Code on a task
function runClaude(task) {
  return new Promise((resolve, reject) => {
    console.log(`\n🤖 Starting Claude Code for task: ${task.title}`);

    const prompt = buildPrompt(task);

    // Spawn Claude Code in non-interactive mode
    const claude = spawn(CONFIG.claudeCommand, [
      '--print',  // Non-interactive, print output
      '-p', prompt,
    ], {
      cwd: CONFIG.workingDir,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        FORCE_COLOR: '0',  // Disable colors for cleaner output
      },
    });

    let stdout = '';
    let stderr = '';

    claude.stdout.on('data', (data) => {
      const text = data.toString();
      stdout += text;
      process.stdout.write(text);  // Stream output
    });

    claude.stderr.on('data', (data) => {
      const text = data.toString();
      stderr += text;
      process.stderr.write(text);
    });

    claude.on('close', (code) => {
      if (code === 0) {
        resolve({ success: true, output: stdout });
      } else {
        reject(new Error(`Claude exited with code ${code}: ${stderr}`));
      }
    });

    claude.on('error', (err) => {
      reject(err);
    });
  });
}

// Check if task was completed by Claude (updated in queue)
function wasTaskCompleted(taskId) {
  const queue = loadTaskQueue();
  return queue.completed.some(t => t.id === taskId);
}

// Process one task
async function processOneTask() {
  const task = getNextTask();

  if (!task) {
    return { processed: false, reason: 'no_pending_tasks' };
  }

  console.log('\n═══════════════════════════════════════════');
  console.log(`📋 Task: ${task.title}`);
  console.log(`   Priority: ${task.priority}`);
  console.log(`   ID: ${task.id}`);
  console.log('═══════════════════════════════════════════\n');

  // Move to inProgress
  startTask(task.id);

  try {
    const result = await runClaude(task);

    // Check if Claude already marked it complete
    if (wasTaskCompleted(task.id)) {
      console.log('\n✅ Task completed by Claude');
    } else {
      // Mark complete with output summary
      const summary = result.output.slice(-500);  // Last 500 chars
      completeTask(task.id, `Completed. ${summary.includes('error') ? 'May have issues.' : 'Success.'}`);
      console.log('\n✅ Task marked as completed');
    }

    return { processed: true, task, success: true };

  } catch (error) {
    console.error('\n❌ Task failed:', error.message);
    failTask(task.id, error.message);
    return { processed: true, task, success: false, error: error.message };
  }
}

// Main loop
async function runLoop(once = false) {
  console.log('═══════════════════════════════════════════');
  console.log('  Claude Task Runner');
  console.log('═══════════════════════════════════════════');
  console.log('');
  console.log('Watches task_queue.json and runs Claude Code');
  console.log('on pending tasks automatically.');
  console.log('');
  console.log('Press Ctrl+C to stop');
  console.log('───────────────────────────────────────────\n');

  while (true) {
    const queue = loadTaskQueue();

    if (!queue) {
      console.error('Failed to load queue, retrying...');
      await new Promise(r => setTimeout(r, CONFIG.pollInterval));
      continue;
    }

    console.log(`\n📊 Queue: ${queue.pending.length} pending | ${queue.inProgress.length} in progress | ${queue.completed.length} completed`);

    if (queue.pending.length > 0) {
      const result = await processOneTask();

      if (once) {
        console.log('\n--once flag set, exiting after single task');
        process.exit(result.success ? 0 : 1);
      }
    } else {
      console.log('⏳ No pending tasks, waiting...');
    }

    await new Promise(r => setTimeout(r, CONFIG.pollInterval));
  }
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  const once = args.includes('--once');

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`Claude Task Runner

Usage:
  node claude_task_runner.cjs           # Run continuously
  node claude_task_runner.cjs --once    # Run one task and exit

Watches task_queue.json for pending tasks and runs Claude Code
to implement them automatically.`);
    process.exit(0);
  }

  await runLoop(once);
}

process.on('SIGINT', () => {
  console.log('\n\n👋 Stopping Claude Task Runner...');
  process.exit(0);
});

main().catch(console.error);
