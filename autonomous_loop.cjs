#!/usr/bin/env node
/**
 * Autonomous ChatGPT <-> Claude Code Loop
 *
 * Continuous development loop WITHOUT human intervention:
 * 1. Claude completes tasks from task_queue.json
 * 2. Claude reports completion to ChatGPT (via web)
 * 3. ChatGPT generates new bullet-point task ideas
 * 4. Claude parses and adds to task_queue.json
 * 5. Repeat forever
 *
 * Usage:
 *   node autonomous_loop.cjs
 *   node autonomous_loop.cjs --thread <thread_id>
 *
 * NO TIMEOUTS. NO APPROVALS. Fully autonomous.
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');

const threadManager = require('./chatgpt_thread_manager.cjs');

const CONFIG = {
  taskQueuePath: path.join(__dirname, 'task_queue.json'),

  // How often to check for completed tasks (ms)
  pollInterval: 10000,  // 10 seconds

  // Wait time after sending to ChatGPT before reading response
  responseWaitTime: 30000,  // 30 seconds for ChatGPT to think

  // Max items to report per cycle (to avoid overwhelming)
  maxReportItems: 5,

  // Prompt templates
  prompts: {
    // Sent to ChatGPT after tasks complete
    statusReport: (completed, projectContext) => `
I've completed the following tasks:

${completed.map((t, i) => `${i + 1}. **${t.title}**
   Result: ${t.result}`).join('\n\n')}

${projectContext ? `\nProject context: ${projectContext}` : ''}

Based on what I've accomplished, please suggest the next 3-5 bullet-point tasks I should work on. Focus on:
- Improving the codebase quality
- Adding useful features
- Fixing any issues
- Performance improvements

Format each task as a numbered list with clear, actionable items. Be specific about what files or components to modify.
`.trim(),

    // Initial prompt to start the loop
    initialize: (projectInfo) => `
I'm starting an autonomous coding session on the Warp Terminal Clone project (Tauri + Vue 3).

Project summary:
${projectInfo}

Please suggest 3-5 specific, actionable tasks I should work on. Format as a numbered list.
`.trim(),
  },
};

// Load task queue
function loadTaskQueue() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG.taskQueuePath, 'utf8'));
  } catch (e) {
    return {
      description: "Task queue for autonomous development",
      config: { autoFetchFromChatGPT: true },
      pending: [],
      inProgress: [],
      completed: [],
      failed: [],
    };
  }
}

// Save task queue
function saveTaskQueue(queue) {
  fs.writeFileSync(CONFIG.taskQueuePath, JSON.stringify(queue, null, 2));
}

// Parse ChatGPT's response for new tasks
function parseTasksFromResponse(text) {
  const tasks = [];
  const lines = text.split('\n');

  let currentTask = null;
  let nextId = Date.now();

  for (const line of lines) {
    // Match numbered items: "1. Task" or "1) Task" or "- Task"
    // Also match emoji numbers: "19️⃣ Task Title"
    const numberedMatch = line.match(/^(\d+)[.\)]\s*\*?\*?(.+?)\*?\*?\s*$/);
    const emojiNumberMatch = line.match(/^(\d+)[\u{FE0F}\u{20E3}️⃣]\s*\*?\*?(.+?)\*?\*?\s*$/u);
    const bulletMatch = line.match(/^[-•]\s*\*?\*?(.+?)\*?\*?\s*$/);

    if (numberedMatch || emojiNumberMatch) {
      if (currentTask) tasks.push(currentTask);
      const match = numberedMatch || emojiNumberMatch;
      currentTask = {
        id: String(nextId++),
        priority: 'medium',
        title: match[2].trim().replace(/\*\*/g, ''),
        description: '',
        createdAt: new Date().toISOString(),
      };

      // Detect priority from keywords
      const titleLower = currentTask.title.toLowerCase();
      if (titleLower.includes('critical') || titleLower.includes('urgent') || titleLower.includes('security')) {
        currentTask.priority = 'high';
      } else if (titleLower.includes('minor') || titleLower.includes('optional') || titleLower.includes('nice to have')) {
        currentTask.priority = 'low';
      }
    } else if (bulletMatch && !currentTask) {
      // Standalone bullet point
      tasks.push({
        id: String(nextId++),
        priority: 'medium',
        title: bulletMatch[1].trim().replace(/\*\*/g, ''),
        description: '',
        createdAt: new Date().toISOString(),
      });
    } else if (currentTask && line.trim() && !line.match(/^(\d+)[.\)]/) && !line.match(/^(\d+)[\u{FE0F}\u{20E3}️⃣]/u)) {
      // Additional description for current task
      currentTask.description += (currentTask.description ? ' ' : '') + line.trim();
    }
  }

  if (currentTask) tasks.push(currentTask);

  return tasks;
}

// Get project summary for context
function getProjectSummary() {
  const queue = loadTaskQueue();
  const recentCompleted = queue.completed.slice(-10);

  let summary = 'Warp Terminal Clone - A Tauri + Vue 3 terminal emulator\n\n';

  if (recentCompleted.length > 0) {
    summary += 'Recently completed:\n';
    recentCompleted.forEach(t => {
      summary += `- ${t.title}\n`;
    });
  }

  return summary;
}

// Report completed tasks to ChatGPT and get new tasks
async function reportAndGetNewTasks(threadId, completedTasks) {
  console.log('\n📤 Reporting to ChatGPT...');
  console.log(`   Completed tasks: ${completedTasks.length}`);

  const projectContext = getProjectSummary();
  const message = CONFIG.prompts.statusReport(completedTasks, projectContext);

  try {
    // Send status report to ChatGPT
    const result = await threadManager.sendToThread(threadId, message, true);

    console.log('📥 Received response from ChatGPT');

    // Parse new tasks from response
    const newTasks = parseTasksFromResponse(result.response);

    console.log(`   Found ${newTasks.length} new tasks`);

    return {
      success: true,
      newTasks,
      response: result.response,
      threadId: result.threadId || threadId,
    };
  } catch (e) {
    console.error('❌ Error communicating with ChatGPT:', e.message);
    return { success: false, error: e.message };
  }
}

// Initialize a new session with ChatGPT
async function initializeSession(threadId = null) {
  console.log('\n🚀 Initializing autonomous session...');

  const projectInfo = getProjectSummary();
  const message = CONFIG.prompts.initialize(projectInfo);

  try {
    const result = await threadManager.sendToThread(threadId, message, true);

    const newTasks = parseTasksFromResponse(result.response);

    console.log(`✅ Session initialized with ${newTasks.length} tasks`);

    return {
      success: true,
      threadId: result.threadId,
      newTasks,
    };
  } catch (e) {
    console.error('❌ Failed to initialize:', e.message);
    return { success: false, error: e.message };
  }
}

// Add new tasks to queue
function addTasksToQueue(tasks) {
  const queue = loadTaskQueue();

  // Avoid duplicates by checking titles
  const existingTitles = new Set([
    ...queue.pending.map(t => t.title.toLowerCase()),
    ...queue.inProgress.map(t => t.title.toLowerCase()),
  ]);

  let added = 0;
  for (const task of tasks) {
    if (!existingTitles.has(task.title.toLowerCase())) {
      queue.pending.push(task);
      existingTitles.add(task.title.toLowerCase());
      added++;
      console.log(`   + Added: ${task.title}`);
    }
  }

  saveTaskQueue(queue);
  console.log(`📝 Added ${added} new tasks to queue`);

  return added;
}

// Get recently completed tasks that haven't been reported
function getUnreportedCompletedTasks(lastReportedId) {
  const queue = loadTaskQueue();

  if (!lastReportedId) {
    // Return last N completed tasks
    return queue.completed.slice(-CONFIG.maxReportItems);
  }

  // Find tasks completed after lastReportedId
  const lastIdx = queue.completed.findIndex(t => t.id === lastReportedId);
  if (lastIdx === -1) {
    return queue.completed.slice(-CONFIG.maxReportItems);
  }

  return queue.completed.slice(lastIdx + 1, lastIdx + 1 + CONFIG.maxReportItems);
}

// Check if there are pending tasks
function hasPendingTasks() {
  const queue = loadTaskQueue();
  return queue.pending.length > 0 || queue.inProgress.length > 0;
}

// Main autonomous loop
async function runAutonomousLoop(initialThreadId = null) {
  console.log('═══════════════════════════════════════════');
  console.log('  Autonomous ChatGPT <-> Claude Code Loop');
  console.log('═══════════════════════════════════════════');
  console.log('');
  console.log('NO TIMEOUTS. NO APPROVALS. Fully autonomous.');
  console.log('');
  console.log('Press Ctrl+C to stop');
  console.log('───────────────────────────────────────────\n');

  let threadId = initialThreadId;
  let lastReportedTaskId = null;
  let lastCompletedCount = 0;

  // Load existing queue state
  const queue = loadTaskQueue();
  if (queue.completed.length > 0) {
    lastReportedTaskId = queue.completed[queue.completed.length - 1].id;
    lastCompletedCount = queue.completed.length;
  }

  // Initialize session if no thread specified
  if (!threadId) {
    // Check if there's a configured thread
    if (queue.config && queue.config.threadId) {
      threadId = queue.config.threadId;
      console.log(`📎 Using configured thread: ${threadId}`);
    } else {
      const init = await initializeSession();
      if (!init.success) {
        console.error('Failed to initialize session. Exiting.');
        process.exit(1);
      }
      threadId = init.threadId;

      // Save thread ID to config
      queue.config = queue.config || {};
      queue.config.threadId = threadId;
      saveTaskQueue(queue);

      // Add initial tasks
      if (init.newTasks.length > 0) {
        addTasksToQueue(init.newTasks);
      }
    }
  }

  console.log(`\n🔗 Thread ID: ${threadId}\n`);

  // Main loop - runs forever
  while (true) {
    try {
      const currentQueue = loadTaskQueue();
      const currentCompletedCount = currentQueue.completed.length;

      // Check if new tasks have been completed
      if (currentCompletedCount > lastCompletedCount) {
        const newlyCompleted = currentQueue.completed.slice(lastCompletedCount);
        console.log(`\n✅ Detected ${newlyCompleted.length} newly completed task(s)`);

        // Report to ChatGPT and get new tasks
        const result = await reportAndGetNewTasks(threadId, newlyCompleted);

        if (result.success && result.newTasks.length > 0) {
          addTasksToQueue(result.newTasks);
        }

        lastCompletedCount = currentCompletedCount;
        if (currentQueue.completed.length > 0) {
          lastReportedTaskId = currentQueue.completed[currentQueue.completed.length - 1].id;
        }
      }

      // Check if we need more tasks
      if (!hasPendingTasks() && currentCompletedCount > 0) {
        console.log('\n📋 No pending tasks - requesting more from ChatGPT...');

        const recentCompleted = currentQueue.completed.slice(-3);
        const result = await reportAndGetNewTasks(threadId, recentCompleted);

        if (result.success && result.newTasks.length > 0) {
          addTasksToQueue(result.newTasks);
        }
      }

      // Status update
      const status = loadTaskQueue();
      console.log(`\n⏳ Status: ${status.pending.length} pending | ${status.inProgress.length} in progress | ${status.completed.length} completed`);

    } catch (e) {
      console.error('Loop error:', e.message);
    }

    // Wait before next check
    await new Promise(r => setTimeout(r, CONFIG.pollInterval));
  }
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  let threadId = null;

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--thread' || args[i] === '-t') {
      threadId = args[i + 1];
      i++;
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`Autonomous ChatGPT <-> Claude Code Loop

Usage:
  node autonomous_loop.cjs                    # Start with configured/new thread
  node autonomous_loop.cjs --thread <id>      # Use specific thread

The loop will:
1. Watch task_queue.json for completed tasks
2. Report completions to ChatGPT
3. Parse ChatGPT's response for new task ideas
4. Add new tasks to task_queue.json
5. Repeat forever

NO manual approval required. Fully autonomous.`);
      process.exit(0);
    }
  }

  await runAutonomousLoop(threadId);
}

// Cleanup
process.on('SIGINT', async () => {
  console.log('\n\n👋 Shutting down autonomous loop...');
  await threadManager.closeBrowser();
  process.exit(0);
});

main().catch(console.error);
