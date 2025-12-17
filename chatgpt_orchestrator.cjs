#!/usr/bin/env node
/**
 * ChatGPT Terminal Orchestrator
 *
 * Watches a ChatGPT thread for your commands (from phone) and executes
 * approved tasks, posting results back to the thread.
 *
 * Usage:
 *   node chatgpt_orchestrator.cjs <thread_id>
 *   node chatgpt_orchestrator.cjs --interactive
 *
 * In the ChatGPT thread:
 *   - Say "terminal mode" or "@terminal" to activate
 *   - ChatGPT proposes tasks with numbered list
 *   - You reply: "y" (all), "1 2" (specific), "skip 3", "wait"
 *   - Terminal executes and posts results back
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const threadManager = require('./chatgpt_thread_manager.cjs');

const CONFIG = {
  pollInterval: 5000,  // Check every 5 seconds
  maxTaskTimeout: 120000,  // 2 min max per task
  workingDir: process.cwd(),
  stateFile: path.join(os.homedir(), '.chatgpt-orchestrator-state.json'),

  // Patterns to identify task proposals from ChatGPT
  taskPatterns: {
    // Numbered list: "1. Do something" or "1) Do something"
    numberedList: /^(\d+)[.\)]\s+(.+)$/gm,
    // Bullet points with action verbs
    bulletAction: /^[-•]\s*(Create|Update|Add|Remove|Fix|Refactor|Install|Run|Build|Test|Deploy|Configure|Set up|Implement|Write|Edit|Delete|Move|Copy|Rename)\s+(.+)$/gim,
    // Code blocks
    codeBlock: /```(\w*)\n([\s\S]*?)```/g,
  },

  // Keywords that indicate executable commands
  executableIndicators: [
    'run', 'execute', 'install', 'build', 'test', 'create', 'update',
    'add', 'remove', 'delete', 'fix', 'deploy', 'configure', 'set up',
  ],

  // Safety: commands that require extra confirmation
  dangerousPatterns: [
    /rm\s+-rf/i,
    /sudo/i,
    /chmod\s+777/i,
    />\s*\/dev\//i,
    /mkfs/i,
    /dd\s+if=/i,
    /:(){ :|:& };:/,  // fork bomb
  ],
};

// State management
function loadState() {
  try {
    if (fs.existsSync(CONFIG.stateFile)) {
      return JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf8'));
    }
  } catch (e) {}
  return {
    activeThread: null,
    activated: false,
    lastProcessedIndex: -1,
    pendingTasks: [],
    executedTasks: [],
  };
}

function saveState(state) {
  fs.writeFileSync(CONFIG.stateFile, JSON.stringify(state, null, 2));
}

// Parse ChatGPT's response to extract proposed tasks
function parseProposedTasks(text) {
  const tasks = [];

  // Find numbered lists
  const lines = text.split('\n');
  let currentTask = null;

  for (const line of lines) {
    const numberedMatch = line.match(/^(\d+)[.\)]\s+(.+)$/);
    if (numberedMatch) {
      if (currentTask) tasks.push(currentTask);
      currentTask = {
        number: parseInt(numberedMatch[1]),
        description: numberedMatch[2].trim(),
        type: 'unknown',
        code: null,
      };

      // Detect task type
      const desc = currentTask.description.toLowerCase();
      if (desc.includes('run') || desc.includes('execute') || desc.startsWith('npm') || desc.startsWith('node')) {
        currentTask.type = 'shell';
      } else if (desc.includes('create') || desc.includes('write') || desc.includes('add')) {
        currentTask.type = 'create';
      } else if (desc.includes('update') || desc.includes('edit') || desc.includes('modify') || desc.includes('fix')) {
        currentTask.type = 'edit';
      } else if (desc.includes('delete') || desc.includes('remove')) {
        currentTask.type = 'delete';
      }
    }
  }

  if (currentTask) tasks.push(currentTask);

  // Extract code blocks and associate with tasks
  const codeBlocks = [];
  let match;
  const codeBlockRegex = /```(\w*)\n([\s\S]*?)```/g;
  while ((match = codeBlockRegex.exec(text)) !== null) {
    codeBlocks.push({
      language: match[1] || 'text',
      code: match[2].trim(),
    });
  }

  // Associate code blocks with tasks (simple: first code block after task description)
  // This is a heuristic - could be improved
  if (codeBlocks.length > 0 && tasks.length > 0) {
    // For now, attach first code block to first shell/create task
    for (const task of tasks) {
      if ((task.type === 'shell' || task.type === 'create') && !task.code && codeBlocks.length > 0) {
        task.code = codeBlocks.shift();
      }
    }
  }

  return tasks;
}

// Check if a command is potentially dangerous
function isDangerous(command) {
  for (const pattern of CONFIG.dangerousPatterns) {
    if (pattern.test(command)) {
      return true;
    }
  }
  return false;
}

// Execute a shell command safely
function executeShellCommand(command, timeout = CONFIG.maxTaskTimeout) {
  return new Promise((resolve) => {
    try {
      // Check for dangerous commands
      if (isDangerous(command)) {
        resolve({
          success: false,
          output: '',
          error: '⚠️ Blocked: Command flagged as potentially dangerous',
        });
        return;
      }

      const result = execSync(command, {
        cwd: CONFIG.workingDir,
        timeout,
        encoding: 'utf8',
        maxBuffer: 1024 * 1024,  // 1MB
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      resolve({
        success: true,
        output: result.substring(0, 500),  // Truncate for mobile readability
        error: null,
      });
    } catch (e) {
      resolve({
        success: false,
        output: e.stdout ? e.stdout.substring(0, 300) : '',
        error: e.message.substring(0, 200),
      });
    }
  });
}

// Format task result for mobile display
function formatResultForMobile(task, result) {
  const icon = result.success ? '✅' : '❌';
  let msg = `${icon} Task ${task.number}: ${task.description.substring(0, 30)}`;

  if (result.success && result.output) {
    // Truncate and format output
    const output = result.output.split('\n').slice(0, 3).join('\n');
    if (output.trim()) {
      msg += `\n\`\`\`\n${output}\n\`\`\``;
    }
  } else if (!result.success) {
    msg += `\n⚠️ ${result.error}`;
  }

  return msg;
}

// Process user approval and determine which tasks to run
function processApproval(approval, tasks) {
  const { type, items } = approval;

  switch (type) {
    case 'approve_all':
      return tasks.map(t => t.number);

    case 'approve_items':
      return items.filter(n => tasks.some(t => t.number === n));

    case 'skip_items':
      return tasks.map(t => t.number).filter(n => !items.includes(n));

    case 'wait':
      return [];

    default:
      return [];
  }
}

// Main orchestrator loop
async function runOrchestrator(threadId) {
  console.log('═══════════════════════════════════════════');
  console.log('  ChatGPT Terminal Orchestrator');
  console.log('═══════════════════════════════════════════');
  console.log(`Thread: ${threadId}`);
  console.log(`Poll interval: ${CONFIG.pollInterval / 1000}s`);
  console.log('');
  console.log('Waiting for activation...');
  console.log('(Say "coding session" or "terminal mode" in ChatGPT)');
  console.log('');
  console.log('Press Ctrl+C to stop');
  console.log('───────────────────────────────────────────\n');

  let state = loadState();
  state.activeThread = threadId;
  state.lastProcessedIndex = -1;
  state.activated = false;
  state.pendingTasks = [];
  saveState(state);

  let lastMessageCount = 0;
  let pendingTasks = [];
  let awaitingApproval = false;

  while (true) {
    try {
      // Read thread
      const thread = await threadManager.readThread(threadId);
      const messages = thread.messages;

      if (messages.length > lastMessageCount) {
        // Process new messages
        for (let i = lastMessageCount; i < messages.length; i++) {
          const msg = messages[i];
          console.log(`[${msg.role.toUpperCase()}] ${msg.text.substring(0, 60)}...`);

          if (msg.role === 'user') {
            // Check for activation
            const parsed = threadManager.parseUserMessage(msg.text);

            if (parsed.type === 'activate') {
              state.activated = true;
              saveState(state);
              console.log('\n🟢 ACTIVATED - Terminal mode enabled\n');

              // Send confirmation to thread
              await threadManager.sendToThread(threadId,
                '🤖 Terminal connected!\n\n' +
                'I\'ll watch for your commands.\n' +
                'Reply with:\n' +
                '• y = approve all\n' +
                '• 1 2 3 = specific items\n' +
                '• skip 2 = skip item\n' +
                '• wait = hold off\n' +
                '• ? = ask question'
              );
            }

            // Check for approval (only if activated and awaiting)
            if (state.activated && awaitingApproval && pendingTasks.length > 0) {
              if (parsed.type === 'approve_all' || parsed.type === 'approve_items' || parsed.type === 'skip_items') {
                const toExecute = processApproval(parsed, pendingTasks);

                if (toExecute.length > 0) {
                  console.log(`\n⚡ Executing tasks: ${toExecute.join(', ')}\n`);

                  // Post starting message
                  await threadManager.sendToThread(threadId,
                    `🔄 Starting ${toExecute.length} task(s)...`
                  );

                  // Execute each task
                  const results = [];
                  for (const taskNum of toExecute) {
                    const task = pendingTasks.find(t => t.number === taskNum);
                    if (!task) continue;

                    console.log(`  Running task ${taskNum}: ${task.description.substring(0, 40)}...`);

                    let result;
                    if (task.type === 'shell' && task.code) {
                      result = await executeShellCommand(task.code.code);
                    } else if (task.type === 'shell') {
                      // Try to extract command from description
                      const cmdMatch = task.description.match(/`([^`]+)`/);
                      if (cmdMatch) {
                        result = await executeShellCommand(cmdMatch[1]);
                      } else {
                        result = { success: false, error: 'No command found' };
                      }
                    } else {
                      result = { success: false, error: 'Task type not yet supported' };
                    }

                    results.push({ task, result });
                    console.log(`  ${result.success ? '✅' : '❌'} Task ${taskNum} ${result.success ? 'complete' : 'failed'}`);
                  }

                  // Post results
                  const resultMsg = results.map(r => formatResultForMobile(r.task, r.result)).join('\n\n');
                  await threadManager.sendToThread(threadId, resultMsg);

                  pendingTasks = [];
                  awaitingApproval = false;
                }
              } else if (parsed.type === 'wait') {
                console.log('\n⏸️  Holding - waiting for further instructions\n');
              } else if (parsed.type === 'question') {
                // Forward question to ChatGPT by just letting it respond naturally
                console.log('\n❓ Question received - ChatGPT will respond\n');
              }
            }
          }

          if (msg.role === 'assistant' && state.activated) {
            // Look for task proposals in ChatGPT's response
            const tasks = parseProposedTasks(msg.text);

            if (tasks.length > 0) {
              console.log(`\n📋 Found ${tasks.length} proposed tasks:`);
              tasks.forEach(t => console.log(`   ${t.number}. [${t.type}] ${t.description.substring(0, 50)}`));
              console.log('\n   Waiting for your approval...\n');

              pendingTasks = tasks;
              awaitingApproval = true;
            }
          }
        }

        lastMessageCount = messages.length;
      }
    } catch (e) {
      console.error('[ERROR]', e.message);
    }

    await new Promise(resolve => setTimeout(resolve, CONFIG.pollInterval));
  }
}

// Interactive mode - select a thread
async function interactiveMode() {
  console.log('Fetching your ChatGPT threads...\n');

  const threads = await threadManager.listThreads();

  console.log('Recent threads:');
  threads.forEach((t, i) => {
    console.log(`  ${i + 1}. ${t.title}`);
  });

  console.log('\nEnter thread number (or paste thread ID):');

  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.question('> ', async (answer) => {
    rl.close();

    let threadId;
    const num = parseInt(answer);

    if (!isNaN(num) && num >= 1 && num <= threads.length) {
      threadId = threads[num - 1].id;
    } else if (answer.length > 10) {
      threadId = answer.trim();
    } else {
      console.error('Invalid selection');
      process.exit(1);
    }

    await runOrchestrator(threadId);
  });
}

// CLI
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--interactive' || args[0] === '-i') {
    await interactiveMode();
  } else if (args[0] === '--help' || args[0] === '-h') {
    console.log(`ChatGPT Terminal Orchestrator

Usage:
  node chatgpt_orchestrator.cjs <thread_id>
  node chatgpt_orchestrator.cjs --interactive

In the ChatGPT thread:
  1. Say "terminal mode" to activate
  2. ChatGPT proposes numbered tasks
  3. Reply with approval:
     • y, go, ok     → approve all
     • 1 2 3         → approve specific
     • skip 2        → skip item 2
     • wait          → hold off
     • ?             → ask question

Examples:
  node chatgpt_orchestrator.cjs abc123-def456
  node chatgpt_orchestrator.cjs -i`);
  } else {
    await runOrchestrator(args[0]);
  }
}

main().catch(console.error);
