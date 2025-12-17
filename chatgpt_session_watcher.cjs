#!/usr/bin/env node
/**
 * ChatGPT Session Watcher
 *
 * Watches for "coding session" (or similar trigger) in ANY ChatGPT thread.
 * When detected, connects to that thread and follows your instructions.
 *
 * Usage:
 *   node chatgpt_session_watcher.cjs
 *
 * On your iPhone:
 *   1. Open ChatGPT app
 *   2. Start new chat or use existing one
 *   3. Type "coding session"
 *   4. Terminal automatically connects and watches for instructions
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const threadManager = require('./chatgpt_thread_manager.cjs');

const CONFIG = {
  // How often to scan for new sessions (ms)
  scanInterval: 10000,  // 10 seconds

  // How often to poll active thread (ms)
  pollInterval: 5000,   // 5 seconds

  // Trigger phrases that activate a session
  triggerPhrases: [
    'coding session',
    'terminal mode',
    'dev mode',
    '@terminal',
  ],

  // State file
  stateFile: path.join(os.homedir(), '.chatgpt-session-watcher.json'),

  // Max task timeout
  maxTaskTimeout: 120000,

  // Dangerous command patterns
  dangerousPatterns: [
    /rm\s+-rf\s+[\/~]/i,
    /sudo/i,
    /chmod\s+777/i,
    /mkfs/i,
    /dd\s+if=/i,
  ],
};

// State
let state = {
  activeThreadId: null,
  activated: false,
  lastScanTime: 0,
  processedMessages: {},  // threadId -> last processed message index
};

function loadState() {
  try {
    if (fs.existsSync(CONFIG.stateFile)) {
      state = JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf8'));
    }
  } catch (e) {}
}

function saveState() {
  fs.writeFileSync(CONFIG.stateFile, JSON.stringify(state, null, 2));
}

function log(msg) {
  const time = new Date().toLocaleTimeString();
  console.log(`[${time}] ${msg}`);
}

// Check if text contains trigger phrase
function containsTrigger(text) {
  const lower = text.toLowerCase();
  return CONFIG.triggerPhrases.some(phrase => lower.includes(phrase));
}

// Check if command is dangerous
function isDangerous(cmd) {
  return CONFIG.dangerousPatterns.some(p => p.test(cmd));
}

// Execute shell command
function executeCommand(cmd) {
  if (isDangerous(cmd)) {
    return { success: false, output: '', error: '⚠️ Blocked: potentially dangerous command' };
  }

  try {
    const output = execSync(cmd, {
      cwd: process.cwd(),
      timeout: CONFIG.maxTaskTimeout,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
    return { success: true, output: output.substring(0, 500), error: null };
  } catch (e) {
    return { success: false, output: '', error: e.message.substring(0, 200) };
  }
}

// Parse numbered tasks from ChatGPT response
function parseTasks(text) {
  const tasks = [];
  const lines = text.split('\n');

  for (const line of lines) {
    const match = line.match(/^(\d+)[.\)]\s+(.+)$/);
    if (match) {
      const desc = match[2].trim();
      // Try to extract command from backticks or description
      const cmdMatch = desc.match(/`([^`]+)`/) || desc.match(/^(ls|pwd|cd|npm|node|git|cat|echo|mkdir|touch|rm|cp|mv|grep|find|curl|wget)\s*.*/i);
      tasks.push({
        number: parseInt(match[1]),
        description: desc,
        command: cmdMatch ? cmdMatch[1] : null,
      });
    }
  }

  return tasks;
}

// Process approval from user
function processApproval(text, tasks) {
  const t = text.trim().toLowerCase();

  // Approve all
  if (/^(y|yes|go|ok|do it|approved?|yep|yup|k|👍)$/i.test(t)) {
    return tasks.map(t => t.number);
  }

  // Specific items: "1 2 3" or "1,2,3"
  if (/^[\d\s,]+$/.test(t)) {
    return t.split(/[\s,]+/).map(Number).filter(n => !isNaN(n) && tasks.some(t => t.number === n));
  }

  // Skip items: "skip 2" or "no 3"
  const skipMatch = t.match(/^(skip|no)\s*([\d\s,]+)$/i);
  if (skipMatch) {
    const skip = skipMatch[2].split(/[\s,]+/).map(Number);
    return tasks.map(t => t.number).filter(n => !skip.includes(n));
  }

  return null;  // Not recognized as approval
}

// Format result for mobile
function formatResult(task, result) {
  const icon = result.success ? '✅' : '❌';
  let msg = `${icon} ${task.number}. ${task.description.substring(0, 30)}`;
  if (result.output) {
    const out = result.output.split('\n').slice(0, 3).join('\n');
    if (out.trim()) msg += `\n\`\`\`\n${out}\n\`\`\``;
  }
  if (!result.success && result.error) {
    msg += `\n⚠️ ${result.error.substring(0, 50)}`;
  }
  return msg;
}

// Scan recent threads for trigger phrase (keeps browser open)
async function scanForTrigger() {
  log('Scanning for "coding session"...');

  try {
    // listThreads keeps browser open
    const threads = await threadManager.listThreads(true);

    // Check the 5 most recent threads
    for (const thread of threads.slice(0, 5)) {
      // Skip if we've already activated this thread
      if (state.activatedThreads && state.activatedThreads.includes(thread.id)) {
        continue;
      }

      try {
        // Keep browser open between reads
        const data = await threadManager.readThread(thread.id, true);

        // Look for trigger in user messages
        for (let i = 0; i < data.messages.length; i++) {
          const msg = data.messages[i];

          // Skip if already processed
          const lastProcessed = state.processedMessages[thread.id] || -1;
          if (i <= lastProcessed) continue;

          if (msg.role === 'user' && containsTrigger(msg.text)) {
            log(`🎯 Found trigger in thread: ${thread.title}`);

            // Mark this thread as activated so we don't trigger again
            if (!state.activatedThreads) state.activatedThreads = [];
            state.activatedThreads.push(thread.id);
            saveState();

            return { threadId: thread.id, title: thread.title, messages: data.messages };
          }
        }

        state.processedMessages[thread.id] = data.messages.length - 1;
      } catch (e) {
        // Skip thread on error
      }
    }
  } catch (e) {
    log(`Scan error: ${e.message}`);
  }

  return null;
}

// Watch active thread for instructions
async function watchActiveThread(threadId) {
  log(`Watching thread: ${threadId}`);

  let lastMessageCount = 0;
  let pendingTasks = [];
  let awaitingApproval = false;

  // Send connection message
  await threadManager.sendToThread(threadId,
    '🤖 Terminal connected!\n\n' +
    'I\'ll execute your approved tasks.\n\n' +
    'Reply:\n' +
    '• y = do all\n' +
    '• 1 2 = specific items\n' +
    '• skip 2 = skip item\n' +
    '• stop = disconnect'
  );

  while (state.activated && state.activeThreadId === threadId) {
    try {
      const data = await threadManager.readThread(threadId, true);
      const messages = data.messages;

      if (messages.length > lastMessageCount) {
        for (let i = lastMessageCount; i < messages.length; i++) {
          const msg = messages[i];

          // User message
          if (msg.role === 'user') {
            const text = msg.text.trim().toLowerCase();

            // Stop command
            if (text === 'stop' || text === 'disconnect' || text === 'exit') {
              log('Received stop command');
              await threadManager.sendToThread(threadId, '👋 Terminal disconnected.');
              state.activated = false;
              state.activeThreadId = null;
              saveState();
              return;
            }

            // Check for approval
            if (awaitingApproval && pendingTasks.length > 0) {
              const approved = processApproval(msg.text, pendingTasks);

              if (approved && approved.length > 0) {
                log(`Executing tasks: ${approved.join(', ')}`);
                await threadManager.sendToThread(threadId, `🔄 Running ${approved.length} task(s)...`, true);

                const results = [];
                for (const num of approved) {
                  const task = pendingTasks.find(t => t.number === num);
                  if (task && task.command) {
                    log(`  Running: ${task.command}`);
                    const result = executeCommand(task.command);
                    results.push(formatResult(task, result));
                  } else if (task) {
                    results.push(`⚠️ ${task.number}. No command found`);
                  }
                }

                await threadManager.sendToThread(threadId, results.join('\n\n'));
                pendingTasks = [];
                awaitingApproval = false;
              } else if (approved !== null && approved.length === 0) {
                await threadManager.sendToThread(threadId, '⏸️ Skipped all tasks.');
                pendingTasks = [];
                awaitingApproval = false;
              }
            }
          }

          // Assistant message - look for tasks
          if (msg.role === 'assistant' && !awaitingApproval) {
            const tasks = parseTasks(msg.text);
            if (tasks.length > 0) {
              log(`Found ${tasks.length} tasks`);
              pendingTasks = tasks;
              awaitingApproval = true;
            }
          }
        }

        lastMessageCount = messages.length;
      }
    } catch (e) {
      log(`Watch error: ${e.message}`);
    }

    await new Promise(r => setTimeout(r, CONFIG.pollInterval));
  }
}

// Main loop
async function main() {
  console.log('═══════════════════════════════════════════');
  console.log('  ChatGPT Session Watcher');
  console.log('═══════════════════════════════════════════');
  console.log('');
  console.log('Waiting for you to say "coding session"');
  console.log('in any ChatGPT thread on your phone...');
  console.log('');
  console.log('Press Ctrl+C to stop');
  console.log('───────────────────────────────────────────\n');

  loadState();

  // Reset state on start
  state.activated = false;
  state.activeThreadId = null;
  saveState();

  while (true) {
    if (!state.activated) {
      // Scan for trigger
      const found = await scanForTrigger();

      if (found) {
        state.activated = true;
        state.activeThreadId = found.threadId;
        saveState();

        log(`✅ Activated! Thread: ${found.title}`);

        // Start watching
        await watchActiveThread(found.threadId);
      }
    }

    await new Promise(r => setTimeout(r, CONFIG.scanInterval));
  }
}

// Cleanup
process.on('SIGINT', async () => {
  log('Shutting down...');
  await threadManager.closeBrowser();
  process.exit();
});

main().catch(console.error);
