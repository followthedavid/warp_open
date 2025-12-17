#!/usr/bin/env node
/**
 * ChatGPT Connect - Simple thread watcher
 *
 * Connects to a specific thread and watches for your commands.
 * No auto-scanning, no spam - just watches and executes.
 *
 * Usage:
 *   node chatgpt_connect.cjs <thread_id>
 */

const { execSync } = require('child_process');
const threadManager = require('./chatgpt_thread_manager.cjs');

const CONFIG = {
  pollInterval: 8000,  // Check every 8 seconds (less aggressive)
  maxTaskTimeout: 120000,
  dangerousPatterns: [
    /rm\s+-rf\s+[\/~]/i,
    /sudo/i,
    /mkfs/i,
  ],
};

let lastMessageCount = 0;
let pendingTasks = [];
let connected = false;

function log(msg) {
  const time = new Date().toLocaleTimeString();
  console.log(`[${time}] ${msg}`);
}

function isDangerous(cmd) {
  return CONFIG.dangerousPatterns.some(p => p.test(cmd));
}

function executeCommand(cmd) {
  if (isDangerous(cmd)) {
    return { success: false, error: '⚠️ Blocked: dangerous' };
  }
  try {
    const output = execSync(cmd, {
      cwd: process.cwd(),
      timeout: CONFIG.maxTaskTimeout,
      encoding: 'utf8',
    });
    return { success: true, output: output.substring(0, 400) };
  } catch (e) {
    return { success: false, error: e.message.substring(0, 150) };
  }
}

function parseTasks(text) {
  const tasks = [];
  for (const line of text.split('\n')) {
    const match = line.match(/^(\d+)[.\)]\s+(.+)$/);
    if (match) {
      const desc = match[2];
      const cmdMatch = desc.match(/`([^`]+)`/);
      tasks.push({
        num: parseInt(match[1]),
        desc: desc.substring(0, 50),
        cmd: cmdMatch ? cmdMatch[1] : null,
      });
    }
  }
  return tasks;
}

function parseApproval(text) {
  const t = text.trim().toLowerCase();
  if (/^(y|yes|go|ok|👍)$/i.test(t)) return { type: 'all' };
  if (/^[\d\s,]+$/.test(t)) return { type: 'items', items: t.split(/[\s,]+/).map(Number) };
  if (/^(skip|no)\s*[\d\s,]+$/i.test(t)) {
    const skip = t.replace(/^(skip|no)\s*/i, '').split(/[\s,]+/).map(Number);
    return { type: 'skip', items: skip };
  }
  if (/^(stop|exit|disconnect)$/i.test(t)) return { type: 'stop' };
  return null;
}

async function watch(threadId) {
  console.log('═══════════════════════════════════════');
  console.log('  Connected to ChatGPT thread');
  console.log('═══════════════════════════════════════');
  console.log(`Thread: ${threadId}`);
  console.log('Watching for tasks...');
  console.log('Press Ctrl+C to stop');
  console.log('───────────────────────────────────────\n');

  // Send ONE connection message
  if (!connected) {
    await threadManager.sendToThread(threadId,
      '🤖 Connected.\n\nReply: y / 1 2 / skip 2 / stop', true);
    connected = true;
    log('Sent connection message');
  }

  // Get initial message count
  const initial = await threadManager.readThread(threadId, true);
  lastMessageCount = initial.messages.length;
  log(`Starting at message ${lastMessageCount}`);

  while (true) {
    try {
      const data = await threadManager.readThread(threadId, true);

      if (data.messages.length > lastMessageCount) {
        for (let i = lastMessageCount; i < data.messages.length; i++) {
          const msg = data.messages[i];

          if (msg.role === 'user') {
            const approval = parseApproval(msg.text);

            if (approval?.type === 'stop') {
              log('Stop received');
              await threadManager.sendToThread(threadId, '👋 Disconnected.');
              await threadManager.closeBrowser();
              process.exit(0);
            }

            if (approval && pendingTasks.length > 0) {
              let toRun = [];
              if (approval.type === 'all') {
                toRun = pendingTasks.map(t => t.num);
              } else if (approval.type === 'items') {
                toRun = approval.items;
              } else if (approval.type === 'skip') {
                toRun = pendingTasks.map(t => t.num).filter(n => !approval.items.includes(n));
              }

              if (toRun.length > 0) {
                log(`Running: ${toRun.join(', ')}`);
                const results = [];

                for (const num of toRun) {
                  const task = pendingTasks.find(t => t.num === num);
                  if (task?.cmd) {
                    const r = executeCommand(task.cmd);
                    const icon = r.success ? '✅' : '❌';
                    let res = `${icon} ${num}. ${task.desc}`;
                    if (r.output) res += `\n\`\`\`\n${r.output.split('\n').slice(0,3).join('\n')}\n\`\`\``;
                    if (r.error) res += `\n⚠️ ${r.error}`;
                    results.push(res);
                  }
                }

                if (results.length > 0) {
                  await threadManager.sendToThread(threadId, results.join('\n\n'), true);
                }
                pendingTasks = [];
              }
            }
          }

          if (msg.role === 'assistant') {
            const tasks = parseTasks(msg.text);
            if (tasks.length > 0) {
              log(`Found ${tasks.length} tasks`);
              pendingTasks = tasks;
            }
          }
        }

        lastMessageCount = data.messages.length;
      }
    } catch (e) {
      log(`Error: ${e.message}`);
    }

    await new Promise(r => setTimeout(r, CONFIG.pollInterval));
  }
}

// Main
const threadId = process.argv[2];
if (!threadId) {
  console.log('Usage: node chatgpt_connect.cjs <thread_id>');
  console.log('\nGet thread ID from ChatGPT URL:');
  console.log('  https://chatgpt.com/c/[THIS-IS-THE-ID]');
  process.exit(1);
}

process.on('SIGINT', async () => {
  log('Shutting down...');
  await threadManager.closeBrowser();
  process.exit();
});

watch(threadId).catch(console.error);
