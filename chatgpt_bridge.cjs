#!/usr/bin/env node
/**
 * ChatGPT Bridge - Context-aware terminal connector
 *
 * Connects to a ChatGPT thread and intelligently interprets the conversation
 * to execute approved tasks.
 *
 * Modes:
 *   --simple   : Pattern matching only (default)
 *   --claude   : Use Claude to interpret conversation context
 *
 * Usage:
 *   node chatgpt_bridge.cjs <thread_id>
 *   node chatgpt_bridge.cjs <thread_id> --claude
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk');
const threadManager = require('./chatgpt_thread_manager.cjs');

const CONFIG = {
  pollInterval: 6000,
  maxTaskTimeout: 120000,
  dangerousPatterns: [
    /rm\s+-rf\s+[\/~]/i,
    /sudo\s+rm/i,
    /mkfs/i,
    /dd\s+if=.*of=\/dev/i,
  ],
};

// State
let conversationHistory = [];
let lastMessageCount = 0;
let pendingAction = null;
let useClaudeMode = false;
let anthropic = null;

function log(msg) {
  const time = new Date().toLocaleTimeString();
  console.log(`[${time}] ${msg}`);
}

function isDangerous(cmd) {
  return CONFIG.dangerousPatterns.some(p => p.test(cmd));
}

function executeCommand(cmd) {
  if (isDangerous(cmd)) {
    return { success: false, output: '', error: '⚠️ Blocked: potentially dangerous' };
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
    return {
      success: false,
      output: e.stdout?.substring(0, 200) || '',
      error: e.message.substring(0, 200)
    };
  }
}

// Simple mode: pattern-based interpretation
function interpretSimple(messages) {
  if (messages.length < 2) return null;

  const lastUser = messages.filter(m => m.role === 'user').pop();
  const lastAssistant = messages.filter(m => m.role === 'assistant').pop();

  if (!lastUser || !lastAssistant) return null;

  const userText = lastUser.text.toLowerCase().trim();

  // Check for approval patterns
  const approvalPatterns = [
    /^(y|yes|yeah|yep|yup|ok|okay|sure|go|do it|sounds good|let'?s do it|approved?|confirm|👍|k)$/i,
    /^(go ahead|proceed|run it|execute|try it|do that|make it so)$/i,
  ];

  const isApproval = approvalPatterns.some(p => p.test(userText));

  if (isApproval) {
    // Look for commands in the assistant's last message
    const codeBlocks = lastAssistant.text.match(/```(?:bash|sh|shell)?\n([\s\S]*?)```/g);
    if (codeBlocks) {
      const commands = codeBlocks.map(block => {
        return block.replace(/```(?:bash|sh|shell)?\n?/g, '').replace(/```/g, '').trim();
      }).filter(cmd => cmd.length > 0);

      if (commands.length > 0) {
        return { type: 'execute', commands };
      }
    }

    // Look for inline commands
    const inlineCmd = lastAssistant.text.match(/`([^`]+)`/g);
    if (inlineCmd) {
      const cmds = inlineCmd.map(c => c.replace(/`/g, '')).filter(c =>
        c.startsWith('npm') || c.startsWith('node') || c.startsWith('git') ||
        c.startsWith('ls') || c.startsWith('cat') || c.startsWith('mkdir') ||
        c.startsWith('cd') || c.startsWith('echo') || c.startsWith('pwd')
      );
      if (cmds.length > 0) {
        return { type: 'execute', commands: cmds };
      }
    }
  }

  // Check for stop
  if (/^(stop|exit|disconnect|bye|done)$/i.test(userText)) {
    return { type: 'stop' };
  }

  return null;
}

// Claude mode: LLM-based interpretation
async function interpretClaude(messages) {
  if (!anthropic) {
    anthropic = new Anthropic();
  }

  // Build conversation context
  const context = messages.map(m => `[${m.role.toUpperCase()}]: ${m.text}`).join('\n\n');

  const prompt = `You are analyzing a conversation between a user and ChatGPT about coding tasks.
Your job is to determine if the user has approved any actions that should be executed in the terminal.

Conversation:
${context}

Based on this conversation, respond with a JSON object:
- If the user approved running commands: {"action": "execute", "commands": ["cmd1", "cmd2"]}
- If the user wants to stop/disconnect: {"action": "stop"}
- If no action is needed yet (still discussing, no approval): {"action": "none"}

Only include shell commands that are explicitly mentioned or clearly implied.
Be conservative - only return commands if you're confident the user approved them.

Respond with ONLY the JSON object, no other text.`;

  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 500,
      messages: [{ role: 'user', content: prompt }],
    });

    const text = response.content[0].text.trim();
    const result = JSON.parse(text);

    if (result.action === 'execute' && result.commands?.length > 0) {
      return { type: 'execute', commands: result.commands };
    }
    if (result.action === 'stop') {
      return { type: 'stop' };
    }
  } catch (e) {
    log(`Claude interpretation error: ${e.message}`);
  }

  return null;
}

// Format results for mobile
function formatResults(results) {
  return results.map(r => {
    const icon = r.success ? '✅' : '❌';
    let msg = `${icon} \`${r.command.substring(0, 30)}\``;
    if (r.output) {
      const out = r.output.split('\n').slice(0, 4).join('\n');
      msg += `\n\`\`\`\n${out}\n\`\`\``;
    }
    if (r.error && !r.success) {
      msg += `\n⚠️ ${r.error.substring(0, 80)}`;
    }
    return msg;
  }).join('\n\n');
}

async function watch(threadId) {
  const mode = useClaudeMode ? 'Claude' : 'Simple';

  console.log('═══════════════════════════════════════');
  console.log('  ChatGPT Bridge');
  console.log('═══════════════════════════════════════');
  console.log(`Thread: ${threadId}`);
  console.log(`Mode: ${mode}`);
  console.log('───────────────────────────────────────');
  console.log('Connecting...\n');

  // Read initial state
  const initial = await threadManager.readThread(threadId, true);
  conversationHistory = initial.messages;
  lastMessageCount = initial.messages.length;

  // Send brief connection notice
  await threadManager.sendToThread(threadId, `🤖 Terminal ready. (${mode} mode)`, true);
  log(`Connected. ${lastMessageCount} existing messages.`);

  // Main loop
  while (true) {
    try {
      const data = await threadManager.readThread(threadId, true);

      if (data.messages.length > lastMessageCount) {
        // New messages
        const newMessages = data.messages.slice(lastMessageCount);
        conversationHistory = data.messages;
        lastMessageCount = data.messages.length;

        for (const msg of newMessages) {
          const preview = msg.text.substring(0, 50).replace(/\n/g, ' ');
          log(`[${msg.role}] ${preview}...`);
        }

        // Interpret the conversation
        let action;
        if (useClaudeMode) {
          action = await interpretClaude(conversationHistory);
        } else {
          action = interpretSimple(conversationHistory);
        }

        if (action) {
          if (action.type === 'stop') {
            log('Stop requested');
            await threadManager.sendToThread(threadId, '👋 Disconnected.');
            await threadManager.closeBrowser();
            process.exit(0);
          }

          if (action.type === 'execute' && action.commands.length > 0) {
            log(`Executing ${action.commands.length} command(s)`);

            const results = [];
            for (const cmd of action.commands) {
              log(`  > ${cmd}`);
              const result = executeCommand(cmd);
              results.push({ command: cmd, ...result });
            }

            const report = formatResults(results);
            await threadManager.sendToThread(threadId, report, true);
          }
        }
      }
    } catch (e) {
      log(`Error: ${e.message}`);
    }

    await new Promise(r => setTimeout(r, CONFIG.pollInterval));
  }
}

// CLI
const args = process.argv.slice(2);
const threadId = args.find(a => !a.startsWith('--'));
useClaudeMode = args.includes('--claude');

if (!threadId) {
  console.log(`ChatGPT Bridge - Context-aware terminal connector

Usage:
  node chatgpt_bridge.cjs <thread_id> [--claude]

Options:
  --claude    Use Claude to interpret conversation (smarter)
  (default)   Simple pattern matching

Examples:
  node chatgpt_bridge.cjs abc123-def456
  node chatgpt_bridge.cjs abc123-def456 --claude

Get thread ID from ChatGPT URL: https://chatgpt.com/c/[THREAD-ID]`);
  process.exit(1);
}

process.on('SIGINT', async () => {
  log('Shutting down...');
  await threadManager.closeBrowser();
  process.exit();
});

watch(threadId).catch(console.error);
