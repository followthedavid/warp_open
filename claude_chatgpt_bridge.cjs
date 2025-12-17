#!/usr/bin/env node
/**
 * Claude-ChatGPT Bridge
 *
 * Enables Claude (running in terminal) to have conversations with ChatGPT
 * for implementation guidance, while you approve from your phone.
 *
 * Flow:
 * 1. Claude sends a question/context to ChatGPT thread
 * 2. ChatGPT responds with suggestions
 * 3. You approve on phone ("y", "do it", etc.)
 * 4. Claude executes the approved actions
 *
 * Usage:
 *   node claude_chatgpt_bridge.cjs <thread_id>
 *   node claude_chatgpt_bridge.cjs --ask <thread_id> "question"
 *   node claude_chatgpt_bridge.cjs --read <thread_id>
 *   node claude_chatgpt_bridge.cjs --context <thread_id>
 */

const fs = require('fs');
const path = require('path');
const threadManager = require('./chatgpt_thread_manager.cjs');

const CONFIG = {
  stateFile: path.join(process.env.HOME, '.claude-chatgpt-state.json'),
  projectStateFile: '/Users/davidquinton/ReverseLab/Warp_Open/CLAUDE_PROJECT_STATE.json',
};

// Load project state
function getProjectState() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG.projectStateFile, 'utf8'));
  } catch (e) {
    return null;
  }
}

// Get conversation context from a thread
async function getThreadContext(threadId) {
  const data = await threadManager.readThread(threadId);

  // Build context summary
  const messages = data.messages;
  const userMessages = messages.filter(m => m.role === 'user').slice(-10);
  const assistantMessages = messages.filter(m => m.role === 'assistant').slice(-10);

  return {
    threadId,
    url: data.url,
    messageCount: messages.length,
    recentUserMessages: userMessages.map(m => m.text.substring(0, 200)),
    recentAssistantMessages: assistantMessages.map(m => m.text.substring(0, 500)),
    lastMessage: messages[messages.length - 1] || null,
  };
}

// Ask ChatGPT a question (Claude asking for help)
async function askChatGPT(threadId, question) {
  const projectState = getProjectState();

  // Prefix with context so ChatGPT knows this is from Claude
  const prefixedQuestion = `[From Claude Terminal]

${question}

---
Project: Warp_Open (${projectState?.completion_status?.overall || 'unknown'}% complete)
Working on: ${projectState?.in_progress?.join(', ') || 'unknown'}`;

  const result = await threadManager.sendToThread(threadId, prefixedQuestion);
  return result;
}

// Get latest response from ChatGPT
async function getLatestResponse(threadId) {
  const data = await threadManager.readThread(threadId);
  const assistantMessages = data.messages.filter(m => m.role === 'assistant');

  if (assistantMessages.length === 0) {
    return null;
  }

  return assistantMessages[assistantMessages.length - 1].text;
}

// Check if user has approved (short mobile responses)
function isApproval(text) {
  const t = text.trim().toLowerCase();
  const approvalPatterns = [
    /^(y|yes|yeah|yep|yup|ok|okay|sure|go|do it|sounds good|approved?|confirm|👍|k)$/i,
    /^(go ahead|proceed|run it|execute|try it|do that|make it so)$/i,
  ];
  return approvalPatterns.some(p => p.test(t));
}

// Check if user wants to stop/wait
function isHold(text) {
  const t = text.trim().toLowerCase();
  return /^(wait|hold|stop|pause|no|nope|cancel|skip)$/i.test(t);
}

// Format conversation for Claude to read
function formatForClaude(messages) {
  return messages.map(m => {
    const role = m.role === 'user' ? 'USER' : 'CHATGPT';
    const text = m.text.substring(0, 1000);
    return `[${role}]: ${text}`;
  }).join('\n\n---\n\n');
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help') {
    console.log(`Claude-ChatGPT Bridge

Commands:
  --read <thread_id>              Read recent conversation
  --ask <thread_id> "question"    Ask ChatGPT a question (as Claude)
  --context <thread_id>           Get thread context summary
  --latest <thread_id>            Get ChatGPT's latest response
  --check-approval <thread_id>    Check if user approved

Examples:
  node claude_chatgpt_bridge.cjs --read 693f18ee-0290-8329-956d-2f873f9308b4
  node claude_chatgpt_bridge.cjs --ask abc123 "What's the best approach for implementing split panes?"
`);
    process.exit(0);
  }

  try {
    switch (command) {
      case '--read': {
        const threadId = args[1];
        if (!threadId) throw new Error('Thread ID required');

        const data = await threadManager.readThread(threadId);
        const recent = data.messages.slice(-10);
        console.log(formatForClaude(recent));
        break;
      }

      case '--ask': {
        const threadId = args[1];
        const question = args.slice(2).join(' ');
        if (!threadId || !question) throw new Error('Thread ID and question required');

        console.log('Sending to ChatGPT...');
        const result = await askChatGPT(threadId, question);
        console.log('\nChatGPT response:');
        console.log(result.response);
        break;
      }

      case '--context': {
        const threadId = args[1];
        if (!threadId) throw new Error('Thread ID required');

        const context = await getThreadContext(threadId);
        console.log(JSON.stringify(context, null, 2));
        break;
      }

      case '--latest': {
        const threadId = args[1];
        if (!threadId) throw new Error('Thread ID required');

        const response = await getLatestResponse(threadId);
        if (response) {
          console.log(response);
        } else {
          console.log('No assistant response found');
        }
        break;
      }

      case '--check-approval': {
        const threadId = args[1];
        if (!threadId) throw new Error('Thread ID required');

        const data = await threadManager.readThread(threadId);
        const userMessages = data.messages.filter(m => m.role === 'user');
        const lastUser = userMessages[userMessages.length - 1];

        if (lastUser) {
          const text = lastUser.text;
          if (isApproval(text)) {
            console.log('APPROVED');
            console.log(text);
          } else if (isHold(text)) {
            console.log('HOLD');
            console.log(text);
          } else {
            console.log('PENDING');
            console.log(text.substring(0, 100));
          }
        } else {
          console.log('NO_USER_MESSAGE');
        }
        break;
      }

      default:
        console.error(`Unknown command: ${command}`);
        process.exit(1);
    }
  } catch (e) {
    console.error('Error:', e.message);
    process.exit(1);
  } finally {
    await threadManager.closeBrowser();
  }
}

module.exports = {
  askChatGPT,
  getLatestResponse,
  getThreadContext,
  isApproval,
  isHold,
  formatForClaude,
};

if (require.main === module) {
  main();
}
