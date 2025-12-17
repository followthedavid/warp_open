#!/usr/bin/env node
/**
 * ChatGPT Thread Manager
 *
 * Manages persistent ChatGPT threads for phone-to-terminal communication.
 *
 * Usage:
 *   node chatgpt_thread_manager.cjs list                    # List recent threads
 *   node chatgpt_thread_manager.cjs read <thread_id>        # Read a thread
 *   node chatgpt_thread_manager.cjs send <thread_id> "msg"  # Send to a thread
 *   node chatgpt_thread_manager.cjs watch <thread_id>       # Watch for updates
 *   node chatgpt_thread_manager.cjs new "message"           # Start new thread
 */

const { chromium } = require('playwright-extra');
const stealth = require('puppeteer-extra-plugin-stealth')();
const path = require('path');
const fs = require('fs');
const os = require('os');

chromium.use(stealth);

const CONFIG = {
  // Use Playwright's Chromium to avoid conflicts with running Brave
  browserPath: null,  // null = use Playwright's bundled Chromium
  userDataDir: path.join(os.homedir(), '.chatgpt-stealth-profile-chromium'),
  windowPosition: { x: -3000, y: -3000 },
  baseUrl: 'https://chatgpt.com',
  stateFile: path.join(os.homedir(), '.chatgpt-thread-state.json'),

  // Polling config
  pollInterval: 5000,  // 5 seconds

  // Selectors
  selectors: {
    conversationLinks: 'nav a[href^="/c/"]',
    userMessage: '[data-message-author-role="user"]',
    assistantMessage: '[data-message-author-role="assistant"]',
    textArea: '#prompt-textarea, textarea[placeholder*="anything"], div[contenteditable="true"]',
    sendButton: 'button[data-testid="send-button"], button[aria-label*="Send"]',
  },

  // Trigger phrases that activate the terminal
  triggerPhrases: [
    'coding session',
    'terminal mode',
    'dev mode',
    'start terminal',
    'activate terminal',
    '@terminal',
  ],

  // Approval patterns (short mobile-friendly)
  approvalPatterns: {
    approveAll: /^(y|yes|go|ok|do it|approved?|confirm|yep|yup|k|👍)$/i,
    approveItems: /^(\d+[\s,]*)+$/,  // "1 2 3" or "1,2,3"
    skipItems: /^(no|skip|not?)\s*(\d+[\s,]*)+$/i,  // "skip 2" or "no 3"
    wait: /^(wait|hold|pause|stop|later)$/i,
    question: /^\?|^(what|how|why|which|explain)/i,
  },
};

// State management
function loadState() {
  try {
    if (fs.existsSync(CONFIG.stateFile)) {
      return JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf8'));
    }
  } catch (e) {}
  return { activeThread: null, lastMessageCount: 0 };
}

function saveState(state) {
  fs.writeFileSync(CONFIG.stateFile, JSON.stringify(state, null, 2));
}

// Utility
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function randomDelay(min, max) {
  return Math.floor(Math.random() * (max - min) + min);
}

async function launchBrowser() {
  if (!fs.existsSync(CONFIG.userDataDir)) {
    throw new Error('No login session found. Run: node chatgpt_web_stealth.cjs --login');
  }

  const launchOptions = {
    headless: false,
    args: [
      '--window-position=10000,10000',
      '--window-size=1280,800',
      '--disable-blink-features=AutomationControlled',
      '--no-first-run',
      '--no-default-browser-check',
      '--no-sandbox',
      '--disable-setuid-sandbox',
    ],
    viewport: { width: 1280, height: 800 },
    ignoreDefaultArgs: ['--enable-automation'],
  };

  // Use custom browser path if specified
  if (CONFIG.browserPath) {
    launchOptions.executablePath = CONFIG.browserPath;
  }

  const context = await chromium.launchPersistentContext(CONFIG.userDataDir, launchOptions);

  // Hide window after launch
  await sleep(500);
  try {
    require('child_process').execSync(
      `osascript -e 'tell application "System Events" to set visible of process "Chromium" to false'`,
      { stdio: 'ignore' }
    );
  } catch (e) {}

  return context;
}

// Shared browser context (reused across operations)
let sharedContext = null;
let sharedPage = null;

async function getSharedBrowser() {
  if (sharedContext) {
    try {
      // Check if still valid
      await sharedContext.pages();
      return { context: sharedContext, page: sharedPage };
    } catch (e) {
      sharedContext = null;
      sharedPage = null;
    }
  }

  sharedContext = await launchBrowser();
  sharedPage = sharedContext.pages()[0] || await sharedContext.newPage();
  return { context: sharedContext, page: sharedPage };
}

async function closeBrowser() {
  if (sharedContext) {
    try {
      await sharedContext.close();
    } catch (e) {}
    sharedContext = null;
    sharedPage = null;
  }
}

// Cleanup on exit
process.on('exit', closeBrowser);
process.on('SIGINT', async () => { await closeBrowser(); process.exit(); });
process.on('SIGTERM', async () => { await closeBrowser(); process.exit(); });

// List recent conversations
async function listThreads(keepOpen = false) {
  const { page } = await getSharedBrowser();

  try {
    await page.goto(CONFIG.baseUrl);
    await sleep(3000);

    const threads = await page.evaluate((selector) => {
      const links = document.querySelectorAll(selector);
      return Array.from(links).slice(0, 15).map(a => {
        const href = a.getAttribute('href');
        const id = href.replace('/c/', '');
        return {
          id,
          title: a.innerText.trim().substring(0, 60),
          url: 'https://chatgpt.com' + href,
        };
      });
    }, CONFIG.selectors.conversationLinks);

    return threads;
  } finally {
    if (!keepOpen) await closeBrowser();
  }
}

// Read messages from a thread
async function readThread(threadId, keepOpen = false) {
  const { page } = await getSharedBrowser();

  try {
    const url = `${CONFIG.baseUrl}/c/${threadId}`;
    await page.goto(url, { waitUntil: 'domcontentloaded' });

    // Wait for messages to load - try multiple times
    let messages = [];
    for (let attempt = 0; attempt < 10; attempt++) {
      await sleep(2000);

      messages = await page.evaluate(() => {
        const msgs = [];
        const allMsgs = document.querySelectorAll('[data-message-author-role]');

        allMsgs.forEach((m, idx) => {
          const role = m.getAttribute('data-message-author-role');
          msgs.push({
            index: idx,
            role,
            text: m.innerText.trim(),
          });
        });

        return msgs;
      });

      if (messages.length > 0) {
        // Give a bit more time for any remaining messages to load
        await sleep(1000);

        // Re-fetch to get any late-loading messages
        messages = await page.evaluate(() => {
          const msgs = [];
          const allMsgs = document.querySelectorAll('[data-message-author-role]');

          allMsgs.forEach((m, idx) => {
            const role = m.getAttribute('data-message-author-role');
            msgs.push({
              index: idx,
              role,
              text: m.innerText.trim(),
            });
          });

          return msgs;
        });
        break;
      }

      console.error(`[INFO] Waiting for messages... attempt ${attempt + 1}/10`);
    }

    return { threadId, url: `${CONFIG.baseUrl}/c/${threadId}`, messages };
  } finally {
    if (!keepOpen) await closeBrowser();
  }
}

// Send a message to a thread
async function sendToThread(threadId, message, keepOpen = false) {
  const { page } = await getSharedBrowser();

  try {
    const url = threadId ? `${CONFIG.baseUrl}/c/${threadId}` : CONFIG.baseUrl;
    await page.goto(url);
    await sleep(3000);

    // Find input - wait for page to settle
    await sleep(2000);

    // Try to find and focus the textarea
    const typed = await page.evaluate((msg) => {
      const textarea = document.querySelector('#prompt-textarea') ||
                       document.querySelector('textarea[placeholder*="anything"]') ||
                       document.querySelector('div[contenteditable="true"]');
      if (textarea) {
        textarea.focus();
        if (textarea.tagName === 'TEXTAREA') {
          textarea.value = msg;
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
          textarea.innerText = msg;
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
        }
        return true;
      }
      return false;
    }, message);

    if (!typed) {
      throw new Error('Could not find input field');
    }

    await sleep(300);

    // Send
    try {
      const sendBtn = await page.waitForSelector(CONFIG.selectors.sendButton, { timeout: 3000 });
      await sendBtn.click();
    } catch (e) {
      await page.keyboard.press('Enter');
    }

    // Wait for response
    await sleep(2000);
    let lastContent = '';
    let stableCount = 0;

    for (let i = 0; i < 60; i++) {  // Max 60 * 2s = 2 min
      const isStreaming = await page.evaluate(() => {
        return !!document.querySelector('.result-streaming, [class*="streaming"]');
      });

      const content = await page.evaluate(() => {
        const msgs = document.querySelectorAll('[data-message-author-role="assistant"]');
        if (msgs.length === 0) return '';
        return msgs[msgs.length - 1].innerText.trim();
      });

      if (content && content === lastContent && !isStreaming) {
        stableCount++;
        if (stableCount >= 2) break;
      } else {
        stableCount = 0;
        lastContent = content;
      }

      await sleep(2000);
    }

    // Get the new thread ID if this was a new conversation
    const newUrl = page.url();
    const newThreadId = newUrl.includes('/c/') ? newUrl.split('/c/')[1].split('?')[0] : null;

    return {
      threadId: newThreadId || threadId,
      response: lastContent,
    };
  } finally {
    if (!keepOpen) await closeBrowser();
  }
}

// Watch a thread for new messages
async function watchThread(threadId, callback) {
  console.error(`[WATCH] Monitoring thread: ${threadId}`);
  console.error(`[WATCH] Poll interval: ${CONFIG.pollInterval}ms`);
  console.error('[WATCH] Press Ctrl+C to stop\n');

  let lastMessageCount = 0;
  let lastUserMessage = '';

  while (true) {
    try {
      const thread = await readThread(threadId);
      const messageCount = thread.messages.length;

      if (messageCount > lastMessageCount) {
        const newMessages = thread.messages.slice(lastMessageCount);

        for (const msg of newMessages) {
          if (msg.role === 'user' && msg.text !== lastUserMessage) {
            lastUserMessage = msg.text;

            // Check for trigger phrases or approval patterns
            const parsed = parseUserMessage(msg.text);
            if (parsed.type !== 'unknown') {
              callback({ type: 'user_input', parsed, raw: msg.text, thread });
            }
          }
        }

        lastMessageCount = messageCount;
      }
    } catch (e) {
      console.error('[WATCH] Error:', e.message);
    }

    await sleep(CONFIG.pollInterval);
  }
}

// Parse user messages for commands/approvals
function parseUserMessage(text) {
  const trimmed = text.trim().toLowerCase();

  // Check trigger phrases
  for (const trigger of CONFIG.triggerPhrases) {
    if (trimmed.includes(trigger)) {
      return { type: 'activate', trigger };
    }
  }

  // Check approval patterns
  if (CONFIG.approvalPatterns.approveAll.test(trimmed)) {
    return { type: 'approve_all' };
  }

  const itemsMatch = trimmed.match(CONFIG.approvalPatterns.approveItems);
  if (itemsMatch) {
    const items = trimmed.split(/[\s,]+/).map(Number).filter(n => !isNaN(n));
    return { type: 'approve_items', items };
  }

  const skipMatch = trimmed.match(CONFIG.approvalPatterns.skipItems);
  if (skipMatch) {
    const items = trimmed.replace(/^(no|skip|not?)\s*/i, '').split(/[\s,]+/).map(Number).filter(n => !isNaN(n));
    return { type: 'skip_items', items };
  }

  if (CONFIG.approvalPatterns.wait.test(trimmed)) {
    return { type: 'wait' };
  }

  if (CONFIG.approvalPatterns.question.test(trimmed)) {
    return { type: 'question', text: trimmed };
  }

  return { type: 'unknown', text: trimmed };
}

// Format message for iPhone readability
function formatForMobile(text, type = 'info') {
  const icons = {
    info: 'ℹ️',
    success: '✅',
    warning: '⚠️',
    error: '❌',
    question: '❓',
    task: '📋',
    running: '🔄',
  };

  const icon = icons[type] || '';

  // Keep lines short for mobile
  const lines = text.split('\n').map(line => {
    if (line.length > 40) {
      return line.substring(0, 37) + '...';
    }
    return line;
  });

  return `${icon} ${lines.join('\n')}`;
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command) {
    console.log(`ChatGPT Thread Manager

Usage:
  list                     List recent threads
  read <thread_id>         Read messages from a thread
  send <thread_id> "msg"   Send message to a thread
  new "msg"                Start new thread
  watch <thread_id>        Watch thread for updates

Examples:
  node chatgpt_thread_manager.cjs list
  node chatgpt_thread_manager.cjs read abc123
  node chatgpt_thread_manager.cjs send abc123 "✅ Task complete"
  node chatgpt_thread_manager.cjs watch abc123`);
    process.exit(0);
  }

  try {
    switch (command) {
      case 'list': {
        console.error('[INFO] Fetching threads...');
        const threads = await listThreads();
        console.log(JSON.stringify(threads, null, 2));
        break;
      }

      case 'read': {
        const threadId = args[1];
        if (!threadId) {
          console.error('Usage: read <thread_id>');
          process.exit(1);
        }
        console.error('[INFO] Reading thread...');
        const thread = await readThread(threadId);
        console.log(JSON.stringify(thread, null, 2));
        break;
      }

      case 'send': {
        const threadId = args[1];
        const message = args[2];
        if (!threadId || !message) {
          console.error('Usage: send <thread_id> "message"');
          process.exit(1);
        }
        console.error('[INFO] Sending message...');
        const result = await sendToThread(threadId, message);
        console.log(JSON.stringify(result, null, 2));
        break;
      }

      case 'new': {
        const message = args[1];
        if (!message) {
          console.error('Usage: new "message"');
          process.exit(1);
        }
        console.error('[INFO] Starting new thread...');
        const result = await sendToThread(null, message);
        console.log(JSON.stringify(result, null, 2));
        break;
      }

      case 'watch': {
        const threadId = args[1];
        if (!threadId) {
          console.error('Usage: watch <thread_id>');
          process.exit(1);
        }

        await watchThread(threadId, (event) => {
          console.log('\n[EVENT]', JSON.stringify(event.parsed));
          console.log('[RAW]', event.raw.substring(0, 100));
        });
        break;
      }

      default:
        console.error(`Unknown command: ${command}`);
        process.exit(1);
    }
  } catch (error) {
    console.error('[ERROR]', error.message);
    process.exit(1);
  }
}

// Export for use as module
module.exports = {
  listThreads,
  readThread,
  sendToThread,
  watchThread,
  parseUserMessage,
  formatForMobile,
  closeBrowser,
  CONFIG,
};

// Run CLI if executed directly
if (require.main === module) {
  main();
}
