#!/usr/bin/env node
/**
 * ChatGPT Web Automation with Stealth Mode
 *
 * Runs an invisible (offscreen) browser with anti-detection measures
 * to automate ChatGPT web interface.
 *
 * Usage:
 *   node chatgpt_web_stealth.cjs "Your prompt here"
 *   node chatgpt_web_stealth.cjs --interactive
 */

const { chromium } = require('playwright-extra');
const stealth = require('puppeteer-extra-plugin-stealth')();
const path = require('path');
const fs = require('fs');
const os = require('os');

// Apply stealth plugin
chromium.use(stealth);

// Configuration
const CONFIG = {
  // Use Playwright's bundled Chromium to avoid conflicts with running browsers
  browserPath: null,  // null = use Playwright's Chromium

  // Offscreen position (invisible but not headless)
  windowPosition: { x: -3000, y: -3000 },
  windowSize: { width: 1280, height: 800 },

  // Persistent profile to maintain login session (shared with thread manager)
  userDataDir: path.join(os.homedir(), '.chatgpt-stealth-profile-chromium'),

  // Timeouts
  navigationTimeout: 60000,
  responseTimeout: 120000,

  // Human-like delays (milliseconds)
  delays: {
    typing: { min: 30, max: 100 },      // Per character
    beforeClick: { min: 100, max: 300 },
    afterPageLoad: { min: 1000, max: 2000 },
    beforeSend: { min: 200, max: 500 },
    pollInterval: 500,
  },

  // ChatGPT selectors (may need updates if UI changes)
  selectors: {
    textArea: '#prompt-textarea, textarea[placeholder*="anything"], div[contenteditable="true"]',
    sendButton: 'button[data-testid="send-button"], button[aria-label*="Send"], button[class*="send"]',
    messageContainer: '[data-message-author-role="assistant"], .agent-turn',
    thinkingIndicator: '[data-testid="thinking"], .result-streaming, [class*="streaming"]',
    loginCheck: '#prompt-textarea, textarea[placeholder*="anything"], div[contenteditable="true"]',
  },

  // URLs
  urls: {
    chat: 'https://chat.openai.com/',
    chatAlt: 'https://chatgpt.com/',
  }
};

// Utility functions
function randomDelay(range) {
  return Math.floor(Math.random() * (range.max - range.min) + range.min);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function humanType(page, selector, text) {
  const element = await page.waitForSelector(selector, { timeout: 10000 });
  await element.click();
  await sleep(randomDelay(CONFIG.delays.beforeClick));

  for (const char of text) {
    await page.keyboard.type(char, { delay: randomDelay(CONFIG.delays.typing) });
  }
}

async function waitForResponse(page) {
  const startTime = Date.now();
  let lastContent = '';
  let stableCount = 0;

  console.error('[DEBUG] Waiting for response...');

  while (Date.now() - startTime < CONFIG.responseTimeout) {
    // Check if still streaming
    const isStreaming = await page.evaluate(() => {
      const streamingEl = document.querySelector('.result-streaming, [class*="streaming"]');
      const thinkingEl = document.querySelector('[data-testid="thinking"]');
      return !!(streamingEl || thinkingEl);
    });

    // Get latest assistant message
    const currentContent = await page.evaluate(() => {
      const messages = document.querySelectorAll('[data-message-author-role="assistant"]');
      if (messages.length === 0) return '';
      const lastMessage = messages[messages.length - 1];
      return lastMessage.innerText || lastMessage.textContent || '';
    });

    if (currentContent && currentContent === lastContent && !isStreaming) {
      stableCount++;
      if (stableCount >= 3) {
        // Response is stable (same content for 3 checks, not streaming)
        console.error('[DEBUG] Response stabilized');
        return currentContent.trim();
      }
    } else {
      stableCount = 0;
      lastContent = currentContent;
    }

    await sleep(CONFIG.delays.pollInterval);
  }

  // Timeout - return whatever we have
  console.error('[DEBUG] Response timeout, returning partial content');
  return lastContent.trim() || '[ERROR: Response timeout]';
}

async function launchBrowser() {
  console.error('[DEBUG] Launching stealth browser...');

  // Ensure profile directory exists
  if (!fs.existsSync(CONFIG.userDataDir)) {
    fs.mkdirSync(CONFIG.userDataDir, { recursive: true });
  }

  const launchOptions = {
    headless: false,
    args: [
      `--window-position=${CONFIG.windowPosition.x},${CONFIG.windowPosition.y}`,
      `--window-size=${CONFIG.windowSize.width},${CONFIG.windowSize.height}`,
      '--disable-blink-features=AutomationControlled',
      '--disable-features=IsolateOrigins,site-per-process',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-infobars',
      '--no-sandbox',
      '--disable-setuid-sandbox',
    ],
    viewport: { width: CONFIG.windowSize.width, height: CONFIG.windowSize.height },
    ignoreDefaultArgs: ['--enable-automation', '--enable-blink-features=IdleDetection'],
  };

  if (CONFIG.browserPath) {
    launchOptions.executablePath = CONFIG.browserPath;
  }

  const context = await chromium.launchPersistentContext(CONFIG.userDataDir, launchOptions);

  return context;
}

async function checkLogin(page) {
  try {
    console.error('[DEBUG] Checking login status...');
    console.error('[DEBUG] Current URL:', page.url());

    // Wait longer for page to fully load
    await sleep(3000);

    // Take screenshot for debugging
    const screenshotPath = '/tmp/chatgpt_debug.png';
    await page.screenshot({ path: screenshotPath });
    console.error('[DEBUG] Screenshot saved to:', screenshotPath);

    // Check if we're redirected to login
    const url = page.url();
    if (url.includes('auth') || url.includes('login')) {
      console.error('[DEBUG] On login/auth page');
      return false;
    }

    // Wait for either login prompt or chat input
    try {
      await page.waitForSelector(CONFIG.selectors.loginCheck, { timeout: 10000 });
    } catch (e) {
      console.error('[DEBUG] No input selector found, checking page content...');
    }

    // Check if we're on the main chat page (logged in)
    const isLoggedIn = await page.evaluate(() => {
      const textarea = document.querySelector('textarea, div[contenteditable="true"], [contenteditable="true"]');
      const loginButton = document.querySelector('button[data-testid="login-button"], a[href*="auth"]');
      const bodyText = document.body.innerText || '';
      const hasLoginPrompt = bodyText.includes('Log in') && bodyText.includes('Sign up') && !bodyText.includes('Send a message');
      return !!textarea || (!loginButton && !hasLoginPrompt);
    });

    console.error('[DEBUG] Login check result:', isLoggedIn);
    return isLoggedIn;
  } catch (e) {
    console.error('[DEBUG] Login check error:', e.message);
    return false;
  }
}

async function sendMessage(page, prompt) {
  console.error('[DEBUG] Finding input field...');

  // Try multiple selectors for the input field
  let inputSelector = null;
  for (const sel of CONFIG.selectors.textArea.split(', ')) {
    try {
      await page.waitForSelector(sel, { timeout: 5000 });
      inputSelector = sel;
      break;
    } catch (e) {
      continue;
    }
  }

  if (!inputSelector) {
    throw new Error('Could not find chat input field');
  }

  console.error('[DEBUG] Typing message...');
  await humanType(page, inputSelector, prompt);

  await sleep(randomDelay(CONFIG.delays.beforeSend));

  // Find and click send button
  console.error('[DEBUG] Looking for send button...');

  // Wait for button to be enabled (it's disabled while empty)
  await sleep(500);

  // Try clicking send button, or press Enter
  try {
    const sendButton = await page.waitForSelector(CONFIG.selectors.sendButton, { timeout: 3000 });
    await sleep(randomDelay(CONFIG.delays.beforeClick));
    await sendButton.click();
    console.error('[DEBUG] Clicked send button');
  } catch (e) {
    // Fallback to Enter key
    console.error('[DEBUG] Send button not found, pressing Enter...');
    await page.keyboard.press('Enter');
  }

  // Wait for response
  await sleep(1000); // Brief wait for request to start
  return await waitForResponse(page);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: node chatgpt_web_stealth.cjs "Your prompt here"');
    console.error('       node chatgpt_web_stealth.cjs --interactive');
    console.error('       node chatgpt_web_stealth.cjs --login (to set up login)');
    process.exit(1);
  }

  const isLoginMode = args[0] === '--login';
  const isInteractive = args[0] === '--interactive';
  const prompt = isLoginMode || isInteractive ? null : args.join(' ');

  let context;
  let page;

  try {
    // For login mode, launch visible browser
    if (isLoginMode) {
      console.error('[LOGIN MODE] Launching visible browser for login...');
      console.error('[LOGIN MODE] Please log in to ChatGPT in the browser window.');
      console.error('[LOGIN MODE] Press Ctrl+C when done.');

      const loginOptions = {
        headless: false,
        args: [
          '--disable-blink-features=AutomationControlled',
          '--no-first-run',
          '--no-default-browser-check',
          '--no-sandbox',
          '--disable-setuid-sandbox',
        ],
        viewport: { width: 1280, height: 800 },
        ignoreDefaultArgs: ['--enable-automation'],
      };

      if (CONFIG.browserPath) {
        loginOptions.executablePath = CONFIG.browserPath;
      }

      const visibleContext = await chromium.launchPersistentContext(CONFIG.userDataDir, loginOptions);

      const visiblePage = visibleContext.pages()[0] || await visibleContext.newPage();
      await visiblePage.goto(CONFIG.urls.chatAlt);

      // Keep browser open until user closes it
      await new Promise(() => {}); // Wait forever
    }

    context = await launchBrowser();
    page = context.pages()[0] || await context.newPage();

    console.error('[DEBUG] Navigating to ChatGPT...');
    await page.goto(CONFIG.urls.chatAlt, { waitUntil: 'domcontentloaded' });
    await sleep(randomDelay(CONFIG.delays.afterPageLoad));

    // Check login status
    const loggedIn = await checkLogin(page);
    if (!loggedIn) {
      console.error('[ERROR] Not logged in to ChatGPT.');
      console.error('[ERROR] Run with --login flag first to set up login:');
      console.error('[ERROR]   node chatgpt_web_stealth.cjs --login');
      await context.close();
      process.exit(1);
    }

    console.error('[DEBUG] Logged in successfully');

    if (isInteractive) {
      // Interactive mode - read prompts from stdin
      const readline = require('readline');
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stderr,
      });

      console.error('[INTERACTIVE] Enter prompts (Ctrl+D to exit):');

      rl.on('line', async (line) => {
        if (line.trim()) {
          try {
            const response = await sendMessage(page, line.trim());
            console.log(response);
          } catch (e) {
            console.error('[ERROR]', e.message);
          }
        }
      });

      rl.on('close', async () => {
        await context.close();
        process.exit(0);
      });
    } else {
      // Single prompt mode
      const response = await sendMessage(page, prompt);
      console.log(response);
      await context.close();
    }

  } catch (error) {
    console.error('[ERROR]', error.message);
    if (context) await context.close();
    process.exit(1);
  }
}

main();
