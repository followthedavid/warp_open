#!/usr/bin/env node
/**
 * desktop_automation.js
 *
 * Automation helper for local desktop LLM apps (ChatGPT, Claude)
 * Uses AppleScript + clipboard for last-resort automation
 *
 * Features:
 * - Multi-retry with exponential backoff
 * - Screenshot capture on failure
 * - Clipboard-based I/O (survives newlines)
 * - Configurable delays per app
 *
 * Usage:
 *   node desktop_automation.js --app ChatGPT --prompt "Hello world"
 *
 * Programmatic:
 *   const { askDesktopApp } = require('./desktop_automation');
 *   askDesktopApp('ChatGPT', 'Hello').then(console.log);
 */

const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// App-specific configuration
const APP_CONFIG = {
  ChatGPT: {
    activationDelay: 800,
    afterPasteDelay: 10000,  // Test with 10 seconds - see if response length changes
    copyDelay: 800,
    bundleId: 'com.openai.chat'
  },
  Claude: {
    activationDelay: 800,
    afterPasteDelay: 2200,
    copyDelay: 400,
    bundleId: 'com.anthropic.claude'
  }
};

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function screenshot(prefix = 'desktop_automation') {
  try {
    const filename = `${prefix}-${timestamp()}.png`;
    const filepath = path.join(process.cwd(), 'test-results', filename);

    // Ensure directory exists
    const dir = path.dirname(filepath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    execSync(`screencapture -x "${filepath}"`);
    return filepath;
  } catch (e) {
    console.error('Screenshot failed:', e.message);
    return null;
  }
}

function setClipboard(text) {
  const tmpFile = path.join(os.tmpdir(), `prompt-${Date.now()}.txt`);
  try {
    fs.writeFileSync(tmpFile, text, 'utf8');
    execSync(`pbcopy < "${tmpFile}"`);
    fs.unlinkSync(tmpFile);
    return true;
  } catch (e) {
    console.error('Clipboard set failed:', e.message);
    return false;
  }
}

function getClipboard() {
  try {
    return execSync('pbpaste', { encoding: 'utf8' });
  } catch (e) {
    console.error('Clipboard get failed:', e.message);
    return '';
  }
}

function runAppleScript(script, timeout = 30000) {
  try {
    // Escape single quotes for shell
    const escaped = script.replace(/'/g, "'\\''");
    const result = execSync(`osascript -e '${escaped}'`, {
      encoding: 'utf8',
      timeout,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return result.trim();
  } catch (e) {
    throw new Error(`AppleScript failed: ${e.message}`);
  }
}

function isAppRunning(appName) {
  try {
    const script = `tell application "System Events" to (name of processes) contains "${appName}"`;
    const result = runAppleScript(script);
    return result === 'true';
  } catch (e) {
    return false;
  }
}

async function askDesktopApp(appName, prompt, options = {}) {
  const config = APP_CONFIG[appName] || APP_CONFIG.ChatGPT;
  const {
    retries = 3,
    retryDelay = 1500,
    captureScreenshots = true
  } = options;

  // Validate app is running
  if (!isAppRunning(appName)) {
    throw new Error(`${appName} is not running`);
  }

  const logs = [];
  let lastError = null;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      logs.push(`Attempt ${attempt}/${retries}`);

      // Step 1: Copy prompt to clipboard
      if (!setClipboard(prompt)) {
        throw new Error('Failed to set clipboard');
      }
      logs.push('Clipboard set');

      // Step 2: Build AppleScript sequence
      const delays = {
        activation: config.activationDelay / 1000,
        afterPaste: config.afterPasteDelay / 1000,
        copy: config.copyDelay / 1000
      };

      const script = `
        tell application "${appName}"
          activate
        end tell
        delay ${delays.activation}

        -- Ensure ChatGPT is truly frontmost by activating again
        tell application "${appName}"
          activate
        end tell
        delay 0.2

        tell application "System Events"
          tell process "${appName}"
            -- Click in the input area (bottom center of window)
            set frontWindow to window 1
            set windowSize to size of frontWindow
            set windowPos to position of frontWindow
            set clickX to (item 1 of windowPos) + ((item 1 of windowSize) / 2)
            set clickY to (item 2 of windowPos) + (item 2 of windowSize) - 100

            click at {clickX, clickY}
            delay 0.3
          end tell

          -- Paste prompt
          keystroke "v" using {command down}
          delay 0.3

          -- Send message with Enter (confirmed working by user)
          keystroke return
          delay 0.5

          -- Clear the input field so we don't accidentally copy it later
          keystroke "a" using {command down}
          delay 0.1
          key code 51  -- Delete/Backspace
          delay 0.3
        end tell

        delay ${delays.afterPaste}

        -- Re-activate ChatGPT before copying to ensure it's still frontmost
        tell application "${appName}"
          activate
        end tell
        delay 0.5

        tell application "System Events"
          --  Just try Cmd+A without clicking anywhere
          keystroke "a" using {command down}
          delay 0.3

          -- Copy everything
          keystroke "c" using {command down}
        end tell

        delay ${delays.copy}

        return "done"
      `;

      logs.push('Executing AppleScript');
      runAppleScript(script);

      // Step 3: Get response from clipboard
      const response = getClipboard();
      logs.push(`Response length: ${response.length}`);

      // Validate response
      if (!response || response.trim().length === 0) {
        throw new Error('Empty response from clipboard');
      }

      // Check if response is just the prompt (automation failed to get reply)
      if (response.trim() === prompt.trim()) {
        throw new Error('Response matches prompt (no reply received)');
      }

      // Success!
      return {
        ok: true,
        method: 'appleScript',
        app: appName,
        response: response.trim(),
        attempt,
        logs
      };

    } catch (e) {
      lastError = e;
      logs.push(`Error: ${e.message}`);

      // Screenshot on last attempt
      if (attempt === retries && captureScreenshots) {
        const screenshotPath = screenshot(`${appName}-failure`);
        logs.push(`Screenshot: ${screenshotPath}`);

        return {
          ok: false,
          error: e.message,
          screenshot: screenshotPath,
          logs
        };
      }

      // Wait before retry
      if (attempt < retries) {
        logs.push(`Waiting ${retryDelay}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }
  }

  return {
    ok: false,
    error: lastError ? lastError.message : 'Unknown error',
    logs
  };
}

// CLI mode
if (require.main === module) {
  const args = process.argv.slice(2);
  const appIndex = args.indexOf('--app');
  const promptIndex = args.indexOf('--prompt');

  if (appIndex === -1 || promptIndex === -1) {
    console.error('Usage: node desktop_automation.js --app ChatGPT --prompt "Your prompt"');
    process.exit(1);
  }

  const appName = args[appIndex + 1];
  const prompt = args[promptIndex + 1];

  askDesktopApp(appName, prompt)
    .then(result => {
      if (result.ok) {
        console.log(result.response);
        process.exit(0);
      } else {
        console.error('ERROR:', result.error);
        console.error('Logs:', result.logs);
        if (result.screenshot) {
          console.error('Screenshot saved:', result.screenshot);
        }
        process.exit(1);
      }
    })
    .catch(err => {
      console.error('FATAL:', err.message);
      process.exit(2);
    });
}

module.exports = { askDesktopApp, isAppRunning };
