#!/usr/bin/env node
/**
 * syncWatcher.js
 *
 * iCloud Drive folder watcher for phone → Mac sync
 * Monitors a designated folder for JSON request files from iOS Shortcuts
 *
 * Features:
 * - Watches iCloud Drive folder for new .json files
 * - Processes incoming prompts from phone
 * - Routes to local LLM or desktop app
 * - Writes response back to iCloud for phone pickup
 *
 * Flow:
 * 1. Phone drops: warp-requests/request-{id}.json
 * 2. Mac processes and generates response
 * 3. Mac writes: warp-responses/response-{id}.json
 * 4. Phone polls for response file
 *
 * Usage:
 *   node syncWatcher.js
 *
 * Environment:
 *   WARP_SYNC_DIR - Custom iCloud folder (default: ~/Library/Mobile Documents/com~apple~CloudDocs/WarpSync)
 *   WARP_POLL_INTERVAL - Poll interval in ms (default: 2000)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration
const HOME = process.env.HOME || require('os').homedir();
const ICLOUD_BASE = path.join(HOME, 'Library/Mobile Documents/com~apple~CloudDocs');
const SYNC_DIR = process.env.WARP_SYNC_DIR || path.join(ICLOUD_BASE, 'WarpSync');
const REQUESTS_DIR = path.join(SYNC_DIR, 'warp-requests');
const RESPONSES_DIR = path.join(SYNC_DIR, 'warp-responses');
const POLL_INTERVAL = parseInt(process.env.WARP_POLL_INTERVAL || '2000', 10);

const AGENT_SERVER_URL = 'http://localhost:4005';

// Logging
function log(level, message, meta = {}) {
  const timestamp = new Date().toISOString();
  console.log(JSON.stringify({ timestamp, level, message, ...meta }));
}

// Ensure directories exist
function ensureDirectories() {
  [SYNC_DIR, REQUESTS_DIR, RESPONSES_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      log('info', `Created directory: ${dir}`);
    }
  });
}

// Check if iCloud Drive is available
function checkICloudAvailable() {
  try {
    if (!fs.existsSync(ICLOUD_BASE)) {
      log('error', 'iCloud Drive not found', { path: ICLOUD_BASE });
      return false;
    }

    // Check if directory is writable
    const testFile = path.join(SYNC_DIR, '.test-write');
    fs.writeFileSync(testFile, 'test');
    fs.unlinkSync(testFile);
    return true;
  } catch (e) {
    log('error', 'iCloud Drive not accessible', { error: e.message });
    return false;
  }
}

// Process a single request file
async function processRequest(requestFile) {
  const requestId = path.basename(requestFile, '.json').replace('request-', '');
  log('info', 'Processing request', { id: requestId, file: requestFile });

  try {
    // Read request
    const rawData = fs.readFileSync(requestFile, 'utf8');
    const request = JSON.parse(rawData);

    // Validate request format
    if (!request.prompt || typeof request.prompt !== 'string') {
      throw new Error('Invalid request: missing or invalid prompt');
    }

    log('info', 'Request parsed', {
      id: requestId,
      promptLength: request.prompt.length,
      priority: request.priority || 'normal'
    });

    // Route based on request parameters
    let response;

    if (request.preferDesktop) {
      // Use desktop app directly
      response = await invokeDesktopApp(request.prompt, request.app || 'ChatGPT');
    } else {
      // Try local LLM first, fallback to desktop
      try {
        response = await invokeLocalLLM(request.prompt, request.model);
      } catch (e) {
        log('warn', 'Local LLM failed, trying desktop app', { error: e.message });
        response = await invokeDesktopApp(request.prompt, request.app || 'ChatGPT');
      }
    }

    // Write response file
    const responseFile = path.join(RESPONSES_DIR, `response-${requestId}.json`);
    const responseData = {
      id: requestId,
      timestamp: Date.now(),
      success: true,
      response: response.text,
      method: response.method,
      processingTime: Date.now() - request.timestamp
    };

    fs.writeFileSync(responseFile, JSON.stringify(responseData, null, 2), 'utf8');
    log('info', 'Response written', { id: requestId, file: responseFile });

    // Delete request file
    fs.unlinkSync(requestFile);
    log('info', 'Request file deleted', { id: requestId });

  } catch (e) {
    log('error', 'Failed to process request', {
      id: requestId,
      error: e.message,
      stack: e.stack
    });

    // Write error response
    const responseFile = path.join(RESPONSES_DIR, `response-${requestId}.json`);
    const errorData = {
      id: requestId,
      timestamp: Date.now(),
      success: false,
      error: e.message
    };

    try {
      fs.writeFileSync(responseFile, JSON.stringify(errorData, null, 2), 'utf8');
    } catch (writeErr) {
      log('error', 'Failed to write error response', { error: writeErr.message });
    }
  }
}

// Invoke local LLM via enhanced server
async function invokeLocalLLM(prompt, model) {
  const response = await fetch(`${AGENT_SERVER_URL}/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      prompt,
      model: model || 'llama3.2:3b-instruct-q4_K_M'
    })
  });

  if (!response.ok) {
    throw new Error(`LLM request failed: ${response.status}`);
  }

  const data = await response.json();

  if (!data.ok) {
    throw new Error(`LLM returned error: ${data.error}`);
  }

  return {
    text: data.route.parsed.response,
    method: 'ollama-http'
  };
}

// Invoke desktop app via AppleScript
async function invokeDesktopApp(prompt, app) {
  const response = await fetch(`${AGENT_SERVER_URL}/invoke-desktop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      app,
      prompt,
      retries: 2
    })
  });

  const data = await response.json();

  if (!data.ok) {
    throw new Error(`Desktop app invocation failed: ${data.error || data.message}`);
  }

  return {
    text: data.response,
    method: 'desktop-automation'
  };
}

// Scan requests directory for new files
function scanForRequests() {
  try {
    const files = fs.readdirSync(REQUESTS_DIR);
    const requestFiles = files
      .filter(f => f.startsWith('request-') && f.endsWith('.json'))
      .map(f => path.join(REQUESTS_DIR, f));

    return requestFiles;
  } catch (e) {
    log('error', 'Failed to scan requests directory', { error: e.message });
    return [];
  }
}

// Main watch loop
async function watchLoop() {
  log('info', 'Starting watch loop', {
    requestsDir: REQUESTS_DIR,
    responsesDir: RESPONSES_DIR,
    pollInterval: POLL_INTERVAL
  });

  while (true) {
    try {
      const requestFiles = scanForRequests();

      if (requestFiles.length > 0) {
        log('info', `Found ${requestFiles.length} pending request(s)`);

        // Process each request sequentially
        for (const file of requestFiles) {
          await processRequest(file);
        }
      }

      // Wait before next poll
      await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL));
    } catch (e) {
      log('error', 'Watch loop error', { error: e.message, stack: e.stack });
      // Continue watching even if an error occurs
      await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL));
    }
  }
}

// Cleanup old response files (older than 24 hours)
function cleanupOldFiles() {
  try {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    const files = fs.readdirSync(RESPONSES_DIR);
    let cleaned = 0;

    files.forEach(file => {
      const filePath = path.join(RESPONSES_DIR, file);
      const stats = fs.statSync(filePath);

      if (now - stats.mtimeMs > maxAge) {
        fs.unlinkSync(filePath);
        cleaned++;
      }
    });

    if (cleaned > 0) {
      log('info', 'Cleaned up old response files', { count: cleaned });
    }
  } catch (e) {
    log('error', 'Cleanup failed', { error: e.message });
  }
}

// Main entry point
async function main() {
  log('info', 'Warp Sync Watcher starting...', {
    syncDir: SYNC_DIR,
    pollInterval: POLL_INTERVAL
  });

  // Check prerequisites
  if (!checkICloudAvailable()) {
    log('error', 'iCloud Drive is not available. Exiting.');
    process.exit(1);
  }

  // Ensure directories exist
  ensureDirectories();

  // Initial cleanup
  cleanupOldFiles();

  // Schedule periodic cleanup
  setInterval(cleanupOldFiles, 60 * 60 * 1000); // Every hour

  // Start watch loop
  await watchLoop();
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  log('info', 'Received SIGINT, shutting down...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  log('info', 'Received SIGTERM, shutting down...');
  process.exit(0);
});

// Start the watcher
if (require.main === module) {
  main().catch(e => {
    log('fatal', 'Fatal error', { error: e.message, stack: e.stack });
    process.exit(1);
  });
}

module.exports = { processRequest, invokeLocalLLM, invokeDesktopApp };
