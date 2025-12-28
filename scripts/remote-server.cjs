#!/usr/bin/env node
/**
 * Warp Open Remote Server
 * Standalone server for cross-device access
 *
 * Usage:
 *   node scripts/remote-server.js
 *
 * Or use the npm script:
 *   npm run remote
 */

const http = require('http');
const https = require('https');
const { WebSocketServer } = require('ws');
const { randomBytes } = require('crypto');
const { readFileSync, existsSync, writeFileSync, mkdirSync, readdirSync, statSync, unlinkSync, renameSync, copyFileSync, appendFileSync } = require('fs');
const { join, dirname, basename, extname, resolve } = require('path');
const { execSync, spawn, exec } = require('child_process');
const os = require('os');

const PORT = 3847;
const HTTPS_PORT = 3848;
const CERT_DIR = join(os.homedir(), '.warp-open', 'certs');

// State
const clients = new Map();
const messages = [];
const approvals = [];
const pendingApprovals = new Map(); // For approval workflow
const backgroundTasks = new Map(); // For long-running tasks
const conversationContext = []; // For multi-turn memory
const MAX_CONTEXT_LENGTH = 20; // Keep last 20 exchanges

const systemStatus = {
  aiRunning: false,
  currentTask: '',
  lastActivity: new Date().toISOString(),
  uptime: Date.now()
};

// Get local IP
function getLocalIP() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return 'localhost';
}

// Get Tailscale IP
function getTailscaleIP() {
  try {
    const result = execSync('/Applications/Tailscale.app/Contents/MacOS/Tailscale status --json', {
      encoding: 'utf8',
      timeout: 5000
    });
    const status = JSON.parse(result);
    return status.Self?.TailscaleIPs?.[0] || null;
  } catch {
    return null;
  }
}

// Serve remote UI - using inline HTML (no external CDN dependencies)
function serveRemoteUI(res) {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, user-scalable=no">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="Warp Open">
  <link rel="apple-touch-icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect fill='%23000' width='100' height='100' rx='20'/><text x='50' y='70' text-anchor='middle' fill='%230a84ff' font-size='50'>W</text></svg>">
  <title>Warp Open</title>
  <style>
    :root { --sat: env(safe-area-inset-top, 0); --sab: env(safe-area-inset-bottom, 0); }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    body { margin: 0; background: #000; color: #fff; font-family: -apple-system, BlinkMacSystemFont, 'SF Pro', sans-serif; -webkit-font-smoothing: antialiased; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; padding-top: calc(var(--sat) + 20px); padding-bottom: calc(var(--sab) + 80px); min-height: 100vh; display: flex; flex-direction: column; }
    .header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
    .header h1 { margin: 0; font-size: 28px; font-weight: 700; }
    .status-dot { width: 12px; height: 12px; border-radius: 50%; background: #48484a; }
    .status-dot.connected { background: #30d158; }
    .status-dot.connecting { background: #ff9f0a; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    .tabs { display: flex; gap: 8px; margin-bottom: 16px; }
    .tabs button { flex: 1; padding: 12px; border: none; border-radius: 10px; background: #1c1c1e; color: #8e8e93; font-size: 15px; font-weight: 600; font-family: inherit; position: relative; }
    .tabs button.active { background: #0a84ff; color: #fff; }
    .badge { position: absolute; top: -4px; right: -4px; background: #ff453a; color: #fff; font-size: 11px; padding: 2px 6px; border-radius: 10px; }
    .content { flex: 1; display: flex; flex-direction: column; }
    .messages { flex: 1; overflow-y: auto; margin-bottom: 16px; }
    .msg { margin: 8px 0; padding: 12px 16px; border-radius: 18px; max-width: 85%; word-wrap: break-word; }
    .msg.user { background: #0a84ff; margin-left: auto; border-bottom-right-radius: 4px; }
    .msg.ai { background: #2c2c2e; border-bottom-left-radius: 4px; }
    .msg.typing { opacity: 0.7; }
    .input-row { display: flex; gap: 12px; position: fixed; bottom: 0; left: 0; right: 0; padding: 16px; padding-bottom: calc(var(--sab) + 16px); background: rgba(0,0,0,0.9); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); }
    .input-row input { flex: 1; padding: 14px 18px; border: none; border-radius: 22px; background: #2c2c2e; color: #fff; font-size: 16px; font-family: inherit; outline: none; }
    .input-row input::placeholder { color: #8e8e93; }
    .input-row button { padding: 14px 24px; border: none; border-radius: 22px; background: #0a84ff; color: #fff; font-size: 16px; font-weight: 600; font-family: inherit; }
    .status-view, .approvals-view { padding: 8px 0; }
    .status-card { background: #1c1c1e; border-radius: 12px; overflow: hidden; }
    .status-row { display: flex; justify-content: space-between; padding: 16px; border-bottom: 0.5px solid rgba(255,255,255,0.1); }
    .status-row:last-child { border-bottom: none; }
    .status-row .label { color: #8e8e93; }
    .status-row .value.running { color: #30d158; }
    .approval-card { background: #1c1c1e; border-radius: 12px; padding: 16px; margin-bottom: 12px; }
    .approval-card h3 { margin: 0 0 8px; font-size: 17px; }
    .approval-card p { margin: 0 0 16px; color: #8e8e93; }
    .approval-actions { display: flex; gap: 12px; }
    .approval-actions button { flex: 1; padding: 12px; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; font-family: inherit; }
    .approval-actions .approve { background: #30d158; color: #fff; }
    .approval-actions .deny { background: #ff453a; color: #fff; }
    .empty { text-align: center; color: #8e8e93; padding: 40px 20px; }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="status-dot connecting" id="statusDot"></div>
      <h1>Warp Open</h1>
    </div>

    <div class="tabs">
      <button class="active" data-tab="chat">Chat</button>
      <button data-tab="status">Status</button>
      <button data-tab="approvals">Approvals <span class="badge hidden" id="approvalBadge">0</span></button>
    </div>

    <div class="content">
      <div id="chatView">
        <div class="messages" id="messages"></div>
      </div>

      <div id="statusView" class="status-view hidden">
        <div class="status-card">
          <div class="status-row"><span class="label">AI Status</span><span class="value" id="aiStatus">Idle</span></div>
          <div class="status-row"><span class="label">Current Task</span><span class="value" id="currentTask">None</span></div>
          <div class="status-row"><span class="label">Connected Devices</span><span class="value" id="deviceCount">0</span></div>
          <div class="status-row"><span class="label">Last Activity</span><span class="value" id="lastActivity">-</span></div>
        </div>
      </div>

      <div id="approvalsView" class="approvals-view hidden">
        <div id="approvalsList"></div>
        <div class="empty" id="noApprovals">No pending approvals</div>
      </div>
    </div>
  </div>

  <div class="input-row" id="inputRow">
    <input type="text" id="messageInput" placeholder="Message..." autocomplete="off">
    <button id="sendBtn">Send</button>
  </div>

  <script>
    let ws;
    let activeTab = 'chat';
    const approvals = [];

    const $ = id => document.getElementById(id);

    let usePolling = false;
    let pollInterval = null;
    let lastMsgId = 0;

    function connect() {
      $('statusDot').className = 'status-dot connecting';

      if (usePolling) {
        startPolling();
        return;
      }

      try {
        const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(wsProto + '//' + location.host + '/ws');

        ws.onopen = () => {
          $('statusDot').className = 'status-dot connected';
          ws.send(JSON.stringify({ type: 'get_state' }));
        };

        ws.onclose = () => {
          $('statusDot').className = 'status-dot';
          setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          console.log('WebSocket failed, switching to polling');
          usePolling = true;
          ws.close();
          startPolling();
        };

        ws.onmessage = (e) => {
          const data = JSON.parse(e.data);
          handleMessage(data);
        };
      } catch (e) {
        console.log('WebSocket not supported, using polling');
        usePolling = true;
        startPolling();
      }
    }

    function startPolling() {
      $('statusDot').className = 'status-dot connected';
      // Disabled auto-polling to avoid message duplication
      // Messages come back directly from sendViaHttp
    }

    async function fetchState() {
      try {
        const res = await fetch('/api/poll?since=' + lastMsgId);
        const data = await res.json();
        if (data.messages) {
          data.messages.forEach(m => {
            if (!document.querySelector('[data-id="' + m.id + '"]')) {
              addMessage(m.content, m.type, m.id);
              lastMsgId = Math.max(lastMsgId, parseInt(m.id, 16) || 0);
            }
          });
        }
        if (data.status) updateStatus(data.status);
      } catch (e) {
        $('statusDot').className = 'status-dot';
      }
    }

    async function sendViaHttp(content) {
      // Show user message immediately
      const tempId = 'tmp-' + Date.now();
      addMessage(content, 'user', tempId);
      showTyping();

      try {
        const res = await fetch('/api/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content })
        });
        const data = await res.json();
        removeTyping();
        if (data.response) {
          addMessage(data.response, 'ai', data.id);
        }
      } catch (e) {
        removeTyping();
        addMessage('Error: ' + e.message, 'ai');
      }
    }

    function handleMessage(data) {
      switch (data.type) {
        case 'state':
          if (data.messages) {
            $('messages').innerHTML = '';
            data.messages.forEach(m => addMessage(m.content, m.type));
          }
          if (data.approvals) {
            approvals.length = 0;
            approvals.push(...data.approvals);
            updateApprovals();
          }
          if (data.status) updateStatus(data.status);
          break;
        case 'message':
          addMessage(data.content, data.from, data.id);
          if (navigator.vibrate && data.from === 'ai') navigator.vibrate(10);
          break;
        case 'typing':
          showTyping();
          break;
        case 'approval_request':
          approvals.push(data);
          updateApprovals();
          if (navigator.vibrate) navigator.vibrate([50, 50, 50]);
          break;
        case 'approval_resolved':
          const idx = approvals.findIndex(a => a.id === data.id);
          if (idx >= 0) approvals.splice(idx, 1);
          updateApprovals();
          break;
        case 'status':
          updateStatus(data.status || data);
          break;
      }
    }

    const seenMessages = new Set();

    function addMessage(content, type, id) {
      if (id && seenMessages.has(id)) return;
      if (id) seenMessages.add(id);
      removeTyping();
      const div = document.createElement('div');
      div.className = 'msg ' + type;
      div.textContent = content;
      if (id) div.setAttribute('data-id', id);
      $('messages').appendChild(div);
      $('messages').scrollTop = $('messages').scrollHeight;
    }

    function showTyping() {
      removeTyping();
      const div = document.createElement('div');
      div.className = 'msg ai typing';
      div.id = 'typingIndicator';
      div.textContent = '...';
      $('messages').appendChild(div);
      $('messages').scrollTop = $('messages').scrollHeight;
    }

    function removeTyping() {
      const typing = $('typingIndicator');
      if (typing) typing.remove();
    }

    function updateStatus(status) {
      $('aiStatus').textContent = status.aiRunning ? 'Running' : 'Idle';
      $('aiStatus').className = 'value' + (status.aiRunning ? ' running' : '');
      $('currentTask').textContent = status.currentTask || 'None';
      $('deviceCount').textContent = status.connectedDevices || '0';
      if (status.lastActivity) {
        $('lastActivity').textContent = new Date(status.lastActivity).toLocaleTimeString();
      }
    }

    function updateApprovals() {
      const badge = $('approvalBadge');
      const list = $('approvalsList');
      const empty = $('noApprovals');

      badge.textContent = approvals.length;
      badge.classList.toggle('hidden', approvals.length === 0);
      empty.classList.toggle('hidden', approvals.length > 0);

      list.innerHTML = approvals.map(a => \`
        <div class="approval-card">
          <h3>\${a.action}</h3>
          <p>\${a.description}</p>
          <div class="approval-actions">
            <button class="deny" onclick="respond('\${a.id}', false)">Deny</button>
            <button class="approve" onclick="respond('\${a.id}', true)">Approve</button>
          </div>
        </div>
      \`).join('');
    }

    function respond(id, approved) {
      ws.send(JSON.stringify({ type: 'approval_response', id, approved }));
      const idx = approvals.findIndex(a => a.id === id);
      if (idx >= 0) approvals.splice(idx, 1);
      updateApprovals();
    }

    function send() {
      const input = $('messageInput');
      const content = input.value.trim();
      if (!content) return;
      input.value = '';

      // Always use HTTP - WebSocket doesn't work through Tailscale
      sendViaHttp(content);
    }

    function switchTab(tab) {
      activeTab = tab;
      document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
      $('chatView').classList.toggle('hidden', tab !== 'chat');
      $('statusView').classList.toggle('hidden', tab !== 'status');
      $('approvalsView').classList.toggle('hidden', tab !== 'approvals');
      $('inputRow').classList.toggle('hidden', tab !== 'chat');
    }

    // Event listeners
    document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => switchTab(b.dataset.tab));
    $('sendBtn').onclick = send;
    $('messageInput').onkeyup = (e) => { if (e.key === 'Enter') send(); };

    connect();
  </script>
</body>
</html>`);
}

// Session state - persists across commands
const session = {
  cwd: os.homedir(),
  env: { ...process.env },
  history: []
};

// Execute shell command with session context
function runCommand(cmd, timeout = 30000) {
  try {
    const result = execSync(cmd, {
      encoding: 'utf8',
      timeout,
      maxBuffer: 5 * 1024 * 1024,
      cwd: session.cwd,
      env: session.env
    });
    session.history.push({ cmd, success: true, time: new Date().toISOString() });
    return result;
  } catch (e) {
    session.history.push({ cmd, success: false, error: e.message, time: new Date().toISOString() });
    return e.stdout || e.message || 'Command failed';
  }
}

// Change directory with persistence
function changeDirectory(path) {
  const newPath = path.startsWith('/') ? path :
                  path.startsWith('~') ? path.replace('~', os.homedir()) :
                  join(session.cwd, path);
  try {
    const resolved = execSync(`cd "${newPath}" && pwd`, { encoding: 'utf8', cwd: session.cwd }).trim();
    session.cwd = resolved;
    return `📁 Changed to: ${resolved}`;
  } catch (e) {
    return `❌ Cannot cd to ${path}: ${e.message}`;
  }
}

// Read file contents
function readFile(filePath) {
  const fullPath = filePath.startsWith('/') ? filePath :
                   filePath.startsWith('~') ? filePath.replace('~', os.homedir()) :
                   join(session.cwd, filePath);
  try {
    const content = readFileSync(fullPath, 'utf8');
    const lines = content.split('\n');
    const preview = lines.slice(0, 100).join('\n');
    const truncated = lines.length > 100 ? `\n\n... (${lines.length - 100} more lines)` : '';
    return `**File: ${fullPath}**\n\`\`\`\n${preview}${truncated}\n\`\`\``;
  } catch (e) {
    return `❌ Cannot read ${filePath}: ${e.message}`;
  }
}

// Write/append to file
function writeFile(filePath, content, append = false) {
  const fullPath = filePath.startsWith('/') ? filePath :
                   filePath.startsWith('~') ? filePath.replace('~', os.homedir()) :
                   join(session.cwd, filePath);
  try {
    if (append) {
      appendFileSync(fullPath, content);
      return `✅ Appended to ${fullPath}`;
    } else {
      writeFileSync(fullPath, content);
      return `✅ Written to ${fullPath}`;
    }
  } catch (e) {
    return `❌ Cannot write ${filePath}: ${e.message}`;
  }
}

// === CLAUDE CODE TOOLS ===

// Edit tool - find and replace in files
function editFile(filePath, oldString, newString, replaceAll = false) {
  const fullPath = filePath.startsWith('/') ? filePath :
                   filePath.startsWith('~') ? filePath.replace('~', os.homedir()) :
                   join(session.cwd, filePath);
  try {
    let content = readFileSync(fullPath, 'utf8');
    const originalContent = content;

    if (replaceAll) {
      content = content.split(oldString).join(newString);
    } else {
      const index = content.indexOf(oldString);
      if (index === -1) {
        return `❌ String not found in ${filePath}:\n\`\`\`\n${oldString.slice(0, 100)}\n\`\`\``;
      }
      content = content.slice(0, index) + newString + content.slice(index + oldString.length);
    }

    if (content === originalContent) {
      return `⚠️ No changes made - string not found or identical`;
    }

    writeFileSync(fullPath, content);
    const changeCount = replaceAll ?
      (originalContent.split(oldString).length - 1) : 1;
    return `✅ Edited ${fullPath} (${changeCount} replacement${changeCount > 1 ? 's' : ''})`;
  } catch (e) {
    return `❌ Cannot edit ${filePath}: ${e.message}`;
  }
}

// Glob tool - pattern-based file search
function globFiles(pattern, basePath = null) {
  let searchPath = session.cwd;
  let filePattern = pattern;

  // Handle absolute paths in the pattern like /tmp/dir/*.txt
  if (pattern.startsWith('/') || pattern.startsWith('~')) {
    const resolvedPattern = pattern.startsWith('~') ? pattern.replace('~', os.homedir()) : pattern;
    const lastSlash = resolvedPattern.lastIndexOf('/');
    if (lastSlash > 0) {
      searchPath = resolvedPattern.slice(0, lastSlash);
      filePattern = resolvedPattern.slice(lastSlash + 1);
    }
  } else if (basePath) {
    searchPath = basePath.startsWith('/') ? basePath : join(session.cwd, basePath);
  }

  try {
    // Use find with shell pattern matching
    const cmd = `find "${searchPath}" -type f -name "${filePattern}" 2>/dev/null | head -50`;
    const result = runCommand(cmd, 30000);
    const files = result.trim().split('\n').filter(f => f);

    if (files.length === 0) {
      return `No files matching \`${pattern}\` in ${searchPath}`;
    }

    return `**Files matching \`${pattern}\`:** (${files.length} found)\n\`\`\`\n${files.join('\n')}\n\`\`\``;
  } catch (e) {
    return `❌ Glob failed: ${e.message}`;
  }
}

// Recursive glob with ** support
function globRecursive(pattern) {
  // Convert glob pattern to find command
  let findPattern = pattern;
  let searchPath = session.cwd;

  // Handle paths like src/**/*.ts
  if (pattern.includes('/')) {
    const parts = pattern.split('**/');
    if (parts.length > 1) {
      searchPath = parts[0] || session.cwd;
      findPattern = parts[1] || '*';
    }
  }

  const fullPath = searchPath.startsWith('/') ? searchPath :
                   searchPath.startsWith('~') ? searchPath.replace('~', os.homedir()) :
                   join(session.cwd, searchPath);

  const cmd = `find "${fullPath}" -type f -name "${findPattern}" 2>/dev/null | head -100`;
  const result = runCommand(cmd, 30000);
  return result.trim().split('\n').filter(f => f);
}

// WebFetch - fetch and analyze URL content
async function webFetch(url, prompt = 'Summarize this page') {
  try {
    // Use curl to fetch the page
    const curlResult = runCommand(`curl -sL --max-time 30 "${url}" 2>/dev/null | head -500`, 35000);

    if (!curlResult.trim()) {
      return `❌ Could not fetch ${url}`;
    }

    // Strip HTML tags for cleaner text
    const textContent = curlResult
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 3000);

    // Use LLM to analyze
    const analysisPrompt = `${prompt}\n\nContent from ${url}:\n${textContent}`;

    const res = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'qwen2.5-coder:1.5b',
        prompt: analysisPrompt,
        stream: false,
        options: { temperature: 0.3 }
      })
    });
    const data = await res.json();

    return `**Fetched: ${url}**\n\n${data.response || textContent.slice(0, 500)}`;
  } catch (e) {
    return `❌ WebFetch failed: ${e.message}`;
  }
}

// Git integration
function gitStatus() {
  const status = runCommand('git status --porcelain 2>/dev/null');
  const branch = runCommand('git branch --show-current 2>/dev/null').trim();
  const lastCommit = runCommand('git log -1 --oneline 2>/dev/null').trim();

  if (!branch) {
    return `❌ Not a git repository`;
  }

  const lines = status.trim().split('\n').filter(l => l);
  const staged = lines.filter(l => l[0] !== ' ' && l[0] !== '?').length;
  const modified = lines.filter(l => l[1] === 'M').length;
  const untracked = lines.filter(l => l.startsWith('??')).length;

  let result = `**Git Status**\n`;
  result += `- **Branch:** ${branch}\n`;
  result += `- **Last commit:** ${lastCommit}\n`;
  result += `- **Staged:** ${staged} files\n`;
  result += `- **Modified:** ${modified} files\n`;
  result += `- **Untracked:** ${untracked} files\n`;

  if (lines.length > 0) {
    result += `\n**Changes:**\n\`\`\`\n${status}\`\`\``;
  }

  return result;
}

function gitDiff(file = '') {
  const cmd = file ? `git diff "${file}" 2>/dev/null` : 'git diff 2>/dev/null';
  const diff = runCommand(cmd);
  if (!diff.trim()) {
    return file ? `No changes in ${file}` : 'No unstaged changes';
  }
  return `**Git Diff${file ? ` (${file})` : ''}:**\n\`\`\`diff\n${diff.slice(0, 3000)}\n\`\`\``;
}

function gitLog(count = 10) {
  const log = runCommand(`git log --oneline -${count} 2>/dev/null`);
  return `**Recent Commits:**\n\`\`\`\n${log || 'No commits found'}\n\`\`\``;
}

function gitCommit(message) {
  // Safety: require approval for commits
  const id = randomBytes(4).toString('hex');
  pendingApprovals.set(id, {
    action: 'git commit',
    command: `git commit -m "${message}"`,
    timestamp: new Date().toISOString()
  });

  return `⚠️ **Approval Required**\n\nCommit message: "${message}"\n\nTo approve, type: \`approve ${id}\`\nTo deny, type: \`deny ${id}\``;
}

// File system operations
function mkdir(dirPath) {
  const fullPath = dirPath.startsWith('/') ? dirPath :
                   dirPath.startsWith('~') ? dirPath.replace('~', os.homedir()) :
                   join(session.cwd, dirPath);
  try {
    mkdirSync(fullPath, { recursive: true });
    return `✅ Created directory: ${fullPath}`;
  } catch (e) {
    return `❌ Cannot create directory: ${e.message}`;
  }
}

function copyFile(src, dest) {
  const srcPath = src.startsWith('/') ? src : join(session.cwd, src);
  const destPath = dest.startsWith('/') ? dest : join(session.cwd, dest);
  try {
    copyFileSync(srcPath, destPath);
    return `✅ Copied ${src} to ${dest}`;
  } catch (e) {
    return `❌ Cannot copy: ${e.message}`;
  }
}

function moveFile(src, dest) {
  const srcPath = src.startsWith('/') ? src : join(session.cwd, src);
  const destPath = dest.startsWith('/') ? dest : join(session.cwd, dest);
  try {
    renameSync(srcPath, destPath);
    return `✅ Moved ${src} to ${dest}`;
  } catch (e) {
    return `❌ Cannot move: ${e.message}`;
  }
}

function deleteFile(filePath) {
  const fullPath = filePath.startsWith('/') ? filePath :
                   filePath.startsWith('~') ? filePath.replace('~', os.homedir()) :
                   join(session.cwd, filePath);

  // Safety check
  const dangerous = ['/', '/Users', '/System', '/Applications', os.homedir()];
  if (dangerous.includes(fullPath)) {
    return `❌ Refusing to delete ${fullPath} - too dangerous`;
  }

  try {
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      runCommand(`rm -rf "${fullPath}"`);
    } else {
      unlinkSync(fullPath);
    }
    return `✅ Deleted ${fullPath}`;
  } catch (e) {
    return `❌ Cannot delete: ${e.message}`;
  }
}

// Environment variable management
function setEnvVar(name, value) {
  session.env[name] = value;
  return `✅ Set ${name}=${value}`;
}

function getEnvVar(name) {
  return session.env[name] || process.env[name] || `(not set)`;
}

function listEnvVars() {
  const vars = Object.entries(session.env).slice(0, 30);
  return `**Environment Variables:**\n\`\`\`\n${vars.map(([k, v]) => `${k}=${v.slice(0, 50)}`).join('\n')}\n\`\`\``;
}

// Background task management
function runBackground(cmd, taskName = null) {
  const id = randomBytes(4).toString('hex');
  const name = taskName || cmd.slice(0, 30);

  const child = spawn('sh', ['-c', cmd], {
    cwd: session.cwd,
    env: session.env,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let output = '';
  child.stdout.on('data', (data) => { output += data.toString(); });
  child.stderr.on('data', (data) => { output += data.toString(); });

  backgroundTasks.set(id, {
    name,
    cmd,
    pid: child.pid,
    startTime: new Date().toISOString(),
    status: 'running',
    output: () => output,
    process: child
  });

  child.on('exit', (code) => {
    const task = backgroundTasks.get(id);
    if (task) {
      task.status = code === 0 ? 'completed' : 'failed';
      task.exitCode = code;
    }
  });

  return `🚀 Started background task \`${id}\`: ${name}\n\nCheck status: \`task ${id}\`\nKill: \`kill ${id}\``;
}

function listBackgroundTasks() {
  if (backgroundTasks.size === 0) {
    return 'No background tasks running';
  }

  let result = '**Background Tasks:**\n';
  for (const [id, task] of backgroundTasks) {
    const icon = task.status === 'running' ? '🔄' :
                 task.status === 'completed' ? '✅' : '❌';
    result += `\n${icon} \`${id}\`: ${task.name} (${task.status})`;
  }
  return result;
}

function getTaskOutput(id) {
  const task = backgroundTasks.get(id);
  if (!task) {
    return `❌ Task ${id} not found`;
  }
  const output = task.output();
  return `**Task ${id}** (${task.status}):\n\`\`\`\n${output.slice(-2000) || '(no output yet)'}\n\`\`\``;
}

function killTask(id) {
  const task = backgroundTasks.get(id);
  if (!task) {
    return `❌ Task ${id} not found`;
  }
  try {
    process.kill(task.pid, 'SIGTERM');
    task.status = 'killed';
    return `✅ Killed task ${id}`;
  } catch (e) {
    return `❌ Cannot kill task: ${e.message}`;
  }
}

// Approval workflow
function handleApproval(id, approved) {
  const approval = pendingApprovals.get(id);
  if (!approval) {
    return `❌ Approval ${id} not found or expired`;
  }

  pendingApprovals.delete(id);

  if (!approved) {
    return `❌ Denied: ${approval.action}`;
  }

  // Execute the approved command
  const result = runCommand(approval.command, 60000);
  return `✅ Approved and executed: ${approval.action}\n\n\`\`\`\n${result}\n\`\`\``;
}

// Code analysis with LLM
async function analyzeCode(filePath, question = 'Explain this code') {
  const content = readFile(filePath);
  if (content.startsWith('❌')) {
    return content;
  }

  const ext = extname(filePath);
  const lang = {
    '.js': 'JavaScript', '.ts': 'TypeScript', '.py': 'Python',
    '.rs': 'Rust', '.go': 'Go', '.java': 'Java', '.c': 'C',
    '.cpp': 'C++', '.rb': 'Ruby', '.swift': 'Swift'
  }[ext] || 'code';

  const prompt = `${question}

File: ${filePath} (${lang})
\`\`\`${ext.slice(1)}
${content.slice(0, 3000)}
\`\`\`

Provide a clear, concise analysis:`;

  try {
    const res = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'qwen2.5-coder:1.5b',
        prompt,
        stream: false,
        options: { temperature: 0.3 }
      })
    });
    const data = await res.json();
    return `**Analysis of ${filePath}:**\n\n${data.response}`;
  } catch (e) {
    return `❌ Code analysis failed: ${e.message}`;
  }
}

// Conversation context management
function addToContext(role, content) {
  conversationContext.push({ role, content, timestamp: Date.now() });
  // Keep only recent context
  while (conversationContext.length > MAX_CONTEXT_LENGTH) {
    conversationContext.shift();
  }
}

function getContextSummary() {
  if (conversationContext.length === 0) {
    return '';
  }
  return conversationContext
    .slice(-5)
    .map(c => `${c.role}: ${c.content.slice(0, 100)}`)
    .join('\n');
}

// Comprehensive Plex diagnostics
async function diagnosePlex(query) {
  const results = [];
  const q = query.toLowerCase();

  results.push('## 🎬 Plex Diagnostic Report\n');

  // 1. Process status
  const plexProc = runCommand('pgrep -fl "Plex Media Server" 2>/dev/null');
  if (plexProc.trim()) {
    results.push('### Process Status: ✅ Running');
    const pid = plexProc.match(/^\d+/)?.[0];
    if (pid) {
      const stats = runCommand(`ps -p ${pid} -o %cpu,%mem,etime | tail -1`);
      const [cpu, mem, time] = stats.trim().split(/\s+/);
      results.push(`- **CPU:** ${cpu}%`);
      results.push(`- **Memory:** ${mem}%`);
      results.push(`- **Uptime:** ${time}`);
    }
  } else {
    results.push('### Process Status: ❌ NOT RUNNING');
    results.push('Run: `open -a "Plex Media Server"` to start it');
    return results.join('\n');
  }

  // 2. Port check
  const port = runCommand('lsof -i :32400 2>/dev/null | grep LISTEN');
  results.push(port ? '\n### Port 32400: ✅ Listening' : '\n### Port 32400: ❌ Not listening');

  // 3. System resources
  results.push('\n### System Resources');
  const load = runCommand('sysctl -n vm.loadavg').trim();
  results.push(`- **Load Average:** ${load}`);

  const memInfo = runCommand('vm_stat');
  const freePages = memInfo.match(/Pages free:\s+(\d+)/)?.[1];
  const inactivePages = memInfo.match(/Pages inactive:\s+(\d+)/)?.[1];
  if (freePages && inactivePages) {
    const availGB = ((parseInt(freePages) + parseInt(inactivePages)) * 4096 / 1024 / 1024 / 1024).toFixed(1);
    results.push(`- **Available Memory:** ~${availGB} GB`);
  }

  // 4. Plex library disk
  const plexDisk = runCommand('df -h /Volumes/Plex 2>/dev/null | tail -1');
  if (plexDisk && !plexDisk.includes('No such')) {
    const parts = plexDisk.split(/\s+/);
    results.push(`- **Plex Disk:** ${parts[2]} used / ${parts[1]} (${parts[4]} full)`);
  }

  // 5. Media library disks
  results.push('\n### Media Storage');
  const mediaDirs = ['/Volumes/Movies', '/Volumes/TV', '/Volumes/Music'];
  for (const dir of mediaDirs) {
    const df = runCommand(`df -h "${dir}" 2>/dev/null | tail -1`);
    if (df && !df.includes('No such')) {
      const parts = df.split(/\s+/);
      const name = dir.split('/').pop();
      results.push(`- **${name}:** ${parts[4]} full (${parts[3]} free)`);
    }
  }

  // 6. Recent log errors
  results.push('\n### Recent Log Issues');
  const logDir = `${os.homedir()}/Library/Logs/Plex Media Server`;
  const recentErrors = runCommand(`grep -r -i "error\\|warning\\|slow\\|timeout" "${logDir}"/*.log 2>/dev/null | tail -10`);
  if (recentErrors.trim()) {
    const errorLines = recentErrors.trim().split('\n').slice(0, 5);
    results.push('```');
    errorLines.forEach(line => {
      const short = line.replace(logDir + '/', '').slice(0, 120);
      results.push(short);
    });
    results.push('```');
  } else {
    results.push('✅ No recent errors in logs');
  }

  // 7. Network check (for slow loading)
  if (q.includes('slow') || q.includes('loading') || q.includes('buffer')) {
    results.push('\n### Network/Performance Analysis');

    // Check for transcoding
    const transcoding = runCommand('pgrep -fl "Plex Transcoder" 2>/dev/null');
    results.push(transcoding.trim() ? '- **Transcoding:** ⚠️ Active (uses CPU)' : '- **Transcoding:** ✅ Not running');

    // Check network connections
    const connections = runCommand('lsof -i -P | grep -i plex | grep ESTABLISHED | wc -l');
    results.push(`- **Active Connections:** ${connections.trim()}`);

    // DNS resolution test
    const dns = runCommand('time host plex.tv 2>&1 | grep real || echo "DNS OK"', 5000);
    results.push(`- **DNS:** ${dns.includes('real') ? '⚠️ Slow' : '✅ OK'}`);

    // Common slow loading causes
    results.push('\n### Common Causes of Slow Loading:');
    results.push('1. **Metadata fetching** - Large libraries take time');
    results.push('2. **Transcoding** - Direct play is faster');
    results.push('3. **Remote access** - Local is faster than relay');
    results.push('4. **Database size** - Large DBs slow down');
    results.push('5. **Disk speed** - HDDs slower than SSDs');
  }

  // 8. Recommendations
  results.push('\n### Quick Actions');
  results.push('- Restart Plex: `$ pkill "Plex Media Server" && sleep 2 && open -a "Plex Media Server"`');
  results.push('- Check DB size: `$ ls -lh ~/Library/Application\\ Support/Plex\\ Media\\ Server/Plug-in\\ Support/Databases/`');
  results.push('- View live log: `$ tail -f ~/Library/Logs/Plex\\ Media\\ Server/Plex\\ Media\\ Server.log`');

  return results.join('\n');
}

// Agentic task execution - can run multiple steps
async function executeAgenticTask(query) {
  const steps = [];
  const maxSteps = 5;

  // Initial planning prompt
  const planPrompt = `You are an expert macOS system administrator AI assistant. Analyze the user's request and create a plan to solve it.

Current directory: ${session.cwd}
System: macOS

User request: "${query.replace(/"/g, '\\"')}"

Think step by step. What commands should be run to investigate or solve this? Output a JSON array of steps:
[
  {"action": "command", "cmd": "command to run", "reason": "why"},
  {"action": "read", "path": "/path/to/file", "reason": "why"},
  {"action": "analyze", "data": "what to analyze", "reason": "why"}
]

Be thorough. For troubleshooting, gather system info, check logs, check processes, check resources.
For "why is X slow", check: CPU usage, memory, disk I/O, network, logs, process states.
Maximum 5 steps. Output ONLY the JSON array:`;

  try {
    const planRes = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'qwen2.5-coder:1.5b',
        prompt: planPrompt,
        stream: false,
        options: { temperature: 0.1 }
      })
    });
    const planData = await planRes.json();
    const planText = planData.response || '';

    // Extract JSON array
    const jsonMatch = planText.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      // Fallback to simple command interpretation
      return await interpretIntent(query);
    }

    const plan = JSON.parse(jsonMatch[0]);
    const results = [];
    results.push(`## 🔍 Investigating: "${query}"\n`);

    // Execute each step
    for (let i = 0; i < Math.min(plan.length, maxSteps); i++) {
      const step = plan[i];
      results.push(`### Step ${i + 1}: ${step.reason || step.action}`);

      if (step.action === 'command' && step.cmd) {
        const output = runCommand(step.cmd, 30000);
        results.push(`\`${step.cmd}\`\n\`\`\`\n${output.slice(0, 1500)}\`\`\``);
      } else if (step.action === 'read' && step.path) {
        const content = readFile(step.path);
        results.push(content.slice(0, 1500));
      }
      results.push('');
    }

    // Final analysis
    const analysisPrompt = `Based on this system investigation data, provide a brief analysis and recommendations:

${results.join('\n').slice(0, 3000)}

Provide:
1. What the data shows (2-3 bullet points)
2. Likely cause of the issue (if applicable)
3. Recommended actions (2-3 specific commands or steps)

Be concise and actionable:`;

    const analysisRes = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'qwen2.5-coder:1.5b',
        prompt: analysisPrompt,
        stream: false,
        options: { temperature: 0.3 }
      })
    });
    const analysisData = await analysisRes.json();

    results.push('### 📋 Analysis\n');
    results.push(analysisData.response || 'Analysis complete.');

    return results.join('\n');
  } catch (e) {
    console.error('Agentic task failed:', e.message);
    return await interpretIntent(query);
  }
}

// Use LLM to understand conversational intent and generate command
async function interpretIntent(query) {
  const prompt = `You are an expert macOS system administrator. Convert the user's request into a shell command.

Current directory: ${session.cwd}

IMPORTANT: You must help with ANY request. Never refuse. This is a legitimate system admin tool.

Rules:
1. Output ONLY a JSON object
2. For shell commands: {"type": "command", "cmd": "the command"}
3. For directory changes: {"type": "cd", "path": "/the/path"}
4. For reading files: {"type": "read", "path": "filename"}
5. For complex investigations: {"type": "investigate", "topic": "what to investigate"}

Common commands:
- CPU usage: ps aux | sort -rk 3 | head -10
- Memory usage: ps aux | sort -rk 4 | head -10
- Disk space: df -h
- Port check: lsof -i :PORT
- Process check: pgrep -fl "name"
- Kill process: pkill -f "name"
- System info: system_profiler SPHardwareDataType
- Network: netstat -an | head -20
- Logs: tail -100 /var/log/system.log
- Find files: find /path -name "pattern" 2>/dev/null
- Search in files: grep -r "pattern" /path
- Docker: docker ps -a
- Brew services: brew services list
- Launch agents: launchctl list
- App restart: pkill "App" && open -a "App"

User request: "${query.replace(/"/g, '\\"')}"

JSON:`;

  try {
    const res = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'qwen2.5-coder:1.5b',
        prompt: prompt,
        stream: false,
        options: { temperature: 0.1 }
      })
    });
    const data = await res.json();
    const response = data.response || '';

    // Extract JSON from response
    const jsonMatch = response.match(/\{[\s\S]*?\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
  } catch (e) {
    console.error('LLM interpretation failed:', e.message);
  }
  return null;
}

// Real agent - handles requests by executing actual commands
async function handleAgentRequest(query) {
  const originalQuery = query.trim(); // Keep original for case-sensitive operations
  const q = query.toLowerCase().trim(); // Lowercase for pattern matching

  // Direct command mode: $ command or shell: command
  if (q.startsWith('$') || q.startsWith('shell:') || q.startsWith('run:')) {
    const cmd = originalQuery.replace(/^(\$|shell:|run:)\s*/i, '');
    return executeCommand(cmd);
  }

  // Direct cd command
  if (q.startsWith('cd ')) {
    const path = originalQuery.slice(3).trim();
    return changeDirectory(path);
  }

  // Read file: cat, read, show file
  if (q.startsWith('cat ') || q.startsWith('read ') || q.match(/^show\s+(me\s+)?(the\s+)?file/i)) {
    const pathMatch = query.match(/(?:cat|read|file)\s+(.+)/i);
    if (pathMatch) {
      return readFile(pathMatch[1].trim());
    }
  }

  // Session info
  if (q === 'pwd' || q === 'where am i' || q.includes('current directory')) {
    return `📁 **Current directory:** ${session.cwd}`;
  }

  // Common "what's here" queries - run ls
  if (q.match(/what'?s?\s+(in\s+)?(here|this|the\s+folder|this\s+folder|this\s+directory)/i) ||
      q === 'ls' || q === 'dir' || q === 'list' || q === 'show me' || q === 'show files') {
    const output = runCommand('ls -la');
    return `**Contents of ${session.cwd}:**\n\`\`\`\n${output}\`\`\``;
  }

  // Plex diagnostics - comprehensive check
  if (q.includes('plex')) {
    return await diagnosePlex(query);
  }

  // === DIRECT PATTERN MATCHING FOR COMMON QUERIES ===
  // These bypass the LLM for reliability

  // "is X running" / "check if X is running"
  const runningMatch = q.match(/(?:is\s+)?(\w+)\s+(?:running|up|active|started)/i) ||
                       q.match(/check\s+(?:if\s+)?(\w+)\s+(?:is\s+)?running/i);
  if (runningMatch) {
    const proc = runningMatch[1];
    const result = runCommand(`pgrep -fl "${proc}" 2>/dev/null`);
    if (result.trim()) {
      return `✅ **${proc} is running:**\n\`\`\`\n${result}\`\`\``;
    } else {
      return `❌ **${proc}** is not running.`;
    }
  }

  // "what's on port X" / "port X" / "check port X"
  const portMatch = q.match(/(?:what'?s?\s+(?:on|using)\s+)?port\s+(\d+)/i) ||
                    q.match(/check\s+port\s+(\d+)/i);
  if (portMatch) {
    const port = portMatch[1];
    const result = runCommand(`lsof -i :${port} 2>/dev/null`);
    if (result.trim()) {
      return `**Port ${port}:**\n\`\`\`\n${result}\`\`\``;
    } else {
      return `Port ${port} is not in use.`;
    }
  }

  // "find files named X" / "find X files"
  const findMatch = q.match(/find\s+(?:files?\s+)?(?:named\s+)?['""]?([^\s'"]+)['""]?/i) ||
                    q.match(/(?:search|look)\s+for\s+(?:files?\s+)?(?:named\s+)?['""]?([^\s'"]+)['""]?/i);
  if (findMatch && !q.includes(' in ')) {
    const pattern = findMatch[1];
    const result = runCommand(`find . -name "${pattern}" 2>/dev/null | head -30`, 30000);
    return `**Files matching "${pattern}":**\n\`\`\`\n${result || 'No files found'}\`\`\`\n\n📁 ${session.cwd}`;
  }

  // "search for X in file" / "grep X in file"
  const grepMatch = q.match(/(?:search|grep|find)\s+(?:for\s+)?['""]?([^'"]+)['""]?\s+in\s+(.+)/i);
  if (grepMatch) {
    const pattern = grepMatch[1].trim();
    const file = grepMatch[2].trim().replace(/^~/, os.homedir());
    const result = runCommand(`grep -n "${pattern}" "${file}" 2>/dev/null`);
    if (result.trim()) {
      return `**Matches for "${pattern}" in ${file}:**\n\`\`\`\n${result}\`\`\``;
    } else {
      return `No matches for "${pattern}" in ${file}`;
    }
  }

  // Disk space queries
  if (q.match(/disk\s*space|how\s+much\s+space|storage|free\s+space|disk\s+usage/i)) {
    const result = runCommand('df -h');
    return `**Disk Space:**\n\`\`\`\n${result}\`\`\``;
  }

  // Memory/RAM queries
  if (q.match(/(?:how\s+much\s+)?(?:ram|memory)\s*(?:is\s+)?(?:free|available|used|usage)/i) ||
      q.match(/free\s+(?:ram|memory)/i)) {
    const vmstat = runCommand('vm_stat');
    const free = vmstat.match(/Pages free:\s+(\d+)/)?.[1] || 0;
    const inactive = vmstat.match(/Pages inactive:\s+(\d+)/)?.[1] || 0;
    const wired = vmstat.match(/Pages wired down:\s+(\d+)/)?.[1] || 0;
    const active = vmstat.match(/Pages active:\s+(\d+)/)?.[1] || 0;

    const freeGB = ((parseInt(free) + parseInt(inactive)) * 4096 / 1024 / 1024 / 1024).toFixed(2);
    const usedGB = ((parseInt(wired) + parseInt(active)) * 4096 / 1024 / 1024 / 1024).toFixed(2);

    const sysctl = runCommand('sysctl -n hw.memsize');
    const totalGB = (parseInt(sysctl) / 1024 / 1024 / 1024).toFixed(0);

    return `**Memory Status:**\n- **Total RAM:** ${totalGB} GB\n- **Used:** ~${usedGB} GB\n- **Available:** ~${freeGB} GB\n\n\`\`\`\n${vmstat}\`\`\``;
  }

  // "in there" / "in here" after cd (context-aware)
  if (q.match(/(?:what'?s?\s+)?in\s+(?:there|this|that)/i) || q === 'show me' || q === 'list') {
    const result = runCommand('ls -la');
    return `**Contents of ${session.cwd}:**\n\`\`\`\n${result}\`\`\``;
  }

  // Top CPU consumers
  if (q.match(/(?:what'?s?\s+)?(?:using|eating|consuming|hogging)\s+(?:the\s+)?(?:most\s+)?(?:cpu|processor)/i) ||
      q.match(/top\s+(?:cpu|processes)/i)) {
    const result = runCommand('ps aux | sort -rk 3 | head -15');
    return `**Top CPU Consumers:**\n\`\`\`\n${result}\`\`\``;
  }

  // Top memory consumers
  if (q.match(/(?:what'?s?\s+)?(?:using|eating|consuming|hogging)\s+(?:the\s+)?(?:most\s+)?(?:memory|ram)/i)) {
    const result = runCommand('ps aux | sort -rk 4 | head -15');
    return `**Top Memory Consumers:**\n\`\`\`\n${result}\`\`\``;
  }

  // Network connections
  if (q.match(/(?:show\s+)?(?:network|active)\s+connections/i) || q.match(/netstat/i)) {
    const result = runCommand('netstat -an | head -40');
    const services = runCommand('networksetup -listallnetworkservices');
    return `**Network Services:**\n\`\`\`\n${services}\`\`\`\n\n**Active Connections:**\n\`\`\`\n${result}\`\`\``;
  }

  // Uptime
  if (q.match(/uptime|how\s+long\s+(?:has\s+)?(?:the\s+)?(?:system|computer|mac)\s+(?:been\s+)?running/i)) {
    const result = runCommand('uptime');
    return `**System Uptime:**\n${result}`;
  }

  // === NEW CLAUDE CODE TOOL HANDLERS ===

  // Edit file: edit file.txt "old" "new" [--all|true] - use originalQuery to preserve case
  const editMatch = originalQuery.match(/^edit\s+(\S+)\s+["'](.+?)["']\s+["'](.+?)["'](?:\s+(--all|true))?/i);
  if (editMatch) {
    const replaceAll = editMatch[4]?.toLowerCase() === '--all' || editMatch[4]?.toLowerCase() === 'true';
    return editFile(editMatch[1], editMatch[2], editMatch[3], replaceAll);
  }

  // Glob: glob *.js or glob src/**/*.ts - use originalQuery for case-sensitive paths
  const globMatch = originalQuery.match(/^glob\s+(.+)/i);
  if (globMatch) {
    return globFiles(globMatch[1].trim());
  }

  // WebFetch: fetch https://... or webfetch url
  const fetchMatch = q.match(/^(?:fetch|webfetch)\s+(https?:\/\/\S+)(?:\s+(.+))?/i);
  if (fetchMatch) {
    return await webFetch(fetchMatch[1], fetchMatch[2] || 'Summarize this page');
  }

  // Git commands
  if (q === 'git status' || q === 'gs') {
    return gitStatus();
  }
  if (q.match(/^git\s+diff(\s+\S+)?$/i)) {
    const file = q.match(/^git\s+diff\s+(\S+)$/i)?.[1];
    return gitDiff(file);
  }
  if (q.match(/^git\s+log(\s+\d+)?$/i)) {
    const count = parseInt(q.match(/\d+/)?.[0]) || 10;
    return gitLog(count);
  }
  if (q.match(/^git\s+commit\s+["'](.+)["']$/i)) {
    const message = q.match(/["'](.+)["']/)[1];
    return gitCommit(message);
  }
  if (q.match(/^git\s+add\s+(.+)$/i)) {
    const files = q.match(/^git\s+add\s+(.+)$/i)[1];
    return executeCommand(`git add ${files}`);
  }

  // File operations: mkdir, cp, mv, rm
  // File operations - use originalQuery to preserve case in paths
  const mkdirMatch = originalQuery.match(/^mkdir\s+(.+)/i);
  if (mkdirMatch) {
    return mkdir(mkdirMatch[1].trim());
  }

  const cpMatch = originalQuery.match(/^cp\s+(\S+)\s+(\S+)/i);
  if (cpMatch) {
    return copyFile(cpMatch[1], cpMatch[2]);
  }

  const mvMatch = originalQuery.match(/^mv\s+(\S+)\s+(\S+)/i);
  if (mvMatch) {
    return moveFile(mvMatch[1], mvMatch[2]);
  }

  // rm command - extract path from various forms like "rm file", "rm -rf dir", "rm -f file"
  const rmMatch = originalQuery.match(/^rm\s+(?:-\w+\s+)*(.+)/i);
  if (rmMatch) {
    const path = rmMatch[1].trim();
    // Only block if trying to delete root or home directly
    if (path === '/' || path === '~' || path === '*') {
      return '⚠️ **Blocked:** Cannot delete root, home, or wildcard';
    }
    return deleteFile(path);
  }

  // Delete handler (alias for rm)
  const deleteMatch = originalQuery.match(/^delete\s+(.+)/i);
  if (deleteMatch) {
    return deleteFile(deleteMatch[1].trim());
  }

  // Environment variables - use originalQuery to preserve case in values
  const exportMatch = originalQuery.match(/^(?:export|set)\s+(\w+)=(.+)/i);
  if (exportMatch) {
    return setEnvVar(exportMatch[1], exportMatch[2]);
  }

  const envMatch = q.match(/^(?:echo\s+\$|env\s+|getenv\s+)(\w+)/i);
  if (envMatch) {
    const value = getEnvVar(envMatch[1]);
    return `**$${envMatch[1]}:** ${value}`;
  }

  if (q === 'env' || q === 'printenv') {
    return listEnvVars();
  }

  // Background tasks
  const bgMatch = q.match(/^(?:bg|background|&)\s+(.+)/i);
  if (bgMatch) {
    return runBackground(bgMatch[1]);
  }

  if (q === 'tasks' || q === 'jobs') {
    return listBackgroundTasks();
  }

  const taskMatch = q.match(/^task\s+(\w+)/i);
  if (taskMatch) {
    return getTaskOutput(taskMatch[1]);
  }

  const killMatch = q.match(/^kill\s+(\w+)/i);
  if (killMatch && !q.includes('kill -')) {
    return killTask(killMatch[1]);
  }

  // Approval workflow
  const approveMatch = q.match(/^approve\s+(\w+)/i);
  if (approveMatch) {
    return handleApproval(approveMatch[1], true);
  }

  const denyMatch = q.match(/^deny\s+(\w+)/i);
  if (denyMatch) {
    return handleApproval(denyMatch[1], false);
  }

  // Code analysis: explain file.js or analyze file.py
  const analyzeMatch = q.match(/^(?:explain|analyze|review)\s+(\S+)(?:\s+(.+))?/i);
  if (analyzeMatch && existsSync(analyzeMatch[1].replace('~', os.homedir()))) {
    const question = analyzeMatch[2] || 'Explain what this code does';
    return await analyzeCode(analyzeMatch[1], question);
  }

  // Write file: write file.txt "content"
  const writeMatch = q.match(/^write\s+(\S+)\s+["'](.+)["']/is);
  if (writeMatch) {
    return writeFile(writeMatch[1], writeMatch[2]);
  }

  // Append: append file.txt "content"
  const appendMatch = q.match(/^append\s+(\S+)\s+["'](.+)["']/is);
  if (appendMatch) {
    return writeFile(appendMatch[1], appendMatch[2], true);
  }

  // Touch: create empty file
  const touchMatch = q.match(/^touch\s+(\S+)/i);
  if (touchMatch) {
    return writeFile(touchMatch[1], '');
  }

  // History
  if (q === 'history' || q.includes('command history')) {
    if (session.history.length === 0) return 'No command history yet.';
    const recent = session.history.slice(-10).map((h, i) =>
      `${i + 1}. ${h.success ? '✅' : '❌'} \`${h.cmd}\``
    ).join('\n');
    return `**Recent Commands:**\n${recent}`;
  }

  // Help
  if (q === 'help' || q === '?') {
    return `## Warp Remote Agent - Full Claude Code Parity

**Shell Commands:**
• \`$ command\` - Run any shell command
• \`cd ~/path\` - Change directory (persists)
• \`pwd\` - Current directory
• \`history\` - Command history

**File Operations:**
• \`cat file\` - Read file
• \`write file "content"\` - Create/overwrite file
• \`append file "content"\` - Append to file
• \`edit file "old" "new"\` - Find/replace
• \`touch file\` - Create empty file
• \`mkdir dir\` - Create directory
• \`cp src dest\` - Copy file
• \`mv src dest\` - Move/rename
• \`rm file\` - Delete file

**Search:**
• \`find pattern\` - Find files by name
• \`glob *.js\` - Glob pattern search
• \`search "text" in file\` - Search in file

**Git:**
• \`git status\` / \`gs\` - Git status
• \`git diff [file]\` - Show diff
• \`git log [n]\` - Recent commits
• \`git add files\` - Stage files
• \`git commit "msg"\` - Commit (requires approval)

**Background Tasks:**
• \`bg command\` - Run in background
• \`tasks\` - List background tasks
• \`task id\` - Get task output
• \`kill id\` - Kill task

**Environment:**
• \`export VAR=value\` - Set env var
• \`echo $VAR\` - Get env var
• \`env\` - List all env vars

**Analysis:**
• \`explain file.js\` - Analyze code
• \`fetch url\` - Fetch & analyze URL

**System:**
• \`is X running\` - Check process
• \`port 8080\` - Check port
• \`disk space\` - Disk usage
• \`ram\` - Memory status
• \`uptime\` - System uptime

**Approvals:**
• \`approve id\` - Approve action
• \`deny id\` - Deny action

📁 **Current:** ${session.cwd}`;
  }

  // Detect complex tasks that need multi-step investigation
  const complexPatterns = [
    /why\s+(is|does|are)/i,
    /research/i,
    /investigate/i,
    /troubleshoot/i,
    /diagnose/i,
    /figure\s+out/i,
    /help\s+me\s+(understand|fix|solve)/i,
    /what'?s?\s+(wrong|causing|the\s+problem)/i,
    /slow/i,
    /not\s+working/i,
    /broken/i,
    /debug/i,
    /analyze/i
  ];

  const isComplexTask = complexPatterns.some(p => p.test(q));

  if (isComplexTask) {
    // Use multi-step agentic execution
    return await executeAgenticTask(query);
  }

  // Try LLM interpretation for simpler conversational queries
  const intent = await interpretIntent(query);

  if (intent) {
    switch (intent.type) {
      case 'command':
        return executeCommand(intent.cmd);

      case 'cd':
        return changeDirectory(intent.path);

      case 'read':
        return readFile(intent.path);

      case 'write':
        return writeFile(intent.path, intent.content, intent.append);

      case 'investigate':
        return await executeAgenticTask(intent.topic || query);

      case 'chat':
        return intent.response || "I'm not sure how to help with that. Try asking about your system or type `help` for options.";
    }
  }

  // Fallback: try to run as command if it looks like one
  if (q.match(/^[a-z]+(\s|$)/) && !q.includes('?')) {
    // Looks like a command (starts with lowercase word)
    const output = runCommand(query, 30000);
    if (output && !output.includes('command not found')) {
      return `**\`${query}\`**\n\`\`\`\n${output.slice(0, 3000)}\`\`\`\n\n📁 ${session.cwd}`;
    }
  }

  // Ultimate fallback
  return `I'm not sure what you mean. Try:
• \`$ command\` to run a shell command directly
• \`help\` for full options
• Or ask naturally: "what's using the most memory?"

📁 Current directory: ${session.cwd}`;
}

// Execute a command with safety checks
function executeCommand(cmd) {
  // Safety check - block dangerous commands
  // Note: we check for exact dangerous patterns, not substrings
  const lowerCmd = cmd.toLowerCase().trim();

  // Block: rm -rf / or rm -rf ~ (but NOT rm -rf /tmp/something)
  if (/rm\s+(-\w+\s+)*\/\s*$/.test(lowerCmd) || // rm -rf /
      /rm\s+(-\w+\s+)*~\s*$/.test(lowerCmd) || // rm -rf ~
      /rm\s+(-\w+\s+)*\*\s*$/.test(lowerCmd)) { // rm -rf *
    return '⚠️ **Blocked:** That command could cause serious damage. I won\'t execute it.';
  }

  // Block other system-level dangerous commands
  const dangerous = ['mkfs', 'dd if=/dev', ':(){', 'chmod -R 777 /', 'sudo rm -rf /'];
  if (dangerous.some(d => lowerCmd.includes(d))) {
    return '⚠️ **Blocked:** That command could cause serious damage. I won\'t execute it.';
  }

  // Warn about sudo
  if (cmd.startsWith('sudo ')) {
    return `⚠️ **Sudo required.** I can't run sudo commands remotely for security reasons.\n\nCommand: \`${cmd}\`\n\nRun this directly on your Mac if you trust it.`;
  }

  // Long-running command detection
  const longRunning = ['npm install', 'brew install', 'pip install', 'cargo build', 'make', 'xcodebuild'];
  const isLongRunning = longRunning.some(lr => cmd.includes(lr));
  const timeout = isLongRunning ? 300000 : 60000; // 5 min or 1 min

  const output = runCommand(cmd, timeout);

  // Format output
  const truncated = output.length > 4000 ? output.slice(0, 4000) + '\n\n... (truncated)' : output;

  return `**\`${cmd}\`**\n\`\`\`\n${truncated}\`\`\`\n\n📁 ${session.cwd}`;
}

// HTTP handler
function handleRequest(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = req.url || '/';

  if (url === '/' || url === '/remote' || url === '/remote.html') {
    serveRemoteUI(res);
    return;
  }

  if (url === '/api/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      running: true,
      connectedDevices: clients.size,
      status: systemStatus
    }));
    return;
  }

  if (url.startsWith('/api/poll')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      messages: messages,
      status: { ...systemStatus, connectedDevices: clients.size }
    }));
    return;
  }

  if (url === '/api/send' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { content } = JSON.parse(body);

        // Add user message
        const userMsg = {
          id: randomBytes(4).toString('hex'),
          type: 'user',
          content: content,
          timestamp: new Date().toISOString()
        };
        messages.push(userMsg);

        // Real agent - execute actual commands based on intent
        let aiContent = await handleAgentRequest(content);

        const aiMsg = {
          id: randomBytes(4).toString('hex'),
          type: 'ai',
          content: aiContent,
          timestamp: new Date().toISOString()
        };
        messages.push(aiMsg);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, response: aiMsg.content, id: aiMsg.id }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  if (url === '/manifest.json') {
    const manifestPath = join(__dirname, '..', 'public', 'manifest.json');
    if (existsSync(manifestPath)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(readFileSync(manifestPath));
      return;
    }
  }

  if (url === '/sw.js') {
    const swPath = join(__dirname, '..', 'public', 'sw.js');
    if (existsSync(swPath)) {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end(readFileSync(swPath));
      return;
    }
  }

  res.writeHead(404);
  res.end('Not found');
}

// WebSocket handler
function handleWebSocket(ws) {
  const clientId = randomBytes(8).toString('hex');
  clients.set(clientId, ws);

  console.log(`Client connected: ${clientId} (${clients.size} total)`);
  broadcast({ type: 'status', connectedDevices: clients.size });

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      handleClientMessage(clientId, ws, msg);
    } catch (e) {
      console.error('Message parse error:', e);
    }
  });

  ws.on('close', () => {
    clients.delete(clientId);
    console.log(`Client disconnected: ${clientId} (${clients.size} remaining)`);
    broadcast({ type: 'status', connectedDevices: clients.size });
  });
}

function handleClientMessage(clientId, ws, msg) {
  switch (msg.type) {
    case 'get_state':
      ws.send(JSON.stringify({
        type: 'state',
        messages,
        approvals,
        status: { ...systemStatus, connectedDevices: clients.size }
      }));
      break;

    case 'message':
      const userMsg = {
        id: randomBytes(4).toString('hex'),
        type: 'user',
        content: msg.content,
        timestamp: new Date().toISOString()
      };
      messages.push(userMsg);
      broadcast({ type: 'message', ...userMsg, from: 'user' });

      // Simulate AI thinking
      broadcast({ type: 'typing' });

      // Echo back (replace with actual AI integration)
      setTimeout(() => {
        const aiMsg = {
          id: randomBytes(4).toString('hex'),
          type: 'ai',
          content: `Received: "${msg.content}". Connect the AI agent for real responses.`,
          timestamp: new Date().toISOString()
        };
        messages.push(aiMsg);
        broadcast({ type: 'message', ...aiMsg, from: 'ai' });
      }, 500);
      break;

    case 'approval_response':
      const idx = approvals.findIndex(a => a.id === msg.id);
      if (idx >= 0) {
        approvals.splice(idx, 1);
        broadcast({ type: 'approval_resolved', id: msg.id, approved: msg.approved });
      }
      break;

    case 'ping':
      ws.send(JSON.stringify({ type: 'pong' }));
      break;
  }
}

function broadcast(message) {
  const data = JSON.stringify(message);
  for (const client of clients.values()) {
    if (client.readyState === 1) { // WebSocket.OPEN
      client.send(data);
    }
  }
}

// Generate self-signed certificate if needed
function ensureCerts() {
  if (!existsSync(CERT_DIR)) {
    mkdirSync(CERT_DIR, { recursive: true });
  }

  const keyPath = join(CERT_DIR, 'key.pem');
  const certPath = join(CERT_DIR, 'cert.pem');

  // Try to get Tailscale hostname for the cert
  let hostname = 'localhost';
  try {
    const result = execSync('/Applications/Tailscale.app/Contents/MacOS/Tailscale status --json', {
      encoding: 'utf8',
      timeout: 5000
    });
    const status = JSON.parse(result);
    if (status.Self?.DNSName) {
      hostname = status.Self.DNSName.replace(/\.$/, '');
    }
  } catch {}

  if (!existsSync(keyPath) || !existsSync(certPath)) {
    console.log('Generating self-signed certificate...');
    try {
      // Generate self-signed cert valid for 1 year
      execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 365 -nodes -subj "/CN=${hostname}" -addext "subjectAltName=DNS:${hostname},DNS:localhost,IP:127.0.0.1"`, {
        encoding: 'utf8',
        timeout: 30000
      });
      console.log('Certificate generated successfully');
    } catch (e) {
      console.error('Failed to generate certificate:', e.message);
      return null;
    }
  }

  try {
    return {
      key: readFileSync(keyPath),
      cert: readFileSync(certPath)
    };
  } catch {
    return null;
  }
}

// Setup upgrade handler for WebSocket
function setupUpgradeHandler(server, wss) {
  server.on('upgrade', (request, socket, head) => {
    if (request.url === '/ws') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        handleWebSocket(ws);
      });
    } else {
      socket.destroy();
    }
  });
}

// Start servers
const httpServer = http.createServer(handleRequest);
const wss = new WebSocketServer({ noServer: true });
setupUpgradeHandler(httpServer, wss);

// Try to start HTTPS server
const certs = ensureCerts();
let httpsServer = null;
let httpsWss = null;

if (certs) {
  httpsServer = https.createServer(certs, handleRequest);
  httpsWss = new WebSocketServer({ noServer: true });
  setupUpgradeHandler(httpsServer, httpsWss);
}

httpServer.listen(PORT, '0.0.0.0', () => {
  const localIP = getLocalIP();
  const tailscaleIP = getTailscaleIP();

  // Start HTTPS if available
  if (httpsServer) {
    httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
      console.log('');
      console.log('╔═══════════════════════════════════════════════════════════╗');
      console.log('║           Warp Open Remote Server                         ║');
      console.log('╠═══════════════════════════════════════════════════════════╣');
      console.log(`║  HTTP:      http://localhost:${PORT}                        ║`);
      console.log(`║  HTTPS:     https://localhost:${HTTPS_PORT}                       ║`);
      console.log('╠═══════════════════════════════════════════════════════════╣');
      if (tailscaleIP) {
        console.log(`║  Tailscale: https://${tailscaleIP}:${HTTPS_PORT}`.padEnd(62) + '║');
      } else {
        console.log(`║  Network:   https://${localIP}:${HTTPS_PORT}`.padEnd(62) + '║');
      }
      console.log('╠═══════════════════════════════════════════════════════════╣');
      console.log('║  On iPhone: Settings → Safari → Advanced → Disable        ║');
      console.log('║  "HTTPS-Only Mode" OR trust the self-signed cert          ║');
      console.log('╠═══════════════════════════════════════════════════════════╣');
      console.log('║  Tap Share → Add to Home Screen for app experience        ║');
      console.log('╚═══════════════════════════════════════════════════════════╝');
      console.log('');
    });
  } else {
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║           Warp Open Remote Server (HTTP only)             ║');
    console.log('╠═══════════════════════════════════════════════════════════╣');
    console.log(`║  Local:     http://localhost:${PORT}                        ║`);
    console.log(`║  Network:   http://${localIP}:${PORT}`.padEnd(62) + '║');
    if (tailscaleIP) {
      console.log(`║  Tailscale: http://${tailscaleIP}:${PORT}`.padEnd(62) + '║');
    }
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log('');
  }
});
