// ai_agent_server.cjs
// Local Agent Bridge server (CommonJS)
// Minimal, local-only HTTP server that holds a command queue, persists state, enforces whitelist,
// and exposes endpoints the frontend can poll to get commands and post results.
//
// Run with: node ai_agent_server.cjs
// (or: npm run agent:start -> see package.json snippet below)

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const os = require('os');

const PORT = process.env.AGENT_PORT ? Number(process.env.AGENT_PORT) : 4005;
const STATE_DIR = path.resolve(__dirname, 'data');
const STATE_FILE = path.join(STATE_DIR, 'agent_state.json');
const WHITELIST_FILE = path.join(STATE_DIR, 'command_whitelist.json');

if (!fs.existsSync(STATE_DIR)) fs.mkdirSync(STATE_DIR, { recursive: true });

// default whitelist (safe commands only)
const DEFAULT_WHITELIST = [
  { cmd: 'ls', args: ['-la'] },
  { cmd: 'cat', args: [] },
  { cmd: 'pwd', args: [] },
  { cmd: 'echo', args: [] },
  { cmd: 'git', args: ['status'] }
];

function loadWhitelist() {
  try {
    if (fs.existsSync(WHITELIST_FILE)) {
      return JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf8'));
    } else {
      fs.writeFileSync(WHITELIST_FILE, JSON.stringify(DEFAULT_WHITELIST, null, 2));
      return DEFAULT_WHITELIST;
    }
  } catch (e) {
    console.error('Failed to load whitelist:', e);
    return DEFAULT_WHITELIST;
  }
}

let whitelist = loadWhitelist();

function defaultState() {
  return {
    queue: [],      // pending commands { id, type, payload, createdAt, approved: bool|null }
    logs: [],       // chronological logs
    results: {},    // result by command id
  };
}

function loadState() {
  try {
    if (!fs.existsSync(STATE_FILE)) {
      const s = defaultState();
      fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2));
      return s;
    }
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Failed to load state file - starting fresh', e);
    return defaultState();
  }
}

function saveState() {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  } catch (e) {
    console.error('Failed to save state', e);
  }
}

function addLog(level, message) {
  state.logs.push({ ts: new Date().toISOString(), level, message });
  // keep bounded logs (10k)
  if (state.logs.length > 10000) state.logs.shift();
  saveState();
}

function genId(prefix = 'cmd') {
  return `${prefix}_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
}

let state = loadState();

// --- Utilities ---
function isWhitelisted(cmd, args) {
  // simple whitelist: command must match and args should match prefix of a whitelisted args set.
  // The whitelist file contains entries like { cmd: 'ls', args: ['-la'] }.
  for (const w of whitelist) {
    if (w.cmd === cmd) {
      // if whitelist entry has args specified, ensure the provided args start with them
      if (!w.args || w.args.length === 0) return true;
      let matches = true;
      for (let i = 0; i < w.args.length; i++) {
        if (args[i] !== w.args[i]) {
          matches = false;
          break;
        }
      }
      if (matches) return true;
    }
  }
  return false;
}

function enqueue(item) {
  const id = genId();
  const entry = Object.assign({ id, createdAt: new Date().toISOString(), approved: null }, item);
  state.queue.push(entry);
  addLog('info', `Enqueued ${entry.type} ${id}`);
  saveState();
  return entry;
}

function dequeue() {
  // return first pending & approved command
  const idx = state.queue.findIndex(q => q.approved === true && !state.results[q.id]);
  if (idx === -1) return null;
  const item = state.queue[idx];
  return item;
}

// Execute whitelisted shell command and capture output (synchronous-ish via events)
function executeShell(id, cmd, args, cwd = process.cwd()) {
  return new Promise((resolve) => {
    addLog('info', `Executing shell command ${cmd} ${args.join(' ')} (id=${id})`);
    const proc = spawn(cmd, args, { cwd, shell: false });
    let out = '';
    let err = '';

    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.stderr.on('data', (d) => { err += d.toString(); });

    proc.on('close', (code) => {
      const result = { id, cmd, args, code, out, err, ts: new Date().toISOString() };
      state.results[id] = result;
      addLog('info', `Command ${id} completed with code ${code}`);
      saveState();
      resolve(result);
    });
    proc.on('error', (e) => {
      const result = { id, cmd, args, code: 1, out: '', err: String(e), ts: new Date().toISOString() };
      state.results[id] = result;
      addLog('error', `Command ${id} failed: ${String(e)}`);
      saveState();
      resolve(result);
    });
  });
}

// --- HTTP API ---
function respondJSON(res, code, obj) {
  const s = JSON.stringify(obj || {});
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(s);
}

function handleOptions(req, res) {
  res.writeHead(204, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end();
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return handleOptions(req, res);

    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    // GET /health
    if (req.method === 'GET' && pathname === '/health') {
      return respondJSON(res, 200, { ok: true, now: new Date().toISOString(), pid: process.pid });
    }

    // GET /state -> returns small state (queue, logs tail)
    if (req.method === 'GET' && pathname === '/state') {
      const tailLogs = state.logs.slice(-200);
      return respondJSON(res, 200, { queue: state.queue, logs: tailLogs, results: state.results });
    }

    // POST /enqueue -> body: { type, payload }
    if (req.method === 'POST' && pathname === '/enqueue') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        let obj = {};
        try { obj = JSON.parse(body || '{}'); } catch (e) { /* ignore */ }
        if (!obj.type || !obj.payload) {
          return respondJSON(res, 400, { error: 'type and payload required' });
        }
        const entry = enqueue({ type: obj.type, payload: obj.payload });
        return respondJSON(res, 200, { ok: true, entry });
      });
      return;
    }

    // POST /approve -> { id, approved: true|false, by: 'user' }
    if (req.method === 'POST' && pathname === '/approve') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        let obj = {};
        try { obj = JSON.parse(body || '{}'); } catch (e) {}
        if (!obj.id) return respondJSON(res, 400, { error: 'id required' });
        const item = state.queue.find(q => q.id === obj.id);
        if (!item) return respondJSON(res, 404, { error: 'not found' });
        item.approved = !!obj.approved;
        item.approvedBy = obj.by || 'unknown';
        item.approvedAt = new Date().toISOString();
        addLog('info', `Command ${obj.id} approved=${item.approved}`);
        saveState();
        return respondJSON(res, 200, { ok: true, item });
      });
      return;
    }

    // POST /execute-now -> force-execute a queued shell command (body: { id })
    if (req.method === 'POST' && pathname === '/execute-now') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', async () => {
        let obj = {};
        try { obj = JSON.parse(body || '{}'); } catch (e) {}
        const id = obj.id;
        const item = state.queue.find(q => q.id === id);
        if (!item) return respondJSON(res, 404, { error: 'not found' });

        // Only support type === 'shell'
        if (item.type !== 'shell') return respondJSON(res, 400, { error: 'unsupported type' });

        const { cmd, args } = item.payload;
        if (!isWhitelisted(cmd, args || [])) {
          addLog('warn', `Attempt to execute non-whitelisted command ${cmd} ${JSON.stringify(args)}`);
          return respondJSON(res, 403, { error: 'command not whitelisted' });
        }

        // mark approved if wasn't explicitly approved
        item.approved = true;
        const r = await executeShell(item.id, cmd, args, item.payload.cwd || process.cwd());
        return respondJSON(res, 200, { ok: true, result: r });
      });
      return;
    }

    // GET /next -> returns next approved command for worker to run
    if (req.method === 'GET' && pathname === '/next') {
      const item = dequeue();
      if (!item) return respondJSON(res, 204, {}); // no content
      return respondJSON(res, 200, { ok: true, item });
    }

    // POST /result -> post result for given id
    if (req.method === 'POST' && pathname === '/result') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        let obj = {};
        try { obj = JSON.parse(body || '{}'); } catch (e) {}
        if (!obj.id) return respondJSON(res, 400, { error: 'id required' });
        state.results[obj.id] = obj.result || {};
        addLog('info', `Result received for ${obj.id}`);
        saveState();
        return respondJSON(res, 200, { ok: true });
      });
      return;
    }

    // GET /whitelist -> returns command whitelist
    if (req.method === 'GET' && pathname === '/whitelist') {
      return respondJSON(res, 200, { whitelist });
    }

    // PUT /whitelist -> replace whitelist (persist)
    if (req.method === 'PUT' && pathname === '/whitelist') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const obj = JSON.parse(body || '{}');
          if (!Array.isArray(obj.whitelist)) return respondJSON(res, 400, { error: 'whitelist array required' });
          whitelist = obj.whitelist;
          fs.writeFileSync(WHITELIST_FILE, JSON.stringify(whitelist, null, 2));
          addLog('info', 'Whitelist updated');
          return respondJSON(res, 200, { ok: true, whitelist });
        } catch (e) {
          return respondJSON(res, 400, { error: String(e) });
        }
      });
      return;
    }

    // GET /logs
    if (req.method === 'GET' && pathname === '/logs') {
      return respondJSON(res, 200, { logs: state.logs.slice(-500) });
    }

    // fallback
    respondJSON(res, 404, { error: 'not found' });

  } catch (e) {
    console.error('Server error', e);
    respondJSON(res, 500, { error: String(e) });
  }
});

server.listen(PORT, () => {
  addLog('info', `AI Agent server started on port ${PORT}`);
  console.log(`AI Agent server running at http://localhost:${PORT}`);
});
