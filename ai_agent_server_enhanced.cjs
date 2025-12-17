// ai_agent_server_enhanced.cjs
// CommonJS Node server that auto-detects multiple local LLM integration points
// and exposes a single /generate endpoint that routes prompts to available backends.
// Run with: node ai_agent_server_enhanced.cjs
//
// Safety: non-destructive by default. CLI binaries list is a whitelist (edit with care).
// Note: socket integration is detected but only reported; implementation for custom socket
// protocols may require adaptation.

const http = require('http');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const os = require('os');

const execFileAsync = promisify(execFile);

const PORT = process.env.AGENT_PORT ? parseInt(process.env.AGENT_PORT, 10) : 4005;
const PROBE_TIMEOUT = 1200; // ms for HTTP probe

// Candidate HTTP ports commonly used by local LLM apps (add/remove as you discover)
const LOCAL_PORTS = [
  11434, // Ollama default
  9999,  // ChatGPT Desktop (requires auth - discovery only)
  1234,  // LM Studio default
  8080,  // LocalAI default
  7860,  // text-generation-webui (oobabooga)
  5001,  // Jan AI
  17800, // hypothetical Anthropic local
  3000, 5173, 4005, // dev/debug
];

// Candidate unix sockets (common patterns; expand as you find them)
const SOCKET_PATHS = [
  '/tmp/chatgpt.sock',
  '/tmp/claude.sock',
  path.join(os.homedir(), '.config', 'chatgpt', 'server.sock'),
];

// Whitelisted CLI binaries inside app bundles (non-exhaustive; edit as needed)
const WHITELISTED_BINARIES = [
  '/Applications/ChatGPT.app/Contents/Resources/chatgpt-cli',
  '/Applications/Claude.app/Contents/Resources/claude-cli',
  '/usr/local/bin/ollama',
  '/opt/homebrew/bin/ollama',
];

// File-watch candidate paths (apps that write tasks to a folder)
const FILE_CHANNELS = [
  path.join(os.homedir(), 'Library', 'Application Support', 'ChatGPT', 'tasks'),
  path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'tasks'),
  path.join(os.homedir(), '.local', 'share', 'llm_bridge', 'inbox'),
];

// backend registry - will populate on discovery
let backends = {
  http: [],    // { port, urlBase? }
  socket: [],  // { path }
  cli: [],     // { path }
  file: [],    // { path }
};

// Simple in-memory log
const logs = [];

// Helper: push log
function log(msg, meta) {
  const entry = { ts: new Date().toISOString(), msg, meta };
  console.log(entry.ts, msg, meta || '');
  logs.push(entry);
  if (logs.length > 2000) logs.shift();
}

// Probe local HTTP port quickly
function probePort(port, pathProbe = '/health') {
  return new Promise(resolve => {
    const req = http.request(
      { method: 'GET', hostname: '127.0.0.1', port, path: pathProbe, timeout: PROBE_TIMEOUT },
      res => {
        // consider 2xx/3xx as alive
        const ok = res.statusCode >= 200 && res.statusCode < 400;
        res.resume();
        resolve(ok);
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

// Synchronous probe for unix socket existence
function probeSocket(s) {
  try {
    return fs.existsSync(s);
  } catch (e) {
    return false;
  }
}

// Check for whitelisted CLI binaries
function probeCLIs() {
  const found = [];
  for (const p of WHITELISTED_BINARIES) {
    try {
      if (fs.existsSync(p)) {
        found.push(p);
      }
    } catch (e) {
      // ignore
    }
  }
  return found;
}

// Probe file channels
function probeFileChannels() {
  const found = [];
  for (const p of FILE_CHANNELS) {
    try {
      if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
        found.push(p);
      }
    } catch (e) { /* ignore */ }
  }
  return found;
}

// Discover backends (populate 'backends' object). Non-blocking, safe.
async function discoverBackends() {
  log('Starting backend discovery');
  const httpFound = [];
  for (const p of LOCAL_PORTS) {
    try {
      const ok = await probePort(p, '/');
      if (ok) {
        httpFound.push({ port: p, sample: `/` });
        log(`HTTP backend found on port ${p}`);
      }
    } catch (e) {
      // ignore
    }
  }
  backends.http = httpFound;

  const sockets = [];
  for (const s of SOCKET_PATHS) {
    if (probeSocket(s)) {
      sockets.push({ path: s });
      log(`Socket backend found at ${s}`);
    }
  }
  backends.socket = sockets;

  const clis = probeCLIs();
  backends.cli = clis.map(p => ({ path: p }));
  for (const c of backends.cli) log('CLI backend found: ' + c.path);

  const files = probeFileChannels();
  backends.file = files.map(p => ({ path: p }));
  for (const f of backends.file) log('File channel backend found: ' + f.path);

  return backends;
}

// Route prompt to a backend type: http -> cli -> file -> socket (configurable fallback order)
async function routePrompt(prompt, opts = {}) {
  const fallbackOrder = opts.order || ['http', 'cli', 'file', 'socket'];
  log('Routing prompt, fallbackOrder=' + fallbackOrder.join(','), { promptPreview: prompt.slice(0, 120) });

  // 1) HTTP backends: POST /generate or /api/generate (Ollama)
  if (fallbackOrder.includes('http') && backends.http.length) {
    for (const h of backends.http) {
      try {
        // Ollama uses /api/generate, others might use /generate
        const isOllama = h.port === 11434;
        const apiPath = isOllama ? '/api/generate' : '/generate';
        const modelToUse = opts.model || 'llama3.2:3b-instruct-q4_K_M';
        const payload = isOllama
          ? { model: modelToUse, prompt, stream: false }
          : { prompt };

        const url = { hostname: '127.0.0.1', port: h.port, path: apiPath, method: 'POST' };
        const resp = await new Promise((resolve, reject) => {
          const req = http.request(url, res => {
            let data = '';
            res.on('data', d => (data += d));
            res.on('end', () => resolve({ status: res.statusCode, body: data }));
          });
          req.on('error', reject);
          req.setTimeout(30000, () => req.destroy(new Error('HTTP backend timeout')));
          req.setHeader = req.setHeader || function () {}; // safety for some Node versions
          req.setHeader('Content-Type', 'application/json');
          req.write(JSON.stringify(payload));
          req.end();
        });
        if (resp.status >= 200 && resp.status < 300) {
          log('HTTP backend succeeded', { port: h.port });
          return { backend: 'http', port: h.port, raw: resp.body, parsed: tryParse(resp.body) };
        } else {
          log('HTTP backend returned non-2xx', { port: h.port, status: resp.status });
        }
      } catch (e) {
        log('HTTP backend error', { port: h.port, err: String(e) });
      }
    }
  }

  // 2) CLI backends: call whitelisted binary with safe args
  if (fallbackOrder.includes('cli') && backends.cli.length) {
    for (const c of backends.cli) {
      try {
        // Example: accepted pattern: binary --prompt "<prompt>" (not universal)
        // This is intentionally conservative — many apps don't expose a CLI
        const args = ['--prompt', prompt];
        log('Attempting CLI backend', { binary: c.path });
        const { stdout, stderr } = await execFileAsync(c.path, args, { timeout: 10000, maxBuffer: 1024 * 1024 });
        if (stdout && stdout.length) {
          log('CLI backend produced output', { binary: c.path });
          return { backend: 'cli', binary: c.path, raw: stdout, parsed: tryParse(stdout) };
        } else {
          log('CLI backend produced no stdout', { binary: c.path, stderr: stderr && stderr.slice(0, 200) });
        }
      } catch (e) {
        log('CLI backend error', { binary: c.path, err: String(e).slice(0, 200) });
      }
    }
  }

  // 3) File channel backends: write request file and optionally wait for response file
  if (fallbackOrder.includes('file') && backends.file.length) {
    for (const f of backends.file) {
      try {
        const inbox = f.path;
        const id = `task_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
        const reqFile = path.join(inbox, `${id}.req.json`);
        const resFile = path.join(inbox, `${id}.res.json`);
        const payload = { id, prompt, createdAt: new Date().toISOString() };
        fs.writeFileSync(reqFile, JSON.stringify(payload, null, 2), { flag: 'w' });
        log('Wrote file-channel request', { reqFile });
        // Wait short time for response (non-blocking long wait)
        const start = Date.now();
        const timeout = 6000; // ms
        while (Date.now() - start < timeout) {
          if (fs.existsSync(resFile)) {
            const content = fs.readFileSync(resFile, 'utf8');
            try {
              const parsed = JSON.parse(content);
              log('File-channel response found', { resFile });
              return { backend: 'file', path: f.path, raw: content, parsed };
            } catch (e) {
              log('File-channel response parse error', { err: String(e) });
              break;
            }
          }
          await sleep(250);
        }
        log('File-channel no response within timeout', { inbox: f.path });
      } catch (e) {
        log('File-channel error', { err: String(e) });
      }
    }
  }

  // 4) Socket - detection only (implementation depends on protocol)
  if (fallbackOrder.includes('socket') && backends.socket.length) {
    // For safety we don't attempt arbitrary socket comms here. Report that socket is available.
    for (const s of backends.socket) {
      log('Socket backend available but protocol not auto-implemented', { path: s.path });
      // If you implement a specific protocol for the socket, add it here.
    }
    // continue to fail
  }

  throw new Error('No backend responded successfully');
}

function tryParse(s) {
  try {
    return JSON.parse(s);
  } catch (e) {
    return null;
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// --- HTTP server endpoints: /health, /discover, /backends, /logs, /generate
const server = http.createServer(async (req, res) => {
  try {
    // parse URL
    const url = req.url || '/';
    if (req.method === 'GET' && url.startsWith('/health')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, now: new Date().toISOString(), pid: process.pid }));
      return;
    }

    if (req.method === 'GET' && url.startsWith('/discover')) {
      // run discovery on demand
      await discoverBackends();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, backends }, null, 2));
      return;
    }

    if (req.method === 'GET' && url.startsWith('/backends')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, backends }, null, 2));
      return;
    }

    if (req.method === 'GET' && url.startsWith('/logs')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, logs: logs.slice(-200) }, null, 2));
      return;
    }

    if (req.method === 'GET' && url.startsWith('/models')) {
      // Fetch available models from Ollama
      try {
        const ollamaBackend = backends.http.find(h => h.port === 11434);
        if (!ollamaBackend) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, models: [], message: 'Ollama not discovered' }));
          return;
        }
        const modelsResp = await new Promise((resolve, reject) => {
          const req = http.request(
            { hostname: '127.0.0.1', port: 11434, path: '/api/tags', method: 'GET' },
            res => {
              let data = '';
              res.on('data', d => (data += d));
              res.on('end', () => resolve({ status: res.statusCode, body: data }));
            }
          );
          req.on('error', reject);
          req.setTimeout(5000, () => req.destroy(new Error('Models fetch timeout')));
          req.end();
        });
        if (modelsResp.status === 200) {
          const parsed = tryParse(modelsResp.body);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, models: parsed?.models || [] }, null, 2));
        } else {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'ollama-error' }));
        }
      } catch (e) {
        log('Models fetch error', { err: String(e) });
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'fetch-failed', message: String(e) }));
      }
      return;
    }

    if (req.method === 'POST' && url.startsWith('/stream')) {
      // Streaming endpoint using Server-Sent Events (SSE)
      let body = '';
      req.on('data', chunk => (body += chunk));
      req.on('end', async () => {
        let json;
        try {
          json = body ? JSON.parse(body) : {};
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'invalid-json' }));
          return;
        }
        const prompt = (json.prompt || '').toString();
        if (!prompt || prompt.trim().length === 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'empty-prompt' }));
          return;
        }

        // Set up SSE headers
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        });

        try {
          const modelToUse = json.model || 'llama3.2:3b-instruct-q4_K_M';
          const ollamaBackend = backends.http.find(h => h.port === 11434);

          if (!ollamaBackend) {
            res.write(`data: ${JSON.stringify({ error: 'ollama-not-found' })}\n\n`);
            res.end();
            return;
          }

          // Stream from Ollama
          const streamReq = http.request(
            {
              hostname: '127.0.0.1',
              port: 11434,
              path: '/api/generate',
              method: 'POST',
              headers: { 'Content-Type': 'application/json' }
            },
            streamRes => {
              streamRes.on('data', chunk => {
                // Forward each chunk as SSE event
                const lines = chunk.toString().split('\n').filter(l => l.trim());
                lines.forEach(line => {
                  try {
                    const parsed = JSON.parse(line);
                    res.write(`data: ${JSON.stringify(parsed)}\n\n`);
                  } catch (e) {
                    // Skip invalid JSON
                  }
                });
              });
              streamRes.on('end', () => {
                res.write('data: [DONE]\n\n');
                res.end();
              });
            }
          );

          streamReq.on('error', err => {
            res.write(`data: ${JSON.stringify({ error: String(err) })}\n\n`);
            res.end();
          });

          streamReq.write(JSON.stringify({ model: modelToUse, prompt, stream: true }));
          streamReq.end();
        } catch (e) {
          res.write(`data: ${JSON.stringify({ error: String(e) })}\n\n`);
          res.end();
        }
      });
      return;
    }

    if (req.method === 'POST' && url.startsWith('/generate')) {
      // Accept JSON body { prompt: "...", model?: "...", fallbackOrder?: [] }
      let body = '';
      req.on('data', chunk => (body += chunk));
      req.on('end', async () => {
        let json;
        try {
          json = body ? JSON.parse(body) : {};
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'invalid-json' }));
          return;
        }
        const prompt = (json.prompt || '').toString();
        if (!prompt || prompt.trim().length === 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'empty-prompt' }));
          return;
        }

        try {
          const result = await routePrompt(prompt, {
            order: json.fallbackOrder,
            model: json.model || 'llama3.2:3b-instruct-q4_K_M'
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, route: result }, null, 2));
        } catch (e) {
          log('Route error', { err: String(e) });
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'no-backend', message: String(e) }));
        }
      });
      return;
    }

    if (req.method === 'POST' && url.startsWith('/invoke-desktop')) {
      // Desktop app automation endpoint
      // Body: { app: "ChatGPT" | "Claude", prompt: "...", retries?: 3 }
      let body = '';
      req.on('data', chunk => (body += chunk));
      req.on('end', async () => {
        let json;
        try {
          json = body ? JSON.parse(body) : {};
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'invalid-json' }));
          return;
        }

        const { app, prompt, retries = 3 } = json;

        // Validate input
        if (!app || !['ChatGPT', 'Claude'].includes(app)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            ok: false,
            error: 'invalid-app',
            message: 'app must be "ChatGPT" or "Claude"'
          }));
          return;
        }

        if (!prompt || typeof prompt !== 'string' || prompt.trim().length === 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'empty-prompt' }));
          return;
        }

        try {
          // Import desktop automation module
          const { askDesktopApp, isAppRunning } = require('./desktop_automation.cjs');

          // Check if app is running first
          if (!isAppRunning(app)) {
            res.writeHead(503, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              ok: false,
              error: 'app-not-running',
              message: `${app} is not running. Please start the app and try again.`
            }));
            return;
          }

          log(`Invoking desktop app: ${app}`, { promptLength: prompt.length, retries });

          // Call desktop automation
          const result = await askDesktopApp(app, prompt, {
            retries,
            captureScreenshots: true
          });

          if (result.ok) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              ok: true,
              app,
              response: result.response,
              method: result.method,
              attempt: result.attempt,
              logs: result.logs
            }, null, 2));
          } else {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              ok: false,
              error: 'automation-failed',
              message: result.error,
              screenshot: result.screenshot,
              logs: result.logs
            }, null, 2));
          }
        } catch (e) {
          log('Desktop automation error', { err: String(e) });
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            ok: false,
            error: 'server-error',
            message: String(e)
          }));
        }
      });
      return;
    }

    // default 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'not_found' }));
  } catch (err) {
    log('Server error', { err: String(err) });
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'server_error', message: String(err) }));
  }
});

// initial discovery (non-blocking)
discoverBackends().catch(e => log('Initial discovery failed', { e: String(e) }));

server.listen(PORT, () => {
  log(`LLM Agent Bridge server listening on http://127.0.0.1:${PORT}`);
  log('Use GET /discover to re-run detection, POST /generate with {"prompt":"..."} to route');
});
