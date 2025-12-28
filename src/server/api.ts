/**
 * Cross-Device API Server
 * Access Warp Open from any Apple device
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────┐
 * │                     Your Mac (Server)                       │
 * │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
 * │  │ Warp Open   │──│  API Server  │──│ Tailscale/Tunnel  │  │
 * │  │ Terminal    │  │  (this file) │  │ (secure access)   │  │
 * │  └─────────────┘  └──────────────┘  └───────────────────┘  │
 * └─────────────────────────────────────────────────────────────┘
 *                              │
 *          ┌──────────────────┴───────────────────┐
 *          ▼                  ▼                   ▼
 *     ┌─────────┐       ┌──────────┐        ┌──────────┐
 *     │ iPhone  │       │   iPad   │        │Apple Watch│
 *     │  App    │       │   App    │        │   App     │
 *     └─────────┘       └──────────┘        └──────────┘
 *
 * Features:
 * - REST API for queries
 * - WebSocket for real-time updates
 * - Apple Push Notifications
 * - Siri Shortcuts integration
 * - End-to-end encryption
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from 'crypto';

// ============================================================================
// TYPES
// ============================================================================

export interface ServerConfig {
  port: number;
  host: string;
  enableAuth: boolean;
  authToken?: string;
  enableEncryption: boolean;
  encryptionPassword?: string;
  allowedOrigins: string[];
  maxConnections: number;

  // Apple integrations
  apnsKeyId?: string;
  apnsTeamId?: string;
  apnsKeyPath?: string;
}

export interface APIRequest {
  id: string;
  type: 'query' | 'command' | 'status' | 'approve' | 'pause' | 'resume';
  payload: unknown;
  deviceId: string;
  deviceType: 'iphone' | 'ipad' | 'watch' | 'mac' | 'tv' | 'homepod' | 'web';
  timestamp: number;
}

export interface APIResponse {
  id: string;
  requestId: string;
  success: boolean;
  data?: unknown;
  error?: string;
  timestamp: number;
}

export interface DeviceSession {
  id: string;
  deviceType: APIRequest['deviceType'];
  socket?: WebSocket;
  lastSeen: Date;
  authenticated: boolean;
  pushToken?: string;
}

export interface PendingApproval {
  id: string;
  type: 'code_change' | 'command' | 'update' | 'decision';
  title: string;
  description: string;
  details: unknown;
  options: ApprovalOption[];
  createdAt: Date;
  expiresAt?: Date;
  priority: 'low' | 'medium' | 'high' | 'critical';
  responded: boolean;
  response?: string;
}

export interface ApprovalOption {
  id: string;
  label: string;
  description?: string;
  isDefault?: boolean;
  isDangerous?: boolean;
}

// ============================================================================
// DEFAULT CONFIG
// ============================================================================

const DEFAULT_CONFIG: ServerConfig = {
  port: 3847,  // WARP on phone keypad
  host: '0.0.0.0',
  enableAuth: true,
  enableEncryption: true,
  allowedOrigins: ['*'],
  maxConnections: 10
};

// ============================================================================
// STATE
// ============================================================================

const config: ServerConfig = { ...DEFAULT_CONFIG };
const sessions = new Map<string, DeviceSession>();
const pendingApprovals = new Map<string, PendingApproval>();
const messageQueue: Array<{ target: string | 'broadcast'; message: unknown }> = [];

let server: ReturnType<typeof createServer> | null = null;
let wss: WebSocketServer | null = null;
let encryptionKey: Buffer | null = null;

// Callbacks for integration with main app
let onQuery: ((query: string, context: unknown) => Promise<string>) | null = null;
let onCommand: ((command: string) => Promise<{ output: string; exitCode: number }>) | null = null;
let onApproval: ((approvalId: string, response: string) => void) | null = null;
let onStatusRequest: (() => unknown) | null = null;

// ============================================================================
// ENCRYPTION
// ============================================================================

function initEncryption(password: string): void {
  encryptionKey = scryptSync(password, 'warp-open-salt', 32);
}

function encrypt(data: string): string {
  if (!encryptionKey) return data;

  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
}

function decrypt(data: string): string {
  if (!encryptionKey) return data;

  const parts = data.split(':');
  if (parts.length !== 3) return data;

  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];

  const decipher = createDecipheriv('aes-256-gcm', encryptionKey, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

function handleHTTPRequest(req: IncomingMessage, res: ServerResponse): void {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Auth check
  if (config.enableAuth && config.authToken) {
    const auth = req.headers.authorization;
    if (!auth || auth !== `Bearer ${config.authToken}`) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
  }

  const url = new URL(req.url || '/', `http://${req.headers.host}`);

  switch (url.pathname) {
    case '/api/status':
      handleStatus(req, res);
      break;

    case '/api/query':
      handleQuery(req, res);
      break;

    case '/api/command':
      handleCommand(req, res);
      break;

    case '/api/approvals':
      handleApprovals(req, res);
      break;

    case '/api/approve':
      handleApprove(req, res);
      break;

    case '/api/shortcuts':
      handleShortcuts(req, res);
      break;

    case '/.well-known/apple-app-site-association':
      handleAppSiteAssociation(req, res);
      break;

    default:
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
  }
}

async function handleStatus(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const status = onStatusRequest ? await onStatusRequest() : { running: true };

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'ok',
    version: '2.0.0',
    uptime: process.uptime(),
    connectedDevices: sessions.size,
    pendingApprovals: pendingApprovals.size,
    ...status
  }));
}

async function handleQuery(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== 'POST') {
    res.writeHead(405);
    res.end();
    return;
  }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    try {
      const data = JSON.parse(body);
      const { query, context } = data;

      if (!onQuery) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Query handler not configured' }));
        return;
      }

      const response = await onQuery(query, context);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, response }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(e) }));
    }
  });
}

async function handleCommand(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== 'POST') {
    res.writeHead(405);
    res.end();
    return;
  }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    try {
      const data = JSON.parse(body);
      const { command } = data;

      if (!onCommand) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Command handler not configured' }));
        return;
      }

      const result = await onCommand(command);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, ...result }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(e) }));
    }
  });
}

async function handleApprovals(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const approvals = Array.from(pendingApprovals.values())
    .filter(a => !a.responded)
    .sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ approvals }));
}

async function handleApprove(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== 'POST') {
    res.writeHead(405);
    res.end();
    return;
  }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    try {
      const { approvalId, response } = JSON.parse(body);

      const approval = pendingApprovals.get(approvalId);
      if (!approval) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Approval not found' }));
        return;
      }

      approval.responded = true;
      approval.response = response;

      if (onApproval) {
        onApproval(approvalId, response);
      }

      // Notify all devices
      broadcast({ type: 'approval_resolved', approvalId, response });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(e) }));
    }
  });
}

function handleShortcuts(req: IncomingMessage, res: ServerResponse): void {
  // Apple Shortcuts integration - returns available actions
  const shortcuts = [
    {
      id: 'ask_warp',
      name: 'Ask Warp',
      description: 'Ask the AI assistant a question',
      parameters: [{ name: 'query', type: 'string', required: true }]
    },
    {
      id: 'run_command',
      name: 'Run Terminal Command',
      description: 'Execute a command in the terminal',
      parameters: [{ name: 'command', type: 'string', required: true }]
    },
    {
      id: 'check_status',
      name: 'Check Status',
      description: 'Get current terminal and AI status',
      parameters: []
    },
    {
      id: 'pending_approvals',
      name: 'Pending Approvals',
      description: 'Check if there are any pending approvals',
      parameters: []
    },
    {
      id: 'approve_action',
      name: 'Approve Action',
      description: 'Approve a pending action',
      parameters: [
        { name: 'approvalId', type: 'string', required: true },
        { name: 'response', type: 'string', required: true }
      ]
    }
  ];

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ shortcuts }));
}

function handleAppSiteAssociation(req: IncomingMessage, res: ServerResponse): void {
  // For Universal Links
  const association = {
    applinks: {
      apps: [],
      details: [
        {
          appID: 'TEAMID.com.warpopen.app',
          paths: ['/approve/*', '/query/*']
        }
      ]
    }
  };

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(association));
}

// ============================================================================
// WEBSOCKET HANDLERS
// ============================================================================

function handleWebSocket(ws: WebSocket, req: IncomingMessage): void {
  const sessionId = randomBytes(16).toString('hex');
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const deviceType = (url.searchParams.get('device') || 'web') as APIRequest['deviceType'];

  const session: DeviceSession = {
    id: sessionId,
    deviceType,
    socket: ws,
    lastSeen: new Date(),
    authenticated: !config.enableAuth
  };

  sessions.set(sessionId, session);
  console.log(`[API] Device connected: ${deviceType} (${sessionId})`);

  // Send welcome
  sendToSession(sessionId, {
    type: 'connected',
    sessionId,
    serverVersion: '2.0.0'
  });

  ws.on('message', (data) => {
    try {
      let message = data.toString();

      if (config.enableEncryption) {
        message = decrypt(message);
      }

      const request: APIRequest = JSON.parse(message);
      handleWebSocketMessage(sessionId, request);

      session.lastSeen = new Date();
    } catch (e) {
      console.error('[API] Message parse error:', e);
    }
  });

  ws.on('close', () => {
    sessions.delete(sessionId);
    console.log(`[API] Device disconnected: ${deviceType} (${sessionId})`);
  });

  ws.on('error', (e) => {
    console.error(`[API] WebSocket error for ${sessionId}:`, e);
  });
}

async function handleWebSocketMessage(sessionId: string, request: APIRequest): Promise<void> {
  const session = sessions.get(sessionId);
  if (!session) return;

  switch (request.type) {
    case 'query':
      if (onQuery) {
        const response = await onQuery(request.payload as string, {});
        sendToSession(sessionId, {
          type: 'query_response',
          requestId: request.id,
          response
        });
      }
      break;

    case 'command':
      if (onCommand) {
        const result = await onCommand(request.payload as string);
        sendToSession(sessionId, {
          type: 'command_response',
          requestId: request.id,
          ...result
        });
      }
      break;

    case 'status':
      const status = onStatusRequest ? await onStatusRequest() : {};
      sendToSession(sessionId, {
        type: 'status_response',
        requestId: request.id,
        ...status
      });
      break;

    case 'approve':
      const { approvalId, response } = request.payload as { approvalId: string; response: string };
      const approval = pendingApprovals.get(approvalId);
      if (approval) {
        approval.responded = true;
        approval.response = response;
        if (onApproval) onApproval(approvalId, response);
        broadcast({ type: 'approval_resolved', approvalId, response });
      }
      break;

    case 'pause':
      broadcast({ type: 'system_paused', by: sessionId });
      break;

    case 'resume':
      broadcast({ type: 'system_resumed', by: sessionId });
      break;
  }
}

// ============================================================================
// MESSAGING
// ============================================================================

function sendToSession(sessionId: string, message: unknown): void {
  const session = sessions.get(sessionId);
  if (!session?.socket || session.socket.readyState !== WebSocket.OPEN) return;

  let data = JSON.stringify(message);

  if (config.enableEncryption) {
    data = encrypt(data);
  }

  session.socket.send(data);
}

function broadcast(message: unknown): void {
  for (const session of sessions.values()) {
    if (session.socket?.readyState === WebSocket.OPEN) {
      sendToSession(session.id, message);
    }
  }
}

// ============================================================================
// APPROVAL SYSTEM
// ============================================================================

function createApproval(approval: Omit<PendingApproval, 'id' | 'createdAt' | 'responded'>): PendingApproval {
  const id = randomBytes(8).toString('hex');

  const pending: PendingApproval = {
    ...approval,
    id,
    createdAt: new Date(),
    responded: false
  };

  pendingApprovals.set(id, pending);

  // Notify all devices
  broadcast({
    type: 'approval_required',
    approval: pending
  });

  // Send push notification
  sendPushNotification({
    title: `Approval Required: ${approval.title}`,
    body: approval.description,
    data: { approvalId: id }
  });

  return pending;
}

async function waitForApproval(approvalId: string, timeoutMs = 0): Promise<string | null> {
  const approval = pendingApprovals.get(approvalId);
  if (!approval) return null;

  return new Promise((resolve) => {
    const check = () => {
      const current = pendingApprovals.get(approvalId);
      if (current?.responded) {
        resolve(current.response || null);
        return;
      }

      if (timeoutMs > 0 && Date.now() - approval.createdAt.getTime() > timeoutMs) {
        resolve(null);
        return;
      }

      setTimeout(check, 500);
    };

    check();
  });
}

// ============================================================================
// PUSH NOTIFICATIONS (APNS)
// ============================================================================

async function sendPushNotification(notification: {
  title: string;
  body: string;
  data?: Record<string, unknown>;
}): Promise<void> {
  // Get all devices with push tokens
  for (const session of sessions.values()) {
    if (!session.pushToken) continue;

    // In production, use @parse/node-apn or similar
    console.log(`[API] Would send push to ${session.deviceType}: ${notification.title}`);
  }
}

// ============================================================================
// SERVER LIFECYCLE
// ============================================================================

export function startServer(options?: Partial<ServerConfig>): void {
  Object.assign(config, options);

  if (config.enableEncryption && config.encryptionPassword) {
    initEncryption(config.encryptionPassword);
  }

  // HTTP Server
  server = createServer(handleHTTPRequest);

  // WebSocket Server
  wss = new WebSocketServer({ server });
  wss.on('connection', handleWebSocket);

  server.listen(config.port, config.host, () => {
    console.log(`[API] Server running on http://${config.host}:${config.port}`);
    console.log(`[API] WebSocket available at ws://${config.host}:${config.port}`);
  });
}

export function stopServer(): void {
  wss?.close();
  server?.close();
  sessions.clear();
  console.log('[API] Server stopped');
}

// ============================================================================
// INTEGRATION HOOKS
// ============================================================================

export function setQueryHandler(handler: typeof onQuery): void {
  onQuery = handler;
}

export function setCommandHandler(handler: typeof onCommand): void {
  onCommand = handler;
}

export function setApprovalHandler(handler: typeof onApproval): void {
  onApproval = handler;
}

export function setStatusHandler(handler: typeof onStatusRequest): void {
  onStatusRequest = handler;
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  createApproval,
  waitForApproval,
  broadcast,
  sendPushNotification,
  sessions,
  pendingApprovals
};

export default {
  startServer,
  stopServer,
  setQueryHandler,
  setCommandHandler,
  setApprovalHandler,
  setStatusHandler,
  createApproval,
  waitForApproval,
  broadcast
};
