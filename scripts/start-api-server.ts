/**
 * API Server Starter
 * Starts the cross-device API server for iPhone/iPad access
 *
 * Usage: npx tsx scripts/start-api-server.ts
 */

import { createServer, IncomingMessage, ServerResponse } from 'http'
import { WebSocketServer, WebSocket } from 'ws'
import { readFileSync, existsSync } from 'fs'
import { join } from 'path'

const PORT = parseInt(process.env.API_PORT || '3847')
const HOST = process.env.API_HOST || '0.0.0.0'

interface ConnectedClient {
  ws: WebSocket
  deviceType: string
  lastSeen: Date
}

const clients: Map<string, ConnectedClient> = new Map()

// Message store for cross-device sync
let messages: Array<{ id: string; type: string; content: string; timestamp: Date }> = []
let pendingApprovals: Array<{ id: string; action: string; description: string }> = []
let systemStatus = { aiRunning: false, currentTask: '', lastActivity: new Date() }

// HTTP Server for static files and REST API
const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`)

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  if (req.method === 'OPTIONS') {
    res.writeHead(200)
    res.end()
    return
  }

  // REST API endpoints
  if (url.pathname === '/api/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      connected: clients.size,
      status: systemStatus,
      uptime: process.uptime()
    }))
    return
  }

  if (url.pathname === '/api/send' && req.method === 'POST') {
    let body = ''
    req.on('data', chunk => body += chunk)
    req.on('end', () => {
      try {
        const { content } = JSON.parse(body)
        const msg = { id: Date.now().toString(), type: 'user', content, timestamp: new Date() }
        messages.push(msg)
        broadcast({ type: 'message', ...msg })
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ success: true, id: msg.id }))
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Invalid JSON' }))
      }
    })
    return
  }

  // Serve static files
  let filePath = url.pathname === '/' ? '/remote.html' : url.pathname
  const publicDir = join(__dirname, '../public')
  const fullPath = join(publicDir, filePath)

  if (existsSync(fullPath)) {
    const content = readFileSync(fullPath)
    const ext = filePath.split('.').pop()
    const contentTypes: Record<string, string> = {
      'html': 'text/html',
      'css': 'text/css',
      'js': 'application/javascript',
      'json': 'application/json',
      'png': 'image/png',
      'svg': 'image/svg+xml',
      'ico': 'image/x-icon'
    }
    res.writeHead(200, { 'Content-Type': contentTypes[ext || 'html'] || 'text/plain' })
    res.end(content)
    return
  }

  res.writeHead(404)
  res.end('Not Found')
})

// WebSocket Server
const wss = new WebSocketServer({ server })

wss.on('connection', (ws, req) => {
  const clientId = Date.now().toString()
  const deviceType = req.headers['user-agent']?.includes('iPhone') ? 'iphone' :
                     req.headers['user-agent']?.includes('iPad') ? 'ipad' : 'web'

  clients.set(clientId, { ws, deviceType, lastSeen: new Date() })
  console.log(`[API] Client connected: ${clientId} (${deviceType})`)

  // Send current state
  ws.send(JSON.stringify({
    type: 'state',
    messages: messages.slice(-50),
    approvals: pendingApprovals,
    status: systemStatus
  }))

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString())

      if (msg.type === 'message') {
        const newMsg = { id: Date.now().toString(), type: 'user', content: msg.content, timestamp: new Date() }
        messages.push(newMsg)
        broadcast({ type: 'message', from: 'user', ...newMsg })

        // Simulate AI response (in real app, this would go to Ollama)
        setTimeout(() => {
          const aiMsg = {
            id: Date.now().toString(),
            type: 'ai',
            content: `Received: "${msg.content}". Processing with local AI...`,
            timestamp: new Date()
          }
          messages.push(aiMsg)
          broadcast({ type: 'message', from: 'ai', ...aiMsg })
        }, 500)
      }

      if (msg.type === 'approval_response') {
        pendingApprovals = pendingApprovals.filter(a => a.id !== msg.id)
        broadcast({ type: 'approval_resolved', id: msg.id, approved: msg.approved })
      }

      if (msg.type === 'get_state') {
        ws.send(JSON.stringify({
          type: 'state',
          messages: messages.slice(-50),
          approvals: pendingApprovals,
          status: systemStatus
        }))
      }
    } catch (e) {
      console.error('[API] Message parse error:', e)
    }
  })

  ws.on('close', () => {
    clients.delete(clientId)
    console.log(`[API] Client disconnected: ${clientId}`)
  })
})

function broadcast(data: unknown) {
  const json = JSON.stringify(data)
  clients.forEach(({ ws }) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(json)
    }
  })
}

// API to add approvals (called from main app)
export function addApproval(approval: { id: string; action: string; description: string }) {
  pendingApprovals.push(approval)
  broadcast({ type: 'approval_request', ...approval })
}

// API to update status (called from main app)
export function updateStatus(status: Partial<typeof systemStatus>) {
  Object.assign(systemStatus, status)
  broadcast({ type: 'status_update', status: systemStatus })
}

// API to add AI message (called from main app)
export function addAIMessage(content: string) {
  const msg = { id: Date.now().toString(), type: 'ai', content, timestamp: new Date() }
  messages.push(msg)
  broadcast({ type: 'message', from: 'ai', ...msg })
}

// Start server
server.listen(PORT, HOST, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║                   Warp Open API Server                           ║
╠══════════════════════════════════════════════════════════════════╣
║  Local:     http://localhost:${PORT}                               ║
║  Network:   http://${getLocalIP()}:${PORT}                          ║
║                                                                  ║
║  iPhone Access:                                                  ║
║  1. Open Safari on iPhone                                        ║
║  2. Go to http://${getLocalIP()}:${PORT}                            ║
║  3. Tap Share → Add to Home Screen                               ║
║                                                                  ║
║  Or use Tailscale:                                               ║
║  tailscale serve --bg ${PORT}                                       ║
╚══════════════════════════════════════════════════════════════════╝
  `)
})

function getLocalIP(): string {
  const { networkInterfaces } = require('os')
  const nets = networkInterfaces()
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address
      }
    }
  }
  return 'localhost'
}
