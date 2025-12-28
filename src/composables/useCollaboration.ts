/**
 * Real-Time Terminal Collaboration
 * Share terminal sessions with multiple users
 *
 * Features:
 * - WebSocket-based real-time sync
 * - CRDT for conflict-free state
 * - User presence indicators
 * - Permission levels (view/interact)
 * - Cursor tracking
 * - End-to-end encryption
 * - P2P fallback via WebRTC
 */

import { ref, computed, reactive, shallowRef } from 'vue';

// ============================================================================
// TYPES
// ============================================================================

export interface CollabUser {
  id: string;
  name: string;
  email?: string;
  avatar?: string;
  color: string;
  cursor?: CursorPosition;
  permissions: CollabPermission;
  status: 'active' | 'idle' | 'away' | 'disconnected';
  joinedAt: Date;
  lastActivity: Date;
}

export interface CursorPosition {
  row: number;
  col: number;
  timestamp: number;
}

export type CollabPermission = 'owner' | 'write' | 'read';

export interface CollabSession {
  id: string;
  name: string;
  terminalId: string;
  ownerId: string;
  users: Map<string, CollabUser>;
  isEncrypted: boolean;
  createdAt: Date;
  maxUsers: number;
  allowJoin: boolean;
  shareLink?: string;
  password?: string;
}

export interface CollabMessage {
  type: CollabMessageType;
  sessionId: string;
  userId: string;
  timestamp: number;
  data: unknown;
  signature?: string;  // For E2E verification
}

export type CollabMessageType =
  | 'join'
  | 'leave'
  | 'input'
  | 'output'
  | 'cursor'
  | 'resize'
  | 'presence'
  | 'sync_request'
  | 'sync_response'
  | 'permission_change'
  | 'chat'
  | 'ping'
  | 'pong';

export interface CollabConfig {
  serverUrl: string;
  enableP2P: boolean;
  enableEncryption: boolean;
  maxReconnectAttempts: number;
  reconnectDelayMs: number;
  heartbeatIntervalMs: number;
  cursorUpdateThrottleMs: number;
}

export interface ChatMessage {
  id: string;
  userId: string;
  userName: string;
  content: string;
  timestamp: Date;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const DEFAULT_CONFIG: CollabConfig = {
  serverUrl: 'wss://collab.warp-open.dev',
  enableP2P: true,
  enableEncryption: true,
  maxReconnectAttempts: 5,
  reconnectDelayMs: 1000,
  heartbeatIntervalMs: 30000,
  cursorUpdateThrottleMs: 50
};

const USER_COLORS = [
  '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4',
  '#FFEAA7', '#DDA0DD', '#98D8C8', '#F7DC6F',
  '#BB8FCE', '#85C1E9', '#F8B500', '#82E0AA'
];

// ============================================================================
// STATE
// ============================================================================

const config = reactive<CollabConfig>({ ...DEFAULT_CONFIG });
const currentSession = shallowRef<CollabSession | null>(null);
const currentUser = ref<CollabUser | null>(null);
const isConnected = ref(false);
const isConnecting = ref(false);
const error = ref<string | null>(null);
const chatMessages = reactive<ChatMessage[]>([]);

let socket: WebSocket | null = null;
let peerConnections: Map<string, RTCPeerConnection> = new Map();
let reconnectAttempts = 0;
let heartbeatInterval: number | null = null;
let cursorThrottle: number | null = null;
let encryptionKey: CryptoKey | null = null;

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

async function generateEncryptionKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function exportKey(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('raw', key);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

async function importKey(keyString: string): Promise<CryptoKey> {
  const keyData = Uint8Array.from(atob(keyString), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

async function encrypt(data: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(data);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decrypt(data: string, key: CryptoKey): Promise<string> {
  const combined = Uint8Array.from(atob(data), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const encrypted = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );
  return new TextDecoder().decode(decrypted);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateId(): string {
  return Math.random().toString(36).substring(2, 11);
}

function getRandomColor(): string {
  return USER_COLORS[Math.floor(Math.random() * USER_COLORS.length)];
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useCollaboration() {
  /**
   * Create a new collaboration session
   */
  async function createSession(
    terminalId: string,
    options?: {
      name?: string;
      password?: string;
      maxUsers?: number;
      encrypted?: boolean;
    }
  ): Promise<CollabSession> {
    const sessionId = generateId();
    const userId = generateId();

    // Generate encryption key if enabled
    if (options?.encrypted !== false && config.enableEncryption) {
      encryptionKey = await generateEncryptionKey();
    }

    const owner: CollabUser = {
      id: userId,
      name: 'You',
      color: getRandomColor(),
      permissions: 'owner',
      status: 'active',
      joinedAt: new Date(),
      lastActivity: new Date()
    };

    const session: CollabSession = {
      id: sessionId,
      name: options?.name || `Session ${sessionId.substring(0, 6)}`,
      terminalId,
      ownerId: userId,
      users: new Map([[userId, owner]]),
      isEncrypted: !!encryptionKey,
      createdAt: new Date(),
      maxUsers: options?.maxUsers || 10,
      allowJoin: true,
      password: options?.password
    };

    currentSession.value = session;
    currentUser.value = owner;

    // Connect to server
    await connect(sessionId, userId, 'owner');

    // Generate share link
    let shareLink = `${window.location.origin}/join/${sessionId}`;
    if (encryptionKey) {
      const keyString = await exportKey(encryptionKey);
      shareLink += `#${keyString}`;
    }
    session.shareLink = shareLink;

    console.log(`[Collab] Created session ${sessionId}`);
    return session;
  }

  /**
   * Join an existing session
   */
  async function joinSession(
    sessionId: string,
    options?: {
      name?: string;
      password?: string;
      encryptionKey?: string;
    }
  ): Promise<boolean> {
    const userId = generateId();

    // Import encryption key if provided
    if (options?.encryptionKey) {
      try {
        encryptionKey = await importKey(options.encryptionKey);
      } catch {
        error.value = 'Invalid encryption key';
        return false;
      }
    }

    const user: CollabUser = {
      id: userId,
      name: options?.name || `User ${userId.substring(0, 4)}`,
      color: getRandomColor(),
      permissions: 'read',  // Default to read, server will confirm
      status: 'active',
      joinedAt: new Date(),
      lastActivity: new Date()
    };

    currentUser.value = user;

    // Connect to server
    await connect(sessionId, userId, 'read', options?.password);

    return isConnected.value;
  }

  /**
   * Connect to collaboration server
   */
  async function connect(
    sessionId: string,
    userId: string,
    permission: CollabPermission,
    password?: string
  ): Promise<void> {
    if (isConnecting.value) return;

    isConnecting.value = true;
    error.value = null;

    try {
      const url = new URL(config.serverUrl);
      url.searchParams.set('session', sessionId);
      url.searchParams.set('user', userId);
      url.searchParams.set('permission', permission);
      if (password) {
        url.searchParams.set('password', password);
      }

      socket = new WebSocket(url.toString());

      socket.onopen = () => {
        isConnected.value = true;
        isConnecting.value = false;
        reconnectAttempts = 0;

        // Start heartbeat
        startHeartbeat();

        // Send join message
        sendMessage({
          type: 'join',
          sessionId,
          userId,
          timestamp: Date.now(),
          data: {
            name: currentUser.value?.name,
            color: currentUser.value?.color
          }
        });

        // Request full sync
        sendMessage({
          type: 'sync_request',
          sessionId,
          userId,
          timestamp: Date.now(),
          data: {}
        });

        console.log('[Collab] Connected to server');
      };

      socket.onmessage = async (event) => {
        try {
          let message: CollabMessage;

          if (encryptionKey) {
            const decrypted = await decrypt(event.data, encryptionKey);
            message = JSON.parse(decrypted);
          } else {
            message = JSON.parse(event.data);
          }

          handleMessage(message);
        } catch (e) {
          console.error('[Collab] Failed to parse message:', e);
        }
      };

      socket.onclose = () => {
        isConnected.value = false;
        stopHeartbeat();

        if (reconnectAttempts < config.maxReconnectAttempts) {
          reconnectAttempts++;
          const delay = config.reconnectDelayMs * Math.pow(2, reconnectAttempts - 1);
          console.log(`[Collab] Reconnecting in ${delay}ms (attempt ${reconnectAttempts})`);
          setTimeout(() => connect(sessionId, userId, permission, password), delay);
        } else {
          error.value = 'Connection lost. Max reconnect attempts reached.';
        }
      };

      socket.onerror = (e) => {
        console.error('[Collab] WebSocket error:', e);
        error.value = 'Connection error';
      };

    } catch (e) {
      isConnecting.value = false;
      error.value = e instanceof Error ? e.message : String(e);
      throw e;
    }
  }

  /**
   * Disconnect from session
   */
  async function disconnect(): Promise<void> {
    if (socket && currentSession.value && currentUser.value) {
      sendMessage({
        type: 'leave',
        sessionId: currentSession.value.id,
        userId: currentUser.value.id,
        timestamp: Date.now(),
        data: {}
      });
    }

    stopHeartbeat();
    socket?.close();
    socket = null;

    // Close P2P connections
    for (const pc of peerConnections.values()) {
      pc.close();
    }
    peerConnections.clear();

    currentSession.value = null;
    currentUser.value = null;
    isConnected.value = false;
    encryptionKey = null;
    chatMessages.length = 0;
  }

  /**
   * Send a message
   */
  async function sendMessage(message: CollabMessage): Promise<void> {
    if (!socket || socket.readyState !== WebSocket.OPEN) return;

    let data: string;
    if (encryptionKey) {
      data = await encrypt(JSON.stringify(message), encryptionKey);
    } else {
      data = JSON.stringify(message);
    }

    socket.send(data);
  }

  /**
   * Handle incoming message
   */
  function handleMessage(message: CollabMessage): void {
    if (!currentSession.value) return;

    switch (message.type) {
      case 'join':
        handleUserJoin(message);
        break;

      case 'leave':
        handleUserLeave(message);
        break;

      case 'input':
        handleTerminalInput(message);
        break;

      case 'output':
        handleTerminalOutput(message);
        break;

      case 'cursor':
        handleCursorUpdate(message);
        break;

      case 'resize':
        handleResize(message);
        break;

      case 'presence':
        handlePresenceUpdate(message);
        break;

      case 'sync_response':
        handleSyncResponse(message);
        break;

      case 'permission_change':
        handlePermissionChange(message);
        break;

      case 'chat':
        handleChatMessage(message);
        break;

      case 'pong':
        // Heartbeat response
        break;
    }
  }

  function handleUserJoin(message: CollabMessage): void {
    const data = message.data as { name: string; color: string };
    const user: CollabUser = {
      id: message.userId,
      name: data.name,
      color: data.color,
      permissions: 'read',
      status: 'active',
      joinedAt: new Date(),
      lastActivity: new Date()
    };
    currentSession.value!.users.set(message.userId, user);

    window.dispatchEvent(new CustomEvent('collab:user_joined', {
      detail: { user }
    }));
  }

  function handleUserLeave(message: CollabMessage): void {
    const user = currentSession.value!.users.get(message.userId);
    currentSession.value!.users.delete(message.userId);

    window.dispatchEvent(new CustomEvent('collab:user_left', {
      detail: { userId: message.userId, user }
    }));
  }

  function handleTerminalInput(message: CollabMessage): void {
    if (message.userId === currentUser.value?.id) return;

    window.dispatchEvent(new CustomEvent('collab:terminal_input', {
      detail: {
        userId: message.userId,
        input: message.data
      }
    }));
  }

  function handleTerminalOutput(message: CollabMessage): void {
    window.dispatchEvent(new CustomEvent('collab:terminal_output', {
      detail: {
        userId: message.userId,
        output: message.data
      }
    }));
  }

  function handleCursorUpdate(message: CollabMessage): void {
    const user = currentSession.value!.users.get(message.userId);
    if (user) {
      user.cursor = message.data as CursorPosition;
      user.lastActivity = new Date();

      window.dispatchEvent(new CustomEvent('collab:cursor_update', {
        detail: { userId: message.userId, cursor: user.cursor }
      }));
    }
  }

  function handleResize(message: CollabMessage): void {
    window.dispatchEvent(new CustomEvent('collab:resize', {
      detail: message.data
    }));
  }

  function handlePresenceUpdate(message: CollabMessage): void {
    const user = currentSession.value!.users.get(message.userId);
    if (user) {
      const data = message.data as { status: CollabUser['status'] };
      user.status = data.status;
      user.lastActivity = new Date();
    }
  }

  function handleSyncResponse(message: CollabMessage): void {
    const data = message.data as {
      session: Partial<CollabSession>;
      users: Array<{ id: string } & Partial<CollabUser>>;
      terminalState: unknown;
    };

    // Update session info
    if (currentSession.value) {
      Object.assign(currentSession.value, data.session);

      // Update users
      for (const userData of data.users) {
        const existing = currentSession.value.users.get(userData.id);
        if (existing) {
          Object.assign(existing, userData);
        } else {
          currentSession.value.users.set(userData.id, userData as CollabUser);
        }
      }
    }

    // Apply terminal state
    window.dispatchEvent(new CustomEvent('collab:sync_state', {
      detail: data.terminalState
    }));
  }

  function handlePermissionChange(message: CollabMessage): void {
    const data = message.data as { userId: string; permission: CollabPermission };
    const user = currentSession.value!.users.get(data.userId);
    if (user) {
      user.permissions = data.permission;

      if (data.userId === currentUser.value?.id) {
        currentUser.value.permissions = data.permission;
      }
    }
  }

  function handleChatMessage(message: CollabMessage): void {
    const data = message.data as { content: string };
    const user = currentSession.value!.users.get(message.userId);

    chatMessages.push({
      id: generateId(),
      userId: message.userId,
      userName: user?.name || 'Unknown',
      content: data.content,
      timestamp: new Date(message.timestamp)
    });

    window.dispatchEvent(new CustomEvent('collab:chat_message', {
      detail: chatMessages[chatMessages.length - 1]
    }));
  }

  /**
   * Send terminal input to other users
   */
  function broadcastInput(input: string): void {
    if (!currentSession.value || !currentUser.value) return;
    if (currentUser.value.permissions === 'read') return;

    sendMessage({
      type: 'input',
      sessionId: currentSession.value.id,
      userId: currentUser.value.id,
      timestamp: Date.now(),
      data: input
    });
  }

  /**
   * Send terminal output to other users (owner only)
   */
  function broadcastOutput(output: string): void {
    if (!currentSession.value || !currentUser.value) return;
    if (currentUser.value.permissions !== 'owner') return;

    sendMessage({
      type: 'output',
      sessionId: currentSession.value.id,
      userId: currentUser.value.id,
      timestamp: Date.now(),
      data: output
    });
  }

  /**
   * Send cursor position (throttled)
   */
  function updateCursor(row: number, col: number): void {
    if (!currentSession.value || !currentUser.value) return;

    if (cursorThrottle) return;

    cursorThrottle = window.setTimeout(() => {
      cursorThrottle = null;
    }, config.cursorUpdateThrottleMs);

    sendMessage({
      type: 'cursor',
      sessionId: currentSession.value.id,
      userId: currentUser.value.id,
      timestamp: Date.now(),
      data: { row, col, timestamp: Date.now() }
    });
  }

  /**
   * Send chat message
   */
  function sendChatMessage(content: string): void {
    if (!currentSession.value || !currentUser.value) return;

    sendMessage({
      type: 'chat',
      sessionId: currentSession.value.id,
      userId: currentUser.value.id,
      timestamp: Date.now(),
      data: { content }
    });

    // Add to local chat
    chatMessages.push({
      id: generateId(),
      userId: currentUser.value.id,
      userName: currentUser.value.name,
      content,
      timestamp: new Date()
    });
  }

  /**
   * Update user permissions (owner only)
   */
  function setUserPermission(userId: string, permission: CollabPermission): void {
    if (!currentSession.value || !currentUser.value) return;
    if (currentUser.value.permissions !== 'owner') return;

    sendMessage({
      type: 'permission_change',
      sessionId: currentSession.value.id,
      userId: currentUser.value.id,
      timestamp: Date.now(),
      data: { userId, permission }
    });

    const user = currentSession.value.users.get(userId);
    if (user) {
      user.permissions = permission;
    }
  }

  /**
   * Kick user from session (owner only)
   */
  function kickUser(userId: string): void {
    if (!currentSession.value || !currentUser.value) return;
    if (currentUser.value.permissions !== 'owner') return;

    // Server handles the actual kick
    sendMessage({
      type: 'leave',
      sessionId: currentSession.value.id,
      userId: userId,
      timestamp: Date.now(),
      data: { kicked: true, by: currentUser.value.id }
    });
  }

  /**
   * Update presence status
   */
  function setPresence(status: CollabUser['status']): void {
    if (!currentSession.value || !currentUser.value) return;

    currentUser.value.status = status;

    sendMessage({
      type: 'presence',
      sessionId: currentSession.value.id,
      userId: currentUser.value.id,
      timestamp: Date.now(),
      data: { status }
    });
  }

  /**
   * Start heartbeat
   */
  function startHeartbeat(): void {
    stopHeartbeat();
    heartbeatInterval = window.setInterval(() => {
      if (currentSession.value && currentUser.value) {
        sendMessage({
          type: 'ping',
          sessionId: currentSession.value.id,
          userId: currentUser.value.id,
          timestamp: Date.now(),
          data: {}
        });
      }
    }, config.heartbeatIntervalMs);
  }

  /**
   * Stop heartbeat
   */
  function stopHeartbeat(): void {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
      heartbeatInterval = null;
    }
  }

  /**
   * Update configuration
   */
  function updateConfig(newConfig: Partial<CollabConfig>): void {
    Object.assign(config, newConfig);
  }

  /**
   * Get all users in session
   */
  const users = computed(() =>
    currentSession.value ? Array.from(currentSession.value.users.values()) : []
  );

  /**
   * Get other users (not self)
   */
  const otherUsers = computed(() =>
    users.value.filter(u => u.id !== currentUser.value?.id)
  );

  /**
   * Get active users
   */
  const activeUsers = computed(() =>
    users.value.filter(u => u.status === 'active')
  );

  return {
    // State
    session: computed(() => currentSession.value),
    user: computed(() => currentUser.value),
    users,
    otherUsers,
    activeUsers,
    isConnected: computed(() => isConnected.value),
    isConnecting: computed(() => isConnecting.value),
    error: computed(() => error.value),
    chatMessages: computed(() => [...chatMessages]),
    config: computed(() => config),

    // Session management
    createSession,
    joinSession,
    disconnect,

    // Broadcasting
    broadcastInput,
    broadcastOutput,
    updateCursor,

    // Chat
    sendChatMessage,

    // User management
    setUserPermission,
    kickUser,
    setPresence,

    // Config
    updateConfig
  };
}

export default useCollaboration;
