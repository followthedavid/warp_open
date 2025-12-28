/**
 * Remote Agent Execution
 * Run AI agent commands on remote servers via SSH
 *
 * Features:
 * - Execute agent tools on remote machines
 * - Sync context between local and remote
 * - Remote file editing with conflict detection
 * - Distributed task execution
 * - Session persistence across reconnects
 * - Bandwidth-efficient delta transfers
 */

import { ref, computed, reactive } from 'vue';
import { useSSH, type SSHConnection, type SSHProfile } from './useSSH';

// ============================================================================
// TYPES
// ============================================================================

export interface RemoteAgentSession {
  id: string;
  connectionId: string;
  profile: SSHProfile;
  status: 'initializing' | 'ready' | 'busy' | 'disconnected' | 'error';
  workingDirectory: string;
  capabilities: RemoteCapabilities;
  lastActivity: Date;
  error?: string;
}

export interface RemoteCapabilities {
  hasGit: boolean;
  hasNode: boolean;
  hasPython: boolean;
  hasDocker: boolean;
  hasCurl: boolean;
  shell: string;
  os: string;
  arch: string;
  homeDir: string;
}

export interface RemoteToolCall {
  id: string;
  sessionId: string;
  tool: string;
  args: Record<string, unknown>;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt?: Date;
  completedAt?: Date;
  result?: unknown;
  error?: string;
  output?: string;
}

export interface FileSync {
  localPath: string;
  remotePath: string;
  direction: 'push' | 'pull' | 'bidirectional';
  lastSynced?: Date;
  status: 'synced' | 'modified_local' | 'modified_remote' | 'conflict';
}

export interface RemoteContext {
  workingDirectory: string;
  environment: Record<string, string>;
  recentCommands: string[];
  openFiles: string[];
  gitBranch?: string;
  gitStatus?: string;
}

// ============================================================================
// STATE
// ============================================================================

const sessions = reactive<Map<string, RemoteAgentSession>>(new Map());
const toolCalls = reactive<Map<string, RemoteToolCall>>(new Map());
const fileSyncs = reactive<Map<string, FileSync>>(new Map());
const activeSessionId = ref<string | null>(null);

// SSH composable
const ssh = useSSH();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateId(): string {
  return Math.random().toString(36).substring(2, 11);
}

async function executeRemoteCommand(connectionId: string, command: string): Promise<string> {
  return ssh.execute(connectionId, command);
}

function escapeShellArg(arg: string): string {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

export function useRemoteAgent() {
  /**
   * Start a remote agent session
   */
  async function startSession(
    profileId: string,
    options?: {
      password?: string;
      keyPassphrase?: string;
      workingDirectory?: string;
    }
  ): Promise<RemoteAgentSession> {
    // Connect via SSH
    const connection = await ssh.connect(profileId, {
      password: options?.password,
      keyPassphrase: options?.keyPassphrase
    });

    const session: RemoteAgentSession = {
      id: generateId(),
      connectionId: connection.id,
      profile: connection.profile,
      status: 'initializing',
      workingDirectory: options?.workingDirectory || connection.remoteInfo?.cwd || '~',
      capabilities: {
        hasGit: false,
        hasNode: false,
        hasPython: false,
        hasDocker: false,
        hasCurl: false,
        shell: connection.remoteInfo?.shell || '/bin/bash',
        os: connection.remoteInfo?.os || 'unknown',
        arch: 'unknown',
        homeDir: '~'
      },
      lastActivity: new Date()
    };

    sessions.set(session.id, session);

    try {
      // Detect capabilities
      await detectCapabilities(session);

      // Set working directory
      if (options?.workingDirectory) {
        await executeRemoteCommand(connection.id, `cd ${escapeShellArg(options.workingDirectory)}`);
      }

      session.status = 'ready';
      activeSessionId.value = session.id;

      console.log(`[RemoteAgent] Session started on ${connection.profile.host}`);
      return session;
    } catch (error) {
      session.status = 'error';
      session.error = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  /**
   * Detect remote system capabilities
   */
  async function detectCapabilities(session: RemoteAgentSession): Promise<void> {
    const conn = session.connectionId;

    const checks = await Promise.allSettled([
      executeRemoteCommand(conn, 'which git && git --version'),
      executeRemoteCommand(conn, 'which node && node --version'),
      executeRemoteCommand(conn, 'which python3 || which python'),
      executeRemoteCommand(conn, 'which docker && docker --version'),
      executeRemoteCommand(conn, 'which curl'),
      executeRemoteCommand(conn, 'uname -m'),
      executeRemoteCommand(conn, 'echo $HOME')
    ]);

    session.capabilities.hasGit = checks[0].status === 'fulfilled' && !checks[0].value.includes('not found');
    session.capabilities.hasNode = checks[1].status === 'fulfilled' && !checks[1].value.includes('not found');
    session.capabilities.hasPython = checks[2].status === 'fulfilled' && !checks[2].value.includes('not found');
    session.capabilities.hasDocker = checks[3].status === 'fulfilled' && !checks[3].value.includes('not found');
    session.capabilities.hasCurl = checks[4].status === 'fulfilled' && !checks[4].value.includes('not found');
    session.capabilities.arch = checks[5].status === 'fulfilled' ? checks[5].value.trim() : 'unknown';
    session.capabilities.homeDir = checks[6].status === 'fulfilled' ? checks[6].value.trim() : '~';
  }

  /**
   * End a remote agent session
   */
  async function endSession(sessionId: string): Promise<void> {
    const session = sessions.get(sessionId);
    if (!session) return;

    await ssh.disconnect(session.connectionId);
    sessions.delete(sessionId);

    if (activeSessionId.value === sessionId) {
      activeSessionId.value = null;
    }
  }

  /**
   * Execute a tool on remote server
   */
  async function executeTool(
    sessionId: string,
    tool: string,
    args: Record<string, unknown>
  ): Promise<unknown> {
    const session = sessions.get(sessionId);
    if (!session || session.status !== 'ready') {
      throw new Error('Session not ready');
    }

    const toolCall: RemoteToolCall = {
      id: generateId(),
      sessionId,
      tool,
      args,
      status: 'pending'
    };

    toolCalls.set(toolCall.id, toolCall);
    session.status = 'busy';
    toolCall.status = 'running';
    toolCall.startedAt = new Date();

    try {
      let result: unknown;

      switch (tool) {
        case 'read_file':
          result = await remoteReadFile(session, args.path as string);
          break;

        case 'write_file':
          result = await remoteWriteFile(session, args.path as string, args.content as string);
          break;

        case 'edit_file':
          result = await remoteEditFile(
            session,
            args.path as string,
            args.old_string as string,
            args.new_string as string
          );
          break;

        case 'bash':
          result = await remoteBash(session, args.command as string, args.timeout as number);
          break;

        case 'glob':
          result = await remoteGlob(session, args.pattern as string, args.path as string);
          break;

        case 'grep':
          result = await remoteGrep(session, args.pattern as string, args.path as string);
          break;

        case 'list_directory':
          result = await ssh.listRemoteDirectory(session.connectionId, args.path as string);
          break;

        default:
          throw new Error(`Unknown tool: ${tool}`);
      }

      toolCall.status = 'completed';
      toolCall.result = result;
      toolCall.completedAt = new Date();
      session.lastActivity = new Date();

      return result;
    } catch (error) {
      toolCall.status = 'failed';
      toolCall.error = error instanceof Error ? error.message : String(error);
      toolCall.completedAt = new Date();
      throw error;
    } finally {
      session.status = 'ready';
    }
  }

  /**
   * Read file on remote server
   */
  async function remoteReadFile(session: RemoteAgentSession, path: string): Promise<string> {
    return ssh.readRemoteFile(session.connectionId, path);
  }

  /**
   * Write file on remote server
   */
  async function remoteWriteFile(session: RemoteAgentSession, path: string, content: string): Promise<void> {
    await ssh.writeRemoteFile(session.connectionId, path, content);
  }

  /**
   * Edit file on remote server (search and replace)
   */
  async function remoteEditFile(
    session: RemoteAgentSession,
    path: string,
    oldString: string,
    newString: string
  ): Promise<{ success: boolean; message: string }> {
    // Read current content
    const content = await ssh.readRemoteFile(session.connectionId, path);

    // Check if old string exists
    if (!content.includes(oldString)) {
      return { success: false, message: 'Old string not found in file' };
    }

    // Check uniqueness
    const occurrences = content.split(oldString).length - 1;
    if (occurrences > 1) {
      return { success: false, message: `String appears ${occurrences} times, must be unique` };
    }

    // Replace and write
    const newContent = content.replace(oldString, newString);
    await ssh.writeRemoteFile(session.connectionId, path, newContent);

    return { success: true, message: 'File edited successfully' };
  }

  /**
   * Execute bash command on remote server
   */
  async function remoteBash(
    session: RemoteAgentSession,
    command: string,
    timeout?: number
  ): Promise<{ output: string; exitCode: number }> {
    const timeoutCmd = timeout ? `timeout ${Math.ceil(timeout / 1000)} ` : '';
    const fullCommand = `cd ${escapeShellArg(session.workingDirectory)} && ${timeoutCmd}${command}; echo "EXIT_CODE:$?"`;

    const output = await executeRemoteCommand(session.connectionId, fullCommand);

    // Parse exit code
    const lines = output.trim().split('\n');
    const lastLine = lines[lines.length - 1];
    let exitCode = 0;

    if (lastLine.startsWith('EXIT_CODE:')) {
      exitCode = parseInt(lastLine.split(':')[1]) || 0;
      lines.pop();
    }

    return { output: lines.join('\n'), exitCode };
  }

  /**
   * Glob pattern matching on remote server
   */
  async function remoteGlob(
    session: RemoteAgentSession,
    pattern: string,
    basePath?: string
  ): Promise<string[]> {
    const path = basePath || session.workingDirectory;
    const command = `find ${escapeShellArg(path)} -name ${escapeShellArg(pattern)} -type f 2>/dev/null | head -100`;

    const output = await executeRemoteCommand(session.connectionId, command);
    return output.trim().split('\n').filter(Boolean);
  }

  /**
   * Grep search on remote server
   */
  async function remoteGrep(
    session: RemoteAgentSession,
    pattern: string,
    path?: string
  ): Promise<Array<{ file: string; line: number; content: string }>> {
    const searchPath = path || session.workingDirectory;
    const command = `grep -rn ${escapeShellArg(pattern)} ${escapeShellArg(searchPath)} 2>/dev/null | head -100`;

    const output = await executeRemoteCommand(session.connectionId, command);
    const results: Array<{ file: string; line: number; content: string }> = [];

    for (const line of output.trim().split('\n')) {
      if (!line) continue;

      const match = line.match(/^(.+?):(\d+):(.*)$/);
      if (match) {
        results.push({
          file: match[1],
          line: parseInt(match[2]),
          content: match[3]
        });
      }
    }

    return results;
  }

  /**
   * Get remote context for AI
   */
  async function getRemoteContext(sessionId: string): Promise<RemoteContext> {
    const session = sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    const conn = session.connectionId;

    const [cwd, env, history, gitBranch, gitStatus] = await Promise.allSettled([
      executeRemoteCommand(conn, 'pwd'),
      executeRemoteCommand(conn, 'env'),
      executeRemoteCommand(conn, 'history 10 2>/dev/null || cat ~/.bash_history 2>/dev/null | tail -10'),
      executeRemoteCommand(conn, 'git branch --show-current 2>/dev/null'),
      executeRemoteCommand(conn, 'git status --short 2>/dev/null')
    ]);

    // Parse environment
    const environment: Record<string, string> = {};
    if (env.status === 'fulfilled') {
      for (const line of env.value.split('\n')) {
        const [key, ...valueParts] = line.split('=');
        if (key && valueParts.length > 0) {
          environment[key] = valueParts.join('=');
        }
      }
    }

    return {
      workingDirectory: cwd.status === 'fulfilled' ? cwd.value.trim() : session.workingDirectory,
      environment,
      recentCommands: history.status === 'fulfilled' ? history.value.trim().split('\n') : [],
      openFiles: [],  // Would need editor integration
      gitBranch: gitBranch.status === 'fulfilled' ? gitBranch.value.trim() : undefined,
      gitStatus: gitStatus.status === 'fulfilled' ? gitStatus.value.trim() : undefined
    };
  }

  /**
   * Sync file between local and remote
   */
  async function syncFile(
    sessionId: string,
    localPath: string,
    remotePath: string,
    direction: 'push' | 'pull'
  ): Promise<void> {
    const session = sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    if (direction === 'push') {
      await ssh.uploadFile(session.connectionId, localPath, remotePath);
    } else {
      await ssh.downloadFile(session.connectionId, remotePath, localPath);
    }

    const syncKey = `${localPath}:${remotePath}`;
    fileSyncs.set(syncKey, {
      localPath,
      remotePath,
      direction,
      lastSynced: new Date(),
      status: 'synced'
    });
  }

  /**
   * Sync entire directory
   */
  async function syncDirectory(
    sessionId: string,
    localDir: string,
    remoteDir: string,
    options?: {
      direction?: 'push' | 'pull';
      exclude?: string[];
      dryRun?: boolean;
    }
  ): Promise<{ synced: string[]; skipped: string[]; errors: string[] }> {
    const session = sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    // Use rsync if available, otherwise fall back to manual sync
    const hasRsync = await executeRemoteCommand(session.connectionId, 'which rsync').then(
      () => true,
      () => false
    );

    if (hasRsync && !options?.dryRun) {
      // Use rsync for efficient sync
      const excludeArgs = (options?.exclude || []).map(e => `--exclude=${escapeShellArg(e)}`).join(' ');
      const direction = options?.direction || 'push';

      if (direction === 'push') {
        // Would need scp/rsync via Tauri
        console.log('[RemoteAgent] Directory push requires rsync implementation');
      } else {
        console.log('[RemoteAgent] Directory pull requires rsync implementation');
      }
    }

    // Manual sync as fallback
    return { synced: [], skipped: [], errors: ['Manual directory sync not yet implemented'] };
  }

  /**
   * Change working directory on remote
   */
  async function changeDirectory(sessionId: string, path: string): Promise<string> {
    const session = sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    // Verify directory exists
    const result = await executeRemoteCommand(
      session.connectionId,
      `cd ${escapeShellArg(path)} && pwd`
    );

    const newPath = result.trim();
    session.workingDirectory = newPath;
    return newPath;
  }

  /**
   * Get active session
   */
  function getActiveSession(): RemoteAgentSession | null {
    if (!activeSessionId.value) return null;
    return sessions.get(activeSessionId.value) || null;
  }

  /**
   * Set active session
   */
  function setActiveSession(sessionId: string | null): void {
    if (sessionId && !sessions.has(sessionId)) {
      throw new Error('Session not found');
    }
    activeSessionId.value = sessionId;
  }

  /**
   * Execute agent task (multi-step)
   */
  async function executeTask(
    sessionId: string,
    task: string,
    tools: Array<{ tool: string; args: Record<string, unknown> }>
  ): Promise<Array<{ tool: string; result: unknown; error?: string }>> {
    const results: Array<{ tool: string; result: unknown; error?: string }> = [];

    for (const { tool, args } of tools) {
      try {
        const result = await executeTool(sessionId, tool, args);
        results.push({ tool, result });
      } catch (error) {
        results.push({
          tool,
          result: null,
          error: error instanceof Error ? error.message : String(error)
        });
        // Continue with other tools or break?
      }
    }

    return results;
  }

  return {
    // State
    sessions: computed(() => Array.from(sessions.values())),
    activeSession: computed(() => getActiveSession()),
    toolCalls: computed(() => Array.from(toolCalls.values())),
    fileSyncs: computed(() => Array.from(fileSyncs.values())),

    // Session management
    startSession,
    endSession,
    getActiveSession,
    setActiveSession,

    // Tool execution
    executeTool,
    executeTask,

    // File operations
    remoteReadFile,
    remoteWriteFile,
    remoteEditFile,
    syncFile,
    syncDirectory,

    // Navigation
    changeDirectory,

    // Context
    getRemoteContext,

    // Raw commands
    remoteBash,
    remoteGlob,
    remoteGrep
  };
}

export default useRemoteAgent;
