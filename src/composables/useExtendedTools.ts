/**
 * Extended AI Tools
 * Additional tools for AI: git, npm, curl, env, docker commands
 */

import { ref, computed } from 'vue';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

export interface ToolResult {
  success: boolean;
  output: string;
  error?: string;
  duration?: number;
}

export interface GitCommandOptions {
  command: string;
  workingDir?: string;
  args?: string[];
}

export interface NpmCommandOptions {
  command: 'install' | 'run' | 'init' | 'test' | 'build' | 'publish' | 'update' | 'uninstall';
  args?: string[];
  workingDir?: string;
}

export interface CurlOptions {
  url: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  data?: string;
  timeout?: number;
}

export interface DockerCommandOptions {
  command: 'ps' | 'images' | 'run' | 'stop' | 'rm' | 'logs' | 'exec' | 'build' | 'pull' | 'push';
  args?: string[];
}

export interface EnvOptions {
  action: 'get' | 'set' | 'unset' | 'list';
  key?: string;
  value?: string;
}

// Track tool usage
const toolHistory = ref<Array<{ tool: string; args: unknown; result: ToolResult; timestamp: Date }>>([]);
const isExecuting = ref(false);

export function useExtendedTools() {
  /**
   * Execute a git command
   */
  async function gitCommand(options: GitCommandOptions): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const { command, workingDir, args = [] } = options;

      // Validate git command (prevent dangerous operations)
      const dangerousCommands = ['push --force', 'reset --hard', 'clean -fd'];
      const fullCommand = `git ${command} ${args.join(' ')}`.trim();

      for (const dangerous of dangerousCommands) {
        if (fullCommand.includes(dangerous)) {
          return {
            success: false,
            output: '',
            error: `Dangerous command blocked: ${dangerous}. Please run manually if intended.`,
          };
        }
      }

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command: fullCommand,
          workingDir,
        });

        const toolResult: ToolResult = {
          success: result.exit_code === 0,
          output: result.stdout || result.stderr,
          error: result.exit_code !== 0 ? result.stderr : undefined,
          duration: Date.now() - start,
        };

        trackUsage('git_command', options, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Execute an npm command
   */
  async function npmCommand(options: NpmCommandOptions): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const { command, args = [], workingDir } = options;
      const fullCommand = `npm ${command} ${args.join(' ')}`.trim();

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command: fullCommand,
          workingDir,
        });

        const toolResult: ToolResult = {
          success: result.exit_code === 0,
          output: result.stdout || result.stderr,
          error: result.exit_code !== 0 ? result.stderr : undefined,
          duration: Date.now() - start,
        };

        trackUsage('npm_command', options, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Execute a curl request
   */
  async function curlRequest(options: CurlOptions): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const { url, method = 'GET', headers = {}, data, timeout = 30 } = options;

      // Build curl command
      let command = `curl -s -X ${method}`;

      // Add timeout
      command += ` --max-time ${timeout}`;

      // Add headers
      for (const [key, value] of Object.entries(headers)) {
        command += ` -H "${key}: ${value}"`;
      }

      // Add data for POST/PUT/PATCH
      if (data && ['POST', 'PUT', 'PATCH'].includes(method)) {
        command += ` -d '${data.replace(/'/g, "'\\''")}'`;
      }

      // Add URL (escape special characters)
      command += ` "${url}"`;

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command,
        });

        const toolResult: ToolResult = {
          success: result.exit_code === 0,
          output: result.stdout,
          error: result.exit_code !== 0 ? result.stderr : undefined,
          duration: Date.now() - start,
        };

        trackUsage('curl_request', options, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Manage environment variables
   */
  async function envCommand(options: EnvOptions): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const { action, key, value } = options;

      if (isTauri && invoke) {
        let command: string;

        switch (action) {
          case 'get':
            if (!key) return { success: false, output: '', error: 'Key required for get' };
            command = `echo $${key}`;
            break;

          case 'set':
            if (!key || value === undefined) {
              return { success: false, output: '', error: 'Key and value required for set' };
            }
            command = `export ${key}="${value}" && echo "Set ${key}"`;
            break;

          case 'unset':
            if (!key) return { success: false, output: '', error: 'Key required for unset' };
            command = `unset ${key} && echo "Unset ${key}"`;
            break;

          case 'list':
            command = 'env | sort';
            break;

          default:
            return { success: false, output: '', error: `Unknown action: ${action}` };
        }

        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command,
        });

        const toolResult: ToolResult = {
          success: result.exit_code === 0,
          output: result.stdout.trim(),
          error: result.exit_code !== 0 ? result.stderr : undefined,
          duration: Date.now() - start,
        };

        trackUsage('env_command', options, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Execute a docker command
   */
  async function dockerCommand(options: DockerCommandOptions): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const { command, args = [] } = options;
      const fullCommand = `docker ${command} ${args.join(' ')}`.trim();

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command: fullCommand,
        });

        const toolResult: ToolResult = {
          success: result.exit_code === 0,
          output: result.stdout || result.stderr,
          error: result.exit_code !== 0 ? result.stderr : undefined,
          duration: Date.now() - start,
        };

        trackUsage('docker_command', options, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * List running processes
   */
  async function listProcesses(filter?: string): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      let command = 'ps aux';
      if (filter) {
        command += ` | grep -i "${filter}" | grep -v grep`;
      }

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command,
        });

        const toolResult: ToolResult = {
          success: true,
          output: result.stdout,
          duration: Date.now() - start,
        };

        trackUsage('list_processes', { filter }, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Kill a process
   */
  async function killProcess(pid: number, signal: number = 15): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const command = `kill -${signal} ${pid}`;

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command,
        });

        const toolResult: ToolResult = {
          success: result.exit_code === 0,
          output: result.exit_code === 0 ? `Sent signal ${signal} to process ${pid}` : result.stderr,
          error: result.exit_code !== 0 ? result.stderr : undefined,
          duration: Date.now() - start,
        };

        trackUsage('kill_process', { pid, signal }, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Get system information
   */
  async function systemInfo(): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const command = `
        echo "=== System Info ==="
        uname -a
        echo ""
        echo "=== Memory ==="
        vm_stat 2>/dev/null || free -h 2>/dev/null || echo "Memory info not available"
        echo ""
        echo "=== Disk ==="
        df -h / 2>/dev/null || echo "Disk info not available"
        echo ""
        echo "=== CPU ==="
        sysctl -n machdep.cpu.brand_string 2>/dev/null || cat /proc/cpuinfo 2>/dev/null | grep "model name" | head -1 || echo "CPU info not available"
      `;

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command,
        });

        const toolResult: ToolResult = {
          success: true,
          output: result.stdout,
          duration: Date.now() - start,
        };

        trackUsage('system_info', {}, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Find files
   */
  async function findFiles(
    pattern: string,
    directory: string = '.',
    maxDepth: number = 5
  ): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const command = `find "${directory}" -maxdepth ${maxDepth} -name "${pattern}" 2>/dev/null | head -100`;

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command,
        });

        const toolResult: ToolResult = {
          success: true,
          output: result.stdout,
          duration: Date.now() - start,
        };

        trackUsage('find_files', { pattern, directory, maxDepth }, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Calculate file/directory size
   */
  async function diskUsage(path: string): Promise<ToolResult> {
    isExecuting.value = true;
    const start = Date.now();

    try {
      const command = `du -sh "${path}" 2>/dev/null`;

      if (isTauri && invoke) {
        const result = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
          command,
        });

        const toolResult: ToolResult = {
          success: result.exit_code === 0,
          output: result.stdout.trim(),
          error: result.exit_code !== 0 ? result.stderr : undefined,
          duration: Date.now() - start,
        };

        trackUsage('disk_usage', { path }, toolResult);
        return toolResult;
      }

      return { success: false, output: '', error: 'Not running in Tauri' };
    } catch (e) {
      return { success: false, output: '', error: String(e), duration: Date.now() - start };
    } finally {
      isExecuting.value = false;
    }
  }

  /**
   * Track tool usage
   */
  function trackUsage(tool: string, args: unknown, result: ToolResult) {
    toolHistory.value.push({
      tool,
      args,
      result,
      timestamp: new Date(),
    });

    // Keep last 100 entries
    if (toolHistory.value.length > 100) {
      toolHistory.value.shift();
    }
  }

  /**
   * Get tool for AI execution
   */
  function getTool(name: string): ((args: Record<string, unknown>) => Promise<ToolResult>) | null {
    const tools: Record<string, (args: Record<string, unknown>) => Promise<ToolResult>> = {
      git_command: async (args) => gitCommand(args as unknown as GitCommandOptions),
      npm_command: async (args) => npmCommand(args as unknown as NpmCommandOptions),
      curl_request: async (args) => curlRequest(args as unknown as CurlOptions),
      env_command: async (args) => envCommand(args as unknown as EnvOptions),
      docker_command: async (args) => dockerCommand(args as unknown as DockerCommandOptions),
      list_processes: async (args) => listProcesses(args.filter as string | undefined),
      kill_process: async (args) => killProcess(args.pid as number, args.signal as number | undefined),
      system_info: async () => systemInfo(),
      find_files: async (args) =>
        findFiles(
          args.pattern as string,
          args.directory as string | undefined,
          args.maxDepth as number | undefined
        ),
      disk_usage: async (args) => diskUsage(args.path as string),
    };

    return tools[name] || null;
  }

  /**
   * Get all available tools for system prompt
   */
  function getToolDescriptions(): string {
    return `
## Extended Tools

### git_command
Execute git commands. Args: command (string), workingDir (optional), args (optional array)
Example: {"tool": "git_command", "args": {"command": "status"}}
Note: Dangerous commands (push --force, reset --hard) are blocked.

### npm_command
Execute npm commands. Args: command (install|run|test|build|etc), args (optional array), workingDir (optional)
Example: {"tool": "npm_command", "args": {"command": "run", "args": ["dev"]}}

### curl_request
Make HTTP requests. Args: url (string), method (GET|POST|PUT|DELETE|PATCH), headers (optional object), data (optional string), timeout (optional number)
Example: {"tool": "curl_request", "args": {"url": "https://api.example.com/data", "method": "GET"}}

### env_command
Manage environment variables. Args: action (get|set|unset|list), key (optional), value (optional)
Example: {"tool": "env_command", "args": {"action": "get", "key": "PATH"}}

### docker_command
Execute docker commands. Args: command (ps|images|run|stop|rm|logs|exec|build|pull|push), args (optional array)
Example: {"tool": "docker_command", "args": {"command": "ps"}}

### list_processes
List running processes. Args: filter (optional string)
Example: {"tool": "list_processes", "args": {"filter": "node"}}

### kill_process
Kill a process by PID. Args: pid (number), signal (optional number, default 15)
Example: {"tool": "kill_process", "args": {"pid": 1234}}

### system_info
Get system information (OS, memory, disk, CPU). No args required.
Example: {"tool": "system_info", "args": {}}

### find_files
Find files by pattern. Args: pattern (string), directory (optional, default "."), maxDepth (optional, default 5)
Example: {"tool": "find_files", "args": {"pattern": "*.ts", "directory": "src"}}

### disk_usage
Get disk usage for path. Args: path (string)
Example: {"tool": "disk_usage", "args": {"path": "."}}
`;
  }

  return {
    isExecuting: computed(() => isExecuting.value),
    toolHistory: computed(() => toolHistory.value),
    gitCommand,
    npmCommand,
    curlRequest,
    envCommand,
    dockerCommand,
    listProcesses,
    killProcess,
    systemInfo,
    findFiles,
    diskUsage,
    getTool,
    getToolDescriptions,
  };
}
