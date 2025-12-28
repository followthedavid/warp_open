/**
 * MCP (Model Context Protocol) Server Support
 * Connect to external MCP servers for extended capabilities.
 * Compatible with Claude Desktop MCP server ecosystem.
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

export type MCPTransport = 'stdio' | 'http' | 'websocket';
export type MCPServerStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

export interface MCPServerConfig {
  id: string;
  name: string;
  description?: string;
  transport: MCPTransport;
  command?: string; // For stdio transport
  args?: string[];
  url?: string; // For http/websocket transport
  env?: Record<string, string>;
  enabled: boolean;
}

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  serverId: string;
}

export interface MCPResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
  serverId: string;
}

export interface MCPPrompt {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
  serverId: string;
}

export interface MCPServer {
  config: MCPServerConfig;
  status: MCPServerStatus;
  tools: MCPTool[];
  resources: MCPResource[];
  prompts: MCPPrompt[];
  error?: string;
  connectedAt?: number;
  version?: string;
}

export interface MCPToolResult {
  content: Array<{
    type: 'text' | 'image' | 'resource';
    text?: string;
    data?: string;
    mimeType?: string;
  }>;
  isError?: boolean;
}

// Storage key for configs
const STORAGE_KEY = 'warp_open_mcp_servers';

// Built-in MCP server configurations (examples)
const BUILTIN_SERVERS: MCPServerConfig[] = [
  {
    id: 'filesystem',
    name: 'Filesystem',
    description: 'Access to local filesystem operations',
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
    enabled: false,
  },
  {
    id: 'github',
    name: 'GitHub',
    description: 'GitHub API integration',
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-github'],
    env: { GITHUB_TOKEN: '' },
    enabled: false,
  },
  {
    id: 'postgres',
    name: 'PostgreSQL',
    description: 'PostgreSQL database access',
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-postgres'],
    env: { DATABASE_URL: '' },
    enabled: false,
  },
  {
    id: 'brave-search',
    name: 'Brave Search',
    description: 'Web search via Brave Search API',
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-brave-search'],
    env: { BRAVE_API_KEY: '' },
    enabled: false,
  },
  {
    id: 'puppeteer',
    name: 'Puppeteer',
    description: 'Browser automation',
    transport: 'stdio',
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-puppeteer'],
    enabled: false,
  },
];

// State
const servers = ref<Map<string, MCPServer>>(new Map());
const customConfigs = ref<MCPServerConfig[]>([]);

// Load configs from storage
function loadConfigs(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      customConfigs.value = JSON.parse(stored);
    }
  } catch (e) {
    console.error('[MCP] Error loading configs:', e);
  }
}

// Save configs to storage
function saveConfigs(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(customConfigs.value));
  } catch (e) {
    console.error('[MCP] Error saving configs:', e);
  }
}

// Initialize
loadConfigs();

export function useMCPServers() {
  const allConfigs = computed(() => [
    ...BUILTIN_SERVERS,
    ...customConfigs.value,
  ]);

  const connectedServers = computed(() =>
    Array.from(servers.value.values()).filter(s => s.status === 'connected')
  );

  const allTools = computed(() => {
    const tools: MCPTool[] = [];
    for (const server of connectedServers.value) {
      tools.push(...server.tools);
    }
    return tools;
  });

  const allResources = computed(() => {
    const resources: MCPResource[] = [];
    for (const server of connectedServers.value) {
      resources.push(...server.resources);
    }
    return resources;
  });

  const allPrompts = computed(() => {
    const prompts: MCPPrompt[] = [];
    for (const server of connectedServers.value) {
      prompts.push(...server.prompts);
    }
    return prompts;
  });

  /**
   * Connect to an MCP server
   */
  async function connect(configId: string): Promise<MCPServer> {
    const config = allConfigs.value.find(c => c.id === configId);
    if (!config) {
      throw new Error(`Server config not found: ${configId}`);
    }

    if (!invoke) {
      throw new Error('Tauri not available');
    }

    // Create server entry
    const server: MCPServer = {
      config,
      status: 'connecting',
      tools: [],
      resources: [],
      prompts: [],
    };

    servers.value.set(config.id, server);

    try {
      // Connect via Tauri backend
      const result = await invoke<{
        tools: MCPTool[];
        resources: MCPResource[];
        prompts: MCPPrompt[];
        version?: string;
      }>('mcp_connect', {
        serverId: config.id,
        transport: config.transport,
        command: config.command,
        args: config.args,
        url: config.url,
        env: config.env,
      });

      // Update server with capabilities
      server.status = 'connected';
      server.connectedAt = Date.now();
      server.version = result.version;
      server.tools = result.tools.map(t => ({ ...t, serverId: config.id }));
      server.resources = result.resources.map(r => ({ ...r, serverId: config.id }));
      server.prompts = result.prompts.map(p => ({ ...p, serverId: config.id }));

      console.log(`[MCP] Connected to ${config.name}:`, {
        tools: server.tools.length,
        resources: server.resources.length,
        prompts: server.prompts.length,
      });

      return server;
    } catch (error) {
      server.status = 'error';
      server.error = error instanceof Error ? error.message : String(error);
      console.error(`[MCP] Failed to connect to ${config.name}:`, error);
      throw error;
    }
  }

  /**
   * Disconnect from an MCP server
   */
  async function disconnect(serverId: string): Promise<void> {
    const server = servers.value.get(serverId);
    if (!server) return;

    if (invoke) {
      try {
        await invoke('mcp_disconnect', { serverId });
      } catch (error) {
        console.error(`[MCP] Error disconnecting from ${serverId}:`, error);
      }
    }

    servers.value.delete(serverId);
    console.log(`[MCP] Disconnected from ${serverId}`);
  }

  /**
   * Call a tool on an MCP server
   */
  async function callTool(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<MCPToolResult> {
    // Find which server has this tool
    const tool = allTools.value.find(t => t.name === toolName);
    if (!tool) {
      throw new Error(`Tool not found: ${toolName}`);
    }

    if (!invoke) {
      throw new Error('Tauri not available');
    }

    try {
      const result = await invoke<MCPToolResult>('mcp_call_tool', {
        serverId: tool.serverId,
        toolName,
        args,
      });

      return result;
    } catch (error) {
      console.error(`[MCP] Tool call error:`, error);
      return {
        content: [{
          type: 'text',
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
        }],
        isError: true,
      };
    }
  }

  /**
   * Read a resource from an MCP server
   */
  async function readResource(uri: string): Promise<string> {
    // Find which server has this resource
    const resource = allResources.value.find(r => r.uri === uri);
    if (!resource) {
      throw new Error(`Resource not found: ${uri}`);
    }

    if (!invoke) {
      throw new Error('Tauri not available');
    }

    const result = await invoke<{ content: string }>('mcp_read_resource', {
      serverId: resource.serverId,
      uri,
    });

    return result.content;
  }

  /**
   * Get a prompt from an MCP server
   */
  async function getPrompt(
    promptName: string,
    args?: Record<string, string>
  ): Promise<string> {
    // Find which server has this prompt
    const prompt = allPrompts.value.find(p => p.name === promptName);
    if (!prompt) {
      throw new Error(`Prompt not found: ${promptName}`);
    }

    if (!invoke) {
      throw new Error('Tauri not available');
    }

    const result = await invoke<{ content: string }>('mcp_get_prompt', {
      serverId: prompt.serverId,
      promptName,
      args,
    });

    return result.content;
  }

  /**
   * Add a custom server config
   */
  function addServer(config: Omit<MCPServerConfig, 'id'>): MCPServerConfig {
    const newConfig: MCPServerConfig = {
      ...config,
      id: `custom_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
    };

    customConfigs.value.push(newConfig);
    saveConfigs();

    return newConfig;
  }

  /**
   * Update a server config
   */
  function updateServer(serverId: string, updates: Partial<MCPServerConfig>): void {
    const index = customConfigs.value.findIndex(c => c.id === serverId);
    if (index >= 0) {
      customConfigs.value[index] = { ...customConfigs.value[index], ...updates };
      saveConfigs();
    }
  }

  /**
   * Remove a server config
   */
  function removeServer(serverId: string): void {
    // Disconnect first if connected
    disconnect(serverId);

    const index = customConfigs.value.findIndex(c => c.id === serverId);
    if (index >= 0) {
      customConfigs.value.splice(index, 1);
      saveConfigs();
    }
  }

  /**
   * Toggle server enabled state
   */
  function toggleServer(serverId: string): void {
    const config = allConfigs.value.find(c => c.id === serverId);
    if (!config) return;

    // For built-in servers, create override in custom configs
    const customIndex = customConfigs.value.findIndex(c => c.id === serverId);
    if (customIndex >= 0) {
      customConfigs.value[customIndex].enabled = !customConfigs.value[customIndex].enabled;
    } else {
      // Create override for built-in
      customConfigs.value.push({
        ...config,
        enabled: !config.enabled,
      });
    }

    saveConfigs();
  }

  /**
   * Get server by ID
   */
  function getServer(serverId: string): MCPServer | undefined {
    return servers.value.get(serverId);
  }

  /**
   * Auto-connect enabled servers
   */
  async function autoConnect(): Promise<void> {
    const enabledConfigs = allConfigs.value.filter(c => c.enabled);

    for (const config of enabledConfigs) {
      try {
        await connect(config.id);
      } catch (error) {
        console.error(`[MCP] Auto-connect failed for ${config.name}:`, error);
      }
    }
  }

  /**
   * Get tool descriptions for AI system prompt
   */
  function getToolsForPrompt(): string {
    if (allTools.value.length === 0) {
      return '';
    }

    let prompt = '\n\n=== MCP SERVER TOOLS ===\n';
    prompt += 'The following tools are available from connected MCP servers:\n\n';

    for (const tool of allTools.value) {
      prompt += `Tool: mcp_${tool.name}\n`;
      prompt += `Server: ${tool.serverId}\n`;
      prompt += `Description: ${tool.description}\n`;
      prompt += `Input Schema: ${JSON.stringify(tool.inputSchema, null, 2)}\n\n`;
    }

    return prompt;
  }

  /**
   * Get resources list for AI context
   */
  function getResourcesForContext(): string {
    if (allResources.value.length === 0) {
      return '';
    }

    let context = '\n\n=== AVAILABLE MCP RESOURCES ===\n';

    for (const resource of allResources.value) {
      context += `- ${resource.uri}: ${resource.name}`;
      if (resource.description) {
        context += ` - ${resource.description}`;
      }
      context += '\n';
    }

    return context;
  }

  /**
   * Export configs for backup
   */
  function exportConfigs(): string {
    return JSON.stringify(customConfigs.value, null, 2);
  }

  /**
   * Import configs from backup
   */
  function importConfigs(json: string): number {
    try {
      const imported = JSON.parse(json) as MCPServerConfig[];
      let count = 0;

      for (const config of imported) {
        if (!customConfigs.value.find(c => c.id === config.id)) {
          customConfigs.value.push(config);
          count++;
        }
      }

      saveConfigs();
      return count;
    } catch (error) {
      console.error('[MCP] Import error:', error);
      return 0;
    }
  }

  /**
   * Get statistics
   */
  function getStats() {
    return {
      totalConfigs: allConfigs.value.length,
      enabledConfigs: allConfigs.value.filter(c => c.enabled).length,
      connectedServers: connectedServers.value.length,
      totalTools: allTools.value.length,
      totalResources: allResources.value.length,
      totalPrompts: allPrompts.value.length,
    };
  }

  return {
    // State
    servers: computed(() => Array.from(servers.value.values())),
    connectedServers,
    allConfigs,
    builtinServers: BUILTIN_SERVERS,
    customConfigs: computed(() => customConfigs.value),
    allTools,
    allResources,
    allPrompts,

    // Connection
    connect,
    disconnect,
    autoConnect,
    getServer,

    // Tools/Resources/Prompts
    callTool,
    readResource,
    getPrompt,

    // Configuration
    addServer,
    updateServer,
    removeServer,
    toggleServer,

    // AI Integration
    getToolsForPrompt,
    getResourcesForContext,

    // Import/Export
    exportConfigs,
    importConfigs,
    getStats,
  };
}
