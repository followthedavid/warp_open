/**
 * Browser Automation System
 * Chrome/browser integration for web automation and testing.
 * Similar to Claude Code's Chrome extension integration.
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

export type BrowserType = 'chrome' | 'firefox' | 'safari' | 'edge';
export type AutomationStatus = 'idle' | 'connecting' | 'connected' | 'executing' | 'error';

export interface BrowserSession {
  id: string;
  browser: BrowserType;
  status: AutomationStatus;
  url?: string;
  title?: string;
  connectedAt?: number;
  error?: string;
}

export interface PageInfo {
  url: string;
  title: string;
  favicon?: string;
  html?: string;
  text?: string;
  screenshot?: string; // Base64
}

export interface ElementInfo {
  selector: string;
  tagName: string;
  text?: string;
  attributes: Record<string, string>;
  isVisible: boolean;
  bounds?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
}

export interface AutomationAction {
  type: 'click' | 'type' | 'scroll' | 'navigate' | 'wait' | 'screenshot' | 'extract';
  selector?: string;
  value?: string;
  options?: Record<string, unknown>;
}

export interface AutomationScript {
  id: string;
  name: string;
  description?: string;
  actions: AutomationAction[];
  createdAt: number;
}

const STORAGE_KEY = 'warp_open_browser_scripts';

// State
const session = ref<BrowserSession | null>(null);
const savedScripts = ref<Map<string, AutomationScript>>(new Map());
const executionLog = ref<Array<{
  action: AutomationAction;
  result: string;
  timestamp: number;
  error?: string;
}>>([]);

// Load scripts from storage
function loadScripts(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      savedScripts.value = new Map(Object.entries(JSON.parse(stored)));
    }
  } catch (e) {
    console.error('[BrowserAutomation] Error loading scripts:', e);
  }
}

// Save scripts to storage
function saveScripts(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(Object.fromEntries(savedScripts.value)));
  } catch (e) {
    console.error('[BrowserAutomation] Error saving scripts:', e);
  }
}

// Initialize
loadScripts();

function generateId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

export function useBrowserAutomation() {
  const isConnected = computed(() => session.value?.status === 'connected');
  const isExecuting = computed(() => session.value?.status === 'executing');

  /**
   * Connect to browser
   */
  async function connect(browser: BrowserType = 'chrome'): Promise<boolean> {
    if (!invoke) {
      // Fallback: Try to use browser's native APIs
      console.log('[BrowserAutomation] Using web-based automation');
    }

    session.value = {
      id: generateId('session'),
      browser,
      status: 'connecting',
    };

    try {
      if (invoke) {
        const result = await invoke<{ success: boolean; sessionId: string }>('browser_connect', {
          browser,
        });

        if (result.success) {
          session.value.status = 'connected';
          session.value.connectedAt = Date.now();
          console.log(`[BrowserAutomation] Connected to ${browser}`);
          return true;
        }
      } else {
        // Simulated connection for web-only mode
        session.value.status = 'connected';
        session.value.connectedAt = Date.now();
        return true;
      }

      throw new Error('Connection failed');
    } catch (error) {
      session.value.status = 'error';
      session.value.error = error instanceof Error ? error.message : String(error);
      return false;
    }
  }

  /**
   * Disconnect from browser
   */
  async function disconnect(): Promise<void> {
    if (!session.value) return;

    if (invoke) {
      try {
        await invoke('browser_disconnect', { sessionId: session.value.id });
      } catch (error) {
        console.error('[BrowserAutomation] Disconnect error:', error);
      }
    }

    session.value = null;
    console.log('[BrowserAutomation] Disconnected');
  }

  /**
   * Navigate to URL
   */
  async function navigate(url: string): Promise<PageInfo | null> {
    if (!session.value || session.value.status !== 'connected') {
      throw new Error('Not connected to browser');
    }

    session.value.status = 'executing';

    try {
      if (invoke) {
        const result = await invoke<PageInfo>('browser_navigate', {
          sessionId: session.value.id,
          url,
        });

        session.value.url = result.url;
        session.value.title = result.title;
        session.value.status = 'connected';

        logAction({ type: 'navigate', value: url }, 'Navigated successfully');
        return result;
      } else {
        // Web-only: open in new tab
        window.open(url, '_blank');
        session.value.url = url;
        session.value.status = 'connected';
        logAction({ type: 'navigate', value: url }, 'Opened in new tab');
        return { url, title: url };
      }
    } catch (error) {
      session.value.status = 'error';
      logAction({ type: 'navigate', value: url }, '', String(error));
      throw error;
    }
  }

  /**
   * Click an element
   */
  async function click(selector: string): Promise<boolean> {
    if (!invoke) {
      logAction({ type: 'click', selector }, 'Simulated click');
      return true;
    }

    try {
      await invoke('browser_click', {
        sessionId: session.value?.id,
        selector,
      });
      logAction({ type: 'click', selector }, 'Clicked successfully');
      return true;
    } catch (error) {
      logAction({ type: 'click', selector }, '', String(error));
      throw error;
    }
  }

  /**
   * Type text into an element
   */
  async function type(selector: string, text: string): Promise<boolean> {
    if (!invoke) {
      logAction({ type: 'type', selector, value: text }, 'Simulated type');
      return true;
    }

    try {
      await invoke('browser_type', {
        sessionId: session.value?.id,
        selector,
        text,
      });
      logAction({ type: 'type', selector, value: text }, 'Typed successfully');
      return true;
    } catch (error) {
      logAction({ type: 'type', selector, value: text }, '', String(error));
      throw error;
    }
  }

  /**
   * Take a screenshot
   */
  async function screenshot(): Promise<string | null> {
    if (!invoke) {
      logAction({ type: 'screenshot' }, 'Screenshot not available in web mode');
      return null;
    }

    try {
      const result = await invoke<{ screenshot: string }>('browser_screenshot', {
        sessionId: session.value?.id,
      });
      logAction({ type: 'screenshot' }, 'Screenshot captured');
      return result.screenshot;
    } catch (error) {
      logAction({ type: 'screenshot' }, '', String(error));
      throw error;
    }
  }

  /**
   * Extract page content
   */
  async function extractContent(selector?: string): Promise<string> {
    if (!invoke) {
      return 'Content extraction not available in web mode';
    }

    try {
      const result = await invoke<{ content: string }>('browser_extract', {
        sessionId: session.value?.id,
        selector,
      });
      logAction({ type: 'extract', selector }, `Extracted ${result.content.length} chars`);
      return result.content;
    } catch (error) {
      logAction({ type: 'extract', selector }, '', String(error));
      throw error;
    }
  }

  /**
   * Wait for element
   */
  async function waitFor(selector: string, timeout: number = 5000): Promise<boolean> {
    if (!invoke) {
      logAction({ type: 'wait', selector }, 'Simulated wait');
      return true;
    }

    try {
      await invoke('browser_wait_for', {
        sessionId: session.value?.id,
        selector,
        timeout,
      });
      logAction({ type: 'wait', selector }, 'Element found');
      return true;
    } catch (error) {
      logAction({ type: 'wait', selector }, '', String(error));
      return false;
    }
  }

  /**
   * Scroll page
   */
  async function scroll(direction: 'up' | 'down' | 'top' | 'bottom', amount?: number): Promise<void> {
    if (!invoke) {
      logAction({ type: 'scroll', value: direction }, 'Simulated scroll');
      return;
    }

    try {
      await invoke('browser_scroll', {
        sessionId: session.value?.id,
        direction,
        amount,
      });
      logAction({ type: 'scroll', value: direction }, 'Scrolled');
    } catch (error) {
      logAction({ type: 'scroll', value: direction }, '', String(error));
      throw error;
    }
  }

  /**
   * Get page info
   */
  async function getPageInfo(): Promise<PageInfo | null> {
    if (!invoke || !session.value) return null;

    try {
      return await invoke<PageInfo>('browser_get_page_info', {
        sessionId: session.value.id,
      });
    } catch (error) {
      console.error('[BrowserAutomation] Error getting page info:', error);
      return null;
    }
  }

  /**
   * Find elements matching selector
   */
  async function findElements(selector: string): Promise<ElementInfo[]> {
    if (!invoke) return [];

    try {
      return await invoke<ElementInfo[]>('browser_find_elements', {
        sessionId: session.value?.id,
        selector,
      });
    } catch (error) {
      console.error('[BrowserAutomation] Error finding elements:', error);
      return [];
    }
  }

  /**
   * Log an action
   */
  function logAction(action: AutomationAction, result: string, error?: string): void {
    executionLog.value.push({
      action,
      result,
      timestamp: Date.now(),
      error,
    });

    // Keep log limited
    if (executionLog.value.length > 100) {
      executionLog.value = executionLog.value.slice(-100);
    }
  }

  /**
   * Execute an automation script
   */
  async function executeScript(script: AutomationScript): Promise<boolean> {
    if (!isConnected.value) {
      await connect();
    }

    for (const action of script.actions) {
      try {
        switch (action.type) {
          case 'navigate':
            if (action.value) await navigate(action.value);
            break;
          case 'click':
            if (action.selector) await click(action.selector);
            break;
          case 'type':
            if (action.selector && action.value) await type(action.selector, action.value);
            break;
          case 'wait':
            if (action.selector) await waitFor(action.selector);
            break;
          case 'scroll':
            await scroll(action.value as 'up' | 'down' || 'down');
            break;
          case 'screenshot':
            await screenshot();
            break;
          case 'extract':
            await extractContent(action.selector);
            break;
        }
      } catch (error) {
        console.error(`[BrowserAutomation] Script error at action ${action.type}:`, error);
        return false;
      }
    }

    return true;
  }

  /**
   * Save a script
   */
  function saveScript(script: Omit<AutomationScript, 'id' | 'createdAt'>): AutomationScript {
    const newScript: AutomationScript = {
      ...script,
      id: generateId('script'),
      createdAt: Date.now(),
    };

    savedScripts.value.set(newScript.id, newScript);
    saveScripts();

    return newScript;
  }

  /**
   * Delete a script
   */
  function deleteScript(scriptId: string): boolean {
    const deleted = savedScripts.value.delete(scriptId);
    if (deleted) {
      saveScripts();
    }
    return deleted;
  }

  /**
   * Get execution log
   */
  function getLog(): typeof executionLog.value {
    return executionLog.value;
  }

  /**
   * Clear execution log
   */
  function clearLog(): void {
    executionLog.value = [];
  }

  /**
   * Check if browser automation is available
   */
  function isAvailable(): boolean {
    return invoke !== null || typeof window !== 'undefined';
  }

  return {
    // State
    session: computed(() => session.value),
    isConnected,
    isExecuting,
    savedScripts: computed(() => Array.from(savedScripts.value.values())),
    executionLog: computed(() => executionLog.value),

    // Connection
    connect,
    disconnect,
    isAvailable,

    // Navigation
    navigate,
    getPageInfo,

    // Interactions
    click,
    type,
    scroll,
    waitFor,

    // Content
    extractContent,
    screenshot,
    findElements,

    // Scripts
    executeScript,
    saveScript,
    deleteScript,

    // Log
    getLog,
    clearLog,
  };
}
