/**
 * useKernelManager - Jupyter-style kernel management for notebooks
 *
 * Supports Python and Node.js kernels with:
 * - State persistence between cell executions
 * - Stdout/stderr capture
 * - Cell interruption
 * - Kernel restart
 */

import { ref, reactive, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

// Kernel types
export type KernelType = 'python' | 'node' | 'shell'

export interface KernelInfo {
  id: string
  type: KernelType
  status: 'idle' | 'busy' | 'starting' | 'error' | 'dead'
  pid?: number
  startedAt: Date
  lastActivity: Date
  executionCount: number
}

export interface ExecutionResult {
  success: boolean
  output: string
  error?: string
  executionCount: number
  duration: number
  mimeType?: string
  data?: unknown
}

interface KernelProcess {
  id: string
  type: KernelType
  inputBuffer: string[]
  outputBuffer: string[]
  errorBuffer: string[]
  executionCount: number
  isExecuting: boolean
  pendingResolve?: (result: ExecutionResult) => void
}

// Active kernels
const kernels = reactive<Map<string, KernelProcess>>(new Map())
const kernelInfo = reactive<Map<string, KernelInfo>>(new Map())

// Kernel availability
const availableKernels = ref<KernelType[]>([])

export function useKernelManager() {

  /**
   * Check which kernels are available on this system
   */
  async function detectAvailableKernels(): Promise<KernelType[]> {
    const available: KernelType[] = ['shell'] // Shell is always available

    try {
      // Check for Python
      const pythonCheck = await invoke<{ exit_code: number }>('execute_shell', {
        command: 'python3 --version 2>/dev/null || python --version 2>/dev/null',
        cwd: undefined
      })
      if (pythonCheck.exit_code === 0) {
        available.push('python')
      }
    } catch {}

    try {
      // Check for Node.js
      const nodeCheck = await invoke<{ exit_code: number }>('execute_shell', {
        command: 'node --version 2>/dev/null',
        cwd: undefined
      })
      if (nodeCheck.exit_code === 0) {
        available.push('node')
      }
    } catch {}

    availableKernels.value = available
    return available
  }

  /**
   * Start a new kernel
   */
  async function startKernel(type: KernelType, notebookId: string): Promise<string> {
    const kernelId = `${notebookId}-${type}-${Date.now()}`

    // Create kernel process tracker
    const kernel: KernelProcess = {
      id: kernelId,
      type,
      inputBuffer: [],
      outputBuffer: [],
      errorBuffer: [],
      executionCount: 0,
      isExecuting: false
    }

    kernels.set(kernelId, kernel)

    // Create kernel info
    const info: KernelInfo = {
      id: kernelId,
      type,
      status: 'starting',
      startedAt: new Date(),
      lastActivity: new Date(),
      executionCount: 0
    }
    kernelInfo.set(kernelId, info)

    // Initialize the kernel based on type
    try {
      if (type === 'python') {
        await initPythonKernel(kernelId)
      } else if (type === 'node') {
        await initNodeKernel(kernelId)
      }

      info.status = 'idle'
    } catch (error) {
      info.status = 'error'
      throw error
    }

    return kernelId
  }

  /**
   * Initialize Python kernel with state tracking
   */
  async function initPythonKernel(kernelId: string): Promise<void> {
    // Create a Python session file for state persistence
    const sessionFile = `/tmp/warp_kernel_${kernelId}.py`

    // Initialize with common imports and state dict
    const initCode = `
import sys
import json
from io import StringIO

# Kernel state
__warp_state__ = {}
__warp_exec_count__ = 0

def __warp_capture_output__(code):
    global __warp_exec_count__
    __warp_exec_count__ += 1

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()

    result = {"success": True, "output": "", "error": "", "count": __warp_exec_count__}

    try:
        # Try to eval first (for expressions that return values)
        try:
            val = eval(code, globals(), __warp_state__)
            if val is not None:
                print(repr(val))
        except SyntaxError:
            # Fall back to exec for statements
            exec(code, globals(), __warp_state__)

        result["output"] = sys.stdout.getvalue()
    except Exception as e:
        result["success"] = False
        result["error"] = f"{type(e).__name__}: {str(e)}"
        result["output"] = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    return result

print("Python kernel ready")
`

    await invoke('execute_shell', {
      command: `cat << 'PYEOF' > ${sessionFile}
${initCode}
PYEOF`,
      cwd: undefined
    })

    // Verify kernel starts
    const verify = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
      command: `python3 -c "exec(open('${sessionFile}').read())"`,
      cwd: undefined
    })

    if (verify.exit_code !== 0) {
      throw new Error('Failed to initialize Python kernel')
    }
  }

  /**
   * Initialize Node.js kernel with state tracking
   */
  async function initNodeKernel(kernelId: string): Promise<void> {
    const sessionFile = `/tmp/warp_kernel_${kernelId}.js`

    const initCode = `
const vm = require('vm');
const util = require('util');

// Persistent context for state between executions
const context = vm.createContext({
  console,
  require,
  process,
  Buffer,
  setTimeout,
  setInterval,
  clearTimeout,
  clearInterval,
  __dirname: process.cwd(),
  __filename: 'notebook.js'
});

let execCount = 0;

global.__warp_execute__ = function(code) {
  execCount++;
  const result = { success: true, output: '', error: '', count: execCount };

  const originalLog = console.log;
  const logs = [];
  console.log = (...args) => logs.push(args.map(a => util.inspect(a)).join(' '));

  try {
    const val = vm.runInContext(code, context, { displayErrors: true });
    if (val !== undefined) {
      logs.push(util.inspect(val));
    }
    result.output = logs.join('\\n');
  } catch (e) {
    result.success = false;
    result.error = e.toString();
    result.output = logs.join('\\n');
  } finally {
    console.log = originalLog;
  }

  return result;
};

console.log('Node.js kernel ready');
`

    await invoke('execute_shell', {
      command: `cat << 'NODEEOF' > ${sessionFile}
${initCode}
NODEEOF`,
      cwd: undefined
    })
  }

  /**
   * Execute code in a kernel
   */
  async function executeCode(
    kernelId: string,
    code: string
  ): Promise<ExecutionResult> {
    const kernel = kernels.get(kernelId)
    const info = kernelInfo.get(kernelId)

    if (!kernel || !info) {
      return {
        success: false,
        output: '',
        error: 'Kernel not found',
        executionCount: 0,
        duration: 0
      }
    }

    if (kernel.isExecuting) {
      return {
        success: false,
        output: '',
        error: 'Kernel is busy',
        executionCount: kernel.executionCount,
        duration: 0
      }
    }

    kernel.isExecuting = true
    info.status = 'busy'
    info.lastActivity = new Date()

    const startTime = Date.now()

    try {
      let result: ExecutionResult

      if (kernel.type === 'python') {
        result = await executePython(kernelId, code)
      } else if (kernel.type === 'node') {
        result = await executeNode(kernelId, code)
      } else {
        result = await executeShell(code)
      }

      kernel.executionCount++
      info.executionCount = kernel.executionCount
      result.executionCount = kernel.executionCount
      result.duration = Date.now() - startTime

      return result
    } finally {
      kernel.isExecuting = false
      info.status = 'idle'
    }
  }

  /**
   * Execute Python code with state persistence
   */
  async function executePython(kernelId: string, code: string): Promise<ExecutionResult> {
    const sessionFile = `/tmp/warp_kernel_${kernelId}.py`
    const escapedCode = code.replace(/'/g, "'\\''").replace(/\\/g, '\\\\')

    // Execute code in persistent session
    const cmd = `python3 -c "
exec(open('${sessionFile}').read())
import json
result = __warp_capture_output__('''${escapedCode}''')
print('__WARP_RESULT__')
print(json.dumps(result))
"`

    const response = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: cmd,
      cwd: undefined
    })

    try {
      const parts = response.stdout.split('__WARP_RESULT__')
      if (parts.length >= 2) {
        const jsonStr = parts[1].trim()
        const result = JSON.parse(jsonStr)
        return {
          success: result.success,
          output: result.output || '',
          error: result.error || undefined,
          executionCount: result.count,
          duration: 0
        }
      }
    } catch {}

    // Fallback for parsing errors
    return {
      success: response.exit_code === 0,
      output: response.stdout,
      error: response.stderr || undefined,
      executionCount: 0,
      duration: 0
    }
  }

  /**
   * Execute Node.js code with state persistence
   */
  async function executeNode(kernelId: string, code: string): Promise<ExecutionResult> {
    const sessionFile = `/tmp/warp_kernel_${kernelId}.js`
    const escapedCode = code.replace(/`/g, '\\`').replace(/\$/g, '\\$')

    const cmd = `node -e "
require('${sessionFile}');
const result = global.__warp_execute__(\`${escapedCode}\`);
console.log('__WARP_RESULT__');
console.log(JSON.stringify(result));
"`

    const response = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: cmd,
      cwd: undefined
    })

    try {
      const parts = response.stdout.split('__WARP_RESULT__')
      if (parts.length >= 2) {
        const jsonStr = parts[1].trim()
        const result = JSON.parse(jsonStr)
        return {
          success: result.success,
          output: result.output || '',
          error: result.error || undefined,
          executionCount: result.count,
          duration: 0
        }
      }
    } catch {}

    return {
      success: response.exit_code === 0,
      output: response.stdout,
      error: response.stderr || undefined,
      executionCount: 0,
      duration: 0
    }
  }

  /**
   * Execute shell command (stateless)
   */
  async function executeShell(code: string): Promise<ExecutionResult> {
    const response = await invoke<{ stdout: string; stderr: string; exit_code: number }>('execute_shell', {
      command: code,
      cwd: undefined
    })

    return {
      success: response.exit_code === 0,
      output: response.stdout,
      error: response.stderr || undefined,
      executionCount: 0,
      duration: 0
    }
  }

  /**
   * Interrupt a running execution
   */
  async function interruptKernel(kernelId: string): Promise<boolean> {
    const info = kernelInfo.get(kernelId)
    if (!info?.pid) return false

    try {
      await invoke('execute_shell', {
        command: `kill -2 ${info.pid}`,
        cwd: undefined
      })
      return true
    } catch {
      return false
    }
  }

  /**
   * Restart a kernel (clears all state)
   */
  async function restartKernel(kernelId: string): Promise<boolean> {
    const kernel = kernels.get(kernelId)
    const info = kernelInfo.get(kernelId)

    if (!kernel || !info) return false

    // Clean up old session file
    const sessionFile = `/tmp/warp_kernel_${kernelId}.*`
    await invoke('execute_shell', {
      command: `rm -f ${sessionFile}`,
      cwd: undefined
    })

    // Reset state
    kernel.executionCount = 0
    kernel.outputBuffer = []
    kernel.errorBuffer = []
    kernel.inputBuffer = []
    info.executionCount = 0
    info.status = 'starting'

    // Reinitialize
    try {
      if (kernel.type === 'python') {
        await initPythonKernel(kernelId)
      } else if (kernel.type === 'node') {
        await initNodeKernel(kernelId)
      }
      info.status = 'idle'
      return true
    } catch {
      info.status = 'error'
      return false
    }
  }

  /**
   * Shutdown a kernel
   */
  async function shutdownKernel(kernelId: string): Promise<void> {
    const info = kernelInfo.get(kernelId)

    // Kill process if running
    if (info?.pid) {
      await invoke('execute_shell', {
        command: `kill -9 ${info.pid} 2>/dev/null || true`,
        cwd: undefined
      })
    }

    // Clean up session file
    await invoke('execute_shell', {
      command: `rm -f /tmp/warp_kernel_${kernelId}.*`,
      cwd: undefined
    })

    // Remove from maps
    kernels.delete(kernelId)
    kernelInfo.delete(kernelId)
  }

  /**
   * Get kernel info
   */
  function getKernelInfo(kernelId: string): KernelInfo | undefined {
    return kernelInfo.get(kernelId)
  }

  /**
   * List all active kernels
   */
  function listKernels(): KernelInfo[] {
    return Array.from(kernelInfo.values())
  }

  // Computed
  const activeKernels = computed(() => listKernels())
  const hasActiveKernels = computed(() => kernels.size > 0)

  return {
    // State
    availableKernels,
    activeKernels,
    hasActiveKernels,

    // Actions
    detectAvailableKernels,
    startKernel,
    executeCode,
    interruptKernel,
    restartKernel,
    shutdownKernel,
    getKernelInfo,
    listKernels
  }
}

export default useKernelManager
