/**
 * useVisualUnderstanding - Screen Capture and Analysis
 *
 * Provides visual context capabilities:
 * - Screen capture (full screen, window, selection)
 * - Image analysis via local vision models
 * - OCR for text extraction
 * - UI element detection
 *
 * Designed to give the AI "eyes" to understand what you're looking at.
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { useConstitution } from './useConstitution'
import { useAuditLog } from './useAuditLog'

// ============================================================================
// TYPES
// ============================================================================

export interface CaptureOptions {
  type: 'fullscreen' | 'window' | 'selection'
  windowName?: string
  delay?: number // Delay before capture in ms
  format?: 'png' | 'jpg'
}

export interface AnalysisResult {
  id: string
  timestamp: Date
  imagePath: string
  description: string
  elements: UIElement[]
  text: string[]
  suggestions?: string[]
  processingTime: number
}

export interface UIElement {
  type: 'button' | 'input' | 'text' | 'image' | 'link' | 'menu' | 'unknown'
  label?: string
  bounds: { x: number; y: number; width: number; height: number }
  confidence: number
}

export interface VisualContext {
  currentScreen: AnalysisResult | null
  recentCaptures: AnalysisResult[]
  isCapturing: boolean
  isAnalyzing: boolean
}

// ============================================================================
// STORAGE
// ============================================================================

const HISTORY_KEY = 'warp_visual_history'
const MAX_HISTORY = 20

function loadHistory(): AnalysisResult[] {
  try {
    const stored = localStorage.getItem(HISTORY_KEY)
    if (stored) {
      return JSON.parse(stored).map((r: any) => ({
        ...r,
        timestamp: new Date(r.timestamp)
      }))
    }
  } catch {}
  return []
}

function saveHistory(history: AnalysisResult[]): void {
  const trimmed = history.slice(-MAX_HISTORY)
  localStorage.setItem(HISTORY_KEY, JSON.stringify(trimmed))
}

// ============================================================================
// COMPOSABLE
// ============================================================================

export function useVisualUnderstanding() {
  const history = ref<AnalysisResult[]>(loadHistory())
  const currentCapture = ref<AnalysisResult | null>(null)
  const isCapturing = ref(false)
  const isAnalyzing = ref(false)
  const error = ref<string | null>(null)

  const constitution = useConstitution()
  const auditLog = useAuditLog()

  // Capture directory
  const captureDir = '~/.warp_open/captures'

  // ========================================================================
  // SCREEN CAPTURE
  // ========================================================================

  /**
   * Initialize capture directory
   */
  async function initCaptureDir(): Promise<void> {
    await invoke('execute_shell', {
      command: `mkdir -p ${captureDir}`,
      cwd: undefined
    })
  }

  /**
   * Capture the screen
   */
  async function captureScreen(options: CaptureOptions = { type: 'fullscreen' }): Promise<string | null> {
    isCapturing.value = true
    error.value = null

    try {
      await initCaptureDir()

      const timestamp = Date.now()
      const filename = `capture_${timestamp}.${options.format || 'png'}`
      const filepath = `${captureDir}/${filename}`

      // Add delay if specified
      if (options.delay) {
        await new Promise(resolve => setTimeout(resolve, options.delay))
      }

      let command: string

      if (options.type === 'window' && options.windowName) {
        // Capture specific window
        command = `screencapture -l $(osascript -e 'tell app "${options.windowName}" to id of window 1') ${filepath}`
      } else if (options.type === 'selection') {
        // Interactive selection (macOS)
        command = `screencapture -i ${filepath}`
      } else {
        // Full screen
        command = `screencapture -x ${filepath}`
      }

      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command,
        cwd: undefined
      })

      if (result.exit_code === 0) {
        // Verify file exists
        const checkResult = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
          command: `test -f ${filepath} && echo "exists"`,
          cwd: undefined
        })

        if (checkResult.stdout.trim() === 'exists') {
          await auditLog.log('screen_capture', `Captured screen: ${options.type}`, {
            details: { filepath, type: options.type },
            riskLevel: 'low'
          })
          return filepath
        }
      }

      error.value = 'Screen capture failed'
      return null

    } catch (err) {
      error.value = `Capture error: ${err}`
      console.error('[Visual] Capture error:', err)
      return null
    } finally {
      isCapturing.value = false
    }
  }

  /**
   * Capture the active window
   */
  async function captureActiveWindow(): Promise<string | null> {
    try {
      // Get active window name
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: `osascript -e 'tell application "System Events" to get name of first application process whose frontmost is true'`,
        cwd: undefined
      })

      if (result.exit_code === 0 && result.stdout.trim()) {
        return captureScreen({
          type: 'window',
          windowName: result.stdout.trim()
        })
      }
    } catch {}

    // Fallback to interactive selection
    return captureScreen({ type: 'selection' })
  }

  // ========================================================================
  // IMAGE ANALYSIS
  // ========================================================================

  /**
   * Analyze an image using local vision model
   */
  async function analyzeImage(imagePath: string, prompt?: string): Promise<AnalysisResult | null> {
    isAnalyzing.value = true
    error.value = null

    const startTime = Date.now()

    try {
      // Check constitution
      const validation = constitution.validateAction('screen_analysis')
      if (!validation.allowed) {
        error.value = validation.reason
        return null
      }

      // Convert image to base64
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: `base64 -i ${imagePath}`,
        cwd: undefined
      })

      if (result.exit_code !== 0) {
        error.value = 'Failed to read image'
        return null
      }

      const base64Image = result.stdout.trim()

      // Try to use llava or other vision model via Ollama
      const analysisPrompt = prompt || 'Describe what you see in this screenshot. Identify any UI elements, buttons, text, and suggest what the user might want to do.'

      // Check if llava is available
      const modelCheck = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: 'ollama list | grep -i llava || ollama list | grep -i vision',
        cwd: undefined
      })

      let description = ''
      let elements: UIElement[] = []
      let extractedText: string[] = []

      if (modelCheck.exit_code === 0 && modelCheck.stdout.trim()) {
        // Use vision model
        const modelName = modelCheck.stdout.trim().split('\n')[0].split(/\s+/)[0]

        const analysisResult = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
          command: `echo '${analysisPrompt}' | ollama run ${modelName} --images ${imagePath}`,
          cwd: undefined
        })

        if (analysisResult.exit_code === 0) {
          description = analysisResult.stdout.trim()
        }
      } else {
        // Fallback: Use OCR only
        description = 'No vision model available. Using OCR extraction only.'
      }

      // Run OCR
      extractedText = await extractText(imagePath)

      // Basic UI element detection (would need proper ML model for accuracy)
      // For now, return a simplified result

      const analysisResult: AnalysisResult = {
        id: `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        imagePath,
        description,
        elements,
        text: extractedText,
        processingTime: Date.now() - startTime
      }

      // Store in history
      history.value.push(analysisResult)
      saveHistory(history.value)

      currentCapture.value = analysisResult

      await auditLog.log('screen_analysis', 'Analyzed screen capture', {
        details: { imagePath, textFound: extractedText.length },
        riskLevel: 'low'
      })

      return analysisResult

    } catch (err) {
      error.value = `Analysis error: ${err}`
      console.error('[Visual] Analysis error:', err)
      return null
    } finally {
      isAnalyzing.value = false
    }
  }

  /**
   * Extract text from image using OCR
   */
  async function extractText(imagePath: string): Promise<string[]> {
    try {
      // Try tesseract
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: `tesseract ${imagePath} stdout 2>/dev/null`,
        cwd: undefined
      })

      if (result.exit_code === 0 && result.stdout.trim()) {
        return result.stdout.trim().split('\n').filter(line => line.trim().length > 0)
      }

      // Fallback: macOS Vision framework via screencapture + shortcuts
      // This is limited but works without additional software
      return []

    } catch {
      return []
    }
  }

  /**
   * Capture and analyze in one step
   */
  async function captureAndAnalyze(
    options: CaptureOptions = { type: 'fullscreen' },
    prompt?: string
  ): Promise<AnalysisResult | null> {
    const imagePath = await captureScreen(options)
    if (!imagePath) return null

    return analyzeImage(imagePath, prompt)
  }

  // ========================================================================
  // CONTEXT HELPERS
  // ========================================================================

  /**
   * Get current visual context summary
   */
  function getCurrentContext(): string {
    if (!currentCapture.value) {
      return 'No screen capture available'
    }

    const capture = currentCapture.value
    let context = capture.description

    if (capture.text.length > 0) {
      context += '\n\nVisible text:\n' + capture.text.slice(0, 10).join('\n')
      if (capture.text.length > 10) {
        context += `\n... and ${capture.text.length - 10} more lines`
      }
    }

    return context
  }

  /**
   * Search history for relevant captures
   */
  function searchHistory(query: string): AnalysisResult[] {
    const lower = query.toLowerCase()
    return history.value.filter(h =>
      h.description.toLowerCase().includes(lower) ||
      h.text.some(t => t.toLowerCase().includes(lower))
    )
  }

  /**
   * Clear capture history
   */
  async function clearHistory(): Promise<void> {
    // Delete capture files
    for (const capture of history.value) {
      try {
        await invoke('execute_shell', {
          command: `rm -f ${capture.imagePath}`,
          cwd: undefined
        })
      } catch {}
    }

    history.value = []
    currentCapture.value = null
    saveHistory([])
  }

  /**
   * Get analysis by ID
   */
  function getAnalysis(id: string): AnalysisResult | undefined {
    return history.value.find(h => h.id === id)
  }

  // ========================================================================
  // CAPABILITIES CHECK
  // ========================================================================

  /**
   * Check available vision capabilities
   */
  async function checkCapabilities(): Promise<{
    screenCapture: boolean
    visionModel: boolean
    ocr: boolean
  }> {
    const capabilities = {
      screenCapture: false,
      visionModel: false,
      ocr: false
    }

    // Check screencapture
    try {
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: 'which screencapture',
        cwd: undefined
      })
      capabilities.screenCapture = result.exit_code === 0
    } catch {}

    // Check vision model
    try {
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: 'ollama list | grep -iE "llava|vision|bakllava|moondream"',
        cwd: undefined
      })
      capabilities.visionModel = result.exit_code === 0 && result.stdout.trim().length > 0
    } catch {}

    // Check tesseract
    try {
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: 'which tesseract',
        cwd: undefined
      })
      capabilities.ocr = result.exit_code === 0
    } catch {}

    return capabilities
  }

  return {
    // State
    history: computed(() => history.value),
    currentCapture: computed(() => currentCapture.value),
    isCapturing: computed(() => isCapturing.value),
    isAnalyzing: computed(() => isAnalyzing.value),
    error: computed(() => error.value),

    // Capture
    captureScreen,
    captureActiveWindow,

    // Analysis
    analyzeImage,
    extractText,
    captureAndAnalyze,

    // Context
    getCurrentContext,
    searchHistory,
    getAnalysis,

    // Management
    clearHistory,
    checkCapabilities
  }
}

export type UseVisualUnderstandingReturn = ReturnType<typeof useVisualUnderstanding>
