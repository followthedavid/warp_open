/**
 * useVoiceInterface - Voice Input/Output for Personal AI
 *
 * Provides voice interaction capabilities:
 * - Speech-to-text via Whisper.cpp (local) or Web Speech API (fallback)
 * - Text-to-speech via system voices
 * - Wake word detection (optional)
 * - Voice command parsing
 *
 * Designed for conversational interaction with the AI daemon.
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'

// ============================================================================
// TYPES
// ============================================================================

export interface VoiceConfig {
  // Speech-to-text
  sttEngine: 'whisper' | 'web_speech' | 'auto'
  whisperModel: 'tiny' | 'base' | 'small' | 'medium' | 'large'
  language: string

  // Text-to-speech
  ttsEnabled: boolean
  ttsVoice: string
  ttsRate: number
  ttsPitch: number

  // Wake word
  wakeWordEnabled: boolean
  wakeWord: string

  // Audio
  microphoneDeviceId?: string
  noiseReduction: boolean
}

export interface TranscriptionResult {
  text: string
  confidence: number
  isFinal: boolean
  language?: string
  duration?: number
}

export interface VoiceCommand {
  type: 'query' | 'action' | 'navigation' | 'unknown'
  intent?: string
  entities?: Record<string, string>
  raw: string
}

// ============================================================================
// STORAGE
// ============================================================================

const CONFIG_KEY = 'warp_voice_config'

function loadConfig(): VoiceConfig {
  try {
    const stored = localStorage.getItem(CONFIG_KEY)
    if (stored) return JSON.parse(stored)
  } catch {}

  return {
    sttEngine: 'auto',
    whisperModel: 'base',
    language: 'en',
    ttsEnabled: true,
    ttsVoice: 'default',
    ttsRate: 1.0,
    ttsPitch: 1.0,
    wakeWordEnabled: false,
    wakeWord: 'hey warp',
    noiseReduction: true
  }
}

function saveConfig(config: VoiceConfig): void {
  localStorage.setItem(CONFIG_KEY, JSON.stringify(config))
}

// ============================================================================
// COMPOSABLE
// ============================================================================

export function useVoiceInterface() {
  const config = ref<VoiceConfig>(loadConfig())
  const isListening = ref(false)
  const isProcessing = ref(false)
  const isSpeaking = ref(false)
  const lastTranscript = ref<TranscriptionResult | null>(null)
  const error = ref<string | null>(null)

  // Audio context and state
  let mediaRecorder: MediaRecorder | null = null
  let audioChunks: Blob[] = []
  let recognition: any = null // Web Speech API
  let audioContext: AudioContext | null = null
  let analyser: AnalyserNode | null = null
  let speechSynthesis: SpeechSynthesis | null = null

  // Audio level for visualization
  const audioLevel = ref(0)

  // ========================================================================
  // SPEECH-TO-TEXT
  // ========================================================================

  /**
   * Check if Whisper is available locally
   */
  async function checkWhisperAvailable(): Promise<boolean> {
    try {
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: 'which whisper-cpp || which whisper',
        cwd: undefined
      })
      return result.exit_code === 0 && result.stdout.trim().length > 0
    } catch {
      return false
    }
  }

  /**
   * Check if Web Speech API is available
   */
  function checkWebSpeechAvailable(): boolean {
    return 'webkitSpeechRecognition' in window || 'SpeechRecognition' in window
  }

  /**
   * Start listening for voice input
   */
  async function startListening(): Promise<void> {
    if (isListening.value) return

    error.value = null

    // Determine which engine to use
    let useWhisper = false
    if (config.value.sttEngine === 'whisper') {
      useWhisper = await checkWhisperAvailable()
      if (!useWhisper) {
        error.value = 'Whisper not available, falling back to Web Speech'
      }
    } else if (config.value.sttEngine === 'auto') {
      useWhisper = await checkWhisperAvailable()
    }

    if (useWhisper) {
      await startWhisperListening()
    } else if (checkWebSpeechAvailable()) {
      startWebSpeechListening()
    } else {
      error.value = 'No speech recognition available'
      return
    }

    isListening.value = true
  }

  /**
   * Start Whisper-based listening (record audio, process with whisper.cpp)
   */
  async function startWhisperListening(): Promise<void> {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: config.value.noiseReduction,
          autoGainControl: true
        }
      })

      // Set up audio visualization
      audioContext = new AudioContext()
      analyser = audioContext.createAnalyser()
      const source = audioContext.createMediaStreamSource(stream)
      source.connect(analyser)
      analyser.fftSize = 256

      // Start audio level monitoring
      startAudioLevelMonitor()

      // Set up media recorder
      mediaRecorder = new MediaRecorder(stream, {
        mimeType: 'audio/webm'
      })

      audioChunks = []

      mediaRecorder.ondataavailable = (e) => {
        if (e.data.size > 0) {
          audioChunks.push(e.data)
        }
      }

      mediaRecorder.onstop = async () => {
        isProcessing.value = true
        try {
          await processWhisperAudio()
        } finally {
          isProcessing.value = false
        }
      }

      // Record in 5-second chunks for real-time processing
      mediaRecorder.start()

    } catch (err) {
      error.value = `Microphone access failed: ${err}`
      console.error('[Voice] Microphone error:', err)
    }
  }

  /**
   * Process recorded audio with Whisper
   */
  async function processWhisperAudio(): Promise<void> {
    if (audioChunks.length === 0) return

    const audioBlob = new Blob(audioChunks, { type: 'audio/webm' })
    audioChunks = []

    // Convert to WAV and save to temp file
    const tempPath = `/tmp/warp_voice_${Date.now()}.webm`

    try {
      // Convert blob to base64 and write to file
      const base64 = await blobToBase64(audioBlob)

      await invoke('execute_shell', {
        command: `echo "${base64}" | base64 -d > ${tempPath}`,
        cwd: undefined
      })

      // Convert to WAV (whisper needs WAV format)
      const wavPath = tempPath.replace('.webm', '.wav')
      await invoke('execute_shell', {
        command: `ffmpeg -i ${tempPath} -ar 16000 -ac 1 -c:a pcm_s16le ${wavPath} -y 2>/dev/null`,
        cwd: undefined
      })

      // Run whisper
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: `whisper-cpp -m ~/.whisper/ggml-${config.value.whisperModel}.bin -f ${wavPath} -l ${config.value.language} --no-timestamps 2>/dev/null || whisper ${wavPath} --model ${config.value.whisperModel} --language ${config.value.language} --output_format txt 2>/dev/null`,
        cwd: undefined
      })

      if (result.exit_code === 0 && result.stdout.trim()) {
        lastTranscript.value = {
          text: result.stdout.trim(),
          confidence: 0.9,
          isFinal: true,
          language: config.value.language
        }
      }

      // Cleanup
      await invoke('execute_shell', {
        command: `rm -f ${tempPath} ${wavPath}`,
        cwd: undefined
      })

    } catch (err) {
      console.error('[Voice] Whisper processing error:', err)
    }
  }

  /**
   * Start Web Speech API listening
   */
  function startWebSpeechListening(): void {
    const SpeechRecognition = (window as any).webkitSpeechRecognition || (window as any).SpeechRecognition
    recognition = new SpeechRecognition()

    recognition.continuous = true
    recognition.interimResults = true
    recognition.lang = config.value.language

    recognition.onresult = (event: any) => {
      const results = event.results
      const lastResult = results[results.length - 1]

      lastTranscript.value = {
        text: lastResult[0].transcript,
        confidence: lastResult[0].confidence,
        isFinal: lastResult.isFinal
      }
    }

    recognition.onerror = (event: any) => {
      error.value = `Speech recognition error: ${event.error}`
      console.error('[Voice] Recognition error:', event.error)
    }

    recognition.onend = () => {
      if (isListening.value) {
        // Restart if still supposed to be listening
        recognition.start()
      }
    }

    recognition.start()
  }

  /**
   * Stop listening
   */
  function stopListening(): void {
    if (!isListening.value) return

    isListening.value = false

    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
      mediaRecorder.stop()
      mediaRecorder.stream.getTracks().forEach(track => track.stop())
    }

    if (recognition) {
      recognition.stop()
      recognition = null
    }

    if (audioContext) {
      audioContext.close()
      audioContext = null
    }

    audioLevel.value = 0
  }

  /**
   * Toggle listening state
   */
  function toggleListening(): void {
    if (isListening.value) {
      stopListening()
    } else {
      startListening()
    }
  }

  // ========================================================================
  // TEXT-TO-SPEECH
  // ========================================================================

  /**
   * Speak text using system TTS
   */
  async function speak(text: string, options?: { voice?: string; rate?: number }): Promise<void> {
    if (!config.value.ttsEnabled) return

    // Try system TTS via say command (macOS)
    try {
      const voice = options?.voice || config.value.ttsVoice
      const rate = options?.rate || config.value.ttsRate

      // Escape text for shell
      const escapedText = text.replace(/"/g, '\\"').replace(/`/g, '\\`')

      isSpeaking.value = true

      await invoke('execute_shell', {
        command: `say -r ${Math.round(rate * 175)} "${escapedText}"`,
        cwd: undefined
      })

      isSpeaking.value = false
    } catch (err) {
      // Fallback to Web Speech API
      speakWebAPI(text, options)
    }
  }

  /**
   * Speak using Web Speech API
   */
  function speakWebAPI(text: string, options?: { voice?: string; rate?: number }): void {
    if (!('speechSynthesis' in window)) return

    const utterance = new SpeechSynthesisUtterance(text)
    utterance.rate = options?.rate || config.value.ttsRate
    utterance.pitch = config.value.ttsPitch

    utterance.onstart = () => { isSpeaking.value = true }
    utterance.onend = () => { isSpeaking.value = false }

    window.speechSynthesis.speak(utterance)
  }

  /**
   * Stop speaking
   */
  function stopSpeaking(): void {
    window.speechSynthesis?.cancel()
    isSpeaking.value = false
  }

  /**
   * Get available voices
   */
  async function getAvailableVoices(): Promise<string[]> {
    try {
      const result = await invoke<{ stdout: string; exit_code: number }>('execute_shell', {
        command: 'say -v ?',
        cwd: undefined
      })
      if (result.exit_code === 0) {
        return result.stdout.split('\n')
          .filter(line => line.trim())
          .map(line => line.split(' ')[0])
      }
    } catch {}

    // Web Speech API fallback
    if ('speechSynthesis' in window) {
      return window.speechSynthesis.getVoices().map(v => v.name)
    }

    return ['default']
  }

  // ========================================================================
  // VOICE COMMAND PARSING
  // ========================================================================

  /**
   * Parse voice input into structured command
   */
  function parseCommand(text: string): VoiceCommand {
    const lower = text.toLowerCase().trim()

    // Action commands
    const actionPatterns: [RegExp, string][] = [
      [/^(run|execute|do)\s+(.+)$/i, 'execute'],
      [/^(open|launch|start)\s+(.+)$/i, 'open'],
      [/^(create|make|new)\s+(.+)$/i, 'create'],
      [/^(delete|remove)\s+(.+)$/i, 'delete'],
      [/^(search|find|look for)\s+(.+)$/i, 'search'],
      [/^(git|commit|push|pull)\s*(.*)$/i, 'git']
    ]

    for (const [pattern, intent] of actionPatterns) {
      const match = lower.match(pattern)
      if (match) {
        return {
          type: 'action',
          intent,
          entities: { target: match[2] || '' },
          raw: text
        }
      }
    }

    // Navigation commands
    const navPatterns: [RegExp, string][] = [
      [/^go to\s+(.+)$/i, 'goto'],
      [/^show( me)?\s+(.+)$/i, 'show'],
      [/^switch to\s+(.+)$/i, 'switch']
    ]

    for (const [pattern, intent] of navPatterns) {
      const match = lower.match(pattern)
      if (match) {
        return {
          type: 'navigation',
          intent,
          entities: { destination: match[2] || match[1] || '' },
          raw: text
        }
      }
    }

    // Default to query
    return {
      type: 'query',
      raw: text
    }
  }

  // ========================================================================
  // HELPERS
  // ========================================================================

  function startAudioLevelMonitor(): void {
    if (!analyser) return

    const dataArray = new Uint8Array(analyser.frequencyBinCount)

    const updateLevel = () => {
      if (!isListening.value || !analyser) {
        audioLevel.value = 0
        return
      }

      analyser.getByteFrequencyData(dataArray)
      const avg = dataArray.reduce((a, b) => a + b, 0) / dataArray.length
      audioLevel.value = avg / 255

      requestAnimationFrame(updateLevel)
    }

    updateLevel()
  }

  async function blobToBase64(blob: Blob): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onloadend = () => {
        const base64 = (reader.result as string).split(',')[1]
        resolve(base64)
      }
      reader.onerror = reject
      reader.readAsDataURL(blob)
    })
  }

  /**
   * Update configuration
   */
  function updateConfig(updates: Partial<VoiceConfig>): void {
    config.value = { ...config.value, ...updates }
    saveConfig(config.value)
  }

  return {
    // State
    config: computed(() => config.value),
    isListening: computed(() => isListening.value),
    isProcessing: computed(() => isProcessing.value),
    isSpeaking: computed(() => isSpeaking.value),
    audioLevel: computed(() => audioLevel.value),
    lastTranscript: computed(() => lastTranscript.value),
    error: computed(() => error.value),

    // STT
    startListening,
    stopListening,
    toggleListening,

    // TTS
    speak,
    stopSpeaking,
    getAvailableVoices,

    // Command parsing
    parseCommand,

    // Configuration
    updateConfig,

    // Capability checks
    checkWhisperAvailable,
    checkWebSpeechAvailable
  }
}

export type UseVoiceInterfaceReturn = ReturnType<typeof useVoiceInterface>
