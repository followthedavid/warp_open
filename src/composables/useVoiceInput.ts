/**
 * Voice Input System
 * Speech-to-text for hands-free terminal interaction.
 * Uses Web Speech API (browser) or whisper.cpp (local).
 */

import { ref, computed, onMounted, onUnmounted } from 'vue';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

export type VoiceProvider = 'webSpeech' | 'whisper';
export type RecordingState = 'idle' | 'recording' | 'processing' | 'error';

export interface VoiceConfig {
  provider: VoiceProvider;
  language: string;
  continuous: boolean;
  interimResults: boolean;
  maxRecordingTime: number; // seconds
  whisperModel?: string; // tiny, base, small, medium, large
  confidenceThreshold: number;
}

export interface TranscriptionResult {
  text: string;
  confidence: number;
  isFinal: boolean;
  timestamp: number;
}

export interface VoiceCommand {
  pattern: RegExp;
  action: (match: RegExpMatchArray) => void;
  description: string;
}

// Default config
const DEFAULT_CONFIG: VoiceConfig = {
  provider: 'webSpeech',
  language: 'en-US',
  continuous: false,
  interimResults: true,
  maxRecordingTime: 30,
  whisperModel: 'base',
  confidenceThreshold: 0.7,
};

// State
const config = ref<VoiceConfig>({ ...DEFAULT_CONFIG });
const state = ref<RecordingState>('idle');
const transcript = ref<string>('');
const interimTranscript = ref<string>('');
const error = ref<string | null>(null);
const isSupported = ref(false);
const recordingStartTime = ref<number | null>(null);
const audioLevel = ref(0);

// Web Speech API recognition instance
let recognition: SpeechRecognition | null = null;

// Voice commands registry
const voiceCommands = ref<VoiceCommand[]>([
  // Built-in commands
  {
    pattern: /^(cancel|stop|abort)$/i,
    action: () => {
      stopRecording();
    },
    description: 'Stop recording',
  },
  {
    pattern: /^clear$/i,
    action: () => {
      transcript.value = '';
      interimTranscript.value = '';
    },
    description: 'Clear transcript',
  },
]);

// Audio analyzer for level visualization
let audioContext: AudioContext | null = null;
let analyser: AnalyserNode | null = null;
let mediaStream: MediaStream | null = null;

export function useVoiceInput() {
  const isRecording = computed(() => state.value === 'recording');
  const isProcessing = computed(() => state.value === 'processing');
  const fullTranscript = computed(() =>
    interimTranscript.value
      ? `${transcript.value} ${interimTranscript.value}`.trim()
      : transcript.value
  );
  const recordingDuration = computed(() => {
    if (!recordingStartTime.value) return 0;
    return Math.floor((Date.now() - recordingStartTime.value) / 1000);
  });

  /**
   * Initialize voice input
   */
  function initialize(): boolean {
    // Check Web Speech API support
    const SpeechRecognitionAPI =
      (window as unknown as { SpeechRecognition?: typeof SpeechRecognition })
        .SpeechRecognition ||
      (window as unknown as { webkitSpeechRecognition?: typeof SpeechRecognition })
        .webkitSpeechRecognition;

    if (SpeechRecognitionAPI) {
      recognition = new SpeechRecognitionAPI();
      isSupported.value = true;
      setupWebSpeechRecognition();
      console.log('[VoiceInput] Web Speech API initialized');
      return true;
    }

    // Check Whisper support via Tauri
    if (isTauri && invoke) {
      isSupported.value = true;
      console.log('[VoiceInput] Whisper mode available');
      return true;
    }

    isSupported.value = false;
    console.warn('[VoiceInput] No speech recognition support');
    return false;
  }

  /**
   * Setup Web Speech API recognition
   */
  function setupWebSpeechRecognition(): void {
    if (!recognition) return;

    recognition.continuous = config.value.continuous;
    recognition.interimResults = config.value.interimResults;
    recognition.lang = config.value.language;

    recognition.onstart = () => {
      state.value = 'recording';
      recordingStartTime.value = Date.now();
      error.value = null;
      console.log('[VoiceInput] Recording started');
    };

    recognition.onresult = (event: SpeechRecognitionEvent) => {
      let finalText = '';
      let interimText = '';

      for (let i = event.resultIndex; i < event.results.length; i++) {
        const result = event.results[i];
        const text = result[0].transcript;

        if (result.isFinal) {
          finalText += text + ' ';

          // Check for voice commands
          processVoiceCommands(text.trim());
        } else {
          interimText += text;
        }
      }

      if (finalText) {
        transcript.value = (transcript.value + ' ' + finalText).trim();
      }
      interimTranscript.value = interimText;
    };

    recognition.onerror = (event: SpeechRecognitionErrorEvent) => {
      console.error('[VoiceInput] Recognition error:', event.error);
      error.value = event.error;
      state.value = 'error';
    };

    recognition.onend = () => {
      if (state.value === 'recording') {
        // Stopped naturally or by timeout
        state.value = 'idle';
        recordingStartTime.value = null;
        console.log('[VoiceInput] Recording ended');
      }
    };
  }

  /**
   * Start recording
   */
  async function startRecording(): Promise<void> {
    if (state.value === 'recording') return;

    error.value = null;
    transcript.value = '';
    interimTranscript.value = '';

    if (config.value.provider === 'webSpeech' && recognition) {
      try {
        // Start audio level monitoring
        await startAudioLevelMonitor();

        recognition.start();

        // Auto-stop after max recording time
        if (config.value.maxRecordingTime > 0) {
          setTimeout(() => {
            if (state.value === 'recording') {
              stopRecording();
            }
          }, config.value.maxRecordingTime * 1000);
        }
      } catch (err) {
        error.value = err instanceof Error ? err.message : String(err);
        state.value = 'error';
      }
    } else if (config.value.provider === 'whisper' && invoke) {
      await startWhisperRecording();
    }
  }

  /**
   * Stop recording
   */
  function stopRecording(): void {
    if (state.value !== 'recording') return;

    if (config.value.provider === 'webSpeech' && recognition) {
      recognition.stop();
    }

    stopAudioLevelMonitor();
    state.value = 'idle';
    recordingStartTime.value = null;
  }

  /**
   * Start Whisper-based recording
   */
  async function startWhisperRecording(): Promise<void> {
    if (!invoke) return;

    try {
      state.value = 'recording';
      recordingStartTime.value = Date.now();

      // Start audio level monitoring
      await startAudioLevelMonitor();

      // Record audio to file
      const result = await invoke<{ audioFile: string }>('start_audio_recording', {
        maxDuration: config.value.maxRecordingTime,
      });

      state.value = 'processing';

      // Transcribe with Whisper
      const transcription = await invoke<{ text: string; confidence: number }>('transcribe_audio', {
        audioFile: result.audioFile,
        model: config.value.whisperModel,
        language: config.value.language,
      });

      transcript.value = transcription.text;

      // Check for voice commands
      processVoiceCommands(transcription.text.trim());

      state.value = 'idle';
      recordingStartTime.value = null;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      state.value = 'error';
    } finally {
      stopAudioLevelMonitor();
    }
  }

  /**
   * Start audio level monitoring for visualization
   */
  async function startAudioLevelMonitor(): Promise<void> {
    try {
      mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
      audioContext = new AudioContext();
      analyser = audioContext.createAnalyser();
      const source = audioContext.createMediaStreamSource(mediaStream);
      source.connect(analyser);

      analyser.fftSize = 256;
      const dataArray = new Uint8Array(analyser.frequencyBinCount);

      const updateLevel = () => {
        if (state.value !== 'recording' || !analyser) return;

        analyser.getByteFrequencyData(dataArray);
        const average = dataArray.reduce((a, b) => a + b, 0) / dataArray.length;
        audioLevel.value = average / 255;

        requestAnimationFrame(updateLevel);
      };

      updateLevel();
    } catch (err) {
      console.warn('[VoiceInput] Could not start audio level monitor:', err);
    }
  }

  /**
   * Stop audio level monitoring
   */
  function stopAudioLevelMonitor(): void {
    audioLevel.value = 0;

    if (mediaStream) {
      mediaStream.getTracks().forEach(track => track.stop());
      mediaStream = null;
    }

    if (audioContext) {
      audioContext.close();
      audioContext = null;
    }

    analyser = null;
  }

  /**
   * Process voice commands
   */
  function processVoiceCommands(text: string): void {
    for (const command of voiceCommands.value) {
      const match = text.match(command.pattern);
      if (match) {
        console.log(`[VoiceInput] Voice command matched: ${command.description}`);
        command.action(match);
        return;
      }
    }
  }

  /**
   * Register a voice command
   */
  function registerCommand(command: VoiceCommand): void {
    voiceCommands.value.push(command);
  }

  /**
   * Remove a voice command
   */
  function removeCommand(pattern: RegExp): void {
    const index = voiceCommands.value.findIndex(
      c => c.pattern.source === pattern.source
    );
    if (index >= 0) {
      voiceCommands.value.splice(index, 1);
    }
  }

  /**
   * Update configuration
   */
  function setConfig(newConfig: Partial<VoiceConfig>): void {
    config.value = { ...config.value, ...newConfig };

    // Re-setup recognition if needed
    if (recognition && config.value.provider === 'webSpeech') {
      recognition.continuous = config.value.continuous;
      recognition.interimResults = config.value.interimResults;
      recognition.lang = config.value.language;
    }
  }

  /**
   * Toggle recording
   */
  function toggleRecording(): void {
    if (state.value === 'recording') {
      stopRecording();
    } else {
      startRecording();
    }
  }

  /**
   * Clear transcript
   */
  function clearTranscript(): void {
    transcript.value = '';
    interimTranscript.value = '';
  }

  /**
   * Get available languages
   */
  function getAvailableLanguages(): Array<{ code: string; name: string }> {
    return [
      { code: 'en-US', name: 'English (US)' },
      { code: 'en-GB', name: 'English (UK)' },
      { code: 'es-ES', name: 'Spanish' },
      { code: 'fr-FR', name: 'French' },
      { code: 'de-DE', name: 'German' },
      { code: 'it-IT', name: 'Italian' },
      { code: 'pt-BR', name: 'Portuguese (Brazil)' },
      { code: 'zh-CN', name: 'Chinese (Simplified)' },
      { code: 'ja-JP', name: 'Japanese' },
      { code: 'ko-KR', name: 'Korean' },
    ];
  }

  /**
   * Check microphone permission
   */
  async function checkMicrophonePermission(): Promise<PermissionState> {
    try {
      const result = await navigator.permissions.query({ name: 'microphone' as PermissionName });
      return result.state;
    } catch {
      return 'prompt';
    }
  }

  /**
   * Request microphone permission
   */
  async function requestMicrophonePermission(): Promise<boolean> {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      stream.getTracks().forEach(track => track.stop());
      return true;
    } catch {
      return false;
    }
  }

  // Lifecycle
  onMounted(() => {
    initialize();
  });

  onUnmounted(() => {
    if (state.value === 'recording') {
      stopRecording();
    }
    stopAudioLevelMonitor();
  });

  return {
    // State
    isSupported: computed(() => isSupported.value),
    isRecording,
    isProcessing,
    state: computed(() => state.value),
    transcript: computed(() => transcript.value),
    interimTranscript: computed(() => interimTranscript.value),
    fullTranscript,
    error: computed(() => error.value),
    audioLevel: computed(() => audioLevel.value),
    recordingDuration,
    config: computed(() => config.value),

    // Methods
    initialize,
    startRecording,
    stopRecording,
    toggleRecording,
    clearTranscript,
    setConfig,

    // Commands
    registerCommand,
    removeCommand,
    commands: computed(() => voiceCommands.value),

    // Utilities
    getAvailableLanguages,
    checkMicrophonePermission,
    requestMicrophonePermission,
  };
}
