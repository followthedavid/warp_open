/**
 * Image Understanding System
 * Analyze images using local vision models (LLaVA, BakLLaVA) via Ollama.
 * Supports screenshots, diagrams, code images, and general image analysis.
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

export type ImageSource = 'file' | 'clipboard' | 'screenshot' | 'url' | 'base64';

export interface ImageAnalysis {
  id: string;
  source: ImageSource;
  sourcePath?: string;
  description: string;
  details?: string;
  extractedText?: string;
  codeBlocks?: Array<{
    language: string;
    code: string;
  }>;
  timestamp: number;
  model: string;
  processingTime: number;
}

export interface AnalysisConfig {
  model: string;
  maxTokens: number;
  temperature: number;
  includeOCR: boolean;
  detectCode: boolean;
}

// Available vision models
const VISION_MODELS = [
  { id: 'llava:7b', name: 'LLaVA 7B', description: 'General purpose vision model' },
  { id: 'llava:13b', name: 'LLaVA 13B', description: 'Higher quality, slower' },
  { id: 'bakllava', name: 'BakLLaVA', description: 'Good for text in images' },
  { id: 'llava-llama3', name: 'LLaVA Llama3', description: 'Latest with Llama3 base' },
];

// Default config
const DEFAULT_CONFIG: AnalysisConfig = {
  model: 'llava:7b',
  maxTokens: 1024,
  temperature: 0.2,
  includeOCR: true,
  detectCode: true,
};

// State
const config = ref<AnalysisConfig>({ ...DEFAULT_CONFIG });
const isProcessing = ref(false);
const currentImage = ref<string | null>(null); // base64
const analysisHistory = ref<ImageAnalysis[]>([]);
const error = ref<string | null>(null);

const MAX_HISTORY = 50;

function generateAnalysisId(): string {
  return `img_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
}

export function useImageUnderstanding() {
  const availableModels = computed(() => VISION_MODELS);

  /**
   * Read image file and convert to base64
   */
  async function readImageFile(path: string): Promise<string> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    const base64 = await invoke<string>('read_image_base64', { path });
    return base64;
  }

  /**
   * Capture screenshot
   */
  async function captureScreenshot(): Promise<string> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    const base64 = await invoke<string>('capture_screenshot', {});
    return base64;
  }

  /**
   * Get image from clipboard
   */
  async function getClipboardImage(): Promise<string | null> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    try {
      const base64 = await invoke<string>('get_clipboard_image', {});
      return base64;
    } catch {
      return null;
    }
  }

  /**
   * Analyze an image with the vision model
   */
  async function analyzeImage(
    imageBase64: string,
    prompt: string,
    options?: Partial<AnalysisConfig>
  ): Promise<ImageAnalysis> {
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    isProcessing.value = true;
    error.value = null;
    currentImage.value = imageBase64;

    const analysisConfig = { ...config.value, ...options };
    const startTime = Date.now();

    try {
      // Query vision model
      const response = await invoke<string>('query_vision_model', {
        model: analysisConfig.model,
        imageBase64,
        prompt,
        maxTokens: analysisConfig.maxTokens,
        temperature: analysisConfig.temperature,
      });

      const analysis: ImageAnalysis = {
        id: generateAnalysisId(),
        source: 'base64',
        description: response,
        timestamp: Date.now(),
        model: analysisConfig.model,
        processingTime: Date.now() - startTime,
      };

      // Extract code blocks if enabled
      if (analysisConfig.detectCode) {
        analysis.codeBlocks = extractCodeBlocks(response);
      }

      // Add to history
      analysisHistory.value.unshift(analysis);
      if (analysisHistory.value.length > MAX_HISTORY) {
        analysisHistory.value = analysisHistory.value.slice(0, MAX_HISTORY);
      }

      return analysis;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      throw err;
    } finally {
      isProcessing.value = false;
    }
  }

  /**
   * Analyze image from file path
   */
  async function analyzeImageFile(
    filePath: string,
    prompt?: string
  ): Promise<ImageAnalysis> {
    const base64 = await readImageFile(filePath);
    const defaultPrompt = prompt || 'Describe this image in detail. If it contains code or text, extract and format it.';

    const analysis = await analyzeImage(base64, defaultPrompt);
    analysis.source = 'file';
    analysis.sourcePath = filePath;

    return analysis;
  }

  /**
   * Analyze screenshot
   */
  async function analyzeScreenshot(prompt?: string): Promise<ImageAnalysis> {
    const base64 = await captureScreenshot();
    const defaultPrompt = prompt || 'Describe what you see in this screenshot. Identify any UI elements, text, or code visible.';

    const analysis = await analyzeImage(base64, defaultPrompt);
    analysis.source = 'screenshot';

    return analysis;
  }

  /**
   * Analyze clipboard image
   */
  async function analyzeClipboard(prompt?: string): Promise<ImageAnalysis> {
    const base64 = await getClipboardImage();
    if (!base64) {
      throw new Error('No image in clipboard');
    }

    const defaultPrompt = prompt || 'Describe this image in detail.';

    const analysis = await analyzeImage(base64, defaultPrompt);
    analysis.source = 'clipboard';

    return analysis;
  }

  /**
   * Extract code from an image (OCR + formatting)
   */
  async function extractCode(imageBase64: string): Promise<Array<{ language: string; code: string }>> {
    const prompt = `Look at this image and extract any code visible.
For each code block:
1. Identify the programming language
2. Extract the exact code, preserving formatting

Respond in this format:
\`\`\`language
code here
\`\`\`

If there's no code, say "No code detected."`;

    const analysis = await analyzeImage(imageBase64, prompt, {
      temperature: 0.1, // Lower for more accurate extraction
      detectCode: true,
    });

    return analysis.codeBlocks || [];
  }

  /**
   * Extract text from image (OCR)
   */
  async function extractText(imageBase64: string): Promise<string> {
    const prompt = `Extract all text visible in this image. Preserve the layout and formatting as much as possible. Only output the extracted text, nothing else.`;

    const analysis = await analyzeImage(imageBase64, prompt, {
      temperature: 0.1,
    });

    return analysis.description;
  }

  /**
   * Describe UI/diagram
   */
  async function describeUI(imageBase64: string): Promise<string> {
    const prompt = `Analyze this UI/diagram:
1. Describe the overall layout
2. List all visible components/elements
3. Describe the visual hierarchy
4. Note any interactions or flow indicated
5. Identify the technology/framework if recognizable`;

    const analysis = await analyzeImage(imageBase64, prompt);
    return analysis.description;
  }

  /**
   * Compare two images
   */
  async function compareImages(
    image1Base64: string,
    image2Base64: string
  ): Promise<string> {
    // Note: This requires a model that can handle multiple images
    // For now, we'll analyze them separately and compare
    const analysis1 = await analyzeImage(image1Base64, 'Describe this image in detail.');
    const analysis2 = await analyzeImage(image2Base64, 'Describe this image in detail.');

    // Use text model to compare descriptions
    if (!invoke) {
      throw new Error('Tauri not available');
    }

    const comparison = await invoke<string>('query_ollama', {
      model: 'qwen2.5-coder:1.5b',
      prompt: `Compare these two image descriptions and identify similarities and differences:

Image 1: ${analysis1.description}

Image 2: ${analysis2.description}

Provide a detailed comparison.`,
    });

    return comparison;
  }

  /**
   * Extract code blocks from text
   */
  function extractCodeBlocks(text: string): Array<{ language: string; code: string }> {
    const codeBlockRegex = /```(\w*)\n([\s\S]*?)```/g;
    const blocks: Array<{ language: string; code: string }> = [];

    let match;
    while ((match = codeBlockRegex.exec(text)) !== null) {
      blocks.push({
        language: match[1] || 'unknown',
        code: match[2].trim(),
      });
    }

    return blocks;
  }

  /**
   * Set configuration
   */
  function setConfig(newConfig: Partial<AnalysisConfig>): void {
    config.value = { ...config.value, ...newConfig };
  }

  /**
   * Clear history
   */
  function clearHistory(): void {
    analysisHistory.value = [];
  }

  /**
   * Get analysis by ID
   */
  function getAnalysis(id: string): ImageAnalysis | undefined {
    return analysisHistory.value.find(a => a.id === id);
  }

  /**
   * Check if vision model is available
   */
  async function isVisionAvailable(): Promise<boolean> {
    if (!invoke) return false;

    try {
      const models = await invoke<Array<{ name: string }>>('list_ollama_models', {});
      return models.some(m =>
        m.name.includes('llava') ||
        m.name.includes('bakllava') ||
        m.name.includes('vision')
      );
    } catch {
      return false;
    }
  }

  /**
   * Get context from image for AI assistant
   */
  async function getImageContext(imageBase64: string): Promise<string> {
    const analysis = await analyzeImage(
      imageBase64,
      'Describe this image comprehensively. Include any text, code, UI elements, or diagrams visible.'
    );

    let context = `[Image Analysis]\n${analysis.description}\n`;

    if (analysis.codeBlocks && analysis.codeBlocks.length > 0) {
      context += '\n[Extracted Code]\n';
      for (const block of analysis.codeBlocks) {
        context += `\`\`\`${block.language}\n${block.code}\n\`\`\`\n`;
      }
    }

    return context;
  }

  return {
    // State
    isProcessing: computed(() => isProcessing.value),
    currentImage: computed(() => currentImage.value),
    analysisHistory: computed(() => analysisHistory.value),
    error: computed(() => error.value),
    config: computed(() => config.value),
    availableModels,

    // Core methods
    analyzeImage,
    analyzeImageFile,
    analyzeScreenshot,
    analyzeClipboard,

    // Specialized analysis
    extractCode,
    extractText,
    describeUI,
    compareImages,

    // Utilities
    readImageFile,
    captureScreenshot,
    getClipboardImage,
    getImageContext,
    isVisionAvailable,

    // Management
    setConfig,
    clearHistory,
    getAnalysis,
  };
}
