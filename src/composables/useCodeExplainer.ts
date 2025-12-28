/**
 * Code Explanation System
 * Analyze and explain code with AI
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

export interface CodeExplanation {
  id: string;
  code: string;
  language: string;
  timestamp: Date;

  // Explanation parts
  summary: string;
  detailedExplanation: string;
  lineByLine?: LineExplanation[];
  complexity?: ComplexityAnalysis;
  suggestions?: string[];
  relatedConcepts?: string[];
}

export interface LineExplanation {
  lineNumber: number;
  code: string;
  explanation: string;
}

export interface ComplexityAnalysis {
  timeComplexity: string;
  spaceComplexity: string;
  cognitiveComplexity: string;
  explanation: string;
}

export type ExplanationLevel = 'beginner' | 'intermediate' | 'expert';
export type ExplanationType = 'quick' | 'detailed' | 'line-by-line' | 'complexity';

const isExplaining = ref(false);
const currentExplanation = ref<CodeExplanation | null>(null);
const explanationHistory = ref<CodeExplanation[]>([]);
const MAX_HISTORY = 20;

export function useCodeExplainer() {
  /**
   * Detect programming language from code
   */
  function detectLanguage(code: string, filename?: string): string {
    // Check filename extension first
    if (filename) {
      const ext = filename.split('.').pop()?.toLowerCase();
      const extMap: Record<string, string> = {
        ts: 'typescript',
        tsx: 'typescript',
        js: 'javascript',
        jsx: 'javascript',
        py: 'python',
        rs: 'rust',
        go: 'go',
        java: 'java',
        rb: 'ruby',
        cpp: 'c++',
        c: 'c',
        cs: 'csharp',
        php: 'php',
        swift: 'swift',
        kt: 'kotlin',
        vue: 'vue',
        sql: 'sql',
        sh: 'bash',
        yaml: 'yaml',
        yml: 'yaml',
        json: 'json',
        md: 'markdown',
        html: 'html',
        css: 'css',
      };
      if (ext && extMap[ext]) return extMap[ext];
    }

    // Heuristic detection
    if (code.includes('fn ') && code.includes('let ') && code.includes('->')) return 'rust';
    if (code.includes('def ') && code.includes(':') && !code.includes('{')) return 'python';
    if (code.includes('func ') && code.includes('package ')) return 'go';
    if (code.includes('function') || code.includes('=>')) return 'javascript';
    if (code.includes('interface ') || code.includes(': string')) return 'typescript';
    if (code.includes('public class') || code.includes('public static void')) return 'java';

    return 'unknown';
  }

  /**
   * Explain code with AI
   */
  async function explainCode(
    code: string,
    options: {
      language?: string;
      filename?: string;
      level?: ExplanationLevel;
      type?: ExplanationType;
      context?: string;
      model?: string;
    } = {}
  ): Promise<CodeExplanation> {
    isExplaining.value = true;

    const {
      language = detectLanguage(code, options.filename),
      level = 'intermediate',
      type = 'detailed',
      context = '',
      model = 'qwen2.5-coder:1.5b',
    } = options;

    try {
      let prompt: string;

      switch (type) {
        case 'quick':
          prompt = buildQuickExplanationPrompt(code, language, level);
          break;
        case 'line-by-line':
          prompt = buildLineByLinePrompt(code, language, level);
          break;
        case 'complexity':
          prompt = buildComplexityPrompt(code, language);
          break;
        default:
          prompt = buildDetailedPrompt(code, language, level, context);
      }

      let response: string;

      if (isTauri && invoke) {
        response = await invoke<string>('query_ollama', { prompt, model });
      } else {
        const res = await fetch('http://localhost:11434/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, prompt, stream: false }),
        });
        const data = await res.json();
        response = data.response;
      }

      const explanation = parseExplanationResponse(response, code, language, type);
      currentExplanation.value = explanation;

      // Add to history
      explanationHistory.value.unshift(explanation);
      if (explanationHistory.value.length > MAX_HISTORY) {
        explanationHistory.value.pop();
      }

      return explanation;
    } catch (e) {
      const errorExplanation: CodeExplanation = {
        id: generateId(),
        code,
        language,
        timestamp: new Date(),
        summary: 'Error generating explanation',
        detailedExplanation: String(e),
      };
      currentExplanation.value = errorExplanation;
      return errorExplanation;
    } finally {
      isExplaining.value = false;
    }
  }

  /**
   * Build quick explanation prompt
   */
  function buildQuickExplanationPrompt(
    code: string,
    language: string,
    level: ExplanationLevel
  ): string {
    return `Briefly explain this ${language} code in 2-3 sentences for a ${level} developer:

\`\`\`${language}
${code}
\`\`\`

Be concise and focus on the main purpose.`;
  }

  /**
   * Build detailed explanation prompt
   */
  function buildDetailedPrompt(
    code: string,
    language: string,
    level: ExplanationLevel,
    context: string
  ): string {
    return `Explain this ${language} code in detail for a ${level} developer.
${context ? `Context: ${context}` : ''}

\`\`\`${language}
${code}
\`\`\`

Provide:
1. A brief summary (1-2 sentences)
2. Detailed explanation of how it works
3. Any potential issues or improvements
4. Related concepts to learn

Format your response as JSON:
{
  "summary": "...",
  "detailedExplanation": "...",
  "suggestions": ["suggestion 1", "suggestion 2"],
  "relatedConcepts": ["concept 1", "concept 2"]
}`;
  }

  /**
   * Build line-by-line explanation prompt
   */
  function buildLineByLinePrompt(
    code: string,
    language: string,
    level: ExplanationLevel
  ): string {
    const lines = code.split('\n');
    const numberedCode = lines.map((line, i) => `${i + 1}: ${line}`).join('\n');

    return `Explain this ${language} code line by line for a ${level} developer:

${numberedCode}

Respond with JSON array of line explanations:
[
  {"lineNumber": 1, "code": "...", "explanation": "..."},
  {"lineNumber": 2, "code": "...", "explanation": "..."}
]

Skip empty lines and comments unless they're important.`;
  }

  /**
   * Build complexity analysis prompt
   */
  function buildComplexityPrompt(code: string, language: string): string {
    return `Analyze the complexity of this ${language} code:

\`\`\`${language}
${code}
\`\`\`

Provide complexity analysis as JSON:
{
  "timeComplexity": "O(n)",
  "spaceComplexity": "O(1)",
  "cognitiveComplexity": "Low/Medium/High",
  "explanation": "Explanation of the complexity analysis"
}`;
  }

  /**
   * Parse AI response into structured explanation
   */
  function parseExplanationResponse(
    response: string,
    code: string,
    language: string,
    type: ExplanationType
  ): CodeExplanation {
    const explanation: CodeExplanation = {
      id: generateId(),
      code,
      language,
      timestamp: new Date(),
      summary: '',
      detailedExplanation: '',
    };

    // Try to parse JSON
    const jsonMatch = response.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[0]);

        if (type === 'line-by-line' && Array.isArray(parsed)) {
          explanation.lineByLine = parsed;
          explanation.summary = 'Line-by-line explanation';
          explanation.detailedExplanation = parsed
            .map((l: LineExplanation) => `Line ${l.lineNumber}: ${l.explanation}`)
            .join('\n');
        } else if (type === 'complexity') {
          explanation.complexity = parsed;
          explanation.summary = `Time: ${parsed.timeComplexity}, Space: ${parsed.spaceComplexity}`;
          explanation.detailedExplanation = parsed.explanation;
        } else {
          explanation.summary = parsed.summary || '';
          explanation.detailedExplanation = parsed.detailedExplanation || parsed.explanation || '';
          explanation.suggestions = parsed.suggestions;
          explanation.relatedConcepts = parsed.relatedConcepts;
        }
      } catch {
        // JSON parse failed, use raw response
        explanation.summary = response.substring(0, 100) + '...';
        explanation.detailedExplanation = response;
      }
    } else {
      // No JSON found, use raw response
      explanation.summary = response.substring(0, 100) + '...';
      explanation.detailedExplanation = response;
    }

    return explanation;
  }

  /**
   * Explain a file
   */
  async function explainFile(
    filePath: string,
    options: {
      level?: ExplanationLevel;
      type?: ExplanationType;
      model?: string;
    } = {}
  ): Promise<CodeExplanation> {
    let code: string;

    try {
      if (isTauri && invoke) {
        code = await invoke<string>('read_file', { path: filePath });
      } else {
        throw new Error('File reading only available in Tauri');
      }
    } catch (e) {
      throw new Error(`Could not read file: ${e}`);
    }

    return explainCode(code, {
      ...options,
      filename: filePath,
    });
  }

  /**
   * Compare two code snippets
   */
  async function compareCode(
    codeA: string,
    codeB: string,
    model: string = 'qwen2.5-coder:1.5b'
  ): Promise<string> {
    const prompt = `Compare these two code snippets and explain the differences:

Code A:
\`\`\`
${codeA}
\`\`\`

Code B:
\`\`\`
${codeB}
\`\`\`

Explain:
1. What changed between A and B
2. Why these changes might have been made
3. Which version is better and why`;

    let response: string;

    if (isTauri && invoke) {
      response = await invoke<string>('query_ollama', { prompt, model });
    } else {
      const res = await fetch('http://localhost:11434/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, prompt, stream: false }),
      });
      const data = await res.json();
      response = data.response;
    }

    return response;
  }

  /**
   * Generate unique ID
   */
  function generateId(): string {
    return `exp-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  return {
    isExplaining: computed(() => isExplaining.value),
    currentExplanation: computed(() => currentExplanation.value),
    explanationHistory: computed(() => explanationHistory.value),
    detectLanguage,
    explainCode,
    explainFile,
    compareCode,
  };
}
