/**
 * Output Syntax Highlighter
 * Highlight terminal output: JSON, errors, paths, URLs, etc.
 */

import { ref, computed } from 'vue';

export interface HighlightRule {
  id: string;
  name: string;
  pattern: RegExp;
  className: string;
  enabled: boolean;
}

export interface HighlightedSegment {
  text: string;
  className?: string;
  url?: string;
  path?: string;
}

// Default highlight rules
const DEFAULT_RULES: HighlightRule[] = [
  // URLs
  {
    id: 'url',
    name: 'URLs',
    pattern: /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
    className: 'highlight-url',
    enabled: true,
  },
  // File paths
  {
    id: 'path-absolute',
    name: 'Absolute Paths',
    pattern: /(?:^|\s)(\/(?:[\w.-]+\/)*[\w.-]+)/g,
    className: 'highlight-path',
    enabled: true,
  },
  // Home paths
  {
    id: 'path-home',
    name: 'Home Paths',
    pattern: /(?:^|\s)(~\/(?:[\w.-]+\/)*[\w.-]+)/g,
    className: 'highlight-path',
    enabled: true,
  },
  // IP addresses
  {
    id: 'ip-address',
    name: 'IP Addresses',
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g,
    className: 'highlight-ip',
    enabled: true,
  },
  // JSON keys
  {
    id: 'json-key',
    name: 'JSON Keys',
    pattern: /"([^"]+)"(?=\s*:)/g,
    className: 'highlight-json-key',
    enabled: true,
  },
  // JSON strings
  {
    id: 'json-string',
    name: 'JSON Strings',
    pattern: /:\s*"([^"]+)"/g,
    className: 'highlight-json-string',
    enabled: true,
  },
  // Numbers
  {
    id: 'numbers',
    name: 'Numbers',
    pattern: /\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/gi,
    className: 'highlight-number',
    enabled: false, // Disabled by default (too noisy)
  },
  // Error keywords
  {
    id: 'error-keywords',
    name: 'Error Keywords',
    pattern: /\b(?:error|fail(?:ed|ure)?|exception|fatal|critical|panic)\b/gi,
    className: 'highlight-error',
    enabled: true,
  },
  // Warning keywords
  {
    id: 'warning-keywords',
    name: 'Warning Keywords',
    pattern: /\b(?:warn(?:ing)?|deprecated|caution)\b/gi,
    className: 'highlight-warning',
    enabled: true,
  },
  // Success keywords
  {
    id: 'success-keywords',
    name: 'Success Keywords',
    pattern: /\b(?:success(?:ful)?|pass(?:ed)?|ok|done|complete(?:d)?|✓|✔)\b/gi,
    className: 'highlight-success',
    enabled: true,
  },
  // Git hashes
  {
    id: 'git-hash',
    name: 'Git Hashes',
    pattern: /\b[a-f0-9]{7,40}\b/g,
    className: 'highlight-hash',
    enabled: true,
  },
  // UUIDs
  {
    id: 'uuid',
    name: 'UUIDs',
    pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    className: 'highlight-uuid',
    enabled: true,
  },
  // Timestamps
  {
    id: 'timestamp',
    name: 'Timestamps',
    pattern: /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g,
    className: 'highlight-timestamp',
    enabled: true,
  },
  // Environment variables
  {
    id: 'env-var',
    name: 'Environment Variables',
    pattern: /\$[A-Z_][A-Z0-9_]*/g,
    className: 'highlight-env',
    enabled: true,
  },
  // Quoted strings
  {
    id: 'quoted-string',
    name: 'Quoted Strings',
    pattern: /'[^']*'|"[^"]*"/g,
    className: 'highlight-string',
    enabled: false,
  },
  // Commands (common ones)
  {
    id: 'commands',
    name: 'Common Commands',
    pattern: /\b(?:git|npm|yarn|cargo|docker|kubectl|make|sudo|cd|ls|cat|grep|find|curl|wget)\b/g,
    className: 'highlight-command',
    enabled: false,
  },
];

const STORAGE_KEY = 'warp_open_highlight_rules';
const rules = ref<HighlightRule[]>([]);

export function useSyntaxHighlighter() {
  /**
   * Load rules from storage
   */
  function loadRules() {
    rules.value = [...DEFAULT_RULES];

    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const customRules = JSON.parse(stored);

        // Merge with defaults
        for (const custom of customRules) {
          const index = rules.value.findIndex(r => r.id === custom.id);
          if (index >= 0) {
            rules.value[index] = {
              ...rules.value[index],
              enabled: custom.enabled,
            };
          } else if (custom.pattern) {
            // Add custom rule
            rules.value.push({
              ...custom,
              pattern: new RegExp(custom.pattern, custom.flags || 'g'),
            });
          }
        }
      }
    } catch (e) {
      console.error('[SyntaxHighlighter] Error loading rules:', e);
    }
  }

  /**
   * Save rules to storage
   */
  function saveRules() {
    try {
      const toSave = rules.value.map(r => ({
        id: r.id,
        enabled: r.enabled,
        // Only save pattern for custom rules
        ...(DEFAULT_RULES.find(d => d.id === r.id)
          ? {}
          : { pattern: r.pattern.source, flags: r.pattern.flags }),
      }));
      localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
    } catch (e) {
      console.error('[SyntaxHighlighter] Error saving rules:', e);
    }
  }

  /**
   * Toggle a rule
   */
  function toggleRule(id: string, enabled?: boolean) {
    const rule = rules.value.find(r => r.id === id);
    if (rule) {
      rule.enabled = enabled ?? !rule.enabled;
      saveRules();
    }
  }

  /**
   * Add a custom rule
   */
  function addRule(rule: Omit<HighlightRule, 'id'> & { id?: string }): string {
    const newRule: HighlightRule = {
      ...rule,
      id: rule.id || `custom-${Date.now()}`,
    };
    rules.value.push(newRule);
    saveRules();
    return newRule.id;
  }

  /**
   * Remove a custom rule
   */
  function removeRule(id: string): boolean {
    // Don't allow removing default rules
    if (DEFAULT_RULES.find(r => r.id === id)) {
      return false;
    }

    const index = rules.value.findIndex(r => r.id === id);
    if (index >= 0) {
      rules.value.splice(index, 1);
      saveRules();
      return true;
    }
    return false;
  }

  /**
   * Highlight text with enabled rules
   */
  function highlight(text: string): HighlightedSegment[] {
    if (!text) return [];

    const enabledRules = rules.value.filter(r => r.enabled);
    if (enabledRules.length === 0) {
      return [{ text }];
    }

    // Find all matches
    interface Match {
      start: number;
      end: number;
      text: string;
      className: string;
      url?: string;
      path?: string;
    }

    const matches: Match[] = [];

    for (const rule of enabledRules) {
      // Reset regex lastIndex
      rule.pattern.lastIndex = 0;

      let match;
      while ((match = rule.pattern.exec(text)) !== null) {
        const matchText = match[0];
        const start = match.index;
        const end = start + matchText.length;

        // Check for URL or path
        let url: string | undefined;
        let path: string | undefined;

        if (rule.id === 'url') {
          url = matchText;
        } else if (rule.id.startsWith('path-')) {
          path = matchText.trim();
        }

        matches.push({
          start,
          end,
          text: matchText,
          className: rule.className,
          url,
          path,
        });
      }
    }

    // Sort by start position
    matches.sort((a, b) => a.start - b.start);

    // Remove overlapping matches (keep earlier ones)
    const filtered: Match[] = [];
    let lastEnd = 0;

    for (const match of matches) {
      if (match.start >= lastEnd) {
        filtered.push(match);
        lastEnd = match.end;
      }
    }

    // Build segments
    const segments: HighlightedSegment[] = [];
    let position = 0;

    for (const match of filtered) {
      // Add text before match
      if (match.start > position) {
        segments.push({ text: text.slice(position, match.start) });
      }

      // Add highlighted match
      segments.push({
        text: match.text,
        className: match.className,
        url: match.url,
        path: match.path,
      });

      position = match.end;
    }

    // Add remaining text
    if (position < text.length) {
      segments.push({ text: text.slice(position) });
    }

    return segments;
  }

  /**
   * Highlight text and return HTML
   */
  function highlightToHtml(text: string): string {
    const segments = highlight(text);

    return segments
      .map(seg => {
        if (!seg.className) {
          return escapeHtml(seg.text);
        }

        const attrs: string[] = [`class="${seg.className}"`];

        if (seg.url) {
          attrs.push(`data-url="${escapeHtml(seg.url)}"`);
        }
        if (seg.path) {
          attrs.push(`data-path="${escapeHtml(seg.path)}"`);
        }

        return `<span ${attrs.join(' ')}>${escapeHtml(seg.text)}</span>`;
      })
      .join('');
  }

  /**
   * Check if text contains any highlightable content
   */
  function hasHighlights(text: string): boolean {
    const enabledRules = rules.value.filter(r => r.enabled);

    for (const rule of enabledRules) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(text)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Escape HTML entities
   */
  function escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Get CSS for highlight classes
   */
  function getHighlightStyles(): string {
    return `
      .highlight-url {
        color: var(--highlight-url, #89b4fa);
        text-decoration: underline;
        cursor: pointer;
      }
      .highlight-path {
        color: var(--highlight-path, #94e2d5);
        cursor: pointer;
      }
      .highlight-ip {
        color: var(--highlight-ip, #f9e2af);
      }
      .highlight-json-key {
        color: var(--highlight-json-key, #cba6f7);
      }
      .highlight-json-string {
        color: var(--highlight-json-string, #a6e3a1);
      }
      .highlight-number {
        color: var(--highlight-number, #fab387);
      }
      .highlight-error {
        color: var(--highlight-error, #f38ba8);
        font-weight: 600;
      }
      .highlight-warning {
        color: var(--highlight-warning, #f9e2af);
        font-weight: 600;
      }
      .highlight-success {
        color: var(--highlight-success, #a6e3a1);
        font-weight: 600;
      }
      .highlight-hash {
        color: var(--highlight-hash, #89b4fa);
        font-family: monospace;
      }
      .highlight-uuid {
        color: var(--highlight-uuid, #cba6f7);
        font-family: monospace;
      }
      .highlight-timestamp {
        color: var(--highlight-timestamp, #74c7ec);
      }
      .highlight-env {
        color: var(--highlight-env, #f5c2e7);
      }
      .highlight-string {
        color: var(--highlight-string, #a6e3a1);
      }
      .highlight-command {
        color: var(--highlight-command, #89dceb);
        font-weight: 500;
      }
    `;
  }

  /**
   * Detect JSON and format it
   */
  function formatJson(text: string): string | null {
    try {
      const trimmed = text.trim();
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
          (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        const parsed = JSON.parse(trimmed);
        return JSON.stringify(parsed, null, 2);
      }
    } catch {
      // Not valid JSON
    }
    return null;
  }

  /**
   * Detect and extract structured data
   */
  function detectStructure(text: string): 'json' | 'table' | 'list' | 'plain' {
    const trimmed = text.trim();

    // JSON detection
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
        (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        JSON.parse(trimmed);
        return 'json';
      } catch {
        // Not valid JSON
      }
    }

    // Table detection (consistent column structure)
    const lines = trimmed.split('\n');
    if (lines.length >= 2) {
      const firstLineParts = lines[0].split(/\s{2,}|\t/).length;
      const consistent = lines.slice(1, 5).every(line => {
        const parts = line.split(/\s{2,}|\t/).length;
        return Math.abs(parts - firstLineParts) <= 1;
      });
      if (consistent && firstLineParts >= 3) {
        return 'table';
      }
    }

    // List detection
    if (lines.every(line => /^[\s]*[-*•]\s/.test(line) || /^[\s]*\d+\.\s/.test(line))) {
      return 'list';
    }

    return 'plain';
  }

  // Initialize
  loadRules();

  return {
    rules: computed(() => rules.value),
    enabledRules: computed(() => rules.value.filter(r => r.enabled)),
    toggleRule,
    addRule,
    removeRule,
    highlight,
    highlightToHtml,
    hasHighlights,
    getHighlightStyles,
    formatJson,
    detectStructure,
    loadRules,
  };
}
