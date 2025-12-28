/**
 * Secret Redaction System
 * Automatically detects and redacts sensitive information in terminal output.
 * Inspired by Warp Terminal's secret redaction feature.
 */

import { ref, computed } from 'vue';

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  replacement: string;
  description: string;
  enabled: boolean;
}

export interface RedactedSecret {
  original: string;
  redacted: string;
  type: string;
  timestamp: number;
  lineNumber?: number;
}

// Common secret patterns
const DEFAULT_PATTERNS: SecretPattern[] = [
  // API Keys
  {
    name: 'aws_access_key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    replacement: '[AWS_ACCESS_KEY_REDACTED]',
    description: 'AWS Access Key ID',
    enabled: true,
  },
  {
    name: 'aws_secret_key',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    replacement: '[AWS_SECRET_KEY_REDACTED]',
    description: 'AWS Secret Access Key (40 char base64)',
    enabled: false, // Too many false positives, disabled by default
  },
  {
    name: 'github_token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    replacement: '[GITHUB_TOKEN_REDACTED]',
    description: 'GitHub Personal Access Token',
    enabled: true,
  },
  {
    name: 'github_oauth',
    pattern: /gho_[A-Za-z0-9]{36}/g,
    replacement: '[GITHUB_OAUTH_REDACTED]',
    description: 'GitHub OAuth Token',
    enabled: true,
  },
  {
    name: 'openai_key',
    pattern: /sk-[A-Za-z0-9]{48,}/g,
    replacement: '[OPENAI_KEY_REDACTED]',
    description: 'OpenAI API Key',
    enabled: true,
  },
  {
    name: 'anthropic_key',
    pattern: /sk-ant-[A-Za-z0-9-_]{90,}/g,
    replacement: '[ANTHROPIC_KEY_REDACTED]',
    description: 'Anthropic API Key',
    enabled: true,
  },
  {
    name: 'stripe_key',
    pattern: /sk_(live|test)_[A-Za-z0-9]{24,}/g,
    replacement: '[STRIPE_KEY_REDACTED]',
    description: 'Stripe API Key',
    enabled: true,
  },
  {
    name: 'slack_token',
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    replacement: '[SLACK_TOKEN_REDACTED]',
    description: 'Slack Token',
    enabled: true,
  },
  {
    name: 'discord_token',
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    replacement: '[DISCORD_TOKEN_REDACTED]',
    description: 'Discord Bot Token',
    enabled: true,
  },
  // Generic Secrets
  {
    name: 'jwt_token',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    replacement: '[JWT_REDACTED]',
    description: 'JSON Web Token',
    enabled: true,
  },
  {
    name: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    replacement: '[PRIVATE_KEY_REDACTED]',
    description: 'Private Key Block',
    enabled: true,
  },
  {
    name: 'basic_auth',
    pattern: /Basic [A-Za-z0-9+/=]{20,}/g,
    replacement: '[BASIC_AUTH_REDACTED]',
    description: 'Basic Auth Header',
    enabled: true,
  },
  {
    name: 'bearer_token',
    pattern: /Bearer [A-Za-z0-9._-]{20,}/g,
    replacement: '[BEARER_TOKEN_REDACTED]',
    description: 'Bearer Token',
    enabled: true,
  },
  // Database
  {
    name: 'postgres_url',
    pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s]+/g,
    replacement: '[POSTGRES_URL_REDACTED]',
    description: 'PostgreSQL Connection URL',
    enabled: true,
  },
  {
    name: 'mysql_url',
    pattern: /mysql:\/\/[^:]+:[^@]+@[^\s]+/g,
    replacement: '[MYSQL_URL_REDACTED]',
    description: 'MySQL Connection URL',
    enabled: true,
  },
  {
    name: 'mongodb_url',
    pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s]+/g,
    replacement: '[MONGODB_URL_REDACTED]',
    description: 'MongoDB Connection URL',
    enabled: true,
  },
  {
    name: 'redis_url',
    pattern: /redis:\/\/[^:]*:[^@]+@[^\s]+/g,
    replacement: '[REDIS_URL_REDACTED]',
    description: 'Redis Connection URL',
    enabled: true,
  },
  // Environment Variables containing secrets
  {
    name: 'env_secret',
    pattern: /(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|AUTH|CREDENTIAL)[=:]\s*['"]?[^\s'"]{8,}['"]?/gi,
    replacement: '[ENV_SECRET_REDACTED]',
    description: 'Environment variable with secret',
    enabled: true,
  },
  // IP/Network
  {
    name: 'ssh_password',
    pattern: /sshpass\s+-p\s+['"]?[^\s'"]+['"]?/g,
    replacement: 'sshpass -p [PASSWORD_REDACTED]',
    description: 'SSH Password in command',
    enabled: true,
  },
];

const STORAGE_KEY = 'warp_open_secret_patterns';

// State
const customPatterns = ref<SecretPattern[]>([]);
const redactionEnabled = ref(true);
const redactedSecrets = ref<RedactedSecret[]>([]);
const maxRedactedHistory = 100;

// Load custom patterns from storage
function loadCustomPatterns(): void {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      customPatterns.value = parsed.map((p: SecretPattern) => ({
        ...p,
        pattern: new RegExp(p.pattern.source || p.pattern, p.pattern.flags || 'g'),
      }));
    }
  } catch (e) {
    console.error('[SecretRedaction] Error loading patterns:', e);
  }
}

// Save custom patterns to storage
function saveCustomPatterns(): void {
  try {
    const toSave = customPatterns.value.map(p => ({
      ...p,
      pattern: { source: p.pattern.source, flags: p.pattern.flags },
    }));
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
  } catch (e) {
    console.error('[SecretRedaction] Error saving patterns:', e);
  }
}

// Initialize
loadCustomPatterns();

export function useSecretRedaction() {
  const allPatterns = computed(() => [
    ...DEFAULT_PATTERNS,
    ...customPatterns.value,
  ]);

  const enabledPatterns = computed(() =>
    allPatterns.value.filter(p => p.enabled)
  );

  /**
   * Redact secrets from text
   * Returns both the redacted text and information about what was redacted
   */
  function redactSecrets(text: string, lineNumber?: number): {
    redacted: string;
    found: RedactedSecret[];
  } {
    if (!redactionEnabled.value) {
      return { redacted: text, found: [] };
    }

    let result = text;
    const found: RedactedSecret[] = [];
    const timestamp = Date.now();

    for (const pattern of enabledPatterns.value) {
      // Reset regex state
      pattern.pattern.lastIndex = 0;

      let match;
      while ((match = pattern.pattern.exec(text)) !== null) {
        const secret: RedactedSecret = {
          original: match[0],
          redacted: pattern.replacement,
          type: pattern.name,
          timestamp,
          lineNumber,
        };
        found.push(secret);

        // Store in history (limited)
        if (redactedSecrets.value.length >= maxRedactedHistory) {
          redactedSecrets.value.shift();
        }
        redactedSecrets.value.push(secret);
      }

      // Reset and do the replacement
      pattern.pattern.lastIndex = 0;
      result = result.replace(pattern.pattern, pattern.replacement);
    }

    return { redacted: result, found };
  }

  /**
   * Check if text contains any secrets
   */
  function containsSecrets(text: string): boolean {
    for (const pattern of enabledPatterns.value) {
      pattern.pattern.lastIndex = 0;
      if (pattern.pattern.test(text)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Add a custom pattern
   */
  function addPattern(pattern: Omit<SecretPattern, 'enabled'>): void {
    customPatterns.value.push({
      ...pattern,
      enabled: true,
    });
    saveCustomPatterns();
  }

  /**
   * Remove a custom pattern
   */
  function removePattern(name: string): void {
    const index = customPatterns.value.findIndex(p => p.name === name);
    if (index >= 0) {
      customPatterns.value.splice(index, 1);
      saveCustomPatterns();
    }
  }

  /**
   * Toggle a pattern on/off
   */
  function togglePattern(name: string): void {
    const pattern = allPatterns.value.find(p => p.name === name);
    if (pattern) {
      pattern.enabled = !pattern.enabled;
      // Only save if it's a custom pattern
      if (customPatterns.value.find(p => p.name === name)) {
        saveCustomPatterns();
      }
    }
  }

  /**
   * Enable/disable all redaction
   */
  function setEnabled(enabled: boolean): void {
    redactionEnabled.value = enabled;
  }

  /**
   * Get redaction statistics
   */
  function getStats() {
    const byType: Record<string, number> = {};
    for (const secret of redactedSecrets.value) {
      byType[secret.type] = (byType[secret.type] || 0) + 1;
    }
    return {
      totalRedacted: redactedSecrets.value.length,
      byType,
      patternsEnabled: enabledPatterns.value.length,
      patternsTotal: allPatterns.value.length,
    };
  }

  /**
   * Clear redaction history
   */
  function clearHistory(): void {
    redactedSecrets.value = [];
  }

  /**
   * Get the original value of a redacted secret (for clipboard copy)
   * Only available for secrets in current session
   */
  function getOriginal(redacted: string, timestamp: number): string | null {
    const secret = redactedSecrets.value.find(
      s => s.redacted === redacted && Math.abs(s.timestamp - timestamp) < 60000
    );
    return secret?.original || null;
  }

  return {
    // State
    enabled: computed(() => redactionEnabled.value),
    patterns: allPatterns,
    enabledPatterns,
    redactionHistory: computed(() => redactedSecrets.value),

    // Methods
    redactSecrets,
    containsSecrets,
    addPattern,
    removePattern,
    togglePattern,
    setEnabled,
    getStats,
    clearHistory,
    getOriginal,
  };
}
