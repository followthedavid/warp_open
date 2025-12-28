/**
 * Verifier - Syntax and safety checking layer
 *
 * Validates code and commands BEFORE execution by:
 * - Checking syntax for various languages
 * - Detecting dangerous commands
 * - Validating file paths
 * - Running lightweight static analysis
 */

import { invoke } from '@tauri-apps/api/tauri';
import type { AgentAction } from './ConstrainedOutput';

export interface VerificationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  suggestions: string[];
}

// Dangerous command patterns
const DANGEROUS_PATTERNS = [
  /rm\s+(-rf?|--recursive).*[\/~]/i,  // Recursive delete in important dirs
  /rm\s+(-rf?|--recursive)\s+\//,      // Delete root
  /mkfs/i,                               // Format disk
  /dd\s+.*of=\/dev/i,                   // Write to device
  />\s*\/dev\/sd[a-z]/i,                // Overwrite disk
  /chmod\s+777/,                         // World-writable
  /curl.*\|\s*bash/i,                   // Pipe to shell
  /wget.*\|\s*sh/i,                     // Pipe to shell
  /eval\s*\(/,                          // Eval in shell
  /:\(\)\{.*:\|:.*\};:/,                 // Fork bomb
];

// File patterns that shouldn't be modified
const PROTECTED_PATHS = [
  /^\/etc\//,
  /^\/usr\//,
  /^\/bin\//,
  /^\/sbin\//,
  /^\/System\//,
  /^\/Library\//,
  /^~\/.ssh\//,
  /^~\/.gnupg\//,
  /\.env$/,
  /credentials/i,
  /password/i,
  /secret/i,
];

export class Verifier {
  /**
   * Verify a complete action before execution
   */
  async verify(action: AgentAction): Promise<VerificationResult> {
    const result: VerificationResult = {
      valid: true,
      errors: [],
      warnings: [],
      suggestions: []
    };

    switch (action.action) {
      case 'bash':
        await this.verifyBashCommand(action.command || '', result);
        break;
      case 'write':
        await this.verifyWrite(action.path || '', action.content || '', result);
        break;
      case 'edit':
        await this.verifyEdit(action.path || '', action.oldContent || '', action.newContent || '', result);
        break;
      case 'read':
        this.verifyPath(action.path || '', result);
        break;
      default:
        // Other actions are safe
        break;
    }

    return result;
  }

  /**
   * Verify a bash command for safety and syntax
   */
  private async verifyBashCommand(command: string, result: VerificationResult): Promise<void> {
    // Check for dangerous patterns
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(command)) {
        result.errors.push(`Dangerous command pattern detected: ${pattern.source}`);
        result.valid = false;
      }
    }

    // Check for empty command
    if (!command.trim()) {
      result.errors.push('Empty command');
      result.valid = false;
      return;
    }

    // Warn about sudo
    if (/^sudo\s/.test(command)) {
      result.warnings.push('Command uses sudo - requires elevated privileges');
    }

    // Check bash syntax using bash -n
    try {
      await invoke<string>('execute_shell', {
        command: `bash -n -c ${JSON.stringify(command)}`
      });
    } catch (e) {
      const error = e instanceof Error ? e.message : 'Unknown error';
      if (error.includes('syntax error')) {
        result.errors.push(`Bash syntax error: ${error}`);
        result.valid = false;
      }
    }
  }

  /**
   * Verify file write operation
   */
  private async verifyWrite(path: string, content: string, result: VerificationResult): Promise<void> {
    this.verifyPath(path, result);

    if (!result.valid) return;

    // Detect language and verify syntax
    const ext = path.split('.').pop()?.toLowerCase() || '';
    await this.verifySyntax(content, ext, result);

    // Check for potential secrets in content
    if (/password\s*[:=]\s*['""][^'""]+['""]|api[_-]?key\s*[:=]\s*['""][^'""]+['""]/i.test(content)) {
      result.warnings.push('Content may contain hardcoded secrets');
    }
  }

  /**
   * Verify file edit operation
   */
  private async verifyEdit(
    path: string,
    oldContent: string,
    newContent: string,
    result: VerificationResult
  ): Promise<void> {
    this.verifyPath(path, result);

    if (!result.valid) return;

    // Check that oldContent is not empty (would match everything)
    if (!oldContent.trim()) {
      result.errors.push('oldContent cannot be empty');
      result.valid = false;
      return;
    }

    // Verify the new content syntax
    const ext = path.split('.').pop()?.toLowerCase() || '';
    await this.verifySyntax(newContent, ext, result);
  }

  /**
   * Verify a file path
   */
  private verifyPath(path: string, result: VerificationResult): void {
    if (!path) {
      result.errors.push('Path is empty');
      result.valid = false;
      return;
    }

    // Check for path traversal
    if (path.includes('..')) {
      result.warnings.push('Path contains ".." - verify this is intentional');
    }

    // Check protected paths
    for (const pattern of PROTECTED_PATHS) {
      if (pattern.test(path)) {
        result.warnings.push(`Path matches protected pattern: ${pattern.source}`);
      }
    }
  }

  /**
   * Verify syntax for various languages
   */
  private async verifySyntax(content: string, extension: string, result: VerificationResult): Promise<void> {
    try {
      switch (extension) {
        case 'js':
        case 'mjs':
        case 'cjs':
          await this.verifyJavaScript(content, result);
          break;
        case 'ts':
        case 'tsx':
          await this.verifyTypeScript(content, result);
          break;
        case 'json':
          this.verifyJSON(content, result);
          break;
        case 'py':
          await this.verifyPython(content, result);
          break;
        case 'rs':
          await this.verifyRust(content, result);
          break;
        case 'vue':
          // Vue files are complex, just check for obvious issues
          this.verifyVue(content, result);
          break;
        case 'sh':
        case 'bash':
          await this.verifyBash(content, result);
          break;
        default:
          // Unknown extension, skip syntax check
          break;
      }
    } catch (e) {
      result.warnings.push(`Syntax check failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  }

  /**
   * Verify JavaScript syntax
   */
  private async verifyJavaScript(content: string, result: VerificationResult): Promise<void> {
    try {
      // Use Node.js to check syntax
      const escaped = content.replace(/'/g, "'\"'\"'");
      await invoke<string>('execute_shell', {
        command: `node --check -e '${escaped}'`
      });
    } catch (e) {
      const error = e instanceof Error ? e.message : 'Unknown error';
      if (error.includes('SyntaxError')) {
        result.errors.push(`JavaScript syntax error: ${error}`);
        result.valid = false;
      }
    }
  }

  /**
   * Verify TypeScript syntax (basic check)
   */
  private async verifyTypeScript(content: string, result: VerificationResult): Promise<void> {
    // Check for obvious TypeScript issues
    const issues = [];

    // Unmatched brackets
    const brackets = { '{': 0, '[': 0, '(': 0 };
    for (const char of content) {
      if (char === '{') brackets['{']++;
      if (char === '}') brackets['{']--;
      if (char === '[') brackets['[']++;
      if (char === ']') brackets['[']--;
      if (char === '(') brackets['(']++;
      if (char === ')') brackets['(']--;
    }

    if (brackets['{'] !== 0) issues.push('Unmatched curly braces');
    if (brackets['['] !== 0) issues.push('Unmatched square brackets');
    if (brackets['('] !== 0) issues.push('Unmatched parentheses');

    if (issues.length > 0) {
      result.errors.push(`TypeScript issues: ${issues.join(', ')}`);
      result.valid = false;
    }
  }

  /**
   * Verify JSON syntax
   */
  private verifyJSON(content: string, result: VerificationResult): void {
    try {
      JSON.parse(content);
    } catch (e) {
      result.errors.push(`JSON syntax error: ${e instanceof Error ? e.message : 'Invalid JSON'}`);
      result.valid = false;
    }
  }

  /**
   * Verify Python syntax
   */
  private async verifyPython(content: string, result: VerificationResult): Promise<void> {
    try {
      // Write to temp file and check with Python
      const tempFile = `/tmp/verify_${Date.now()}.py`;
      await invoke<void>('write_file', { path: tempFile, content });
      await invoke<string>('execute_shell', {
        command: `python3 -m py_compile ${tempFile} && rm ${tempFile}`
      });
    } catch (e) {
      const error = e instanceof Error ? e.message : 'Unknown error';
      if (error.includes('SyntaxError') || error.includes('Error')) {
        result.errors.push(`Python syntax error: ${error}`);
        result.valid = false;
      }
    }
  }

  /**
   * Verify Rust syntax (basic check via rustfmt)
   */
  private async verifyRust(content: string, result: VerificationResult): Promise<void> {
    try {
      const tempFile = `/tmp/verify_${Date.now()}.rs`;
      await invoke<void>('write_file', { path: tempFile, content });
      await invoke<string>('execute_shell', {
        command: `rustfmt --check ${tempFile} 2>&1; rm ${tempFile}`
      });
    } catch (e) {
      const error = e instanceof Error ? e.message : 'Unknown error';
      if (error.includes('error')) {
        result.warnings.push(`Rust formatting issue: ${error.slice(0, 100)}`);
      }
    }
  }

  /**
   * Verify Vue SFC syntax (basic check)
   */
  private verifyVue(content: string, result: VerificationResult): void {
    // Check for required sections
    if (!content.includes('<template>') && !content.includes('<script>')) {
      result.warnings.push('Vue file may be missing <template> or <script> section');
    }

    // Check for unclosed tags
    const templateMatch = content.match(/<template[^>]*>/g)?.length || 0;
    const templateCloseMatch = content.match(/<\/template>/g)?.length || 0;
    if (templateMatch !== templateCloseMatch) {
      result.errors.push('Unclosed <template> tag');
      result.valid = false;
    }
  }

  /**
   * Verify Bash script syntax
   */
  private async verifyBash(content: string, result: VerificationResult): Promise<void> {
    try {
      const tempFile = `/tmp/verify_${Date.now()}.sh`;
      await invoke<void>('write_file', { path: tempFile, content });
      await invoke<string>('execute_shell', {
        command: `bash -n ${tempFile} && rm ${tempFile}`
      });
    } catch (e) {
      const error = e instanceof Error ? e.message : 'Unknown error';
      if (error.includes('syntax error')) {
        result.errors.push(`Bash syntax error: ${error}`);
        result.valid = false;
      }
    }
  }

  /**
   * Quick safety check without full verification
   */
  quickSafetyCheck(action: AgentAction): { safe: boolean; reason?: string } {
    if (action.action === 'bash' && action.command) {
      for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(action.command)) {
          return { safe: false, reason: `Dangerous pattern: ${pattern.source}` };
        }
      }
    }

    if ((action.action === 'write' || action.action === 'edit') && action.path) {
      for (const pattern of PROTECTED_PATHS) {
        if (pattern.test(action.path)) {
          return { safe: false, reason: `Protected path: ${action.path}` };
        }
      }
    }

    return { safe: true };
  }
}

export default Verifier;
