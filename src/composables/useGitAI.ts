/**
 * Git AI Integration
 * Auto-generate commit messages, PR descriptions, and code review
 */

import { ref, computed } from 'vue';
import { gitStatus, gitDiff, getCurrentBranch, gitCommit, gitAdd } from '../utils/gitOps';
import { executeCommand } from '../utils/commandOps';

// Check if we're running in Tauri
const isTauri = '__TAURI__' in window;

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
let invoke: InvokeFn | null = null;

if (isTauri) {
  import('@tauri-apps/api/tauri').then(module => {
    invoke = module.invoke as InvokeFn;
  });
}

export interface CommitSuggestion {
  type: 'feat' | 'fix' | 'docs' | 'style' | 'refactor' | 'test' | 'chore';
  scope?: string;
  subject: string;
  body?: string;
  breaking?: boolean;
}

export interface PRDescription {
  title: string;
  summary: string;
  changes: string[];
  testPlan?: string;
  breaking?: string;
}

const isGenerating = ref(false);
const lastCommitMessage = ref<string | null>(null);
const lastPRDescription = ref<PRDescription | null>(null);

export function useGitAI() {
  /**
   * Generate a commit message from staged/unstaged changes
   */
  async function generateCommitMessage(
    repoPath?: string,
    model: string = 'qwen2.5-coder:1.5b'
  ): Promise<CommitSuggestion | null> {
    isGenerating.value = true;

    try {
      // Get the diff
      const diff = await gitDiff(undefined, repoPath);
      const status = await gitStatus(repoPath);

      if (!diff && !status.output) {
        console.log('[GitAI] No changes to commit');
        return null;
      }

      // Build prompt for AI
      const prompt = `Analyze this git diff and generate a conventional commit message.

Git Status:
${status.output}

Git Diff:
${diff.substring(0, 4000)}

Generate a commit message following Conventional Commits format:
- type: feat|fix|docs|style|refactor|test|chore
- scope: optional, the area of code affected
- subject: short description (50 chars max)
- body: optional longer description

Respond with ONLY valid JSON in this exact format:
{"type":"feat","scope":"api","subject":"add user authentication","body":"Implement JWT-based auth flow"}`;

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

      // Parse JSON response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const suggestion = JSON.parse(jsonMatch[0]) as CommitSuggestion;
        lastCommitMessage.value = formatCommitMessage(suggestion);
        return suggestion;
      }

      return null;
    } catch (e) {
      console.error('[GitAI] Error generating commit message:', e);
      return null;
    } finally {
      isGenerating.value = false;
    }
  }

  /**
   * Format a commit suggestion into a string
   */
  function formatCommitMessage(suggestion: CommitSuggestion): string {
    let message = suggestion.type;
    if (suggestion.scope) {
      message += `(${suggestion.scope})`;
    }
    if (suggestion.breaking) {
      message += '!';
    }
    message += `: ${suggestion.subject}`;

    if (suggestion.body) {
      message += `\n\n${suggestion.body}`;
    }

    return message;
  }

  /**
   * Generate a PR description from commits
   */
  async function generatePRDescription(
    baseBranch: string = 'main',
    repoPath?: string,
    model: string = 'qwen2.5-coder:1.5b'
  ): Promise<PRDescription | null> {
    isGenerating.value = true;

    try {
      const currentBranch = await getCurrentBranch(repoPath);

      // Get commits between branches
      const logResult = await executeCommand(
        `git log ${baseBranch}..${currentBranch} --oneline`,
        repoPath
      );
      const commits = logResult.stdout;

      // Get full diff
      const diffResult = await executeCommand(
        `git diff ${baseBranch}...${currentBranch}`,
        repoPath
      );
      const diff = diffResult.stdout;

      if (!commits && !diff) {
        console.log('[GitAI] No changes for PR');
        return null;
      }

      const prompt = `Generate a Pull Request description for these changes.

Branch: ${currentBranch} -> ${baseBranch}

Commits:
${commits}

Diff Summary (first 3000 chars):
${diff.substring(0, 3000)}

Generate a PR description with:
- title: concise PR title
- summary: 1-2 sentence overview
- changes: list of key changes
- testPlan: how to test this PR

Respond with ONLY valid JSON:
{"title":"...","summary":"...","changes":["change 1","change 2"],"testPlan":"..."}`;

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

      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const description = JSON.parse(jsonMatch[0]) as PRDescription;
        lastPRDescription.value = description;
        return description;
      }

      return null;
    } catch (e) {
      console.error('[GitAI] Error generating PR description:', e);
      return null;
    } finally {
      isGenerating.value = false;
    }
  }

  /**
   * Format PR description as markdown
   */
  function formatPRDescription(pr: PRDescription): string {
    let md = `## Summary\n${pr.summary}\n\n`;
    md += `## Changes\n`;
    for (const change of pr.changes) {
      md += `- ${change}\n`;
    }
    if (pr.testPlan) {
      md += `\n## Test Plan\n${pr.testPlan}\n`;
    }
    if (pr.breaking) {
      md += `\n## Breaking Changes\n${pr.breaking}\n`;
    }
    return md;
  }

  /**
   * Smart commit: generate message and commit in one step
   */
  async function smartCommit(
    files: string[] | string = '.',
    repoPath?: string,
    model?: string
  ): Promise<{ success: boolean; message?: string; error?: string }> {
    try {
      // Stage files first
      await gitAdd(files, repoPath);

      // Generate commit message
      const suggestion = await generateCommitMessage(repoPath, model);
      if (!suggestion) {
        return { success: false, error: 'Could not generate commit message' };
      }

      const message = formatCommitMessage(suggestion);

      // Commit with generated message
      const result = await gitCommit(message, repoPath);

      return {
        success: result.success,
        message: result.success ? message : undefined,
        error: result.error,
      };
    } catch (e) {
      return { success: false, error: String(e) };
    }
  }

  /**
   * Analyze code for review suggestions
   */
  async function reviewCode(
    diff: string,
    model: string = 'qwen2.5-coder:1.5b'
  ): Promise<string[]> {
    const prompt = `Review this code diff and provide constructive feedback.
Focus on:
- Potential bugs
- Security issues
- Performance concerns
- Code style improvements
- Missing tests

Diff:
${diff.substring(0, 4000)}

Respond with a JSON array of review comments:
["comment 1", "comment 2", ...]`;

    try {
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

      const jsonMatch = response.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
      return [];
    } catch (e) {
      console.error('[GitAI] Error reviewing code:', e);
      return [];
    }
  }

  return {
    isGenerating: computed(() => isGenerating.value),
    lastCommitMessage: computed(() => lastCommitMessage.value),
    lastPRDescription: computed(() => lastPRDescription.value),
    generateCommitMessage,
    formatCommitMessage,
    generatePRDescription,
    formatPRDescription,
    smartCommit,
    reviewCode,
  };
}
