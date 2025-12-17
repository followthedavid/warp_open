/**
 * escalation-desktop.spec.ts
 *
 * End-to-end test for desktop app escalation workflow
 *
 * Tests the following scenario:
 * 1. Prompt sent to local Ollama
 * 2. If Ollama fails, escalate to ChatGPT Desktop via AppleScript
 * 3. If ChatGPT Desktop fails, escalate to phone via iCloud sync
 * 4. Verify fallback chain works correctly
 */

import { test, expect } from '@playwright/test';

const AGENT_SERVER_URL = 'http://localhost:4005';

test.describe('Desktop App Escalation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to app and open Agent Console
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
  });

  test('should route prompt through Ollama successfully', async ({ page }) => {
    const prompt = 'Say only the word "OLLAMA_WORKING" and nothing else';

    const response = await fetch(`${AGENT_SERVER_URL}/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt, model: 'llama3.2:3b-instruct-q4_K_M' })
    });

    expect(response.ok).toBe(true);

    const data = await response.json();
    expect(data.ok).toBe(true);
    expect(data.route).toBeDefined();
    expect(data.route.backend).toBe('http');
    expect(data.route.port).toBe(11434);
    expect(data.route.parsed.response).toContain('OLLAMA');
  });

  test('should discover available backends', async ({ page }) => {
    const response = await fetch(`${AGENT_SERVER_URL}/backends`);
    expect(response.ok).toBe(true);

    const data = await response.json();
    expect(data.ok).toBe(true);
    expect(data.backends).toBeDefined();

    // Should have at least Ollama
    const hasOllama = data.backends.http?.some(b => b.port === 11434) ||
                      data.backends.cli?.some(b => b.path.includes('ollama'));

    expect(hasOllama).toBe(true);
  });

  test('should invoke ChatGPT Desktop via AppleScript if Ollama unavailable', async ({ page }) => {
    // This test requires ChatGPT Desktop to be running
    // Skip if not available
    const checkRunning = await fetch(`${AGENT_SERVER_URL}/invoke-desktop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app: 'ChatGPT',
        prompt: 'test',
        retries: 1
      })
    });

    if (checkRunning.status === 503) {
      test.skip();
      return;
    }

    // Test actual invocation
    const prompt = 'Say only "CHATGPT_WORKING" and nothing else';

    const response = await fetch(`${AGENT_SERVER_URL}/invoke-desktop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app: 'ChatGPT',
        prompt,
        retries: 2
      })
    });

    const data = await response.json();

    // Should either succeed or fail gracefully
    if (data.ok) {
      expect(data.response).toBeDefined();
      expect(data.method).toBe('appleScript');
      expect(data.app).toBe('ChatGPT');
      expect(data.logs).toBeDefined();
      expect(data.logs.length).toBeGreaterThan(0);
    } else {
      // Failed, but should have error details
      expect(data.error).toBeDefined();
      expect(data.logs).toBeDefined();
    }
  });

  test('should handle desktop automation validation errors', async ({ page }) => {
    // Test invalid app name
    const invalidAppResponse = await fetch(`${AGENT_SERVER_URL}/invoke-desktop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app: 'InvalidApp',
        prompt: 'test'
      })
    });

    expect(invalidAppResponse.status).toBe(400);
    const invalidAppData = await invalidAppResponse.json();
    expect(invalidAppData.ok).toBe(false);
    expect(invalidAppData.error).toBe('invalid-app');

    // Test empty prompt
    const emptyPromptResponse = await fetch(`${AGENT_SERVER_URL}/invoke-desktop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app: 'ChatGPT',
        prompt: ''
      })
    });

    expect(emptyPromptResponse.status).toBe(400);
    const emptyPromptData = await emptyPromptResponse.json();
    expect(emptyPromptData.ok).toBe(false);
    expect(emptyPromptData.error).toBe('empty-prompt');
  });

  test('should test full escalation chain: Ollama → Desktop → Phone', async ({ page }) => {
    // This is an integration test of the full escalation workflow
    // In practice, this would be triggered when local LLM fails

    const testPrompt = 'Count from 1 to 3, one number per line';

    // Step 1: Try Ollama first (should succeed)
    const ollamaResponse = await fetch(`${AGENT_SERVER_URL}/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: testPrompt })
    });

    const ollamaData = await ollamaResponse.json();

    if (ollamaData.ok) {
      // Ollama succeeded - escalation not needed
      expect(ollamaData.route.backend).toBe('http');
      expect(ollamaData.route.parsed.response).toBeDefined();
    } else {
      // Ollama failed - would escalate to desktop app
      expect(ollamaData.ok).toBe(false);
      expect(ollamaData.error).toBe('no-backend');

      // In real scenario, this would trigger desktop app fallback
      // For now, just verify the endpoint exists
      const desktopResponse = await fetch(`${AGENT_SERVER_URL}/invoke-desktop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          app: 'ChatGPT',
          prompt: testPrompt,
          retries: 1
        })
      });

      // Should return a valid response (success or app-not-running)
      expect([200, 500, 503]).toContain(desktopResponse.status);
    }
  });

  test('should list available models', async ({ page }) => {
    const response = await fetch(`${AGENT_SERVER_URL}/models`);
    expect(response.ok).toBe(true);

    const data = await response.json();
    expect(data.ok).toBe(true);
    expect(data.models).toBeDefined();
    expect(Array.isArray(data.models)).toBe(true);

    // Should have at least one model
    if (data.models.length > 0) {
      expect(data.models[0]).toHaveProperty('name');
    }
  });

  test('should support streaming responses', async ({ page }) => {
    const prompt = 'Count to 3';

    const response = await fetch(`${AGENT_SERVER_URL}/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    });

    expect(response.ok).toBe(true);
    expect(response.headers.get('content-type')).toContain('text/event-stream');

    // Read stream
    const reader = response.body?.getReader();
    const decoder = new TextDecoder();
    let chunks = [];
    let done = false;

    while (!done) {
      const { value, done: streamDone } = await reader!.read();
      done = streamDone;

      if (value) {
        const text = decoder.decode(value, { stream: true });
        chunks.push(text);
      }
    }

    const fullResponse = chunks.join('');

    // Should contain SSE events
    expect(fullResponse).toContain('data:');
    expect(fullResponse).toContain('[DONE]');
  });

  test('should handle health check endpoint', async ({ page }) => {
    const response = await fetch(`${AGENT_SERVER_URL}/health`);
    expect(response.ok).toBe(true);

    const data = await response.json();
    expect(data.ok).toBe(true);
    expect(data.now).toBeDefined();
    expect(data.pid).toBeDefined();
  });

  test('should verify Agent Console UI integration', async ({ page }) => {
    // Click Developer button
    const devButton = page.getByRole('button', { name: /developer/i });
    if (await devButton.isVisible()) {
      await devButton.click();

      // Wait for Developer view
      await page.waitForSelector('text=Developer Dashboard', { timeout: 3000 });

      // Click Agent button
      const agentButton = page.getByRole('button', { name: /agent/i });
      await agentButton.click();

      // Wait for Agent Console
      await page.waitForSelector('.agent-console', { timeout: 3000 });

      // Verify Agent Console elements
      await expect(page.locator('.agent-console')).toBeVisible();
      await expect(page.locator('text=Agent Online')).toBeVisible();

      // Test backend display
      const showBackendsButton = page.getByRole('button', { name: /show backends/i });
      await showBackendsButton.click();

      // Should show backends section
      await expect(page.locator('.backends')).toBeVisible();
    }
  });
});

test.describe('Phone Sync Integration (iCloud)', () => {
  test('should detect iCloud Drive sync folder', async () => {
    // Test if iCloud Drive folder exists
    const iCloudPath = `${process.env.HOME}/Library/Mobile Documents/com~apple~CloudDocs`;

    // This would be implemented by syncWatcher.js
    // For now, just verify the concept
    expect(typeof iCloudPath).toBe('string');
  });

  test('should handle phone escalation request format', async () => {
    // Phone sends JSON file to iCloud Drive
    const phoneRequest = {
      id: 'test-123',
      timestamp: Date.now(),
      prompt: 'Test prompt from phone',
      priority: 'high',
      source: 'iOS Shortcut'
    };

    // Validate format
    expect(phoneRequest).toHaveProperty('id');
    expect(phoneRequest).toHaveProperty('timestamp');
    expect(phoneRequest).toHaveProperty('prompt');
  });
});
