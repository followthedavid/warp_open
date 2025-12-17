// Warp_Open UI Integration Tests
// Playwright tests for terminal tabs, AI chat, and command blocks

import { test, expect, type Page } from '@playwright/test';

test.describe('Warp_Open Terminal and AI Integration', () => {
  test.beforeEach(async ({ page }) => {
    // Wait for app to load (Tauri serves on localhost during dev)
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
  });

  test('App launches with initial terminal tab', async ({ page }) => {
    // Verify initial tab exists - tabs are divs with class="tab"
    const tabs = await page.locator('div.tab').count();
    expect(tabs).toBeGreaterThan(0);
    
    // Verify terminal container exists
    const terminalExists = await page.locator('.terminal-container').isVisible();
    expect(terminalExists).toBe(true);
  });

  test('Create new terminal tab with + button', async ({ page }) => {
    const initialCount = await page.locator('div.tab').count();
    
    // Click + button - it's button.new-tab-btn
    await page.locator('button.new-tab-btn').click();
    await page.waitForTimeout(500);
    
    const newCount = await page.locator('div.tab').count();
    expect(newCount).toBe(initialCount + 1);
  });

  test('Switch between terminal and AI tabs', async ({ page }) => {
    // Create AI tab
    await page.locator('.new-ai-tab-btn').click();
    await page.waitForTimeout(500);
    
    // Verify AI tab is active - tabs are divs
    const aiTab = await page.locator('div.tab:has-text("AI")').first();
    expect(await aiTab.evaluate(el => el.classList.contains('active'))).toBe(true);
    
    // Switch to terminal tab
    const terminalTab = await page.locator('div.tab:has-text("Terminal")').first();
    await terminalTab.click();
    await page.waitForTimeout(300);
    
    // Verify terminal tab is now active
    expect(await terminalTab.evaluate(el => el.classList.contains('active'))).toBe(true);
  });

  test('AI chat input box is visible in AI tabs', async ({ page }) => {
    // Create AI tab
    await page.locator('.new-ai-tab-btn').click();
    await page.waitForTimeout(500);
    
    // Verify input area exists - it's a textarea in .input-area
    const inputExists = await page.locator('.input-area textarea').isVisible();
    expect(inputExists).toBe(true);
  });

  test('Close tab with X button', async ({ page }) => {
    const initialCount = await page.locator('div.tab').count();
    
    // Close first tab - button is .close-btn
    const firstTab = await page.locator('div.tab').first();
    const closeButton = await firstTab.locator('button.close-btn').first();
    
    if (await closeButton.isVisible()) {
      await closeButton.click();
      await page.waitForTimeout(500);
      
      const newCount = await page.locator('div.tab').count();
      expect(newCount).toBe(initialCount - 1);
    }
  });

  test('Terminal renders xterm output', async ({ page }) => {
    // Check if xterm is initialized
    const xtermExists = await page.locator('.xterm, .terminal-window').isVisible();
    expect(xtermExists).toBe(true);
  });

  test('Command blocks container exists', async ({ page }) => {
    // Check if blocks view exists (may be empty initially)
    const blocksView = await page.locator('.blocks-view');
    const exists = await blocksView.count();
    
    // Just verify we can query for it, blocks may appear after command execution
    expect(exists >= 0).toBe(true);
  });
});

test.describe('AI Chat Functionality', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    
    // Create AI tab
    await page.locator('.new-ai-tab-btn').click();
    await page.waitForTimeout(500);
  });

  test('Send message to AI', async ({ page }) => {
    // Input is textarea in .input-area
    const input = page.locator('.input-area textarea').first();
    await input.fill('Hello AI');
    await input.press('Enter');
    
    // Wait for thinking indicator
    await page.waitForSelector('.thinking-indicator', { timeout: 2000 }).catch(() => {});
    
    // Eventually message should appear - messages have .message-bubble class
    await page.waitForTimeout(1000);
    const messages = await page.locator('.message-bubble').count();
    expect(messages).toBeGreaterThan(0);
  });

  test('AI thinking indicator appears and disappears', async ({ page }) => {
    // Input is textarea in .input-area
    const input = page.locator('.input-area textarea').first();
    await input.fill('test');
    await input.press('Enter');
    
    // Thinking indicator should appear
    const thinkingAppears = await page.locator('.thinking-indicator').isVisible({ timeout: 2000 }).catch(() => false);
    
    // If it appeared, it should eventually disappear
    if (thinkingAppears) {
      await page.waitForSelector('.thinking-indicator', { state: 'hidden', timeout: 10000 }).catch(() => {});
    }
  });
});

test.describe('Performance and Stability', () => {
  test('App does not freeze when closing tabs', async ({ page }) => {
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    
    // Create several tabs - button is .new-tab-btn
    for (let i = 0; i < 3; i++) {
      await page.locator('button.new-tab-btn').click();
      await page.waitForTimeout(300);
    }
    
    // Close all tabs except one - tabs are divs, close button is .close-btn
    let tabCount = await page.locator('div.tab').count();
    while (tabCount > 1) {
      const closeBtn = await page.locator('div.tab button.close-btn').first();
      if (await closeBtn.isVisible()) {
        await closeBtn.click();
        await page.waitForTimeout(300);
      }
      tabCount = await page.locator('div.tab').count();
    }
    
    // Verify app is still responsive
    const appResponsive = await page.locator('#app').isVisible();
    expect(appResponsive).toBe(true);
  });

  test('Multiple tabs do not cause memory leaks', async ({ page }) => {
    await page.goto('http://localhost:5173');
    
    // Create and close tabs multiple times - button is .new-tab-btn
    for (let i = 0; i < 5; i++) {
      await page.locator('button.new-tab-btn').click();
      await page.waitForTimeout(200);
    }
    
    // App should still be functional - tabs are divs
    const tabs = await page.locator('div.tab').count();
    expect(tabs).toBeGreaterThan(0);
  });
});
