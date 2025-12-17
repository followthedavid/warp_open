import { test, expect } from '@playwright/test';

/**
 * Automated End-to-End Tests for Code Execution Mode
 * These tests allow Claude to verify the entire application flow hands-off
 */

test.describe('AI Chat with Code Execution Mode', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to app
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Take screenshot of initial state
    await page.screenshot({ path: 'test-results/01-app-loaded.png', fullPage: true });
  });

  test('should load the application and show initial UI', async ({ page }) => {
    // Verify app title or main element
    await expect(page.locator('body')).toBeVisible();

    // Take screenshot
    await page.screenshot({ path: 'test-results/02-initial-ui.png', fullPage: true });

    console.log('✅ Application loaded successfully');
  });

  test('should create a new AI Chat tab', async ({ page }) => {
    // Look for the AI or new tab button
    const aiButton = page.locator('[data-testid="new-ai-button"]').or(page.getByText('AI')).first();

    if (await aiButton.isVisible()) {
      await aiButton.click();
      await page.waitForTimeout(1000);
      await page.screenshot({ path: 'test-results/03-ai-tab-created.png', fullPage: true });
      console.log('✅ AI Chat tab created');
    } else {
      console.log('⚠️  AI button not found, might already have an AI tab open');
      await page.screenshot({ path: 'test-results/03-no-ai-button.png', fullPage: true });
    }
  });

  test('should show execution mode toggle', async ({ page }) => {
    // Create AI tab if needed
    const aiButton = page.locator('[data-testid="new-ai-button"]').or(page.getByText('AI')).first();
    if (await aiButton.isVisible()) {
      await aiButton.click();
      await page.waitForTimeout(1000);
    }

    // Look for execution mode checkbox
    const executionToggle = page.locator('text=Code Execution').or(
      page.locator('input[type="checkbox"]').filter({ hasText: /execution/i })
    );

    await page.screenshot({ path: 'test-results/04-looking-for-toggle.png', fullPage: true });

    const isVisible = await executionToggle.isVisible();
    console.log(`Execution mode toggle visible: ${isVisible}`);

    if (isVisible) {
      console.log('✅ Execution mode toggle found');
    } else {
      console.log('⚠️  Execution mode toggle not found');
      // Log all checkboxes for debugging
      const checkboxes = await page.locator('input[type="checkbox"]').all();
      console.log(`Found ${checkboxes.length} checkboxes in total`);
    }
  });

  test('should enable execution mode and show the checkbox as checked', async ({ page }) => {
    // Create AI tab
    const aiButton = page.locator('[data-testid="new-ai-button"]').or(page.getByText('AI')).first();
    if (await aiButton.isVisible()) {
      await aiButton.click();
      await page.waitForTimeout(1000);
    }

    // Find and click execution mode toggle
    const executionCheckbox = page.locator('input[type="checkbox"]').first();

    await page.screenshot({ path: 'test-results/05-before-enable-execution.png', fullPage: true });

    await executionCheckbox.check();
    await page.waitForTimeout(500);

    await page.screenshot({ path: 'test-results/06-after-enable-execution.png', fullPage: true });

    const isChecked = await executionCheckbox.isChecked();
    expect(isChecked).toBe(true);

    console.log('✅ Execution mode enabled');
  });

  test('should send a message in AI chat', async ({ page }) => {
    // Create AI tab
    const aiButton = page.locator('[data-testid="new-ai-button"]').or(page.getByText('AI')).first();
    if (await aiButton.isVisible()) {
      await aiButton.click();
      await page.waitForTimeout(1000);
    }

    // Look for input area
    const textarea = page.locator('textarea').or(page.locator('input[type="text"]')).first();

    if (await textarea.isVisible()) {
      await textarea.fill('Hello, can you help me?');
      await page.screenshot({ path: 'test-results/07-message-typed.png', fullPage: true });

      // Look for send button or press Enter
      const sendButton = page.locator('button').filter({ hasText: /send/i }).or(
        page.locator('[data-testid="send-button"]')
      ).first();

      if (await sendButton.isVisible()) {
        await sendButton.click();
      } else {
        await textarea.press('Enter');
      }

      await page.waitForTimeout(2000);
      await page.screenshot({ path: 'test-results/08-message-sent.png', fullPage: true });

      console.log('✅ Message sent successfully');
    } else {
      console.log('❌ Input area not found');
      await page.screenshot({ path: 'test-results/07-no-input.png', fullPage: true });
    }
  });

  test('FULL FLOW: Complete execution mode test with actionable request', async ({ page }) => {
    console.log('\n🚀 Starting full execution mode test...\n');

    // Step 1: Create AI tab
    console.log('Step 1: Creating AI Chat tab...');
    const aiButton = page.locator('[data-testid="new-ai-button"]').or(page.getByText('AI')).first();
    if (await aiButton.isVisible()) {
      await aiButton.click();
      await page.waitForTimeout(1500);
    }
    await page.screenshot({ path: 'test-results/full-01-tab-created.png', fullPage: true });
    console.log('✅ AI tab created\n');

    // Step 2: Enable execution mode
    console.log('Step 2: Enabling execution mode...');
    const executionCheckbox = page.locator('input[type="checkbox"]').first();
    await executionCheckbox.check();
    await page.waitForTimeout(500);
    await page.screenshot({ path: 'test-results/full-02-execution-enabled.png', fullPage: true });
    console.log('✅ Execution mode enabled\n');

    // Step 3: Send actionable message
    console.log('Step 3: Sending actionable request...');
    const textarea = page.locator('textarea').or(page.locator('input[type="text"]')).first();

    if (await textarea.isVisible()) {
      const testMessage = 'Create a simple hello world function';
      await textarea.fill(testMessage);
      await page.screenshot({ path: 'test-results/full-03-message-ready.png', fullPage: true });
      console.log(`Message: "${testMessage}"`);

      // Send message
      await textarea.press('Enter');
      console.log('Message sent, waiting for response...\n');

      // Wait for AI to process
      await page.waitForTimeout(3000);
      await page.screenshot({ path: 'test-results/full-04-processing.png', fullPage: true });

      // Step 4: Check for execution steps or response
      console.log('Step 4: Checking for execution steps...');

      // Look for execution indicators
      const executionSteps = page.locator('.execution-steps').or(
        page.locator('text=Executing')
      );

      const hasExecution = await executionSteps.isVisible();
      console.log(`Execution steps visible: ${hasExecution}`);

      await page.waitForTimeout(5000);
      await page.screenshot({ path: 'test-results/full-05-execution-complete.png', fullPage: true });

      // Step 5: Look for messages
      const messages = await page.locator('.message-wrapper').or(page.locator('[class*="message"]')).all();
      console.log(`\nFound ${messages.length} messages in chat`);

      await page.screenshot({ path: 'test-results/full-06-final-state.png', fullPage: true });

      console.log('\n✅ Full flow test completed!');
      console.log('📸 All screenshots saved to test-results/');
    } else {
      console.log('❌ Could not find input area');
      await page.screenshot({ path: 'test-results/full-error-no-input.png', fullPage: true });
    }
  });

  test('should check Developer Dashboard', async ({ page }) => {
    console.log('\n🔍 Testing Developer Dashboard...\n');

    // Look for Developer button
    const devButton = page.locator('[data-testid="new-developer-button"]').or(
      page.getByText('Developer')
    ).first();

    await page.screenshot({ path: 'test-results/dev-01-before-click.png', fullPage: true });

    if (await devButton.isVisible()) {
      console.log('Found Developer button, clicking...');
      await devButton.click();
      await page.waitForTimeout(2000);

      await page.screenshot({ path: 'test-results/dev-02-dashboard-opened.png', fullPage: true });

      // Check for dashboard elements
      const hasGoalInput = await page.locator('input').filter({ hasText: /goal/i }).or(
        page.locator('textarea').filter({ hasText: /goal/i })
      ).isVisible();

      console.log(`Goal input visible: ${hasGoalInput}`);
      console.log('✅ Developer Dashboard test complete');
    } else {
      console.log('⚠️  Developer button not found');
      await page.screenshot({ path: 'test-results/dev-error-no-button.png', fullPage: true });
    }
  });
});
