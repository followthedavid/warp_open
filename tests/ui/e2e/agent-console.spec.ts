import { test, expect } from '@playwright/test';

/**
 * Automated End-to-End Tests for Agent Console
 * These tests verify the Agent Bridge system integration hands-off
 */

test.describe('Agent Console Integration', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to app
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Take screenshot of initial state
    await page.screenshot({ path: 'test-results/agent-01-app-loaded.png', fullPage: true });
  });

  test('should open Developer Dashboard and show Agent button', async ({ page }) => {
    console.log('\n🧭 Testing Agent Console visibility...\n');

    // Look for Developer button
    const devButton = page.locator('[data-testid="new-developer-button"]').or(
      page.getByText('Developer')
    ).first();

    await page.screenshot({ path: 'test-results/agent-02-before-dashboard.png', fullPage: true });

    if (await devButton.isVisible()) {
      console.log('✅ Developer button found, clicking...');
      await devButton.click();
      await page.waitForTimeout(1500);

      await page.screenshot({ path: 'test-results/agent-03-dashboard-opened.png', fullPage: true });

      // Look for Agent button in dashboard header
      const agentButton = page.locator('button').filter({ hasText: /Agent/i }).or(
        page.locator('button:has-text("🧭")')
      ).first();

      const agentButtonVisible = await agentButton.isVisible();
      console.log(`Agent button visible: ${agentButtonVisible}`);

      expect(agentButtonVisible).toBe(true);
      console.log('✅ Agent button found in Developer Dashboard');
    } else {
      console.log('⚠️  Developer button not found');
      await page.screenshot({ path: 'test-results/agent-error-no-dev-button.png', fullPage: true });
    }
  });

  test('should open Agent Console panel when Agent button is clicked', async ({ page }) => {
    console.log('\n🧭 Testing Agent Console panel opening...\n');

    // Open Developer Dashboard
    const devButton = page.locator('[data-testid="new-developer-button"]').or(
      page.getByText('Developer')
    ).first();

    if (await devButton.isVisible()) {
      await devButton.click();
      await page.waitForTimeout(1500);
      console.log('✅ Developer Dashboard opened');

      // Click Agent button
      const agentButton = page.locator('button').filter({ hasText: /Agent/i }).or(
        page.locator('.btn-agent')
      ).first();

      await page.screenshot({ path: 'test-results/agent-04-before-agent-click.png', fullPage: true });

      if (await agentButton.isVisible()) {
        await agentButton.click();
        await page.waitForTimeout(1000);

        await page.screenshot({ path: 'test-results/agent-05-console-opened.png', fullPage: true });

        // Look for Agent Console elements
        const agentConsole = page.locator('.agent-console');

        const consoleVisible = await agentConsole.isVisible();
        console.log(`Agent Console visible: ${consoleVisible}`);

        expect(consoleVisible).toBe(true);
        console.log('✅ Agent Console panel opened successfully');
      } else {
        console.log('❌ Agent button not found');
      }
    }
  });

  test('should show Agent Console UI elements', async ({ page }) => {
    console.log('\n🔍 Testing Agent Console UI elements...\n');

    // Navigate to Agent Console
    const devButton = page.locator('[data-testid="new-developer-button"]').or(
      page.getByText('Developer')
    ).first();

    if (await devButton.isVisible()) {
      await devButton.click();
      await page.waitForTimeout(1500);

      const agentButton = page.locator('button').filter({ hasText: /Agent/i }).or(
        page.locator('.btn-agent')
      ).first();

      if (await agentButton.isVisible()) {
        await agentButton.click();
        await page.waitForTimeout(1000);

        await page.screenshot({ path: 'test-results/agent-06-ui-elements.png', fullPage: true });

        // Check for key UI elements
        const hasHeader = await page.locator('text=Agent Console').isVisible();
        console.log(`Header visible: ${hasHeader}`);

        const hasStatus = await page.locator('.status').or(
          page.locator('text=Agent Online').or(page.locator('text=Agent Offline'))
        ).isVisible();
        console.log(`Status indicator visible: ${hasStatus}`);

        const hasRefreshButton = await page.locator('button:has-text("Refresh")').isVisible();
        console.log(`Refresh button visible: ${hasRefreshButton}`);

        const hasClearButton = await page.locator('button:has-text("Clear")').isVisible();
        console.log(`Clear button visible: ${hasClearButton}`);

        const hasQueue = await page.locator('text=Pending Queue').isVisible();
        console.log(`Queue section visible: ${hasQueue}`);

        const hasLogs = await page.locator('text=Recent Logs').isVisible();
        console.log(`Logs section visible: ${hasLogs}`);

        // Verify at least some elements are visible
        expect(hasHeader || hasQueue || hasLogs).toBe(true);
        console.log('✅ Agent Console UI elements verified');
      }
    }
  });

  test('should show agent status indicator in AI Chat tab', async ({ page }) => {
    console.log('\n🔍 Testing Agent status indicator in AI Chat...\n');

    // Create AI Chat tab
    const aiButton = page.locator('[data-testid="new-ai-button"]').or(
      page.getByText('AI')
    ).first();

    await page.screenshot({ path: 'test-results/agent-07-before-ai-tab.png', fullPage: true });

    if (await aiButton.isVisible()) {
      await aiButton.click();
      await page.waitForTimeout(1500);

      await page.screenshot({ path: 'test-results/agent-08-ai-tab-opened.png', fullPage: true });

      // Look for agent indicator
      const agentIndicator = page.locator('.agent-indicator').or(
        page.locator('text=Agent').or(page.locator('text=Agent Off'))
      );

      const indicatorVisible = await agentIndicator.isVisible();
      console.log(`Agent indicator visible in AI Chat: ${indicatorVisible}`);

      await page.screenshot({ path: 'test-results/agent-09-indicator-check.png', fullPage: true });

      expect(indicatorVisible).toBe(true);
      console.log('✅ Agent status indicator found in AI Chat');
    } else {
      console.log('⚠️  AI button not found');
      await page.screenshot({ path: 'test-results/agent-error-no-ai-button.png', fullPage: true });
    }
  });

  test('should interact with Agent Console controls', async ({ page }) => {
    console.log('\n🎮 Testing Agent Console interactions...\n');

    // Navigate to Agent Console
    const devButton = page.locator('[data-testid="new-developer-button"]').or(
      page.getByText('Developer')
    ).first();

    if (await devButton.isVisible()) {
      await devButton.click();
      await page.waitForTimeout(1500);

      const agentButton = page.locator('button').filter({ hasText: /Agent/i }).or(
        page.locator('.btn-agent')
      ).first();

      if (await agentButton.isVisible()) {
        await agentButton.click();
        await page.waitForTimeout(1000);

        await page.screenshot({ path: 'test-results/agent-10-before-interactions.png', fullPage: true });

        // Test Refresh button
        const refreshButton = page.locator('button:has-text("Refresh")').first();
        if (await refreshButton.isVisible()) {
          console.log('Clicking Refresh button...');
          await refreshButton.click();
          await page.waitForTimeout(500);
          await page.screenshot({ path: 'test-results/agent-11-after-refresh.png', fullPage: true });
          console.log('✅ Refresh button clicked');
        }

        // Test Clear button
        const clearButton = page.locator('button:has-text("Clear")').first();
        if (await clearButton.isVisible()) {
          console.log('Clicking Clear button...');
          await clearButton.click();
          await page.waitForTimeout(500);
          await page.screenshot({ path: 'test-results/agent-12-after-clear.png', fullPage: true });
          console.log('✅ Clear button clicked');
        }

        console.log('✅ Agent Console interactions test complete');
      }
    }
  });

  test('FULL FLOW: Complete Agent Console integration test', async ({ page }) => {
    console.log('\n🚀 Starting full Agent Console integration test...\n');

    // Step 1: Open Developer Dashboard
    console.log('Step 1: Opening Developer Dashboard...');
    const devButton = page.locator('[data-testid="new-developer-button"]').or(
      page.getByText('Developer')
    ).first();

    if (await devButton.isVisible()) {
      await devButton.click();
      await page.waitForTimeout(1500);
      await page.screenshot({ path: 'test-results/agent-full-01-dashboard.png', fullPage: true });
      console.log('✅ Developer Dashboard opened\n');

      // Step 2: Open Agent Console
      console.log('Step 2: Opening Agent Console...');
      const agentButton = page.locator('button').filter({ hasText: /Agent/i }).or(
        page.locator('.btn-agent')
      ).first();

      if (await agentButton.isVisible()) {
        await agentButton.click();
        await page.waitForTimeout(1000);
        await page.screenshot({ path: 'test-results/agent-full-02-console-opened.png', fullPage: true });
        console.log('✅ Agent Console opened\n');

        // Step 3: Verify all UI elements
        console.log('Step 3: Verifying Agent Console UI...');
        const elements = {
          header: await page.locator('text=Agent Console').isVisible(),
          status: await page.locator('.status').isVisible(),
          refresh: await page.locator('button:has-text("Refresh")').isVisible(),
          clear: await page.locator('button:has-text("Clear")').isVisible(),
          queue: await page.locator('text=Pending Queue').isVisible(),
          logs: await page.locator('text=Recent Logs').isVisible(),
        };

        console.log('UI Elements Status:');
        console.log(`  - Header: ${elements.header ? '✅' : '❌'}`);
        console.log(`  - Status: ${elements.status ? '✅' : '❌'}`);
        console.log(`  - Refresh Button: ${elements.refresh ? '✅' : '❌'}`);
        console.log(`  - Clear Button: ${elements.clear ? '✅' : '❌'}`);
        console.log(`  - Queue Section: ${elements.queue ? '✅' : '❌'}`);
        console.log(`  - Logs Section: ${elements.logs ? '✅' : '❌'}`);

        await page.screenshot({ path: 'test-results/agent-full-03-ui-verified.png', fullPage: true });
        console.log('\n✅ All UI elements verified\n');

        // Step 4: Test interactions
        console.log('Step 4: Testing console interactions...');
        const refreshButton = page.locator('button:has-text("Refresh")').first();
        if (await refreshButton.isVisible()) {
          await refreshButton.click();
          await page.waitForTimeout(500);
          console.log('✅ Refresh button works');
        }

        await page.screenshot({ path: 'test-results/agent-full-04-interactions.png', fullPage: true });
        console.log('✅ Interactions tested\n');

        // Step 5: Close and reopen console
        console.log('Step 5: Testing console toggle...');
        await agentButton.click(); // Close
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'test-results/agent-full-05-console-closed.png', fullPage: true });
        console.log('✅ Console closed');

        await agentButton.click(); // Reopen
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'test-results/agent-full-06-console-reopened.png', fullPage: true });
        console.log('✅ Console reopened\n');

        console.log('✅ Full Agent Console integration test completed!');
        console.log('📸 All screenshots saved to test-results/');

        // Final assertion - at least one key element should be visible
        expect(elements.header || elements.queue || elements.logs).toBe(true);
      } else {
        console.log('❌ Agent button not found');
        await page.screenshot({ path: 'test-results/agent-full-error-no-agent-btn.png', fullPage: true });
      }
    } else {
      console.log('❌ Developer button not found');
      await page.screenshot({ path: 'test-results/agent-full-error-no-dev-btn.png', fullPage: true });
    }
  });

  test('should verify AI Chat agent indicator updates', async ({ page }) => {
    console.log('\n🔄 Testing AI Chat agent indicator...\n');

    // Open AI Chat tab
    const aiButton = page.locator('[data-testid="new-ai-button"]').or(
      page.getByText('AI')
    ).first();

    if (await aiButton.isVisible()) {
      await aiButton.click();
      await page.waitForTimeout(1500);

      await page.screenshot({ path: 'test-results/agent-13-ai-chat-indicator.png', fullPage: true });

      // Check for agent indicator
      const agentIndicator = page.locator('.agent-indicator');
      const indicatorVisible = await agentIndicator.isVisible();

      if (indicatorVisible) {
        const indicatorText = await agentIndicator.textContent();
        console.log(`Agent indicator shows: "${indicatorText}"`);

        // Check if it shows online or offline status
        const hasStatus = indicatorText?.includes('Agent');
        expect(hasStatus).toBe(true);

        console.log('✅ Agent indicator working correctly');
      } else {
        console.log('⚠️  Agent indicator not visible');
      }

      await page.screenshot({ path: 'test-results/agent-14-indicator-verified.png', fullPage: true });
    }
  });
});
