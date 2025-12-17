import { test, expect } from '@playwright/test';

/**
 * Enhanced Debugging Test for Agent Console
 * This test captures detailed information to help Claude debug the UI integration
 */

test.describe('Agent Console Debug', () => {
  test('COMPREHENSIVE DEBUG: Agent Console Integration', async ({ page }) => {
    console.log('\n🔍 Starting comprehensive Agent Console debug test...\n');

    // Capture all console messages
    const consoleMessages: string[] = [];
    const consoleErrors: string[] = [];

    page.on('console', msg => {
      const text = `[${msg.type()}] ${msg.text()}`;
      consoleMessages.push(text);
      if (msg.type() === 'error') {
        consoleErrors.push(text);
        console.log('❌ BROWSER ERROR:', text);
      } else {
        console.log('📝 Console:', text);
      }
    });

    // Capture page errors
    page.on('pageerror', error => {
      const errorText = `PAGE ERROR: ${error.message}`;
      consoleErrors.push(errorText);
      console.log('❌', errorText);
    });

    // Navigate to app
    console.log('Step 1: Loading application...');
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: 'test-results/debug-01-app-loaded.png', fullPage: true });
    console.log('✅ App loaded\n');

    // Check for initial errors
    if (consoleErrors.length > 0) {
      console.log('⚠️  Errors on initial load:', consoleErrors);
    }

    // Step 2: Open Developer Dashboard
    console.log('Step 2: Opening Developer Dashboard...');
    const devButton = page.locator('[data-testid="new-developer-button"]').or(
      page.getByText('Developer')
    ).first();

    const devButtonVisible = await devButton.isVisible();
    console.log(`Developer button visible: ${devButtonVisible}`);

    if (!devButtonVisible) {
      console.log('❌ Developer button not found!');
      await page.screenshot({ path: 'test-results/debug-error-no-dev-button.png', fullPage: true });
      return;
    }

    await devButton.click();
    await page.waitForTimeout(2000); // Give Vue time to render
    await page.screenshot({ path: 'test-results/debug-02-dashboard-opened.png', fullPage: true });
    console.log('✅ Dashboard opened\n');

    // Step 3: Inspect Agent button
    console.log('Step 3: Inspecting Agent button...');
    const agentButton = page.locator('button').filter({ hasText: /Agent/i }).or(
      page.locator('.btn-agent')
    ).first();

    const agentButtonVisible = await agentButton.isVisible();
    console.log(`Agent button visible: ${agentButtonVisible}`);

    if (!agentButtonVisible) {
      console.log('❌ Agent button not found!');
      await page.screenshot({ path: 'test-results/debug-error-no-agent-button.png', fullPage: true });

      // List all buttons
      const allButtons = await page.locator('button').all();
      console.log(`Total buttons on page: ${allButtons.length}`);
      for (let i = 0; i < Math.min(allButtons.length, 10); i++) {
        const text = await allButtons[i].textContent();
        console.log(`  Button ${i}: "${text}"`);
      }
      return;
    }

    // Get button properties
    const agentButtonText = await agentButton.textContent();
    const agentButtonClass = await agentButton.getAttribute('class');
    console.log(`Agent button text: "${agentButtonText}"`);
    console.log(`Agent button class: "${agentButtonClass}"`);

    await page.screenshot({ path: 'test-results/debug-03-before-click.png', fullPage: true });

    // Step 4: Click Agent button and inspect state
    console.log('\nStep 4: Clicking Agent button...');
    await agentButton.click();
    await page.waitForTimeout(1500); // Give Vue time to render
    await page.screenshot({ path: 'test-results/debug-04-after-click.png', fullPage: true });
    console.log('✅ Agent button clicked\n');

    // Check for errors after click
    if (consoleErrors.length > 0) {
      console.log('⚠️  Errors after clicking Agent button:');
      consoleErrors.forEach(err => console.log(`  - ${err}`));
    }

    // Step 5: Inspect DOM for Agent Console
    console.log('Step 5: Inspecting DOM for Agent Console...');

    // Check if .agent-console exists in DOM
    const agentConsoleInDOM = await page.locator('.agent-console').count();
    console.log(`Elements with .agent-console class: ${agentConsoleInDOM}`);

    if (agentConsoleInDOM > 0) {
      console.log('✅ Agent Console element found in DOM!');

      // Check visibility and positioning
      const isVisible = await page.locator('.agent-console').isVisible();
      const boundingBox = await page.locator('.agent-console').boundingBox();
      const computedStyle = await page.locator('.agent-console').evaluate(el => {
        const styles = window.getComputedStyle(el);
        return {
          display: styles.display,
          visibility: styles.visibility,
          opacity: styles.opacity,
          position: styles.position,
          zIndex: styles.zIndex,
          top: styles.top,
          right: styles.right,
          width: styles.width,
          height: styles.height,
        };
      });

      console.log(`  - Visible (Playwright): ${isVisible}`);
      console.log(`  - Bounding box:`, boundingBox);
      console.log(`  - Computed styles:`, computedStyle);

      // Get innerHTML to see what's inside
      const innerHTML = await page.locator('.agent-console').innerHTML();
      console.log(`  - Inner HTML length: ${innerHTML.length} characters`);
      console.log(`  - Inner HTML preview: ${innerHTML.substring(0, 200)}...`);

    } else {
      console.log('❌ Agent Console element NOT found in DOM!');

      // Check if AgentConsole component is registered
      const pageContent = await page.content();
      const hasAgentConsoleTag = pageContent.includes('agent-console');
      console.log(`  - Page HTML contains 'agent-console': ${hasAgentConsoleTag}`);

      // List all elements with classes containing 'agent'
      const agentElements = await page.locator('[class*="agent"]').all();
      console.log(`  - Elements with 'agent' in class: ${agentElements.length}`);
      for (let i = 0; i < Math.min(agentElements.length, 5); i++) {
        const className = await agentElements[i].getAttribute('class');
        console.log(`    ${i}: ${className}`);
      }
    }

    // Step 6: Check for specific Agent Console elements
    console.log('\nStep 6: Checking for Agent Console UI elements...');
    const elements = {
      header: await page.locator('text=Agent Console').count(),
      status: await page.locator('.status').count(),
      queue: await page.locator('text=Pending Queue').count(),
      logs: await page.locator('text=Recent Logs').count(),
    };

    console.log('Agent Console UI elements:');
    console.log(`  - Header ("Agent Console"): ${elements.header}`);
    console.log(`  - Status indicator: ${elements.status}`);
    console.log(`  - Queue section: ${elements.queue}`);
    console.log(`  - Logs section: ${elements.logs}`);

    await page.screenshot({ path: 'test-results/debug-05-dom-inspection.png', fullPage: true });

    // Step 7: Evaluate Vue app state (if accessible)
    console.log('\nStep 7: Checking Vue app state...');
    const vueAppExists = await page.evaluate(() => {
      return typeof (window as any).__VUE__ !== 'undefined' ||
             typeof (window as any).__vue__ !== 'undefined' ||
             document.querySelector('#app')?.__vueParentComponent !== undefined;
    });
    console.log(`Vue app detected: ${vueAppExists}`);

    // Step 8: Check network requests
    console.log('\nStep 8: Checking network activity...');
    const networkLogs: string[] = [];
    page.on('response', response => {
      if (response.url().includes('localhost')) {
        networkLogs.push(`${response.status()} ${response.url()}`);
      }
    });

    // Make a test request to agent server
    await page.evaluate(async () => {
      try {
        const response = await fetch('http://localhost:4005/health');
        const data = await response.json();
        console.log('Agent server health check:', data);
      } catch (error) {
        console.error('Failed to reach agent server:', error);
      }
    });

    await page.waitForTimeout(1000);
    console.log('Network requests:', networkLogs.length > 0 ? networkLogs : 'None captured');

    // Step 9: Try clicking Agent button again to toggle
    console.log('\nStep 9: Toggling Agent button again...');
    await agentButton.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: 'test-results/debug-06-after-toggle.png', fullPage: true });

    const agentConsoleAfterToggle = await page.locator('.agent-console').count();
    console.log(`Agent Console in DOM after toggle: ${agentConsoleAfterToggle}`);

    // Final summary
    console.log('\n📊 DEBUG SUMMARY:');
    console.log('================');
    console.log(`Total console messages: ${consoleMessages.length}`);
    console.log(`Total console errors: ${consoleErrors.length}`);
    console.log(`Agent button found: ${agentButtonVisible}`);
    console.log(`Agent Console in DOM: ${agentConsoleInDOM > 0}`);
    console.log(`Vue app detected: ${vueAppExists}`);

    if (consoleErrors.length > 0) {
      console.log('\n❌ ERRORS FOUND:');
      consoleErrors.forEach((err, i) => console.log(`${i + 1}. ${err}`));
    } else {
      console.log('\n✅ No console errors detected');
    }

    await page.screenshot({ path: 'test-results/debug-07-final.png', fullPage: true });
    console.log('\n📸 All debug screenshots saved to test-results/\n');

    // This test always passes - it's for debugging only
    expect(true).toBe(true);
  });
});
