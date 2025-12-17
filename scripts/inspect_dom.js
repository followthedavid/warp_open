// Automated DOM Inspector for Warp_Open
// Captures actual CSS selectors and component structure

import { chromium } from '@playwright/test';

async function inspectDOM() {
  console.log('🔍 Starting DOM inspection...\n');
  
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  
  try {
    // Navigate to app
    console.log('📱 Loading app at http://localhost:5173...');
    await page.goto('http://localhost:5173');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000); // Give app time to initialize
    
    console.log('✅ App loaded\n');
    console.log('═'.repeat(60));
    console.log('DOM INSPECTION RESULTS');
    console.log('═'.repeat(60));
    console.log('');
    
    // Inspect main app container
    const appExists = await page.locator('#app').count();
    console.log(`📦 Main App Container (#app): ${appExists > 0 ? '✅ Found' : '❌ Not found'}`);
    
    // Inspect tabs
    console.log('\n🔖 TAB COMPONENTS:');
    const tabSelectors = [
      '.tab',
      '[role="tab"]',
      'button.tab',
      '.tab-item',
      '[data-tab-id]',
      '.unified-tab-bar button',
      '.unified-tab-bar > *'
    ];
    
    for (const selector of tabSelectors) {
      const count = await page.locator(selector).count();
      if (count > 0) {
        console.log(`  ✅ "${selector}" - Found ${count} element(s)`);
        
        // Get first element details
        const first = page.locator(selector).first();
        const classes = await first.evaluate(el => el.className).catch(() => 'N/A');
        const text = await first.textContent().catch(() => 'N/A');
        console.log(`     Classes: ${classes}`);
        console.log(`     Text: ${text?.trim()}`);
      }
    }
    
    // Inspect buttons
    console.log('\n🔘 BUTTON COMPONENTS:');
    const buttonSelectors = [
      'button:has-text("+")',
      '.new-ai-tab-btn',
      'button[title*="AI"]',
      'button:has-text("🤖")',
      '.unified-tab-bar button',
    ];
    
    for (const selector of buttonSelectors) {
      const count = await page.locator(selector).count();
      if (count > 0) {
        console.log(`  ✅ "${selector}" - Found ${count} element(s)`);
        const text = await page.locator(selector).first().textContent().catch(() => 'N/A');
        console.log(`     Text: ${text?.trim()}`);
      }
    }
    
    // Inspect terminal
    console.log('\n💻 TERMINAL COMPONENTS:');
    const terminalSelectors = [
      '.terminal-container',
      '.terminal-window',
      '.xterm',
      '[class*="terminal"]',
      '#app > div:nth-child(2)',
    ];
    
    for (const selector of terminalSelectors) {
      const count = await page.locator(selector).count();
      const visible = count > 0 ? await page.locator(selector).first().isVisible() : false;
      if (count > 0) {
        console.log(`  ${visible ? '✅' : '⚠️'} "${selector}" - Found ${count}, Visible: ${visible}`);
      }
    }
    
    // Inspect AI chat input
    console.log('\n✏️ AI CHAT INPUT:');
    const inputSelectors = [
      '.ai-input',
      'input[placeholder*="message"]',
      'textarea[placeholder*="message"]',
      'input[type="text"]',
      'textarea',
    ];
    
    for (const selector of inputSelectors) {
      const count = await page.locator(selector).count();
      const visible = count > 0 ? await page.locator(selector).first().isVisible() : false;
      if (count > 0) {
        console.log(`  ${visible ? '✅' : '⚠️'} "${selector}" - Found ${count}, Visible: ${visible}`);
        const placeholder = await page.locator(selector).first().getAttribute('placeholder').catch(() => 'N/A');
        console.log(`     Placeholder: ${placeholder}`);
      }
    }
    
    // Get full DOM structure snapshot
    console.log('\n📋 FULL DOM STRUCTURE:');
    const html = await page.evaluate(() => {
      const app = document.querySelector('#app');
      if (!app) return 'No #app found';
      
      function getStructure(el, depth = 0) {
        const indent = '  '.repeat(depth);
        const tag = el.tagName.toLowerCase();
        const classes = el.className ? `.${el.className.split(' ').join('.')}` : '';
        const id = el.id ? `#${el.id}` : '';
        const text = el.childNodes.length === 1 && el.childNodes[0].nodeType === 3 
          ? ` "${el.textContent.trim().substring(0, 30)}"` 
          : '';
        
        let result = `${indent}<${tag}${id}${classes}>${text}\n`;
        
        if (depth < 4) { // Limit depth
          Array.from(el.children).forEach(child => {
            result += getStructure(child, depth + 1);
          });
        }
        
        return result;
      }
      
      return getStructure(app);
    });
    
    console.log(html.substring(0, 2000)); // First 2000 chars
    
    console.log('\n' + '═'.repeat(60));
    console.log('✅ DOM INSPECTION COMPLETE');
    console.log('═'.repeat(60));
    
  } catch (error) {
    console.error('❌ Error during inspection:', error.message);
  } finally {
    await browser.close();
  }
}

// Run inspection
inspectDOM().catch(console.error);
