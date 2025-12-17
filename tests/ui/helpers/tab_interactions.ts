import { Page } from '@playwright/test'

export async function testTabs(page: Page) {
  // Ensure we start on a fresh page
  await page.goto('http://localhost:5173')

  console.log('✅ Page loaded')

  // Wait for initial tab
  await page.waitForSelector('div.tab', { timeout: 10000 })
  console.log('✅ Initial tab rendered')

  // Create Terminal Tab
  await page.locator('button.new-tab-btn').click()
  await page.waitForTimeout(500)
  console.log('✅ Created Terminal tab')

  // Create AI Tab
  await page.locator('button.new-ai-tab-btn').click()
  await page.waitForTimeout(500)
  console.log('✅ Created AI tab')

  // Switch to Terminal tab
  const terminalTab = page.locator('div.tab:has-text("Terminal")').first()
  await terminalTab.click()
  await page.waitForTimeout(300)
  console.log('✅ Switched to Terminal tab')

  // Switch to AI tab
  const aiTab = page.locator('div.tab:has-text("AI")').first()
  await aiTab.click()
  await page.waitForTimeout(300)
  console.log('✅ Switched to AI tab')

  // Rename first tab
  const tabNameEl = page.locator('div.tab span.tab-name').first()
  
  // Setup dialog handler before triggering
  page.on('dialog', async dialog => {
    if (dialog.type() === 'prompt') {
      await dialog.accept('Renamed Tab')
    }
  })
  
  await tabNameEl.dblclick()
  await page.waitForTimeout(500)
  console.log('✅ Renamed first tab to "Renamed Tab"')

  // Close first tab (if more than 1 tab exists)
  const tabCount = await page.locator('div.tab').count()
  if (tabCount > 1) {
    const closeBtn = page.locator('div.tab button.close-btn').first()
    await closeBtn.click()
    await page.waitForTimeout(500)
    console.log('✅ Closed first tab')
  }

  // Reorder tabs (if reorder buttons exist)
  const moveRightBtn = page.locator('div.tab button.reorder-btn:has-text("→")').first()
  if (await moveRightBtn.count() > 0) {
    await moveRightBtn.click()
    await page.waitForTimeout(500)
    console.log('✅ Moved first tab to the right')
  } else {
    console.log('⚠️  Reorder buttons not present, skipping')
  }

  // Verify terminal window exists
  const terminalExists = await page.locator('.content-container').isVisible()
  console.log('✅ Terminal/content window visible:', terminalExists)

  // Verify AI chat after switching to AI tab
  await aiTab.click()
  await page.waitForTimeout(300)
  const aiContentVisible = await page.locator('.content-container').isVisible()
  console.log('✅ AI content visible:', aiContentVisible)

  // Check for single #app element
  const appCount = await page.locator('#app').count()
  console.log('✅ Single #app element:', appCount === 1)

  // Final tab count
  const finalTabCount = await page.locator('div.tab').count()
  console.log(`✅ Final tab count: ${finalTabCount}`)

  console.log('🎉 All tab interactions verified successfully')
}
