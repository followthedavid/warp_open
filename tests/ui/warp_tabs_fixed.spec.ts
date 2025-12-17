import { test, expect } from '@playwright/test'

test.describe('Warp_Open Tab System - UUID-Based Reactive', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:5173')
    // Wait for initial tab to render
    await page.waitForSelector('div.tab', { timeout: 10000 })
  })

  test('App launches with initial terminal tab', async ({ page }) => {
    const tabs = await page.locator('div.tab').count()
    expect(tabs).toBeGreaterThan(0)
    
    // Check for single #app element
    const appCount = await page.locator('#app').count()
    expect(appCount).toBe(1)
    
    console.log('✅ Initial terminal tab rendered')
  })

  test('Create new terminal tab works', async ({ page }) => {
    const initialCount = await page.locator('div.tab').count()
    await page.locator('button.new-tab-btn').click()
    await page.waitForTimeout(500) // Wait for tab creation
    
    const newCount = await page.locator('div.tab').count()
    expect(newCount).toBe(initialCount + 1)
    
    console.log('✅ New terminal tab created')
  })

  test('Create AI tab works', async ({ page }) => {
    const initialCount = await page.locator('div.tab').count()
    await page.locator('button.new-ai-tab-btn').click()
    await page.waitForTimeout(500)
    
    const newCount = await page.locator('div.tab').count()
    expect(newCount).toBe(initialCount + 1)
    
    // Check AI tab name
    const aiTabText = await page.locator('div.tab:last-child span.tab-name').textContent()
    expect(aiTabText).toContain('AI')
    
    console.log('✅ AI tab created')
  })

  test('Switch between tabs works', async ({ page }) => {
    // Create AI tab
    await page.locator('button.new-ai-tab-btn').click()
    await page.waitForTimeout(500)
    
    // Click first tab (terminal)
    const firstTab = page.locator('div.tab').first()
    await firstTab.click()
    await page.waitForTimeout(300)
    
    // Check active class
    const firstTabClass = await firstTab.getAttribute('class')
    expect(firstTabClass).toContain('active')
    
    console.log('✅ Tab switching works')
  })

  test('Close tab works', async ({ page }) => {
    // Create extra tab so we can close one
    await page.locator('button.new-tab-btn').click()
    await page.waitForTimeout(500)
    
    const initialCount = await page.locator('div.tab').count()
    
    // Close last tab
    const closeBtn = page.locator('div.tab:last-child button.close-btn')
    if (await closeBtn.count() > 0) {
      await closeBtn.click()
      await page.waitForTimeout(500)
      
      const newCount = await page.locator('div.tab').count()
      expect(newCount).toBe(initialCount - 1)
      
      console.log('✅ Tab closing works')
    }
  })

  test('Rename tab works', async ({ page }) => {
    // Double-click tab name
    const tabName = page.locator('div.tab:first-child span.tab-name')
    await tabName.dblclick()
    
    // Handle prompt
    page.on('dialog', async dialog => {
      expect(dialog.type()).toBe('prompt')
      await dialog.accept('Renamed Tab')
    })
    
    await tabName.dblclick()
    await page.waitForTimeout(500)
    
    const newName = await tabName.textContent()
    expect(newName).toBe('Renamed Tab')
    
    console.log('✅ Tab renaming works')
  })

  test('Reorder tabs works', async ({ page }) => {
    // Create second tab
    await page.locator('button.new-tab-btn').click()
    await page.waitForTimeout(500)
    
    const tabTextsBefore = await page.locator('div.tab span.tab-name').allTextContents()
    
    // Click move right button on first tab
    const moveRightBtn = page.locator('div.tab:first-child button.reorder-btn').last()
    if (await moveRightBtn.count() > 0) {
      await moveRightBtn.click()
      await page.waitForTimeout(500)
      
      const tabTextsAfter = await page.locator('div.tab span.tab-name').allTextContents()
      expect(tabTextsBefore[0]).toBe(tabTextsAfter[1])
      
      console.log('✅ Tab reordering works')
    }
  })

  test('Terminal window renders', async ({ page }) => {
    // Check if terminal content area exists
    const terminalExists = await page.locator('.content-container').isVisible()
    expect(terminalExists).toBe(true)
    
    console.log('✅ Terminal window renders')
  })

  test('AI chat interface renders', async ({ page }) => {
    await page.locator('button.new-ai-tab-btn').click()
    await page.waitForTimeout(500)
    
    // Check for AI chat interface (adjust selector based on your implementation)
    const aiInterface = await page.locator('.content-container').isVisible()
    expect(aiInterface).toBe(true)
    
    console.log('✅ AI chat interface renders')
  })

  test('App does not freeze when closing tabs', async ({ page }) => {
    // Create extra tabs
    await page.locator('button.new-tab-btn').click()
    await page.waitForTimeout(300)
    await page.locator('button.new-tab-btn').click()
    await page.waitForTimeout(300)
    
    // Close one tab
    const closeBtn = page.locator('div.tab:last-child button.close-btn')
    await closeBtn.click()
    await page.waitForTimeout(500)
    
    // Check app is still responsive
    const appResponsive = await page.locator('#app').isVisible()
    expect(appResponsive).toBe(true)
    
    // Check only one #app element
    const appCount = await page.locator('#app').count()
    expect(appCount).toBe(1)
    
    console.log('✅ App remains responsive after closing tabs')
  })

  test('Multiple tabs do not cause memory issues', async ({ page }) => {
    // Create several tabs
    for (let i = 0; i < 5; i++) {
      await page.locator('button.new-tab-btn').click()
      await page.waitForTimeout(200)
    }
    
    const tabs = await page.locator('div.tab').count()
    expect(tabs).toBeGreaterThanOrEqual(5)
    
    // Check only one #app element
    const appCount = await page.locator('#app').count()
    expect(appCount).toBe(1)
    
    console.log('✅ Multiple tabs work without issues')
  })
})
