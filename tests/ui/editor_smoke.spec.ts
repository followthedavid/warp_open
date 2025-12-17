import { test, expect } from '@playwright/test'

test.describe('Cursor_Open editor-first shell', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
  })

  test('creates an editor tab and shows tab entry', async ({ page }) => {
    await page.click('[data-testid="new-file-button"]')
    await expect(page.locator('[data-testid="tab-item"]').first()).toBeVisible()
  })

  test('AI panel accepts input', async ({ page }) => {
    await page.click('[data-testid="new-ai-button"]')
    await page.fill('.ai-panel input[type="text"], .ai-panel textarea', 'hello from test')
    await page.keyboard.press('Enter')
    await page.waitForTimeout(500)
    await expect(page.locator('.ai-panel .message-wrapper').first()).toBeVisible()
  })
})

