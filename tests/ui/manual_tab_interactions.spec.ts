import { test } from '@playwright/test'
import { testTabs } from './helpers/tab_interactions'

test('Full manual tab interaction test', async ({ page }) => {
  await testTabs(page)
})
