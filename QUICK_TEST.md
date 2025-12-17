# Quick Test Guide

## ✅ Manual Testing Checklist

Run the dev server:
```bash
npm run tauri:dev
```

### Test Each Feature:

1. **Initial Tab** ✅
   - App should launch with one terminal tab
   - Tab should be visible in tab bar

2. **Create Terminal Tab** ✅
   - Click `+` button
   - New terminal tab should appear
   - Should automatically switch to new tab

3. **Create AI Tab** ✅
   - Click `🤖` button
   - New AI tab should appear
   - Should automatically switch to AI tab

4. **Switch Tabs** ✅
   - Click on any tab
   - Content area should change
   - Active tab should have visual indicator

5. **Rename Tab** ✅
   - Double-click on tab name
   - Prompt should appear
   - Enter new name
   - Tab name should update

6. **Reorder Tabs** ✅
   - Look for ← → buttons on tabs
   - Click → to move tab right
   - Click ← to move tab left
   - Tab order should change

7. **Close Tab** ✅
   - Click ✕ button on a tab (not the last one)
   - Tab should disappear
   - Should auto-switch to another tab
   - App should NOT freeze

8. **Multiple Tabs** ✅
   - Create 5+ tabs
   - Switch between them
   - All should work smoothly
   - No freezing or lag

### Expected Results:

- ✅ All operations smooth and instant
- ✅ No freezing or delays
- ✅ Tabs maintain state when switching
- ✅ Terminal content persists
- ✅ AI messages persist
- ✅ Only ONE #app element (check DevTools)

### If Something Fails:

1. Open browser DevTools (Cmd+Option+I)
2. Check Console for errors
3. Check Elements tab - should see ONE #app div
4. Report issue with:
   - What action was taken
   - What happened
   - Console errors
   - Screenshot if possible

## 🧪 Automated Testing

Run Playwright tests:
```bash
# All tests
npx playwright test tests/ui/warp_tabs_fixed.spec.ts

# With visible browser
npx playwright test tests/ui/manual_tab_interactions.spec.ts --headed

# Single test
npx playwright test -g "Create new terminal tab"
```

Expected: All 11 tests pass ✅

## 🎯 Quick Status Check

```bash
# Check files modified
git status

# See changes
git diff src/composables/useTabs.ts
git diff src/App.vue
git diff src/components/TabManager.vue
```

## 📊 Success Indicators

All of these should be TRUE:
- [ ] Tabs create instantly
- [ ] Tabs switch without delay
- [ ] Tabs close without freezing app
- [ ] Tabs can be renamed
- [ ] Tabs can be reordered
- [ ] Console has no errors
- [ ] Only 1 #app element in DOM
- [ ] All Playwright tests pass
