# Warp_Open Automated Test Harness

Complete testing infrastructure for Warp_Open terminal application.

---

## 🎯 Overview

This test harness provides **fully automated testing** for all Warp_Open functionality:

- ✅ **Rust Backend Tests** - PTY operations, AI tools, database operations
- ✅ **Playwright UI Tests** - Terminal tabs, AI chat, command blocks, tab management
- ✅ **Integration Tests** - End-to-end workflows
- ✅ **Continuous Testing** - Watch mode for development
- ✅ **Smoke Tests** - Quick feedback during development

---

## 📁 Test Structure

```
warp_tauri/
├── src-tauri/
│   └── tests/
│       ├── pty_integration.rs      # PTY backend tests
│       └── ai_tools_integration.rs # AI tool execution tests
├── tests/
│   └── ui/
│       └── warp_tabs.spec.ts       # Playwright UI tests
├── scripts/
│   ├── run_full_tests.sh           # Master test runner
│   ├── run_smoke_tests.sh          # Quick tests
│   └── run_watch_tests.sh          # Continuous testing
└── playwright.config.ts             # Playwright configuration
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd /Users/davidquinton/ReverseLab/Warp_Open/warp_tauri

# Install Playwright
npm install -D @playwright/test

# Install Playwright browsers
npx playwright install chromium
```

### 2. Run All Tests

```bash
./scripts/run_full_tests.sh
```

This runs:
1. All Rust backend tests
2. Starts dev server
3. All Playwright UI tests
4. Generates comprehensive report

**Output**: Logs in `/tmp/warp_*_tests.log`

---

## 🧪 Test Commands

### Full Test Suite (recommended before commits)

```bash
./scripts/run_full_tests.sh
```

**Duration**: ~2-3 minutes  
**Runs**: All Rust + All UI tests  
**Use when**: Before committing changes, after bug fixes

---

### Smoke Tests (fast feedback)

```bash
./scripts/run_smoke_tests.sh
```

**Duration**: ~30 seconds  
**Runs**: Library tests + compile check  
**Use when**: During active development, quick validation

---

### Watch Mode (continuous testing)

```bash
./scripts/run_watch_tests.sh
```

**Runs**: Smoke tests automatically on file changes  
**Use when**: Writing new features, refactoring  
**Exit**: Press `Ctrl+C`

---

### Individual Test Suites

**Rust tests only**:
```bash
cd src-tauri
cargo test
```

**Playwright tests only** (requires dev server running):
```bash
npx playwright test
```

**Specific test file**:
```bash
npx playwright test tests/ui/warp_tabs.spec.ts
```

---

## 📊 Test Coverage

### Rust Backend Tests (`src-tauri/tests/`)

**PTY Integration** (`pty_integration.rs`):
- ✅ PTY spawning
- ✅ Command execution
- ✅ Exit code handling
- ✅ Multiple concurrent PTY sessions

**AI Tools** (`ai_tools_integration.rs`):
- ✅ Tool execution
- ✅ Duplicate prevention
- ✅ Result filtering from UI
- ✅ Error handling

---

### Playwright UI Tests (`tests/ui/warp_tabs.spec.ts`)

**Terminal and AI Integration**:
- ✅ App launches with initial terminal tab
- ✅ Create new terminal tab with + button
- ✅ Switch between terminal and AI tabs
- ✅ AI chat input box visible in AI tabs
- ✅ Close tab with X button
- ✅ Terminal renders xterm output
- ✅ Command blocks appear when present

**AI Chat Functionality**:
- ✅ Send message to AI
- ✅ AI thinking indicator appears/disappears
- ✅ Messages display correctly

**Performance and Stability**:
- ✅ App doesn't freeze when closing tabs
- ✅ Multiple tabs don't cause memory leaks

**Total**: 13 automated UI tests

---

## 🐛 Testing Specific Features

### Test Terminal Tabs

```bash
npx playwright test -g "terminal tab"
```

### Test AI Chat

```bash
npx playwright test -g "AI Chat"
```

### Test Performance

```bash
npx playwright test -g "Performance"
```

---

## 🔍 Debugging Failed Tests

### View Test Logs

```bash
# Rust tests
cat /tmp/warp_rust_tests.log

# UI tests
cat /tmp/warp_ui_tests.log

# Dev server (if tests fail to start)
cat /tmp/warp_test_server.log
```

### Run Tests with Debug Output

**Playwright debug mode**:
```bash
PWDEBUG=1 npx playwright test tests/ui/warp_tabs.spec.ts
```

**Rust verbose output**:
```bash
cd src-tauri
cargo test -- --nocapture
```

### View Playwright HTML Report

```bash
npx playwright show-report
```

Shows:
- Screenshots of failures
- Trace viewer for failed tests
- Detailed step-by-step execution

---

## ⚡ Test Performance

| Test Suite | Duration | Tests | Purpose |
|------------|----------|-------|---------|
| **Smoke Tests** | ~30s | 10 | Fast validation |
| **Rust Backend** | ~20s | 8 | Backend logic |
| **Playwright UI** | ~2min | 13 | Frontend + integration |
| **Full Suite** | ~3min | 21 | Complete validation |

---

## 🔧 Extending Tests

### Adding New Rust Test

Create `src-tauri/tests/my_feature.rs`:

```rust
#[test]
fn test_my_feature() {
    // Test implementation
    assert!(true);
}
```

### Adding New UI Test

Edit `tests/ui/warp_tabs.spec.ts`:

```typescript
test('My new feature works', async ({ page }) => {
  await page.goto('http://localhost:5173');
  // Test implementation
  expect(true).toBe(true);
});
```

---

## 🎨 Test Output Example

```
════════════════════════════════════════════════════════
  Warp_Open Full Test Suite
════════════════════════════════════════════════════════

[1/3] Running Rust backend tests...
────────────────────────────────────────────────────────
running 8 tests
test test_pty_spawns_successfully ... ok
test test_pty_executes_simple_command ... ok
test test_ai_tool_execution ... ok
test test_no_duplicate_tool_execution ... ok
✓ Rust tests passed

[2/3] Starting Warp_Open dev server...
────────────────────────────────────────────────────────
Dev server PID: 12345
Waiting for server to start...
✓ Dev server ready

[3/3] Running Playwright UI tests...
────────────────────────────────────────────────────────
Running 13 tests using 1 worker

  13 passed (45.2s)
✓ UI tests passed

════════════════════════════════════════════════════════
  Test Results Summary
════════════════════════════════════════════════════════

✓ Rust Backend Tests: PASSED
✓ Playwright UI Tests: PASSED

Logs:
  - Rust tests: /tmp/warp_rust_tests.log
  - UI tests: /tmp/warp_ui_tests.log
  - Dev server: /tmp/warp_test_server.log

════════════════════════════════════════════════════════
  ALL TESTS PASSED ✓
════════════════════════════════════════════════════════
```

---

## 🚨 CI/CD Integration

### GitHub Actions (example)

```yaml
name: Warp_Open Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: npm install
      - name: Run tests
        run: ./scripts/run_full_tests.sh
```

---

## 📝 Test Maintenance

### When to Update Tests

**Update tests when**:
- ✅ Adding new features
- ✅ Fixing bugs (add regression test)
- ✅ Changing UI layout
- ✅ Modifying backend APIs

**Keep tests**:
- ✅ Fast (< 5 minutes total)
- ✅ Reliable (no flaky tests)
- ✅ Comprehensive (cover critical paths)
- ✅ Maintainable (clear, documented)

---

## 🔗 Related Documentation

- [Recovery Scan Report](./RECOVERY_SCAN_REPORT.md) - Current system state
- [Phase 3 Notebook](./docs/PHASE3_NOTEBOOK.md) - Autonomy features
- [Playwright Docs](https://playwright.dev/) - UI testing guide
- [Rust Testing](https://doc.rust-lang.org/book/ch11-00-testing.html) - Backend testing

---

## ✅ Success Criteria

**Test harness is working when**:
1. All tests pass on clean system
2. Tests catch real bugs (regression prevention)
3. Tests run in <5 minutes
4. <5% flaky test rate
5. Easy to add new tests
6. Clear failure messages

---

## 🎯 Next Steps

1. **Run first full test suite**: `./scripts/run_full_tests.sh`
2. **Fix any failing tests**
3. **Add tests for new features**
4. **Set up CI integration** (optional)
5. **Run tests before every commit**

---

## 📞 Support

**Test failures?** Check logs in `/tmp/warp_*_tests.log`  
**Playwright issues?** Run `npx playwright install`  
**Rust test issues?** Run `cargo clean && cargo test`

---

**End of Test Harness Documentation**

✅ **Status**: Test harness installed and ready  
🎯 **Next**: Run `./scripts/run_full_tests.sh` to validate
