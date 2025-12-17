# Phase 3 Quick Reference

## Test Commands

### Run All Tests
```bash
cd src-tauri && cargo test
```

### Phase-Specific Tests
```bash
# Phase 1-3 Integration (5 tests)
cargo test --test phase1_3_integration

# Phase 3 In-Process (2 tests)
cargo test --test phase3_inproc_runner -- --nocapture

# Test Runner Unit Tests (2 tests)
cargo test --lib test_runner
```

### Single Test with Verbose Output
```bash
cargo test --test phase3_inproc_runner test_phase3_inproc_runner -- --nocapture
```

## Expected Results
- **Total**: 28 tests across all modules
- **Phase 1-3**: 7 tests (5 + 2)
- **Status**: ✅ All passing

## Key Files

### Implementation
- `src/conversation.rs` - State management, autonomy settings
- `src/commands.rs` - Tauri command handlers
- `src/test_runner.rs` - Synchronous test executor
- `src/lib.rs` - Library interface for tests

### Tests
- `tests/phase1_3_integration.rs` - Phase 1-3 integration tests
- `tests/phase3_inproc_runner.rs` - Phase 3 in-process execution tests

### Documentation
- `PHASE3_COMPLETE.md` - Completion summary with bug fix details
- `docs/PHASE3_VERIFIED.md` - Detailed verification documentation
- `docs/PHASE1_3_DOCUMENTATION.md` - Complete Phase 1-3 documentation

### CI
- `.github/workflows/phase3-tests.yml` - Automated testing workflow

## Bug Fix Applied

**Issue**: Mutex deadlock in `update_autonomy_settings()`

**Fix**: Extract values before locking to prevent multiple lock acquisitions in print macros

**Location**: `src/conversation.rs:288-295`

## Common Issues

### Test Hangs
- Check for multiple lock acquisitions in same method
- Ensure no nested locks without releasing previous lock
- Use `-- --nocapture` flag to see where test hangs

### Compilation Errors
- Ensure `[lib]` section exists in `Cargo.toml`
- Verify all modules are exposed in `src/lib.rs`
- Check that test files import correct modules

### CI Failures
- Verify working directory is `src-tauri`
- Check `RUST_BACKTRACE=1` is set for detailed errors
- Ensure all dependencies are in `Cargo.toml`

## Next Steps

Phase 3 complete. Ready for Phase 4 (Learning System):
- Phase 4A: Telemetry & Safe Observability
- Phase 4B: Offline Policy Trainer  
- Phase 4C: Safe Policy Deployment
