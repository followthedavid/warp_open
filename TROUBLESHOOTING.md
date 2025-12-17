# Troubleshooting Guide

## Error: "command ai_query_stream not found"

This error means the Rust backend wasn't compiled with the new streaming command.

### Solution: Clean Rebuild

```bash
cd ~/ReverseLab/Warp_Open/warp_tauri

# Stop any running instances
pkill -f tauri
pkill -f vite

# Clean Rust build cache
cd src-tauri && cargo clean && cd ..

# Clean frontend cache
rm -rf node_modules/.vite dist

# Rebuild and start
npm run tauri:dev
```

The first build after `cargo clean` takes 5-10 minutes. Subsequent builds are much faster.

### Quick Start (After First Build)

Use the included start script:

```bash
./start.sh
```

Or manually:

```bash
npm run tauri:dev
```

---

## Other Common Issues

### Ollama Connection Errors

**Symptom**: Messages show `[Ollama not available]`

**Solution**:
```bash
# Terminal 1
ollama serve

# Terminal 2
./start.sh
```

### Port 5173 Already in Use

**Symptom**: `Error: Port 5173 is already in use`

**Solution**:
```bash
lsof -ti:5173 | xargs kill -9
npm run tauri:dev
```

### Tab Names Show "[object PointerEvent]"

**Symptom**: Tab displays weird text instead of name

**Solution**: This should be fixed in the current code. If it persists:
```bash
rm -rf node_modules/.vite dist
npm run tauri:dev
```

### Messages Not Persisting

**Symptom**: Conversations disappear on restart

**Check**:
1. Browser console for localStorage errors
2. Available disk space
3. Try clearing and restarting:
   ```javascript
   // In browser console (Cmd+Option+I)
   localStorage.clear()
   location.reload()
   ```

### Streaming Lag or Timeout

**Symptom**: AI responses very slow or timeout

**Solutions**:
1. Check Ollama is not overloaded:
   ```bash
   ollama list
   # Make sure only one model is loaded
   ```

2. Use a smaller model:
   ```bash
   ollama pull qwen2.5:3b
   ```
   
   Then edit `src-tauri/src/commands.rs` line 154:
   ```rust
   "model": "qwen2.5:3b",  // Changed from llama3.2
   ```

3. Close other applications (8GB RAM limit)

### Build Errors

**Symptom**: Rust compilation fails

**Solution**:
```bash
# Update Rust toolchain
rustup update

# Check Cargo.toml dependencies
cd src-tauri
cargo check

# If still failing, check error message for missing dependencies
```

### Frontend TypeScript Errors

**Symptom**: Vue/TS compilation errors

**Solution**:
```bash
# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Check for syntax errors in .vue files
npm run dev
```

---

## Verification Steps

After fixing an issue, verify with these steps:

### 1. Backend Test
```bash
cd src-tauri
cargo build
# Should complete without errors
```

### 2. Frontend Test
```bash
npm run dev
# Vite should start on http://localhost:5173
# Open browser console - no errors
```

### 3. Integration Test
```bash
npm run tauri:dev
# Native window opens
# Type message → AI responds
# Type /shell pwd → shows directory
```

### 4. Full Feature Test
- [ ] Create new tab
- [ ] Rename tab
- [ ] Send AI message
- [ ] See streaming response
- [ ] Execute /shell command
- [ ] Drag-and-drop tabs
- [ ] Close and reopen app
- [ ] History restored

---

## Getting Help

### Check Logs

**Frontend logs**:
- Open DevTools: `Cmd+Option+I`
- Check Console tab

**Backend logs**:
- Terminal running `npm run tauri:dev`
- Look for `[ai_query_stream]` messages

**Ollama logs**:
- Terminal running `ollama serve`
- Shows model loading and API calls

### Debug Mode

Enable verbose logging:

**Frontend** (add to `src/main.ts`):
```typescript
window.__TAURI_DEBUG__ = true
```

**Backend** (in commands.rs):
```rust
eprintln!("[DEBUG] Variable: {:?}", variable);
```

### System Info

Check your environment:
```bash
# Node version
node --version  # Should be 16+

# Rust version
rustc --version  # Should be 1.70+

# Ollama version
ollama --version

# Available models
ollama list

# Disk space
df -h

# Memory usage
top -l 1 | grep PhysMem
```

---

## Reset to Clean State

If all else fails, complete reset:

```bash
cd ~/ReverseLab/Warp_Open/warp_tauri

# Kill all processes
pkill -f tauri
pkill -f vite
pkill -f ollama

# Clean everything
rm -rf node_modules package-lock.json
rm -rf src-tauri/target
rm -rf node_modules/.vite dist

# Reinstall
npm install

# Rebuild
npm run tauri:dev
```

This takes 10-15 minutes but ensures a completely fresh build.

---

## Known Limitations

1. **8GB RAM**: Running 8B+ models will cause swapping. Stick to 3B quantized models.

2. **First message slow**: Ollama loads model into memory on first use. Subsequent messages are faster.

3. **No GPU acceleration**: M2 Neural Engine not yet supported by Ollama. Uses CPU only.

4. **Streaming latency**: Depends on model size and CPU load. 3B models respond quickly.

5. **localStorage limit**: ~5-10MB limit. Long conversations may hit this. Export/clear old tabs if needed.

---

## Performance Optimization

### For 8GB M2 Mac Mini

1. **Use quantized models**:
   - ✅ `llama3.2:3b-instruct-q4_K_M` (recommended)
   - ✅ `qwen2.5:3b` (faster)
   - ⚠️ `llama3.1:8b` (will swap)
   - ❌ `llama3:70b` (not possible)

2. **Close unused apps** before AI sessions

3. **Monitor memory**:
   ```bash
   watch -n 1 'top -l 1 | grep PhysMem'
   ```

4. **Limit conversation length**: Export and clear old tabs

5. **One model at a time**: Don't run multiple Ollama instances

---

**Still having issues?**

Check the full setup guide: `AI_TERMINAL_SETUP.md`

Or review the quick start: `QUICKSTART.md`
