# Build From Scratch Guide

Complete step-by-step guide to rebuild the entire Warp-Tauri application from zero.

## Prerequisites

### System Requirements
- macOS 11+ (Big Sur or later) or Linux
- 8GB+ RAM recommended
- 10GB+ disk space

### Required Software

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. Install Node.js (v18+)
# Using nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
nvm use 18

# 3. Install Tauri CLI
cargo install tauri-cli

# 4. Install Ollama (for AI features)
# macOS:
brew install ollama

# Pull a model
ollama pull qwen2.5-coder:7b
```

---

## Phase 1: Project Setup

### 1.1 Create Vue Project

```bash
npm create vite@latest warp-tauri -- --template vue-ts
cd warp-tauri
npm install
```

### 1.2 Initialize Tauri

```bash
npm install -D @tauri-apps/cli @tauri-apps/api
npx tauri init
```

When prompted:
- App name: `warp-tauri`
- Window title: `Warp Terminal`
- Dev server: `http://localhost:5173`
- Build command: `npm run build`
- Output dir: `../dist`

### 1.3 Install Dependencies

```bash
# Frontend dependencies
npm install xterm xterm-addon-fit xterm-addon-web-links
npm install monaco-editor
npm install vuedraggable@next
npm install -D vitest @vue/test-utils jsdom

# Dev dependencies
npm install -D typescript @types/node
```

### 1.4 Update package.json

```json
{
  "scripts": {
    "dev": "vite",
    "build": "vue-tsc --noEmit && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "tauri": "tauri",
    "tauri:dev": "tauri dev",
    "tauri:build": "tauri build"
  }
}
```

---

## Phase 2: Rust Backend

### 2.1 Update Cargo.toml

Create `src-tauri/Cargo.toml`:

```toml
[package]
name = "warp-tauri"
version = "0.1.0"
edition = "2021"

[dependencies]
tauri = { version = "1.5", features = ["shell-open"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
portable-pty = "0.8"
reqwest = { version = "0.11", features = ["json", "stream"] }
tokio = { version = "1", features = ["full"] }
lazy_static = "1.4"
shellexpand = "3.0"
futures = "0.3"

[features]
default = ["custom-protocol"]
custom-protocol = ["tauri/custom-protocol"]

[build-dependencies]
tauri-build = { version = "1.5", features = [] }
```

### 2.2 Create PTY Module

Create `src-tauri/src/pty.rs`:

```rust
use portable_pty::{native_pty_system, CommandBuilder, PtyPair, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager};

lazy_static::lazy_static! {
    static ref PTY_STORE: Arc<Mutex<HashMap<String, PtyInstance>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

struct PtyInstance {
    #[allow(dead_code)]
    pair: PtyPair,
    writer: Box<dyn Write + Send>,
}

#[tauri::command]
pub async fn create_pty(
    app: AppHandle,
    pane_id: String,
    shell: Option<String>,
    cwd: Option<String>,
) -> Result<(), String> {
    let pty_system = native_pty_system();

    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;

    let shell = shell.unwrap_or_else(|| {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string())
    });

    let mut cmd = CommandBuilder::new(&shell);
    cmd.arg("-l");

    if let Some(dir) = cwd {
        let expanded = shellexpand::tilde(&dir).to_string();
        cmd.cwd(expanded);
    }

    let _child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.try_clone_writer().map_err(|e| e.to_string())?;

    // Store instance
    {
        let mut store = PTY_STORE.lock().unwrap();
        store.insert(pane_id.clone(), PtyInstance { pair, writer });
    }

    // Spawn reader thread
    let pane_id_clone = pane_id.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]).to_string();
                    app.emit_all(&format!("pty-output-{}", pane_id_clone), data).ok();
                }
                Err(_) => break,
            }
        }
        app.emit_all(&format!("pty-exit-{}", pane_id_clone), ()).ok();
    });

    Ok(())
}

#[tauri::command]
pub fn write_to_pty(pane_id: String, data: String) -> Result<(), String> {
    let mut store = PTY_STORE.lock().unwrap();
    let pty = store.get_mut(&pane_id).ok_or("PTY not found")?;
    pty.writer.write_all(data.as_bytes()).map_err(|e| e.to_string())?;
    pty.writer.flush().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn resize_pty(pane_id: String, cols: u16, rows: u16) -> Result<(), String> {
    let store = PTY_STORE.lock().unwrap();
    let pty = store.get(&pane_id).ok_or("PTY not found")?;
    pty.pair.master
        .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn destroy_pty(pane_id: String) -> Result<(), String> {
    let mut store = PTY_STORE.lock().unwrap();
    store.remove(&pane_id);
    Ok(())
}
```

### 2.3 Create Ollama Module

Create `src-tauri/src/ollama.rs`:

```rust
use serde::{Deserialize, Serialize};
use std::time::Duration;

const OLLAMA_URL: &str = "http://localhost:11434";

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

#[tauri::command]
pub async fn query_ollama(prompt: String, model: String) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;

    let request = OllamaRequest {
        model,
        prompt,
        stream: false,
    };

    let response = client
        .post(format!("{}/api/generate", OLLAMA_URL))
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Ollama connection failed: {}", e))?;

    let result: OllamaResponse = response.json().await.map_err(|e| e.to_string())?;
    Ok(result.response)
}

#[derive(Serialize, Deserialize)]
pub struct OllamaModel {
    pub name: String,
}

#[derive(Deserialize)]
struct ModelsResponse {
    models: Vec<OllamaModel>,
}

#[tauri::command]
pub async fn list_ollama_models() -> Result<Vec<OllamaModel>, String> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/tags", OLLAMA_URL))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let result: ModelsResponse = response.json().await.map_err(|e| e.to_string())?;
    Ok(result.models)
}
```

### 2.4 Create Commands Module

Create `src-tauri/src/commands.rs`:

```rust
use serde::Serialize;

#[tauri::command]
pub fn read_file(path: String) -> Result<String, String> {
    let expanded = shellexpand::tilde(&path).to_string();
    std::fs::read_to_string(&expanded)
        .map_err(|e| format!("Failed to read {}: {}", path, e))
}

#[tauri::command]
pub fn write_file(path: String, content: String) -> Result<(), String> {
    let expanded = shellexpand::tilde(&path).to_string();
    let path = std::path::Path::new(&expanded);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    std::fs::write(path, content).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_directory(path: String, prefix: String) -> Result<Vec<String>, String> {
    let expanded = shellexpand::tilde(&path).to_string();
    let dir = std::path::Path::new(&expanded);

    if !dir.is_dir() {
        return Err("Not a directory".to_string());
    }

    let mut entries = Vec::new();
    let prefix_lower = prefix.to_lowercase();

    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();

        if name.to_lowercase().starts_with(&prefix_lower) {
            let display = if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                format!("{}/", name)
            } else {
                name
            };
            entries.push(display);
        }
    }

    entries.sort();
    entries.truncate(50);
    Ok(entries)
}

#[tauri::command]
pub fn current_working_dir() -> Result<String, String> {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct ShellOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[tauri::command]
pub fn execute_shell(command: String, cwd: Option<String>) -> Result<ShellOutput, String> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    let mut cmd = std::process::Command::new(&shell);
    cmd.arg("-c").arg(&command);

    if let Some(dir) = cwd {
        let expanded = shellexpand::tilde(&dir).to_string();
        cmd.current_dir(expanded);
    }

    let output = cmd.output().map_err(|e| e.to_string())?;

    Ok(ShellOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}
```

### 2.5 Create Main Entry Point

Create `src-tauri/src/main.rs`:

```rust
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod commands;
mod ollama;
mod pty;

use commands::{current_working_dir, execute_shell, list_directory, read_file, write_file};
use ollama::{list_ollama_models, query_ollama};
use pty::{create_pty, destroy_pty, resize_pty, write_to_pty};

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            // PTY
            create_pty,
            write_to_pty,
            resize_pty,
            destroy_pty,
            // Files
            read_file,
            write_file,
            list_directory,
            current_working_dir,
            // Shell
            execute_shell,
            // Ollama
            query_ollama,
            list_ollama_models,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

---

## Phase 3: Frontend Core

### 3.1 Create Directory Structure

```bash
mkdir -p src/composables
mkdir -p src/components
mkdir -p src/assets
```

### 3.2 Create Core Composables

Create each composable file following the patterns in COMPOSABLES_REFERENCE.md:

1. `src/composables/usePty.ts` - PTY management
2. `src/composables/useTerminalBuffer.ts` - Output buffering
3. `src/composables/useTabs.ts` - Tab management
4. `src/composables/useSplitPane.ts` - Pane splitting
5. `src/composables/useTheme.ts` - Theming
6. `src/composables/useSessionStore.ts` - Session persistence
7. `src/composables/useSnapshots.ts` - Workspace snapshots
8. `src/composables/useToast.ts` - Toast notifications

### 3.3 Create Terminal Component

Create `src/components/TerminalPane.vue`:

```vue
<template>
  <div class="terminal-pane" ref="containerRef">
    <div ref="xtermRef" class="xterm-container"></div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { Terminal } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { WebLinksAddon } from 'xterm-addon-web-links'
import { invoke } from '@tauri-apps/api/tauri'
import { listen } from '@tauri-apps/api/event'

const props = defineProps<{
  paneId: string
}>()

const xtermRef = ref<HTMLElement | null>(null)
const terminal = ref<Terminal | null>(null)
const fitAddon = new FitAddon()

onMounted(async () => {
  if (!xtermRef.value) return

  // Create terminal
  const term = new Terminal({
    cursorBlink: true,
    fontSize: 14,
    fontFamily: "'SF Mono', Monaco, monospace",
    theme: {
      background: '#1a1a2e',
      foreground: '#e0e0e0',
      cursor: '#6366f1',
    }
  })

  term.loadAddon(fitAddon)
  term.loadAddon(new WebLinksAddon())
  term.open(xtermRef.value)
  fitAddon.fit()

  terminal.value = term

  // Create PTY
  await invoke('create_pty', { paneId: props.paneId })

  // Listen for output
  await listen<string>(`pty-output-${props.paneId}`, (event) => {
    term.write(event.payload)
  })

  // Send input to PTY
  term.onData((data) => {
    invoke('write_to_pty', { paneId: props.paneId, data })
  })

  // Handle resize
  const resizeObserver = new ResizeObserver(() => {
    fitAddon.fit()
    invoke('resize_pty', {
      paneId: props.paneId,
      cols: term.cols,
      rows: term.rows
    })
  })
  resizeObserver.observe(xtermRef.value)
})

onUnmounted(async () => {
  await invoke('destroy_pty', { paneId: props.paneId })
  terminal.value?.dispose()
})
</script>

<style scoped>
.terminal-pane {
  width: 100%;
  height: 100%;
  background: #1a1a2e;
}

.xterm-container {
  width: 100%;
  height: 100%;
}
</style>
```

### 3.4 Create App Component

Update `src/App.vue`:

```vue
<template>
  <div id="app" :class="{ dark: isDark }">
    <div class="title-bar">
      <div class="title">Warp Terminal</div>
    </div>
    <div class="main">
      <TerminalPane :paneId="'main'" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import TerminalPane from './components/TerminalPane.vue'

const isDark = ref(true)
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

#app {
  width: 100vw;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: #1a1a2e;
  color: #e0e0e0;
}

.title-bar {
  height: 40px;
  background: #252545;
  display: flex;
  align-items: center;
  justify-content: center;
  -webkit-app-region: drag;
}

.main {
  flex: 1;
  overflow: hidden;
}
</style>
```

---

## Phase 4: Warp Features

### 4.1 Blocks Feature

Create:
- `src/composables/useBlocks.ts`
- `src/components/BlockList.vue`
- `src/components/CommandBlock.vue`
- `src/components/BlockHeader.vue`
- `src/components/BlockBody.vue`

### 4.2 Autocomplete Feature

Create:
- `src/composables/useAutocomplete.ts`
- `src/components/AutocompleteDropdown.vue`

### 4.3 Workflows Feature

Create:
- `src/composables/useWorkflows.ts`
- `src/components/WorkflowPanel.vue`
- `src/components/WorkflowCard.vue`

### 4.4 Notebook Feature

Create:
- `src/composables/useNotebook.ts`
- `src/components/NotebookPanel.vue`
- `src/components/NotebookCell.vue`

### 4.5 AI Command Search

Create:
- `src/composables/useAICommandSearch.ts`
- `src/components/AICommandSearch.vue`

---

## Phase 5: Claude Code Features

### 5.1 Tools Framework

Create `src/composables/useTools.ts` with:
- Read, Write, Edit tools
- Bash, Grep, Glob tools
- ListDir, GetCwd tools
- Tool parsing (XML, JSON, function call formats)

### 5.2 Agent Mode

Create:
- `src/composables/useAgentMode.ts`
- `src/components/AgentPanel.vue`

---

## Phase 6: Testing

### 6.1 Configure Vitest

Create `vitest.config.ts`:

```typescript
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
    globals: true,
  },
})
```

### 6.2 Create Mock

Create `src/__tests__/mocks/tauri.ts`:

```typescript
export const mockInvoke = vi.fn()

vi.mock('@tauri-apps/api/tauri', () => ({
  invoke: mockInvoke,
}))

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
  emit: vi.fn(),
}))
```

### 6.3 Write Tests

Create tests for each composable following patterns in existing test files.

---

## Phase 7: Build & Deploy

### 7.1 Development

```bash
npm run tauri dev
```

### 7.2 Production Build

```bash
npm run tauri build
```

### 7.3 Output

Builds are located in:
- macOS: `src-tauri/target/release/bundle/dmg/`
- Linux: `src-tauri/target/release/bundle/appimage/`
- Windows: `src-tauri/target/release/bundle/msi/`

---

## Verification Checklist

### Terminal
- [ ] PTY creates and connects
- [ ] Input/output works
- [ ] Resize works
- [ ] Multiple panes work

### Warp Features
- [ ] Blocks detect commands
- [ ] Autocomplete shows suggestions
- [ ] Workflows execute
- [ ] Notebook cells run
- [ ] AI search finds commands

### Claude Code Features
- [ ] Tools execute correctly
- [ ] Agent mode loops work
- [ ] Ollama connection works

### UI
- [ ] Tabs work
- [ ] Split panes work
- [ ] Theme switching works
- [ ] Session recovery works

### Tests
- [ ] All unit tests pass
- [ ] Build completes without errors
