# Rust Backend Reference

Complete documentation for all Rust modules and Tauri commands.

## Table of Contents

1. [Project Structure](#project-structure)
2. [Tauri Commands](#tauri-commands)
3. [PTY Module](#pty-module)
4. [Ollama Module](#ollama-module)
5. [Commands Module](#commands-module)
6. [Configuration](#configuration)

---

## Project Structure

```
src-tauri/
├── src/
│   ├── main.rs              # Entry point, command registration
│   ├── commands.rs          # File system and utility commands
│   ├── pty.rs               # PTY management
│   ├── ollama.rs            # LLM integration
│   ├── monitoring.rs        # Performance monitoring
│   └── lib.rs               # Library exports
├── Cargo.toml               # Dependencies
├── tauri.conf.json          # Tauri configuration
├── build.rs                 # Build script
└── icons/                   # App icons
```

---

## Tauri Commands

All commands are registered in `main.rs`:

```rust
fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            // PTY commands
            create_pty,
            write_to_pty,
            resize_pty,
            destroy_pty,

            // File commands
            read_file,
            write_file,
            list_directory,
            current_working_dir,

            // Shell commands
            execute_shell,

            // Ollama commands
            query_ollama,
            query_ollama_stream,
            list_ollama_models,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

---

## PTY Module

### pty.rs

Manages pseudo-terminal processes for shell sessions.

#### Data Structures

```rust
use portable_pty::{native_pty_system, CommandBuilder, PtyPair, PtySize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Global PTY store - maps pane ID to PTY instance
pub struct PtyStore {
    ptys: HashMap<String, PtyInstance>,
}

pub struct PtyInstance {
    pair: PtyPair,
    child: Box<dyn portable_pty::Child + Send>,
    reader: Box<dyn std::io::Read + Send>,
    writer: Box<dyn std::io::Write + Send>,
}

lazy_static! {
    static ref PTY_STORE: Arc<Mutex<PtyStore>> = Arc::new(Mutex::new(PtyStore::new()));
}
```

#### Commands

##### create_pty

Creates a new PTY for a terminal pane.

```rust
#[tauri::command]
pub async fn create_pty(
    app: AppHandle,
    pane_id: String,
    shell: Option<String>,
    cwd: Option<String>,
    env: Option<HashMap<String, String>>,
) -> Result<(), String> {
    let pty_system = native_pty_system();

    // Create PTY with default size
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;

    // Build command
    let shell = shell.unwrap_or_else(|| {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string())
    });

    let mut cmd = CommandBuilder::new(&shell);
    cmd.arg("-l"); // Login shell

    if let Some(dir) = cwd {
        cmd.cwd(dir);
    }

    if let Some(env_vars) = env {
        for (key, value) in env_vars {
            cmd.env(key, value);
        }
    }

    // Spawn child process
    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;

    // Get reader/writer
    let reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.try_clone_writer().map_err(|e| e.to_string())?;

    // Store PTY
    let mut store = PTY_STORE.lock().unwrap();
    store.ptys.insert(pane_id.clone(), PtyInstance {
        pair,
        child,
        reader,
        writer,
    });

    // Start output reader thread
    spawn_output_reader(app, pane_id, reader);

    Ok(())
}

fn spawn_output_reader(app: AppHandle, pane_id: String, mut reader: Box<dyn Read + Send>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]).to_string();
                    app.emit_all(&format!("pty-output-{}", pane_id), data).ok();
                }
                Err(_) => break,
            }
        }
        app.emit_all(&format!("pty-exit-{}", pane_id), ()).ok();
    });
}
```

##### write_to_pty

Writes data to a PTY (keyboard input).

```rust
#[tauri::command]
pub fn write_to_pty(pane_id: String, data: String) -> Result<(), String> {
    let mut store = PTY_STORE.lock().unwrap();
    let pty = store.ptys.get_mut(&pane_id)
        .ok_or("PTY not found")?;

    pty.writer.write_all(data.as_bytes())
        .map_err(|e| e.to_string())?;
    pty.writer.flush()
        .map_err(|e| e.to_string())
}
```

##### resize_pty

Resizes the PTY dimensions.

```rust
#[tauri::command]
pub fn resize_pty(pane_id: String, cols: u16, rows: u16) -> Result<(), String> {
    let store = PTY_STORE.lock().unwrap();
    let pty = store.ptys.get(&pane_id)
        .ok_or("PTY not found")?;

    pty.pair.master.resize(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }).map_err(|e| e.to_string())
}
```

##### destroy_pty

Destroys a PTY and cleans up resources.

```rust
#[tauri::command]
pub fn destroy_pty(pane_id: String) -> Result<(), String> {
    let mut store = PTY_STORE.lock().unwrap();

    if let Some(mut pty) = store.ptys.remove(&pane_id) {
        // Kill child process
        pty.child.kill().ok();
        pty.child.wait().ok();
    }

    Ok(())
}
```

---

## Ollama Module

### ollama.rs

Integration with Ollama for local LLM inference.

#### Configuration

```rust
const OLLAMA_BASE_URL: &str = "http://localhost:11434";
const DEFAULT_MODEL: &str = "qwen2.5-coder:7b";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
```

#### Commands

##### query_ollama

Sends a prompt to Ollama and returns the complete response.

```rust
#[tauri::command]
pub async fn query_ollama(prompt: String, model: Option<String>) -> Result<String, String> {
    let model = model.unwrap_or_else(|| DEFAULT_MODEL.to_string());

    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;

    let request = OllamaRequest {
        model,
        prompt,
        stream: false,
        options: Some(OllamaOptions {
            temperature: 0.7,
            num_predict: 2048,
            top_p: 0.9,
        }),
    };

    let response = client
        .post(format!("{}/api/generate", OLLAMA_BASE_URL))
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Ollama: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Ollama error: {}", response.status()));
    }

    let result: OllamaResponse = response.json().await
        .map_err(|e| e.to_string())?;

    Ok(result.response)
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Serialize)]
struct OllamaOptions {
    temperature: f32,
    num_predict: i32,
    top_p: f32,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
    done: bool,
}
```

##### query_ollama_stream

Streams response tokens in real-time via Tauri events.

```rust
#[tauri::command]
pub async fn query_ollama_stream(
    app: AppHandle,
    prompt: String,
    model: Option<String>,
    request_id: String,
) -> Result<(), String> {
    let model = model.unwrap_or_else(|| DEFAULT_MODEL.to_string());

    let client = reqwest::Client::new();

    let request = OllamaRequest {
        model,
        prompt,
        stream: true,
        options: None,
    };

    let response = client
        .post(format!("{}/api/generate", OLLAMA_BASE_URL))
        .json(&request)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&chunk);

        // Parse NDJSON stream
        for line in text.lines() {
            if let Ok(partial) = serde_json::from_str::<OllamaStreamChunk>(line) {
                app.emit_all(
                    &format!("ollama-stream-{}", request_id),
                    OllamaStreamEvent {
                        token: partial.response,
                        done: partial.done,
                    }
                ).ok();
            }
        }
    }

    Ok(())
}

#[derive(Deserialize)]
struct OllamaStreamChunk {
    response: String,
    done: bool,
}

#[derive(Serialize, Clone)]
struct OllamaStreamEvent {
    token: String,
    done: bool,
}
```

##### list_ollama_models

Lists available Ollama models.

```rust
#[tauri::command]
pub async fn list_ollama_models() -> Result<Vec<OllamaModel>, String> {
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/api/tags", OLLAMA_BASE_URL))
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Ollama: {}", e))?;

    let result: OllamaModelsResponse = response.json().await
        .map_err(|e| e.to_string())?;

    Ok(result.models)
}

#[derive(Deserialize)]
struct OllamaModelsResponse {
    models: Vec<OllamaModel>,
}

#[derive(Serialize, Deserialize)]
pub struct OllamaModel {
    name: String,
    size: u64,
    modified_at: String,
}
```

---

## Commands Module

### commands.rs

File system and utility commands.

##### read_file

Reads a file's contents.

```rust
#[tauri::command]
pub fn read_file(path: String) -> Result<String, String> {
    // Expand ~ to home directory
    let expanded = shellexpand::tilde(&path).to_string();
    let path = std::path::Path::new(&expanded);

    if !path.exists() {
        return Err(format!("File not found: {}", path.display()));
    }

    if !path.is_file() {
        return Err(format!("Not a file: {}", path.display()));
    }

    std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read file: {}", e))
}
```

##### write_file

Writes content to a file.

```rust
#[tauri::command]
pub fn write_file(path: String, content: String) -> Result<(), String> {
    let expanded = shellexpand::tilde(&path).to_string();
    let path = std::path::Path::new(&expanded);

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directories: {}", e))?;
    }

    std::fs::write(path, content)
        .map_err(|e| format!("Failed to write file: {}", e))
}
```

##### list_directory

Lists directory contents for autocomplete.

```rust
#[tauri::command]
pub fn list_directory(path: String, prefix: String) -> Result<Vec<String>, String> {
    let expanded = shellexpand::tilde(&path).to_string();
    let dir_path = std::path::Path::new(&expanded);

    if !dir_path.is_dir() {
        return Err("Not a directory".to_string());
    }

    let mut entries = Vec::new();
    let prefix_lower = prefix.to_lowercase();

    for entry in std::fs::read_dir(dir_path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();

        // Filter by prefix
        if name.to_lowercase().starts_with(&prefix_lower) {
            let display = if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                format!("{}/", name)
            } else {
                name
            };
            entries.push(display);
        }
    }

    // Sort: directories first, then alphabetically
    entries.sort_by(|a, b| {
        let a_dir = a.ends_with('/');
        let b_dir = b.ends_with('/');
        match (a_dir, b_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.to_lowercase().cmp(&b.to_lowercase()),
        }
    });

    // Limit results
    entries.truncate(50);

    Ok(entries)
}
```

##### current_working_dir

Gets the current working directory.

```rust
#[tauri::command]
pub fn current_working_dir() -> Result<String, String> {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}
```

##### execute_shell

Executes a shell command and returns output.

```rust
#[tauri::command]
pub fn execute_shell(
    command: String,
    cwd: Option<String>,
) -> Result<ShellOutput, String> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    let mut cmd = std::process::Command::new(&shell);
    cmd.arg("-c").arg(&command);

    if let Some(dir) = cwd {
        let expanded = shellexpand::tilde(&dir).to_string();
        cmd.current_dir(expanded);
    }

    let output = cmd.output()
        .map_err(|e| format!("Failed to execute: {}", e))?;

    Ok(ShellOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}

#[derive(Serialize)]
pub struct ShellOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}
```

---

## Configuration

### Cargo.toml

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
```

### tauri.conf.json

```json
{
  "build": {
    "beforeBuildCommand": "npm run build",
    "beforeDevCommand": "npm run dev",
    "devPath": "http://localhost:5173",
    "distDir": "../dist"
  },
  "package": {
    "productName": "Warp Terminal",
    "version": "0.1.0"
  },
  "tauri": {
    "allowlist": {
      "all": false,
      "shell": {
        "all": false,
        "open": true
      },
      "fs": {
        "all": true,
        "scope": ["$HOME/**", "/tmp/**", "./**"]
      },
      "path": {
        "all": true
      }
    },
    "bundle": {
      "active": true,
      "icon": [
        "icons/32x32.png",
        "icons/128x128.png",
        "icons/icon.icns",
        "icons/icon.ico"
      ],
      "identifier": "com.warp.terminal",
      "targets": "all"
    },
    "security": {
      "csp": null
    },
    "windows": [
      {
        "fullscreen": false,
        "height": 800,
        "width": 1200,
        "resizable": true,
        "title": "Warp Terminal",
        "decorations": false,
        "transparent": true
      }
    ]
  }
}
```

---

## Event System

### PTY Events

Frontend listens for PTY output:

```typescript
// Listen for PTY output
await listen<string>(`pty-output-${paneId}`, (event) => {
  terminal.write(event.payload)
})

// Listen for PTY exit
await listen<void>(`pty-exit-${paneId}`, () => {
  console.log('PTY exited')
})
```

### Ollama Stream Events

```typescript
// Listen for streaming tokens
await listen<{token: string, done: boolean}>(`ollama-stream-${requestId}`, (event) => {
  if (!event.payload.done) {
    appendToken(event.payload.token)
  } else {
    onComplete()
  }
})
```

---

## Error Handling

All commands return `Result<T, String>` where errors are human-readable strings.

```rust
// Pattern for error handling
fn some_command() -> Result<T, String> {
    operation()
        .map_err(|e| format!("Friendly error message: {}", e))?;
    Ok(result)
}
```

Frontend handles errors:

```typescript
try {
  const result = await invoke('command_name', { params })
} catch (error) {
  // error is the String from Rust
  toast.error(error as string)
}
```
