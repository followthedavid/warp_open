# AI Chat Testing Guide

## ✅ Fixed Issues
- **tabId type mismatch**: Changed from `u32` to `u64` in Rust backend to support large timestamp-based IDs
- **Shell command output**: Now combines stdout and stderr for complete output display

## 🧪 Test the AI Chat Interface

### 1. Basic AI Chat
In the Tauri window, you should see:
- Tab bar at top with "AI Assistant" tab
- Welcome message: "Hello! I'm your AI assistant..."
- Input box at bottom

**Test:**
```
Type: Hello, can you help me?
Press: Enter
```

**Expected Result:**
- Your message appears in blue bubble on the right
- AI response appears in gray bubble on the left:
  ```
  AI Response: I received your message 'Hello, can you help me?'. 
  This is a placeholder. Connect me to Ollama to get real AI responses!
  ```

### 2. Shell Command Execution
**Test:**
```
Type: /shell ls -la
Press: Enter
```

**Expected Result:**
- Your message appears: `/shell ls -la`
- Directory listing appears in AI bubble

**More Shell Tests:**
```
/shell pwd
/shell echo "Hello from shell"
/shell date
```

### 3. Multi-Tab Sessions
**Test:**
```
1. Click the '+' button in tab bar
2. New tab opens with its own welcome message
3. Type different messages in each tab
4. Switch between tabs - each maintains its own history
```

### 4. Tab Management
**Test:**
- **Rename**: Double-click tab name, type new name, press Enter
- **Close**: Click '×' button on tab (can't close last tab)
- **Switch**: Click any tab to activate it

### 5. Persistence
**Test:**
```
1. Type some messages in a tab
2. Close the Tauri app completely
3. Restart: npm run tauri:dev
4. Your tabs and conversation history should restore
```

## 🔧 Connect to Real Ollama (Optional)

To get real AI responses instead of placeholders:

1. Make sure Ollama is running:
```bash
ollama serve
```

2. Edit `src-tauri/src/commands.rs` line 127-149

3. Replace the placeholder with:
```rust
use reqwest;

#[tauri::command]
pub async fn ai_query(
    tab_id: u64,
    prompt: String,
) -> Result<String, String> {
    eprintln!("[ai_query] Tab {} prompt: {}", tab_id, prompt);
    
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:11434/api/generate")
        .json(&serde_json::json!({
            "model": "llama3.2:3b-instruct-q4_K_M",
            "prompt": prompt,
            "stream": false
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())?;
    
    let text = response["response"]
        .as_str()
        .unwrap_or("No response")
        .to_string();
    
    Ok(text)
}
```

4. Add `reqwest` and `serde_json` to `Cargo.toml`:
```toml
[dependencies]
reqwest = { version = "0.11", features = ["json"] }
serde_json = "1.0"
```

5. Restart the dev server

## 📊 Expected Console Output

When you send messages, check the terminal running `npm run tauri:dev`:

```
[ai_query] Tab 1734345678901 prompt: Hello
```

When you run shell commands:
```
[execute_shell] Executing: ls -la
```

## ✨ Features Working
- ✅ Multiple AI tabs with independent conversations
- ✅ Persistent conversation history (localStorage)
- ✅ Shell command execution via `/shell`
- ✅ Tab rename (double-click)
- ✅ Tab close (× button)
- ✅ Auto-scrolling messages
- ✅ Thinking indicator while processing
- ✅ Large tab IDs (timestamp-based) supported

## 🐛 Troubleshooting

**Issue:** "AI Error: invalid args `tabId`"
- **Fixed:** Backend now uses `u64` instead of `u32`

**Issue:** Shell commands return empty output
- **Fixed:** Now combines stdout and stderr

**Issue:** Tabs don't persist after restart
- **Check:** Browser localStorage should show `ai_tabs` key
- **Fix:** Clear localStorage and restart if corrupted

**Issue:** Can't type in input box
- **Check:** Click in the input area to focus it
- **Try:** Refresh the page in dev mode
