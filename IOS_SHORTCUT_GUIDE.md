# iOS Shortcuts Integration Guide

Complete guide for setting up phone → Mac sync via iCloud Drive

## Overview

This integration allows you to send prompts from your iPhone to your Mac, where they are processed by local LLMs or desktop apps, with responses synced back via iCloud Drive.

**Flow:**
1. iPhone: Tap Shortcut → Enter prompt
2. iPhone: Shortcut writes JSON to iCloud Drive
3. Mac: `syncWatcher.js` detects new request
4. Mac: Routes to Ollama → ChatGPT Desktop → Claude Desktop
5. Mac: Writes response JSON to iCloud Drive
6. iPhone: Shortcut polls for response and displays result

---

## Prerequisites

### Mac Setup

1. **iCloud Drive enabled** with at least 1GB free space
2. **Warp Sync Watcher running**:
   ```bash
   cd /Users/davidquinton/ReverseLab/Warp_Open/warp_tauri
   node syncWatcher.js
   ```

3. **Enhanced Agent Server running**:
   ```bash
   npm run agent:enhanced
   ```

4. **At least one LLM available**:
   - Ollama (preferred)
   - ChatGPT Desktop app
   - Claude Desktop app

### iPhone Setup

1. **iCloud Drive enabled** (Settings → [Your Name] → iCloud → iCloud Drive)
2. **Shortcuts app** installed (built-in on iOS)
3. **Files app** installed (built-in on iOS)

---

## iOS Shortcut Setup

### Method 1: Manual Creation (Recommended)

Create a new Shortcut with these steps:

#### Step 1: Get Input
```
Action: Ask for Input
- Prompt: "What would you like to ask?"
- Input Type: Text
- Default Answer: (leave empty)
```

#### Step 2: Generate Request ID
```
Action: Get Current Date
- Date Format: Custom
- Format: yyyyMMdd-HHmmss

Action: Set Variable
- Variable Name: RequestID
- Value: [Current Date]
```

#### Step 3: Create Request JSON
```
Action: Dictionary
- Key: id | Type: Text | Value: [RequestID]
- Key: timestamp | Type: Number | Value: [Current Date as Unix timestamp]
- Key: prompt | Type: Text | Value: [Provided Input]
- Key: priority | Type: Text | Value: normal
- Key: source | Type: Text | Value: iOS Shortcut

Action: Get Dictionary Value
- Key: (Get entire dictionary)
- Format as JSON

Action: Set Variable
- Variable Name: RequestJSON
- Value: [JSON from Dictionary]
```

#### Step 4: Write to iCloud Drive
```
Action: Save File
- File: [RequestJSON]
- Destination Path: iCloud Drive/WarpSync/warp-requests/
- Filename: request-[RequestID].json
- Overwrite: Yes
```

#### Step 5: Show Initial Notification
```
Action: Show Notification
- Title: "Warp Processing"
- Body: "Sent to Mac. Waiting for response..."
```

#### Step 6: Poll for Response
```
Action: Repeat 30 times
  - Wait 2 seconds

  - Get File
    - Path: iCloud Drive/WarpSync/warp-responses/response-[RequestID].json
    - If File Exists: Continue
    - If Not Found: Continue Loop

  - If [File Exists]
    - Get Dictionary from JSON

    - Get Dictionary Value
      - Key: success

    - If [success] is true
      - Get Dictionary Value
        - Key: response

      - Show Notification
        - Title: "Warp Response"
        - Body: [response value]

      - Show Result
        - [response value]

      - Exit Shortcut

    - Otherwise
      - Get Dictionary Value
        - Key: error

      - Show Alert
        - Title: "Error"
        - Message: [error value]

      - Exit Shortcut

End Repeat
```

#### Step 7: Timeout Handler
```
Action: Show Alert
- Title: "Timeout"
- Message: "No response from Mac after 60 seconds. Check that syncWatcher.js is running."
```

---

### Method 2: Import from JSON (Advanced)

Save this as `WarpAsk.shortcut` and import via Files app:

```json
{
  "WFWorkflowActions": [
    {
      "WFWorkflowActionIdentifier": "is.workflow.actions.ask",
      "WFWorkflowActionParameters": {
        "WFInputType": "Text",
        "WFAskActionPrompt": "What would you like to ask?"
      }
    },
    {
      "WFWorkflowActionIdentifier": "is.workflow.actions.date",
      "WFWorkflowActionParameters": {
        "WFDateFormatStyle": "Custom",
        "WFDateFormat": "yyyyMMdd-HHmmss"
      }
    },
    {
      "WFWorkflowActionIdentifier": "is.workflow.actions.setvariable",
      "WFWorkflowActionParameters": {
        "WFVariableName": "RequestID"
      }
    },
    {
      "WFWorkflowActionIdentifier": "is.workflow.actions.dictionary",
      "WFWorkflowActionParameters": {
        "WFItems": {
          "Value": {
            "WFDictionaryFieldValueItems": [
              {
                "WFKey": "id",
                "WFItemType": 0,
                "WFValue": "{{RequestID}}"
              },
              {
                "WFKey": "timestamp",
                "WFItemType": 3,
                "WFValue": "{{CurrentDate}}"
              },
              {
                "WFKey": "prompt",
                "WFItemType": 0,
                "WFValue": "{{ProvidedInput}}"
              },
              {
                "WFKey": "priority",
                "WFItemType": 0,
                "WFValue": "normal"
              },
              {
                "WFKey": "source",
                "WFItemType": 0,
                "WFValue": "iOS Shortcut"
              }
            ]
          }
        }
      }
    },
    {
      "WFWorkflowActionIdentifier": "is.workflow.actions.getvalueforkey",
      "WFWorkflowActionParameters": {
        "WFDictionaryKey": "All Keys",
        "WFGetDictionaryValueType": "All Keys"
      }
    },
    {
      "WFWorkflowActionIdentifier": "is.workflow.actions.documentpicker.save",
      "WFWorkflowActionParameters": {
        "WFFileDestinationPath": "iCloud Drive/WarpSync/warp-requests/request-{{RequestID}}.json",
        "WFAskWhereToSave": false,
        "WFFileOverwriteIfExists": true
      }
    },
    {
      "WFWorkflowActionIdentifier": "is.workflow.actions.notification",
      "WFWorkflowActionParameters": {
        "WFNotificationActionTitle": "Warp Processing",
        "WFNotificationActionBody": "Sent to Mac. Waiting for response..."
      }
    },
    {
      "WFWorkflowActionIdentifier": "is.workflow.actions.repeat.count",
      "WFWorkflowActionParameters": {
        "WFRepeatCount": 30
      }
    }
  ],
  "WFWorkflowClientVersion": "2605.0.5",
  "WFWorkflowMinimumClientVersion": 1113,
  "WFWorkflowMinimumClientVersionString": "1113",
  "WFWorkflowTypes": [
    "NCWidget",
    "WatchKit"
  ]
}
```

---

## File Format Specifications

### Request File Format

Filename: `request-{timestamp}.json`

```json
{
  "id": "20251210-143025",
  "timestamp": 1702217425000,
  "prompt": "What is the weather like today?",
  "priority": "normal",
  "source": "iOS Shortcut",
  "preferDesktop": false,
  "app": "ChatGPT",
  "model": "llama3.2:3b-instruct-q4_K_M"
}
```

**Fields:**
- `id` (required): Unique request identifier (timestamp-based)
- `timestamp` (required): Unix timestamp in milliseconds
- `prompt` (required): The user's question/prompt
- `priority` (optional): "normal" | "high" | "low"
- `source` (optional): Identifier for the requesting client
- `preferDesktop` (optional): Force desktop app usage (skip local LLM)
- `app` (optional): "ChatGPT" | "Claude" (for desktop routing)
- `model` (optional): Ollama model name override

### Response File Format

Filename: `response-{request-id}.json`

**Success Response:**
```json
{
  "id": "20251210-143025",
  "timestamp": 1702217428000,
  "success": true,
  "response": "The weather is sunny with a high of 72°F...",
  "method": "ollama-http",
  "processingTime": 3000
}
```

**Error Response:**
```json
{
  "id": "20251210-143025",
  "timestamp": 1702217428000,
  "success": false,
  "error": "All backends unavailable"
}
```

---

## Advanced Features

### Priority Routing

Set `priority: "high"` to prefer desktop apps over local LLM:

```json
{
  "id": "20251210-143025",
  "prompt": "Complex reasoning task...",
  "priority": "high",
  "preferDesktop": true,
  "app": "ChatGPT"
}
```

### Model Selection

Override the default Ollama model:

```json
{
  "id": "20251210-143025",
  "prompt": "Write code...",
  "model": "deepseek-coder:6.7b"
}
```

### Conditional Routing in Shortcut

Add logic to route based on prompt content:

```
If [Prompt] contains "code"
  - Set Variable: preferDesktop = false
  - Set Variable: model = "deepseek-coder:6.7b"

If [Prompt] contains "research"
  - Set Variable: preferDesktop = true
  - Set Variable: app = "ChatGPT"
```

---

## Troubleshooting

### iPhone Side

**Problem:** "File not found" error when saving request

**Solution:**
1. Check iCloud Drive is enabled (Settings → [Name] → iCloud)
2. Verify folder exists: Files app → iCloud Drive → WarpSync → warp-requests
3. If folder doesn't exist, create it manually or run syncWatcher.js once on Mac

---

**Problem:** Response never appears (timeout after 60s)

**Solution:**
1. Check Mac is running `syncWatcher.js`
2. Check Mac is connected to internet (for iCloud sync)
3. Verify request file appeared on Mac:
   ```bash
   ls ~/Library/Mobile\ Documents/com~apple~CloudDocs/WarpSync/warp-requests/
   ```
4. Check sync watcher logs on Mac

---

### Mac Side

**Problem:** `syncWatcher.js` exits with "iCloud Drive not available"

**Solution:**
1. Enable iCloud Drive in System Preferences → Apple ID → iCloud
2. Wait for initial sync to complete (can take 5-10 minutes first time)
3. Verify path exists:
   ```bash
   ls ~/Library/Mobile\ Documents/com~apple~CloudDocs/
   ```

---

**Problem:** Requests not being processed

**Solution:**
1. Check syncWatcher logs for errors
2. Verify enhanced agent server is running:
   ```bash
   curl http://localhost:4005/health
   ```
3. Test manual request:
   ```bash
   echo '{"id":"test","timestamp":1702217425000,"prompt":"Hello"}' > \
     ~/Library/Mobile\ Documents/com~apple~CloudDocs/WarpSync/warp-requests/request-test.json
   ```

---

## Testing the Integration

### 1. Test Mac Components

```bash
# Terminal 1: Start sync watcher
node syncWatcher.js

# Terminal 2: Create test request
cat > ~/Library/Mobile\ Documents/com~apple~CloudDocs/WarpSync/warp-requests/request-test-$(date +%s).json <<EOF
{
  "id": "test-$(date +%s)",
  "timestamp": $(date +%s)000,
  "prompt": "Say 'Hello from test'",
  "source": "manual test"
}
EOF

# Terminal 3: Watch for response
watch -n 1 'ls -lt ~/Library/Mobile\ Documents/com~apple~CloudDocs/WarpSync/warp-responses/ | head -5'
```

### 2. Test iPhone Shortcut

1. Open Shortcuts app
2. Tap your "Warp Ask" shortcut
3. Enter: "Count to 5"
4. Wait for notification with response
5. Verify response appears within 10 seconds

---

## Performance Optimization

### Reduce Latency

1. **Keep Mac awake**: System Preferences → Energy Saver → Prevent sleep when display off
2. **Increase poll frequency**: Set `WARP_POLL_INTERVAL=1000` (1 second)
3. **Use local LLM**: Faster than desktop automation
4. **Reduce model size**: Use `llama3.2:3b` instead of `llama3.1:8b`

### Battery Optimization (iPhone)

1. **Increase poll delay** in Shortcut from 2s to 5s
2. **Reduce max retries** from 30 to 15
3. **Use Wi-Fi only**: Disable cellular for Files app

---

## Integration with Siri

Add to Siri for voice activation:

1. Open Shortcuts app
2. Long-press "Warp Ask" shortcut
3. Tap "Add to Siri"
4. Record phrase: "Ask Warp"
5. Tap "Done"

Now you can say: "Hey Siri, ask Warp" → speak your prompt → get response

---

## Security Considerations

**Files are stored in iCloud Drive:**
- Only accessible to your Apple ID
- Encrypted in transit
- Not shared with third parties

**Best Practices:**
1. Don't include sensitive credentials in prompts
2. Review responses before sharing
3. Clear old response files periodically:
   ```bash
   rm ~/Library/Mobile\ Documents/com~apple~CloudDocs/WarpSync/warp-responses/*.json
   ```

---

## Automation Scripts

### Auto-start on Mac Login

Create `~/Library/LaunchAgents/com.warp.sync-watcher.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.warp.sync-watcher</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/node</string>
        <string>/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/syncWatcher.js</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/warp-sync-watcher.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/warp-sync-watcher-error.log</string>
</dict>
</plist>
```

Load with:
```bash
launchctl load ~/Library/LaunchAgents/com.warp.sync-watcher.plist
```

---

## Future Enhancements

- [ ] Add support for image attachments
- [ ] Implement conversation history
- [ ] Add streaming responses (SSE via long-polling)
- [ ] Support multi-turn conversations
- [ ] Add response caching
- [ ] Implement priority queue
- [ ] Add analytics/usage tracking

---

**End of iOS Shortcuts Integration Guide**

For questions or issues, check the main project documentation or Mac console logs.
