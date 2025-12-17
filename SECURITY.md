# Security Documentation

This document describes the security decisions and boundaries in Warp_Open.

## Security Philosophy

**Warp_Open is designed with "trust by default, but verify" in mind.**

- All AI features are local-only (Ollama) - nothing leaves your machine
- Air-Gapped Mode allows complete AI disable for sensitive environments
- Clipboard operations are controllable via settings
- No telemetry, no cloud sync, no external connections

## Threat Model

Warp_Open is a local terminal application. The primary threats are:

1. **Malicious OSC sequences** from untrusted output
2. **Clipboard exfiltration** via terminal escapes
3. **Link hijacking** via hyperlink sequences
4. **AI context leakage** to external services

## Security Controls

### Air-Gapped Mode (AI Disable)

**Risk**: AI features could process sensitive terminal data.

**Mitigation**:
- Global toggle to completely disable all AI features
- Visual indicator shows AI status in the top bar
- When disabled:
  - AI overlay keyboard shortcut is blocked
  - AI Panel button is hidden
  - No AI-related network requests
  - No context collection

**Implementation**: `src/composables/useSecuritySettings.ts`
```typescript
const securitySettings = {
  aiEnabled: true,           // Master toggle for AI
  clipboardWriteEnabled: true // OSC 52 clipboard writes
}
```

**User Control**: Click the AI status button in the top bar to toggle.

### OSC 8: Hyperlinks

**Risk**: Malicious servers could send hyperlink sequences pointing to dangerous URLs.

**Mitigation**:
- Only `http://` and `https://` protocols are allowed
- All other protocols (`file://`, `javascript:`, etc.) are blocked
- URLs are validated before opening

**Implementation**: `src/components/TerminalPane.vue`
```javascript
const webLinksAddon = new WebLinksAddon((event, uri) => {
  const url = new URL(uri)
  if (url.protocol === 'http:' || url.protocol === 'https:') {
    open(uri)
  } else {
    console.warn('[TerminalPane] Blocked non-http link:', uri)
  }
})
```

### OSC 52: Clipboard Operations

**Risk**: Malicious programs could read clipboard contents or silently write to it.

**Mitigation**:
- **Read operations**: Always blocked (cannot exfiltrate clipboard)
- **Write operations**: Controlled by security settings
- All operations are logged to console
- User can disable clipboard writes in settings

**Implementation**: `src/components/TerminalPane.vue`
```javascript
terminal.parser.registerOscHandler(52, (data) => {
  // Read requests are ALWAYS blocked
  if (b64Data === '?') {
    console.log('[TerminalPane] OSC 52 clipboard read request BLOCKED')
    return true
  }

  // Write requests respect security settings
  if (!isClipboardWriteAllowed()) {
    console.log('[TerminalPane] OSC 52 clipboard write BLOCKED')
    return true
  }

  // Allowed write
  const decoded = atob(b64Data)
  navigator.clipboard.writeText(decoded)
  return true
})
```

### AI Overlay

**Risk**: AI context could leak sensitive terminal data.

**Mitigation**:
- AI overlay is a pure UI component
- Never executes commands directly
- Context is read-only and limited:
  - Current working directory
  - Recent output (last 50 lines, ~2KB max)
- User must explicitly copy/paste suggestions
- **Local LLM only (Ollama)** - no cloud APIs
- AI can be completely disabled via Air-Gapped Mode

**What AI Never Sees**:
- Environment variables
- Passwords or credentials
- SSH keys or certificates
- Full command history
- Other pane content

**Implementation**: `src/components/AIOverlay.vue`
```javascript
const context = {
  cwd: props.cwd || 'unknown',
  recentOutput: (props.recentOutput || '').slice(-2000), // Hard limit
  query,
}
```

### Session Persistence

**Risk**: Session files could contain sensitive data.

**Mitigation**:
- Session files stored in user's app data directory
- No credentials or environment variables stored
- Only layout structure and working directories saved
- PTYs are re-created on restore (no process state)
- Atomic writes prevent corruption
- Automatic backup for crash recovery

**Location**: `~/.warp_open/session.json`

**What Is Stored**:
- Tab names and types
- Pane layout structure
- Working directories
- Active tab/pane state

**What Is Never Stored**:
- Terminal content/history
- Environment variables
- Passwords or credentials
- AI conversation history (stored separately per-pane)

### PTY Isolation

**Risk**: Panes could interfere with each other.

**Mitigation**:
- Each pane owns its own PTY process
- PTYs are never shared between panes
- Input goes only to the focused pane
- PTY cleanup on pane close
- Leak detection on app shutdown

## Tauri Security

Warp_Open uses Tauri's security features:

### CSP (Content Security Policy)
- Scripts only from self
- Styles only from self and inline
- No external connections (except Ollama localhost)

### Tauri Allowlist
Only necessary APIs are exposed:
- `clipboard` - For copy/paste operations
- `fs` - Limited to specific paths
- `window` - For window management

### Window Security
- `devtools` disabled in production
- No remote content loaded

## Security Settings

Users can configure security via:

1. **UI Toggle**: AI status button in the top bar
2. **localStorage**: `warp_open_security_settings`

```json
{
  "aiEnabled": true,
  "clipboardWriteEnabled": true,
  "clipboardWritePrompt": false
}
```

## Network Behavior

**Warp_Open makes NO external network requests** except:

1. **Ollama API** (localhost:11434) - Only when AI is enabled
   - User's query + limited context
   - Responses from local LLM

That's it. No telemetry. No analytics. No cloud sync.

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email security concerns to [maintainer email]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work on a fix.

## Security Checklist for Contributors

When adding new features:

- [ ] Validate all external input
- [ ] Don't expose internal state unnecessarily
- [ ] Use allowlists over blocklists
- [ ] Log security-relevant events
- [ ] Test with malicious input
- [ ] Document security implications
- [ ] Respect Air-Gapped Mode for AI features
- [ ] Never store credentials or secrets

## Audit History

| Date | Scope | Findings |
|------|-------|----------|
| 2025-12-14 | OSC handlers | Implemented read blocking for OSC 52 |
| 2025-12-14 | Hyperlinks | Protocol allowlist for OSC 8 |
| 2025-12-14 | AI context | Limited to 2KB recent output |
| 2025-12-14 | Air-Gapped Mode | Added global AI disable toggle |
| 2025-12-14 | Clipboard | Added configurable OSC 52 permission |
| 2025-12-14 | Session | Added atomic writes + backup recovery |
