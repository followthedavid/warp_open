# Personal Automation Intelligence System

**Document Version:** 1.0.0
**Created:** 2025-12-27
**Last Updated:** 2025-12-27
**Status:** Active Development

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Overview](#system-overview)
3. [Session Log](#session-log)
4. [Architecture](#architecture)
5. [Component Reference](#component-reference)
6. [Safety Model](#safety-model)
7. [Configuration Guide](#configuration-guide)
8. [Usage Examples](#usage-examples)
9. [Scheduled Tasks](#scheduled-tasks)
10. [Future Work](#future-work)

---

## Executive Summary

The Personal Automation Intelligence (PAI) system is a local-first, privacy-preserving autonomous assistant inspired by the AI "Samantha" from the movie "Her". It provides:

- **Deep Context Intelligence**: Knows all your projects, code patterns, and past solutions
- **24/7 Autonomous Operation**: Works while you sleep to improve your codebase
- **Privacy Protection**: Automates account anonymization and email cleaning
- **Constitutional Safety**: Hardcoded rules prevent misuse of intimate access

**Philosophy:** "Intimacy without leverage" - the system has deep access to your data but no mechanism to weaponize it.

---

## System Overview

### What It Does

| Capability | Description | Risk Level |
|------------|-------------|------------|
| **Universal Memory** | Indexes all code files with embeddings for semantic search | Low |
| **Cross-Project Intelligence** | Recognizes patterns across projects ("you built this before") | Low |
| **Autonomous Code Improvement** | Scans and fixes formatting, types, docs, security issues | Medium |
| **Account Anonymization** | Changes emails to iCloud Hide My Email across websites | High |
| **Email Cleaning** | Quarantines spam, preserves receipts, safe unsubscribe | Medium |
| **Token Management** | Securely stores and auto-refreshes API tokens | Medium |

### What It Won't Do (Constitutional Constraints)

- ❌ Send source code or personal files externally
- ❌ Delete files/emails without quarantine period
- ❌ Make architectural changes without approval
- ❌ Access credentials except for approved endpoints
- ❌ Operate if dead man's switch expires

---

## Session Log

### Session: 2025-12-27

#### Goals Discussed
1. Build autonomous intelligence system inspired by "Her"
2. 24/7 operation for code improvement
3. Privacy automation (iCloud Hide My Email, email cleaning)
4. Deep context across all projects
5. Safe web searching without risk
6. Constitutional safety constraints

#### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `useConstitution.ts` | 350 | Hardcoded safety rules, data classification |
| `useAuditLog.ts` | 400 | Immutable, cryptographically-chained action logging |
| `useUniversalMemory.ts` | 750 | File indexing, embeddings, cross-project intelligence |
| `useTokenVault.ts` | 400 | Secure API token storage (macOS Keychain) |
| `useAccountAnonymizer.ts` | 600 | iCloud Hide My Email automation |
| `useEmailCleaner.ts` | 650 | Inbox management, receipt preservation |
| `useAutonomousImprover.ts` | 700 | Code scanning and improvement |
| `useDaemonOrchestrator.ts` | 600 | 24/7 task coordination |

**Total: 8 files, 4,450+ lines of TypeScript**

#### Commits Made

1. `736ad06` - feat: 100% Claude Code + Warp Terminal parity - 39 features complete
2. `4c393f2` - feat: Personal Automation Intelligence - "Her" parity system

#### Design Decisions

1. **Revised Safety Model**: Changed from "no internet" to "controlled internet with audit"
   - Reason: Pure isolation makes the system useless for legitimate automation
   - Solution: Data classification + allowlisted endpoints + full audit trail

2. **Quarantine Before Delete**: All deletions go through 7-day quarantine
   - Reason: Prevents accidental data loss from autonomous operation
   - Applies to: Emails, code changes, any destructive action

3. **Receipt Preservation**: Hardcoded patterns to NEVER delete receipts
   - Reason: Financial records are irreplaceable
   - Implementation: Pattern matching in useEmailCleaner.ts

4. **Cross-Project Pattern Recognition**: Embeddings-based similarity search
   - Reason: "You built this before" is a key feature
   - Implementation: Ollama nomic-embed-text model

---

## Architecture

### System Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    useDaemonOrchestrator                            │
│                    (24/7 Background Coordinator)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ Scheduled    │  │  Approval    │  │   Health     │               │
│  │   Tasks      │  │    Queue     │  │  Monitoring  │               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
│         │                 │                 │                        │
└─────────┼─────────────────┼─────────────────┼────────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         SUBSYSTEMS                                   │
├─────────────────┬─────────────────┬─────────────────┬───────────────┤
│ Universal       │ Autonomous      │ Account         │ Email         │
│ Memory          │ Improver        │ Anonymizer      │ Cleaner       │
│                 │                 │                 │               │
│ • File indexing │ • Code scanning │ • Browser auto  │ • Spam detect │
│ • Embeddings    │ • Risk classify │ • iCloud HME    │ • Unsubscribe │
│ • Pattern match │ • Auto-apply    │ • Password sync │ • Quarantine  │
│ • Solutions DB  │ • Approval queue│ • Screenshot    │ • Receipts    │
└────────┬────────┴────────┬────────┴────────┬────────┴───────┬───────┘
         │                 │                 │                │
         ▼                 ▼                 ▼                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      SAFETY INFRASTRUCTURE                           │
├─────────────────────────────────────┬───────────────────────────────┤
│         useConstitution             │         useAuditLog           │
│                                     │                               │
│ • Data classification               │ • Cryptographic chain         │
│ • Allowlisted endpoints             │ • Tamper detection            │
│ • PII sanitization                  │ • Rollback data               │
│ • Dead man's switch                 │ • Complete transparency       │
└─────────────────────────────────────┴───────────────────────────────┘
         │                                     │
         ▼                                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        useTokenVault                                 │
│                   (Secure Credential Storage)                        │
│                                                                      │
│ • macOS Keychain integration       • Endpoint-restricted access      │
│ • Auto-refresh with logging        • Usage auditing                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
User's Projects
     │
     ▼
┌─────────────────┐
│ Universal       │ ──► Embeddings (Ollama) ──► Semantic Search
│ Memory          │ ──► Pattern Extraction  ──► Cross-Project Match
│                 │ ──► Solution Memory     ──► "You did this before"
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Autonomous      │ ──► Scan for issues ──► Risk Classification
│ Improver        │ ──► Low risk: Auto-apply
│                 │ ──► High risk: Queue for approval
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Audit Log       │ ──► Every action logged
│                 │ ──► Rollback data stored
│                 │ ──► Hash chain for integrity
└─────────────────┘
```

---

## Component Reference

### useConstitution.ts

**Purpose:** Hardcoded safety rules that cannot be overridden by prompts or user input during automation.

#### Constants

```typescript
// Data that can NEVER be transmitted externally
NEVER_TRANSMIT_PATTERNS: RegExp[]
// Example: /\.ts$/, /\.env/, /password/i, etc.

// Directories completely off-limits
BLOCKED_DIRECTORIES: string[]
// Example: ~/.ssh, ~/Documents, ~/.aws

// Allowed API endpoints
ALLOWLISTED_ENDPOINTS: string[]
// Example: api.github.com, registry.npmjs.org, localhost:11434

// Actions requiring human approval
REQUIRES_APPROVAL: string[]
// Example: delete_file_permanent, change_password, send_email

// Auto-approved actions
AUTO_APPROVED_ACTIONS: string[]
// Example: read_file, format_code, add_documentation
```

#### Key Functions

```typescript
// Check if data can leave the machine
canTransmit(filepath: string, destination: string): { allowed: boolean; reason?: string }

// Sanitize PII from search queries
sanitizeQuery(query: string): { sanitized: string; piiFound: boolean }

// Validate any action against constitution
validateAction(action: string, target?: string, destination?: string): {
  allowed: boolean
  requiresApproval: boolean
  reason?: string
}

// Dead man's switch
checkin(): void
isAlive(maxHours?: number): boolean
```

---

### useAuditLog.ts

**Purpose:** Immutable, cryptographically-chained action logging for complete transparency.

#### Entry Structure

```typescript
interface AuditEntry {
  id: string
  timestamp: Date
  category: ActionCategory  // 'file_read', 'code_modify', etc.
  action: string
  target?: string
  details?: Record<string, unknown>
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  automated: boolean
  approved: boolean
  success: boolean
  rollbackData?: string  // Data needed to undo this action
  previousHash: string   // Chain integrity
  hash: string           // SHA-256 of this entry
}
```

#### Key Functions

```typescript
// Log an action
log(category: ActionCategory, action: string, options?: {...}): Promise<AuditEntry>

// Verify chain integrity (detect tampering)
verifyChain(): Promise<{ valid: boolean; brokenAt?: number }>

// Get actions that can be rolled back
getRollbackCandidates(): AuditEntry[]

// Export full log
exportLog(filepath: string): Promise<void>
```

---

### useUniversalMemory.ts

**Purpose:** Deep context system - knows all your files, patterns, and solutions.

#### Data Structures

```typescript
interface FileMemory {
  path: string
  project: string
  language: string
  lastModified: Date
  embedding?: number[]     // Semantic vector
  patterns: string[]       // Detected patterns (e.g., 'async-function', 'try-catch')
  imports: string[]
  exports: string[]
}

interface PatternMemory {
  name: string
  files: string[]          // Where this pattern is used
  frequency: number
  embedding?: number[]
}

interface SolutionMemory {
  problem: string
  solution: string
  codeSnippet?: string
  files: string[]
  successCount: number
}
```

#### Key Functions

```typescript
// Index a directory
indexDirectory(dirPath: string): Promise<number>

// Semantic search
search(query: string, options?: {
  types?: Array<'file' | 'pattern' | 'solution'>
  limit?: number
  minScore?: number
}): Promise<SearchResult[]>

// Find similar files
findSimilar(filepath: string): Promise<SearchResult[]>

// Cross-project pattern recognition
findPatternUsage(patternName: string): { file: FileMemory; project: string }[]

// Remember a solution
rememberSolution(problem: string, solution: string, options?: {...}): Promise<SolutionMemory>
```

---

### useTokenVault.ts

**Purpose:** Secure storage and management of API tokens.

#### Features

- macOS Keychain integration (falls back to encrypted localStorage)
- Endpoint-restricted usage (tokens can only be used for specific endpoints)
- Automatic refresh for OAuth tokens
- Usage logging and auditing

#### Key Functions

```typescript
// Add a token
addToken(name: string, service: string, tokenValue: string, options?: {
  type?: 'api_key' | 'oauth_token' | 'personal_access_token'
  expiresAt?: Date
  allowedEndpoints?: string[]
  autoRefresh?: boolean
}): Promise<TokenEntry>

// Get a token (with validation)
getToken(tokenId: string, endpoint: string): Promise<{ token: string | null; error?: string }>

// Check vault health
checkHealth(): Promise<{
  totalTokens: number
  expiredTokens: number
  expiringSoon: number
  issues: string[]
}>
```

---

### useAccountAnonymizer.ts

**Purpose:** Automate changing emails to iCloud Hide My Email addresses across websites.

#### Workflow

1. Import accounts from Apple Passwords or LastPass
2. Generate iCloud Hide My Email addresses
3. Use browser automation to change email on each site
4. Sync new credentials back to password managers
5. Screenshot each change for audit trail

#### Key Functions

```typescript
// Import accounts
importAccounts(source: 'apple_passwords' | 'lastpass_csv', data?: string): Promise<number>

// Anonymize a single account
anonymizeAccount(accountId: string, options?: {
  headless?: boolean
  screenshotDir?: string
}): Promise<boolean>

// Batch operation
createTask(accountIds: string[]): AnonymizationTask
runTask(taskId: string): Promise<void>
pauseTask(taskId: string): void
resumeTask(taskId: string): Promise<void>
```

---

### useEmailCleaner.ts

**Purpose:** Safe inbox management with receipt preservation.

#### Safety Features

- **NEVER deletes receipts** (pattern-matched)
- **7-day quarantine** before permanent deletion
- **Safe unsubscribe** (clicks links, doesn't use bulk tools)
- **Sender reputation** tracking

#### Protected Patterns (Never Deleted)

```typescript
const RECEIPT_PATTERNS = [
  /order\s*confirm/i,
  /receipt/i,
  /invoice/i,
  /payment\s*confirm/i,
  /shipping\s*confirm/i,
  // ... more
]

const IMPORTANT_PATTERNS = [
  /password\s*reset/i,
  /security\s*alert/i,
  /tax\s*(document|form)/i,
  // ... more
]
```

#### Key Functions

```typescript
// Classify an email
classifyEmail(email: Partial<Email>): {
  category: 'primary' | 'spam' | 'receipt' | ...
  isReceipt: boolean
  isImportant: boolean
}

// Run cleaning pass
runCleaningPass(options?: { dryRun?: boolean }): Promise<{
  kept: number
  quarantined: number
  unsubscribed: number
}>

// Restore from quarantine
restoreFromQuarantine(emailId: string): Promise<boolean>

// Purge old quarantine (after 7 days)
purgeQuarantine(): Promise<number>
```

---

### useAutonomousImprover.ts

**Purpose:** The "perpetual ladder" - continuously improves your codebase.

#### Improvement Types

| Type | Risk | Auto-Apply? | Description |
|------|------|-------------|-------------|
| `formatting` | Low | Yes | Inconsistent indentation, trailing whitespace |
| `types` | Low | Yes | Missing TypeScript types, excessive `any` |
| `documentation` | Low | Yes | Missing JSDoc comments |
| `lint_fix` | Low | Yes | ESLint auto-fixable issues |
| `dead_code` | Medium | No | Commented code, unused TODO comments |
| `security` | High | No | Hardcoded secrets, SQL injection risks |
| `performance` | Medium | No | Sync file ops, N+1 queries |
| `refactor` | High | No | Code restructuring |
| `pattern` | Medium | No | Better patterns from other projects |

#### Key Functions

```typescript
// Scan a project
scanProject(projectPath: string): Promise<ScanResult>

// Apply an improvement
applyImprovement(improvementId: string): Promise<boolean>

// Rollback
rollbackImprovement(improvementId: string): Promise<boolean>

// Auto-apply low-risk (respects preferences)
autoApplyLowRisk(): Promise<number>
```

---

### useDaemonOrchestrator.ts

**Purpose:** Coordinates all systems for 24/7 operation.

#### Default Schedule

| Time | Task | Priority |
|------|------|----------|
| Every 30m | Health Check | Critical |
| Every 1h | Memory Index | Normal |
| Every 2h | Code Improvement Scan | Normal |
| Every 6h | Token Refresh | High |
| 4:00 AM | Backup | Normal |
| 6:00 AM | Email Clean | Low |

#### Key Functions

```typescript
// Lifecycle
start(): void
stop(): void
isAlive(): boolean

// Task management
addTask(task: Omit<ScheduledTask, 'id' | 'stats'>): ScheduledTask
setTaskEnabled(taskId: string, enabled: boolean): void
triggerTask(taskId: string): Promise<boolean>

// Approval system
requestApproval(type: TaskType, action: string, options: {...}): ApprovalRequest
approve(approvalId: string): Promise<boolean>
reject(approvalId: string, reason?: string): Promise<void>
```

---

## Safety Model

### Data Classification

```
┌─────────────────────────────────────────────────────────────────┐
│                    NEVER TRANSMIT                                │
│                                                                  │
│  • Source code (.ts, .js, .py, .rs, etc.)                       │
│  • Personal documents (PDFs, photos, videos)                     │
│  • Financial data (bank statements, tax docs)                    │
│  • Medical records                                               │
│  • Private keys, SSH keys, credentials                          │
│  • Personal notes, journals, diaries                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              TRANSMIT TO ALLOWLISTED ENDPOINTS ONLY              │
│                                                                  │
│  • api.github.com (git operations)                              │
│  • registry.npmjs.org (package installs)                        │
│  • localhost:11434 (Ollama - local LLM)                         │
│  • appleid.apple.com (iCloud API)                               │
│  • lastpass.com/api (password sync)                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 TRANSMIT WITH SANITIZATION                       │
│                                                                  │
│  • Web searches → PII stripped automatically                    │
│  • Error lookups → Stack traces sanitized                       │
│  • Documentation fetches → URL only, no context                 │
└─────────────────────────────────────────────────────────────────┘
```

### Approval Requirements

| Action | Risk | Approval |
|--------|------|----------|
| Read any file | Low | Auto |
| Format code | Low | Auto |
| Add types/docs | Low | Auto |
| Create git branch | Medium | Auto |
| Refactor code | High | Required |
| Delete file (permanent) | Critical | Required |
| Change password | Critical | Required |
| Send email | High | Required |

### Dead Man's Switch

The daemon will stop operating if:
- No `checkin()` call for 24 hours
- Constitution violations exceed threshold
- Audit log integrity is compromised

---

## Configuration Guide

### Initial Setup

```typescript
// In your App.vue or main.ts
import { useDaemonOrchestrator } from './composables/useDaemonOrchestrator'

const daemon = useDaemonOrchestrator()

// Configure memory indexing paths
daemon.subsystems.memory.config.indexedPaths = [
  '~/Developer',
  '~/Projects',
  '~/Code'
]
daemon.subsystems.memory.config.excludePatterns = [
  'node_modules', '.git', 'dist', 'build'
]
daemon.subsystems.memory.saveConfig()

// Start the daemon
daemon.start()
```

### Improvement Preferences

```typescript
const improver = daemon.subsystems.improver

// Configure what to auto-apply
improver.preferences.autoApplyLowRisk = true
improver.preferences.autoApplyFormatting = true
improver.preferences.autoApplyTypes = true
improver.preferences.autoApplyDocs = true
improver.preferences.maxChangesPerScan = 20
improver.savePreferences()
```

### Token Setup

```typescript
const vault = daemon.subsystems.tokenVault

// Add a GitHub token
await vault.addToken('GitHub', 'github.com', 'ghp_xxxx', {
  type: 'personal_access_token',
  allowedEndpoints: ['api.github.com'],
  expiresAt: new Date('2025-12-31')
})
```

---

## Usage Examples

### Finding Similar Code

```typescript
const memory = daemon.subsystems.memory

// Search for authentication-related code
const results = await memory.search('user authentication login', {
  types: ['file', 'solution'],
  limit: 10
})

// Find files similar to current one
const similar = await memory.findSimilar('/path/to/currentFile.ts')
```

### Manual Improvement Scan

```typescript
const improver = daemon.subsystems.improver

// Scan a specific project
const result = await improver.scanProject('~/Developer/my-project')
console.log(`Found ${result.improvementsFound} improvements`)

// Apply a specific improvement
await improver.applyImprovement('imp_xxx')

// Rollback if needed
await improver.rollbackImprovement('imp_xxx')
```

### Checking Approvals

```typescript
// Get pending approvals
const pending = daemon.pendingApprovals.value

for (const approval of pending) {
  console.log(`${approval.action} - ${approval.description}`)

  // Approve or reject
  await daemon.approve(approval.id)
  // or
  await daemon.reject(approval.id, 'Not needed')
}
```

---

## Scheduled Tasks

### Default Task Configuration

```typescript
const defaultTasks = [
  {
    name: 'Index Codebase',
    type: 'memory_index',
    intervalMinutes: 60,
    enabled: true
  },
  {
    name: 'Scan for Improvements',
    type: 'code_improve',
    intervalMinutes: 120,
    enabled: true
  },
  {
    name: 'Refresh Tokens',
    type: 'token_refresh',
    intervalMinutes: 360,
    enabled: true
  },
  {
    name: 'System Health Check',
    type: 'health_check',
    intervalMinutes: 30,
    enabled: true
  },
  {
    name: 'Backup Configuration',
    type: 'backup',
    cronPattern: '0 4 * * *',  // 4am daily
    enabled: true
  },
  {
    name: 'Clean Inbox',
    type: 'email_clean',
    cronPattern: '0 6 * * *',  // 6am daily
    enabled: false  // Disabled until configured
  }
]
```

### Adding Custom Tasks

```typescript
daemon.addTask({
  type: 'custom',
  name: 'My Custom Task',
  description: 'Does something custom',
  intervalMinutes: 120,
  nextRun: new Date(),
  enabled: true,
  priority: 'normal'
})
```

---

## Future Work

### Planned Features

- [ ] Voice interface (Whisper + Piper TTS)
- [ ] Visual understanding (screen capture + LLaVA)
- [ ] Calendar integration
- [ ] IMAP/Gmail API integration for email
- [ ] Real iCloud Hide My Email API
- [ ] Proactive suggestions ("you usually do X at this time")
- [ ] Learning from approval patterns

### Integration Points

- [ ] Warp_Open UI integration
- [ ] System tray icon for status
- [ ] Mobile notifications via PWA
- [ ] Tailscale integration for remote approval

---

## Changelog

### 2025-12-27
- Initial implementation of 8 core composables
- Constitutional safety model established
- Audit logging with hash chain
- Universal memory with embeddings
- Account anonymizer framework
- Email cleaner with receipt protection
- Autonomous code improver
- Daemon orchestrator for 24/7 operation

---

*This document will be updated as development continues.*
