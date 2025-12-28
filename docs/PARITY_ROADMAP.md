# Warp_Open Parity Roadmap

## Goal: 100% Feature Parity with Claude Code + Warp Terminal

---

## Part 1: The Intelligence Gap (Most Critical)

### Problem: Ollama models are not smart enough

**Option A: Use Claude API directly**
- Pros: Same intelligence as Claude Code, battle-tested
- Cons: Costs money, requires internet, not "local-first"
- Implementation: ~2 hours (swap Ollama endpoint for Anthropic API)

**Option B: Use a smarter local model**
- `deepseek-coder-v2:33b` - Good at code, needs 24GB+ VRAM
- `codestral:22b` - Mistral's code model
- `qwen2.5:32b` - Better reasoning than 7b
- Cons: Slower, needs beefy hardware

**Option C: Hybrid approach (RECOMMENDED)**
- Use Ollama for fast/simple tasks (autocomplete, quick questions)
- Use Claude API for complex tasks (multi-file edits, planning)
- Let user choose per-task or auto-detect complexity

```rust
// Pseudo-code for hybrid routing
fn route_query(query: &str, complexity: Complexity) -> Backend {
    match complexity {
        Complexity::Simple => Backend::Ollama,      // "what does this error mean?"
        Complexity::Medium => Backend::Ollama,      // "fix this bug"
        Complexity::Complex => Backend::Claude,     // "refactor this module"
        Complexity::Agentic => Backend::Claude,     // "build feature X"
    }
}
```

---

## Part 2: The Agentic Loop (What Makes Claude Code Work)

### Current Warp_Open Flow:
```
User message → AI response → Done
```

### Claude Code Flow:
```
User message
    → AI thinks + plans
    → AI calls tool
    → System executes tool
    → Result fed back to AI
    → AI calls another tool (loop)
    → ... (continues until task done)
    → AI gives final response
```

### Implementation Required:

**1. Agentic Loop Controller** (`src-tauri/src/agent_loop.rs`)
```rust
pub struct AgentLoop {
    max_iterations: u32,
    current_iteration: u32,
    tool_results: Vec<ToolResult>,
    state: AgentState,
}

impl AgentLoop {
    pub async fn run(&mut self, initial_prompt: &str) -> Result<String> {
        loop {
            // 1. Send context to LLM
            let response = self.query_llm().await?;

            // 2. Parse for tool calls
            if let Some(tool_call) = parse_tool_call(&response) {
                // 3. Execute tool
                let result = self.execute_tool(tool_call).await?;

                // 4. Add result to context
                self.tool_results.push(result);

                // 5. Check if done or continue
                if self.is_task_complete() || self.current_iteration >= self.max_iterations {
                    break;
                }
                self.current_iteration += 1;
            } else {
                // No tool call = final response
                return Ok(response);
            }
        }
    }
}
```

**2. Tool Result Feedback**
- Currently: Tool executes, result shown to user only
- Needed: Tool result automatically fed back to AI for next step

**3. Iteration Limits & Safety**
- Max 25 iterations per task (like Claude Code)
- Cost tracking for API calls
- User can cancel mid-loop

---

## Part 3: Context Management (Memory)

### Current Problem:
- Conversation truncates to ~10 messages
- AI forgets what it did 5 minutes ago

### Solution: Sliding Window + Summarization

**1. Conversation Summarization**
```rust
struct ConversationManager {
    full_history: Vec<Message>,      // Everything ever said
    working_context: Vec<Message>,   // What AI sees (summarized)
    summary: String,                 // "Previously: user asked to build X..."
}

impl ConversationManager {
    fn prepare_context(&self) -> Vec<Message> {
        let mut ctx = vec![];

        // Always include system prompt
        ctx.push(self.system_prompt.clone());

        // Add summary of old conversation
        if !self.summary.is_empty() {
            ctx.push(Message::system(format!(
                "[Previous context summary]\n{}",
                self.summary
            )));
        }

        // Add recent messages (last 20)
        ctx.extend(self.full_history.iter().rev().take(20).rev().cloned());

        ctx
    }

    async fn maybe_summarize(&mut self) {
        if self.full_history.len() > 50 {
            // Use AI to summarize old messages
            self.summary = summarize_conversation(&self.full_history[..30]).await;
            // Keep only recent in working memory
        }
    }
}
```

**2. File Context Caching**
- Remember which files were read this session
- Include file summaries in context
- Don't re-read files unnecessarily

---

## Part 4: Planning System

### What Claude Code Has:
- `EnterPlanMode` - Stop and plan before coding
- `TodoWrite` - Track tasks
- `ExitPlanMode` - Get approval before executing

### Implementation:

**1. Plan Mode State**
```typescript
interface PlanState {
  isInPlanMode: boolean;
  currentPlan: string;
  planFile: string;
  todos: Todo[];
  awaitingApproval: boolean;
}
```

**2. Todo Tracking**
```rust
#[derive(Serialize, Deserialize)]
pub struct Todo {
    pub content: String,
    pub status: TodoStatus,  // pending, in_progress, completed
    pub created_at: i64,
}

#[tauri::command]
pub fn todo_write(todos: Vec<Todo>) -> Result<(), String> {
    // Persist todos
    // Emit event to UI
}
```

**3. Plan File**
- Write plan to `~/.warp_open/plans/{task_id}.md`
- Show plan in UI for approval
- User can edit before approving

---

## Part 5: Self-Correction & Error Handling

### Current Problem:
- Tool fails → Error shown to user → AI doesn't know

### Solution:

**1. Automatic Error Feedback**
```rust
async fn execute_tool_with_feedback(tool: ToolCall) -> ToolResult {
    match execute_tool(tool).await {
        Ok(result) => ToolResult::Success(result),
        Err(e) => {
            // Feed error back to AI automatically
            ToolResult::Error {
                error: e.to_string(),
                suggestion: suggest_fix(&e),
            }
        }
    }
}
```

**2. Retry Logic**
```rust
const MAX_RETRIES: u32 = 3;

async fn execute_with_retry(tool: ToolCall) -> Result<String> {
    for attempt in 0..MAX_RETRIES {
        match execute_tool(&tool).await {
            Ok(result) => return Ok(result),
            Err(e) if is_retryable(&e) => {
                // Let AI try a different approach
                let fixed_tool = ai_fix_tool_call(&tool, &e).await?;
                tool = fixed_tool;
            }
            Err(e) => return Err(e),
        }
    }
}
```

---

## Part 6: Warp Terminal UX Features

### Already Implemented (but broken):
- [ ] Command blocks - needs debugging
- [ ] Split panes - works
- [ ] Tabs - works

### Missing:
- [ ] **Ghost text autocomplete** - AI suggests as you type
- [ ] **# AI trigger** - Type # in terminal to invoke AI inline
- [ ] **Command palette** - ⌘K for quick actions
- [ ] **Workflows** - Saved command sequences
- [ ] **AI command suggestions** - "Did you mean...?"

### Ghost Text Implementation:
```typescript
// In TerminalPane.vue
const ghostText = ref('')
const showGhost = ref(false)

// Debounced autocomplete
watch(inputBuffer, debounce(async (input) => {
  if (input.length > 2) {
    ghostText.value = await invoke('get_ai_completion', {
      partial: input,
      cwd: currentCwd.value
    })
    showGhost.value = true
  }
}, 300))

// Tab to accept
terminal.attachCustomKeyEventHandler((e) => {
  if (e.key === 'Tab' && showGhost.value) {
    // Insert ghost text
    invoke('send_input', { id: ptyId, input: ghostText.value })
    showGhost.value = false
    return false
  }
})
```

---

## Part 7: Testing & Reliability

### Current State:
- 339 Rust unit tests
- No integration tests
- No E2E tests for AI features

### Needed:
1. **AI Tool Integration Tests** - Verify each tool works with real AI
2. **Agentic Loop Tests** - Multi-step task completion
3. **Regression Tests** - Prevent UI bugs like infinite bubbles

---

## Implementation Priority

### Phase 1: Fix Current Bugs (1-2 days)
1. Fix infinite bubbles bug
2. Fix disappearing text
3. Debug command blocks

### Phase 2: Agentic Loop (3-5 days)
1. Implement agent loop controller
2. Add tool result feedback
3. Add iteration limits

### Phase 3: Context Management (2-3 days)
1. Conversation summarization
2. File context caching
3. Sliding window

### Phase 4: Planning System (2-3 days)
1. Todo tracking
2. Plan mode
3. Approval flow

### Phase 5: Intelligence Upgrade (1-2 days)
1. Claude API integration
2. Hybrid routing
3. Model selection UI

### Phase 6: Warp UX Features (3-5 days)
1. Ghost text autocomplete
2. # AI trigger
3. Command palette

### Phase 7: Testing (Ongoing)
1. Integration tests
2. E2E tests
3. Performance benchmarks

---

## Total Estimated Effort

| Phase | Effort | Priority |
|-------|--------|----------|
| Phase 1: Bug Fixes | 1-2 days | CRITICAL |
| Phase 2: Agentic Loop | 3-5 days | HIGH |
| Phase 3: Context | 2-3 days | HIGH |
| Phase 4: Planning | 2-3 days | MEDIUM |
| Phase 5: Intelligence | 1-2 days | HIGH |
| Phase 6: UX Features | 3-5 days | MEDIUM |
| Phase 7: Testing | Ongoing | HIGH |

**Total: ~15-22 days of focused work**

---

## Decision Needed: Intelligence Backend

Before starting, you need to decide:

1. **Ollama Only** - Free, private, but limited intelligence
2. **Claude API Only** - Smart, costs ~$20-100/month depending on usage
3. **Hybrid** - Best of both, more complex to implement

My recommendation: **Start with Claude API** for the agentic features (Phase 2-4), then add Ollama for simple tasks later. The agentic loop won't work well with current local models.
