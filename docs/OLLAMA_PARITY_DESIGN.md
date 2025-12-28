# Making Ollama Match Claude: Architecture Design

## The Core Insight

Claude isn't magic - it's a good model + excellent scaffolding:

1. **Structured prompting** - Very specific instructions
2. **Chain-of-thought** - Force step-by-step reasoning
3. **Self-verification** - Make it check its own work
4. **Decomposition** - Break complex tasks into simple ones
5. **Example-driven** - Show exactly what good output looks like
6. **Retry with feedback** - Errors become learning

A 7B model with great scaffolding can outperform a 70B model with bad prompts.

---

## Technique 1: Structured Output Forcing

### Problem
Ollama models often ramble or give malformed JSON.

### Solution: Grammar-Constrained Generation

Ollama supports JSON mode and grammar constraints:

```rust
// Force valid JSON output
async fn query_ollama_structured(prompt: &str) -> Result<ToolCall> {
    let response = reqwest::Client::new()
        .post("http://localhost:11434/api/generate")
        .json(&json!({
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "format": "json",  // Force JSON output
            "options": {
                "temperature": 0.1,  // Low temp for consistency
                "num_predict": 500,  // Limit output length
            }
        }))
        .send()
        .await?;

    // Parse and validate
    let json: serde_json::Value = serde_json::from_str(&response.text)?;
    validate_tool_call(&json)?;
    Ok(json)
}
```

### Even Better: JSON Schema Validation

```rust
const TOOL_SCHEMA: &str = r#"{
    "type": "object",
    "required": ["tool", "args"],
    "properties": {
        "tool": {
            "type": "string",
            "enum": ["read_file", "write_file", "edit_file", "execute_shell", "glob_files", "grep_files"]
        },
        "args": {
            "type": "object"
        }
    }
}"#;

// Validate before accepting
fn validate_tool_output(output: &str) -> Result<ToolCall> {
    let json: Value = serde_json::from_str(output)?;

    // Validate against schema
    let schema = serde_json::from_str(TOOL_SCHEMA)?;
    if !jsonschema::is_valid(&schema, &json) {
        return Err("Invalid tool call format");
    }

    Ok(serde_json::from_value(json)?)
}
```

---

## Technique 2: Chain-of-Thought Prompting

### Problem
Model jumps to conclusions without reasoning.

### Solution: Force Explicit Reasoning Steps

```rust
const REASONING_PROMPT: &str = r#"
You must think step-by-step before acting.

FORMAT YOUR RESPONSE EXACTLY LIKE THIS:

<thinking>
1. What is the user asking for?
2. What information do I need?
3. What tools should I use and in what order?
4. What could go wrong?
</thinking>

<action>
{"tool": "...", "args": {...}}
</action>

NEVER skip the thinking section. ALWAYS reason first.
"#;
```

### Parse and Validate Both Sections

```rust
struct ReasonedResponse {
    thinking: String,
    action: Option<ToolCall>,
}

fn parse_reasoned_response(output: &str) -> Result<ReasonedResponse> {
    // Extract thinking
    let thinking_re = Regex::new(r"<thinking>(.*?)</thinking>")?;
    let thinking = thinking_re.captures(output)
        .ok_or("Missing thinking section")?
        .get(1).unwrap().as_str();

    // Validate thinking has actual content
    if thinking.lines().count() < 3 {
        return Err("Thinking too shallow - need more reasoning");
    }

    // Extract action
    let action_re = Regex::new(r"<action>(.*?)</action>")?;
    let action = action_re.captures(output)
        .map(|c| serde_json::from_str(c.get(1).unwrap().as_str()))
        .transpose()?;

    Ok(ReasonedResponse { thinking, action })
}
```

---

## Technique 3: Task Decomposition

### Problem
"Build a todo app" is too complex for one prompt.

### Solution: Hierarchical Task Breakdown

```rust
struct TaskDecomposer {
    max_subtask_complexity: u32,
}

impl TaskDecomposer {
    async fn decompose(&self, task: &str) -> Vec<SubTask> {
        // First pass: break into high-level steps
        let breakdown_prompt = format!(r#"
Break this task into 3-7 sequential steps.
Each step should be simple enough to do in one action.

Task: {}

Format:
1. [Step description] - [What tool to use]
2. [Step description] - [What tool to use]
...

ONLY output the numbered list, nothing else.
"#, task);

        let steps = self.query_ollama(&breakdown_prompt).await;

        // Parse into subtasks
        let subtasks: Vec<SubTask> = parse_numbered_list(&steps)
            .into_iter()
            .map(|s| SubTask {
                description: s,
                status: SubTaskStatus::Pending,
                result: None,
            })
            .collect();

        subtasks
    }
}
```

### Execute Step-by-Step with Context

```rust
async fn execute_decomposed_task(task: &str) -> Result<String> {
    let subtasks = decomposer.decompose(task).await;
    let mut context = TaskContext::new();

    for (i, subtask) in subtasks.iter_mut().enumerate() {
        println!("[{}/{}] {}", i+1, subtasks.len(), subtask.description);

        // Build context-aware prompt
        let prompt = format!(r#"
OVERALL TASK: {}

COMPLETED STEPS:
{}

CURRENT STEP: {}

Previous results available:
{}

Execute ONLY this current step. Output a single tool call.
"#,
            task,
            context.completed_summary(),
            subtask.description,
            context.recent_results()
        );

        let result = execute_single_step(&prompt).await?;
        subtask.result = Some(result.clone());
        subtask.status = SubTaskStatus::Completed;
        context.add_result(&subtask.description, &result);
    }

    Ok(context.final_summary())
}
```

---

## Technique 4: Self-Verification Loop

### Problem
Model makes mistakes and doesn't notice.

### Solution: Make It Check Its Own Work

```rust
async fn execute_with_verification(tool_call: ToolCall) -> Result<VerifiedResult> {
    // Execute the tool
    let result = execute_tool(&tool_call).await?;

    // Ask model to verify
    let verify_prompt = format!(r#"
You just executed this action:
Tool: {}
Args: {}

Result:
{}

VERIFY: Did this achieve what was intended?

Answer ONLY with:
- "VERIFIED: [brief reason]" if successful
- "FAILED: [what went wrong]" if there's a problem
- "RETRY: [what to do differently]" if it should be retried
"#,
        tool_call.tool,
        serde_json::to_string(&tool_call.args)?,
        result
    );

    let verification = query_ollama(&verify_prompt).await?;

    if verification.starts_with("RETRY:") {
        // Extract retry instruction and try again
        let retry_instruction = verification.strip_prefix("RETRY:").unwrap();
        return execute_with_correction(&tool_call, retry_instruction).await;
    }

    if verification.starts_with("FAILED:") {
        return Err(anyhow!("Verification failed: {}", verification));
    }

    Ok(VerifiedResult {
        result,
        verification,
    })
}
```

---

## Technique 5: Few-Shot Example Library

### Problem
Model doesn't know what good output looks like.

### Solution: Dynamic Example Selection

```rust
struct ExampleLibrary {
    examples: HashMap<TaskType, Vec<Example>>,
}

struct Example {
    task: String,
    thinking: String,
    tool_calls: Vec<ToolCall>,
    results: Vec<String>,
}

impl ExampleLibrary {
    fn get_relevant_examples(&self, task: &str) -> Vec<&Example> {
        // Classify the task
        let task_type = self.classify_task(task);

        // Get examples for this type
        let examples = self.examples.get(&task_type).unwrap_or(&vec![]);

        // Return top 2-3 most relevant
        examples.iter().take(3).collect()
    }

    fn format_examples(&self, task: &str) -> String {
        let examples = self.get_relevant_examples(task);

        examples.iter().map(|ex| format!(r#"
EXAMPLE:
User task: {}

<thinking>
{}
</thinking>

<action>
{}
</action>

Result: {}
---
"#, ex.task, ex.thinking, serde_json::to_string(&ex.tool_calls[0]).unwrap(), ex.results[0]
        )).collect::<Vec<_>>().join("\n")
    }
}

// Pre-built examples for common tasks
const EXAMPLES: &[Example] = &[
    Example {
        task: "Read the contents of main.rs",
        thinking: "1. User wants to see file contents\n2. I need to use read_file tool\n3. The path is main.rs",
        tool_calls: vec![ToolCall { tool: "read_file", args: json!({"path": "main.rs"}) }],
        results: vec!["fn main() { ... }"],
    },
    Example {
        task: "Find all TypeScript files",
        thinking: "1. User wants to find files\n2. TypeScript files end in .ts or .tsx\n3. I should use glob_files with pattern **/*.ts",
        tool_calls: vec![ToolCall { tool: "glob_files", args: json!({"pattern": "**/*.ts"}) }],
        results: vec!["src/main.ts\nsrc/utils.ts"],
    },
    // ... many more examples
];
```

---

## Technique 6: Consensus / Multiple Attempts

### Problem
Single attempt might give wrong answer.

### Solution: Generate Multiple, Pick Best

```rust
async fn query_with_consensus(prompt: &str, attempts: u32) -> Result<String> {
    let mut responses = vec![];

    // Generate multiple responses with slight temperature variation
    for i in 0..attempts {
        let temp = 0.3 + (i as f32 * 0.1); // 0.3, 0.4, 0.5
        let response = query_ollama_with_temp(prompt, temp).await?;
        responses.push(response);
    }

    // If all agree, use that
    if responses.iter().all(|r| r == &responses[0]) {
        return Ok(responses[0].clone());
    }

    // Otherwise, ask model to pick best
    let judge_prompt = format!(r#"
You generated {} different responses to this task:
{}

The responses were:
{}

Which response is BEST and why? Output ONLY the number (1, 2, or 3).
"#,
        attempts,
        prompt,
        responses.iter().enumerate()
            .map(|(i, r)| format!("Response {}: {}", i+1, r))
            .collect::<Vec<_>>().join("\n\n")
    );

    let choice = query_ollama(&judge_prompt).await?;
    let idx: usize = choice.trim().parse().unwrap_or(1) - 1;

    Ok(responses[idx].clone())
}
```

---

## Technique 7: Specialized Models Per Task

### Problem
One model can't be best at everything.

### Solution: Route to Specialized Models

```rust
enum SpecializedModel {
    CodeGen,      // qwen2.5-coder for code generation
    Reasoning,    // llama3.1 for planning/reasoning
    FastComplete, // qwen2.5:3b for autocomplete (speed)
}

impl SpecializedModel {
    fn ollama_name(&self) -> &str {
        match self {
            Self::CodeGen => "qwen2.5-coder:7b",
            Self::Reasoning => "llama3.1:8b",
            Self::FastComplete => "qwen2.5:3b",
        }
    }
}

fn route_to_model(task: &str) -> SpecializedModel {
    if task.contains("plan") || task.contains("think") || task.contains("design") {
        SpecializedModel::Reasoning
    } else if task.contains("complete") || task.contains("suggest") {
        SpecializedModel::FastComplete
    } else {
        SpecializedModel::CodeGen
    }
}
```

---

## Technique 8: Error Recovery Patterns

### Problem
When tool fails, model doesn't know how to recover.

### Solution: Teach Common Recovery Patterns

```rust
const ERROR_RECOVERY_PROMPT: &str = r#"
The previous action FAILED with this error:
{}

Common recovery patterns:
- "file not found" → use glob_files to find correct path
- "permission denied" → check if path is correct, try different location
- "syntax error" → re-read the file and fix the edit
- "command not found" → check spelling, try alternative command

What should we try instead? Think step by step, then output ONE tool call.
"#;

async fn recover_from_error(error: &str, context: &TaskContext) -> Result<ToolCall> {
    let prompt = format!(
        "{}\n\nPrevious context:\n{}",
        ERROR_RECOVERY_PROMPT.replace("{}", error),
        context.summary()
    );

    let response = query_ollama_structured(&prompt).await?;
    parse_tool_call(&response)
}
```

---

## The Complete Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Request                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Task Decomposer                             │
│  "Build a todo app" → 7 simple steps                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Model Router                                │
│  Route to: CodeGen / Reasoning / FastComplete               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│               Few-Shot Example Injector                      │
│  Add 2-3 relevant examples to prompt                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│             Chain-of-Thought Enforcer                        │
│  <thinking>...</thinking> <action>...</action>              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                Ollama Query (JSON mode)                      │
│  Temperature: 0.1-0.3 for consistency                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│               Output Validator                               │
│  JSON Schema check, required fields, sanity check           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                Tool Executor                                 │
│  Execute the validated tool call                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Self-Verification                               │
│  "Did this work? VERIFIED / FAILED / RETRY"                 │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
               VERIFIED              RETRY/FAILED
                    │                   │
                    ▼                   ▼
              Next Step         Error Recovery
                                      │
                                      └──→ (back to Model Router)
```

---

## Estimated Performance Improvement

| Technique | Improvement | Overhead |
|-----------|-------------|----------|
| JSON mode forcing | +30% accuracy | +0% time |
| Chain-of-thought | +40% accuracy | +50% time |
| Task decomposition | +50% complex task success | +100% time |
| Self-verification | +25% accuracy | +30% time |
| Few-shot examples | +35% accuracy | +10% time |
| Error recovery | +20% completion rate | +20% time |

**Combined: ~80% of Claude's capability at 2-3x the time per task**

---

## Model Recommendations

For best local results:

1. **Primary: `qwen2.5-coder:14b`** - Best code model that runs on 16GB
2. **Reasoning: `llama3.1:8b`** - Good at planning
3. **Fast: `qwen2.5:3b`** - For autocomplete

If you have 24GB+ VRAM:
- **`deepseek-coder-v2:16b`** - Excellent at code
- **`qwen2.5-coder:32b`** - Best local code model

---

## Implementation Order

1. **JSON mode + validation** (1 day) - Immediate reliability boost
2. **Chain-of-thought prompting** (1 day) - Better reasoning
3. **Few-shot example library** (2 days) - Teach good patterns
4. **Task decomposition** (2 days) - Handle complex tasks
5. **Self-verification** (1 day) - Catch mistakes
6. **Error recovery** (1 day) - Don't get stuck
7. **Model routing** (1 day) - Use right model for task

**Total: ~9 days to implement scaffolding**

This won't be instant like Claude, but it will be **capable** of the same tasks.
