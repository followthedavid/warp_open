// Task Decomposer
//
// Breaks complex tasks into simple, sequential steps.
// Each step should be achievable with a single tool call.

use serde::{Deserialize, Serialize};
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubTask {
    pub id: usize,
    pub description: String,
    pub suggested_tool: Option<String>,
    pub status: SubTaskStatus,
    pub result: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubTaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPlan {
    pub original_task: String,
    pub subtasks: Vec<SubTask>,
    pub current_step: usize,
    pub is_complete: bool,
}

impl TaskPlan {
    pub fn new(task: &str, subtasks: Vec<SubTask>) -> Self {
        Self {
            original_task: task.to_string(),
            subtasks,
            current_step: 0,
            is_complete: false,
        }
    }

    /// Get the current subtask
    pub fn current(&self) -> Option<&SubTask> {
        self.subtasks.get(self.current_step)
    }

    /// Get the current subtask mutably
    pub fn current_mut(&mut self) -> Option<&mut SubTask> {
        self.subtasks.get_mut(self.current_step)
    }

    /// Mark current step as completed and move to next
    pub fn complete_current(&mut self, result: String) {
        if let Some(subtask) = self.subtasks.get_mut(self.current_step) {
            subtask.status = SubTaskStatus::Completed;
            subtask.result = Some(result);
        }
        self.current_step += 1;
        if self.current_step >= self.subtasks.len() {
            self.is_complete = true;
        }
    }

    /// Mark current step as failed
    pub fn fail_current(&mut self, error: String) {
        if let Some(subtask) = self.subtasks.get_mut(self.current_step) {
            subtask.status = SubTaskStatus::Failed;
            subtask.error = Some(error);
        }
    }

    /// Get summary of completed steps for context
    pub fn completed_summary(&self) -> String {
        self.subtasks.iter()
            .filter(|s| s.status == SubTaskStatus::Completed)
            .map(|s| {
                let result = s.result.as_deref().unwrap_or("(no result)");
                // Truncate long results
                let truncated = if result.len() > 200 {
                    format!("{}...", &result[..200])
                } else {
                    result.to_string()
                };
                format!("✓ {}: {}", s.description, truncated)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get progress as a fraction
    pub fn progress(&self) -> (usize, usize) {
        let completed = self.subtasks.iter()
            .filter(|s| s.status == SubTaskStatus::Completed)
            .count();
        (completed, self.subtasks.len())
    }
}

pub struct TaskDecomposer {
    max_subtasks: usize,
    min_subtasks: usize,
}

impl TaskDecomposer {
    pub fn new() -> Self {
        Self {
            max_subtasks: 10,
            min_subtasks: 2,
        }
    }

    /// Generate the prompt to decompose a task
    pub fn get_decomposition_prompt(&self, task: &str) -> String {
        format!(r#"Break this task into {}-{} simple, sequential steps.
Each step should be doable with ONE tool call.

Task: {}

Available tools: read_file, write_file, edit_file, execute_shell, glob_files, grep_files, web_fetch

Format your response EXACTLY like this:
1. [Step description] -> [tool_name]
2. [Step description] -> [tool_name]
...

RULES:
- Each step must be simple (one action)
- Steps must be in logical order
- Include the tool name after ->
- No explanations, just the numbered list
"#, self.min_subtasks, self.max_subtasks, task)
    }

    /// Parse decomposition response from LLM
    pub fn parse_decomposition(&self, response: &str) -> Result<Vec<SubTask>, String> {
        let line_re = Regex::new(r"(\d+)\.\s*(.+?)(?:\s*->\s*(\w+))?$").unwrap();

        let mut subtasks = Vec::new();

        for line in response.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(caps) = line_re.captures(trimmed) {
                let id: usize = caps.get(1).unwrap().as_str().parse().unwrap_or(subtasks.len() + 1);
                let description = caps.get(2).unwrap().as_str().trim().to_string();
                let tool = caps.get(3).map(|m| m.as_str().to_string());

                subtasks.push(SubTask {
                    id,
                    description,
                    suggested_tool: tool,
                    status: SubTaskStatus::Pending,
                    result: None,
                    error: None,
                });
            }
        }

        if subtasks.len() < self.min_subtasks {
            return Err(format!(
                "Too few steps: {} (need at least {})",
                subtasks.len(),
                self.min_subtasks
            ));
        }

        if subtasks.len() > self.max_subtasks {
            // Truncate to max
            subtasks.truncate(self.max_subtasks);
        }

        Ok(subtasks)
    }

    /// Check if a task needs decomposition
    pub fn needs_decomposition(&self, task: &str) -> bool {
        let lower = task.to_lowercase();

        // Multi-step indicators
        let multi_step_words = [
            " and ", " then ", " after ", " before ",
            "create", "build", "implement", "refactor",
            "set up", "configure", "migrate",
        ];

        // Simple task indicators (single step)
        let simple_words = [
            "read", "show", "what is", "find", "search",
            "list", "run", "execute", "explain",
        ];

        // Count indicators
        let multi_count = multi_step_words.iter()
            .filter(|w| lower.contains(*w))
            .count();

        let simple_count = simple_words.iter()
            .filter(|w| lower.contains(*w))
            .count();

        // Also check length - longer tasks usually need decomposition
        let word_count = task.split_whitespace().count();

        multi_count > simple_count || word_count > 15
    }

    /// Create a simple single-step plan for simple tasks
    pub fn create_simple_plan(&self, task: &str) -> TaskPlan {
        TaskPlan::new(task, vec![
            SubTask {
                id: 1,
                description: task.to_string(),
                suggested_tool: None,
                status: SubTaskStatus::Pending,
                result: None,
                error: None,
            }
        ])
    }

    /// Generate context prompt for executing a subtask
    pub fn get_subtask_prompt(&self, plan: &TaskPlan) -> Option<String> {
        let current = plan.current()?;

        let mut prompt = format!(
            r#"OVERALL TASK: {}

PROGRESS: Step {}/{}"#,
            plan.original_task,
            plan.current_step + 1,
            plan.subtasks.len()
        );

        // Add completed steps summary
        let completed = plan.completed_summary();
        if !completed.is_empty() {
            prompt.push_str("\n\nCOMPLETED STEPS:\n");
            prompt.push_str(&completed);
        }

        // Add current step
        prompt.push_str(&format!(
            r#"

CURRENT STEP: {}

Execute ONLY this step. Output ONE tool call."#,
            current.description
        ));

        if let Some(tool) = &current.suggested_tool {
            prompt.push_str(&format!("\nSuggested tool: {}", tool));
        }

        Some(prompt)
    }
}

impl Default for TaskDecomposer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_decomposition() {
        let decomposer = TaskDecomposer::new();
        let response = r#"
1. Read the current file contents -> read_file
2. Find the function to modify -> grep_files
3. Edit the function -> edit_file
4. Run the tests -> execute_shell
"#;
        let result = decomposer.parse_decomposition(response);
        assert!(result.is_ok());
        let subtasks = result.unwrap();
        assert_eq!(subtasks.len(), 4);
        assert_eq!(subtasks[0].suggested_tool, Some("read_file".to_string()));
        assert_eq!(subtasks[2].suggested_tool, Some("edit_file".to_string()));
    }

    #[test]
    fn test_needs_decomposition() {
        let decomposer = TaskDecomposer::new();

        // Simple tasks
        assert!(!decomposer.needs_decomposition("read main.rs"));
        assert!(!decomposer.needs_decomposition("show me the file"));
        assert!(!decomposer.needs_decomposition("run the tests"));

        // Complex tasks
        assert!(decomposer.needs_decomposition("create a new module and add tests"));
        assert!(decomposer.needs_decomposition("refactor the user authentication system"));
        assert!(decomposer.needs_decomposition("implement a caching layer for the API"));
    }

    #[test]
    fn test_task_plan_progress() {
        let subtasks = vec![
            SubTask {
                id: 1,
                description: "Step 1".to_string(),
                suggested_tool: None,
                status: SubTaskStatus::Pending,
                result: None,
                error: None,
            },
            SubTask {
                id: 2,
                description: "Step 2".to_string(),
                suggested_tool: None,
                status: SubTaskStatus::Pending,
                result: None,
                error: None,
            },
        ];

        let mut plan = TaskPlan::new("Test task", subtasks);

        assert_eq!(plan.progress(), (0, 2));
        assert!(!plan.is_complete);

        plan.complete_current("Result 1".to_string());
        assert_eq!(plan.progress(), (1, 2));
        assert!(!plan.is_complete);

        plan.complete_current("Result 2".to_string());
        assert_eq!(plan.progress(), (2, 2));
        assert!(plan.is_complete);
    }

    #[test]
    fn test_completed_summary() {
        let subtasks = vec![
            SubTask {
                id: 1,
                description: "Read file".to_string(),
                suggested_tool: None,
                status: SubTaskStatus::Completed,
                result: Some("File contents here".to_string()),
                error: None,
            },
            SubTask {
                id: 2,
                description: "Edit file".to_string(),
                suggested_tool: None,
                status: SubTaskStatus::Pending,
                result: None,
                error: None,
            },
        ];

        let plan = TaskPlan::new("Test", subtasks);
        let summary = plan.completed_summary();

        assert!(summary.contains("Read file"));
        assert!(summary.contains("File contents here"));
        assert!(!summary.contains("Edit file"));
    }

    #[test]
    fn test_too_few_steps_rejected() {
        let decomposer = TaskDecomposer::new();
        let response = "1. Do everything";
        let result = decomposer.parse_decomposition(response);
        assert!(result.is_err());
    }
}
