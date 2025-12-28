// Few-Shot Example Library
//
// Provides relevant examples to teach the model what good output looks like.
// Examples are selected based on task similarity.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Example {
    pub task_type: TaskType,
    pub user_request: String,
    pub thinking: String,
    pub tool_call: String,
    pub result: String,
    pub follow_up: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskType {
    ReadFile,
    WriteFile,
    EditFile,
    FindFiles,
    SearchCode,
    RunCommand,
    MultiStep,
    Debug,
    Refactor,
    Explain,
}

impl TaskType {
    /// Classify a user request into a task type
    pub fn classify(request: &str) -> Self {
        let lower = request.to_lowercase();

        // Multi-step indicators
        if lower.contains(" and ") || lower.contains(" then ") ||
           lower.contains("create") && lower.contains("test") {
            return Self::MultiStep;
        }

        // Specific patterns
        if lower.contains("read") || lower.contains("show me") || lower.contains("what's in") {
            return Self::ReadFile;
        }
        if lower.contains("write") || lower.contains("create file") || lower.contains("new file") {
            return Self::WriteFile;
        }
        if lower.contains("edit") || lower.contains("change") || lower.contains("modify") ||
           lower.contains("replace") || lower.contains("update") {
            return Self::EditFile;
        }
        if lower.contains("find") || lower.contains("where") || lower.contains("list") {
            return Self::FindFiles;
        }
        if lower.contains("search") || lower.contains("grep") || lower.contains("look for") {
            return Self::SearchCode;
        }
        if lower.contains("run") || lower.contains("execute") || lower.contains("build") ||
           lower.contains("test") || lower.contains("install") {
            return Self::RunCommand;
        }
        if lower.contains("debug") || lower.contains("fix") || lower.contains("error") ||
           lower.contains("bug") || lower.contains("broken") {
            return Self::Debug;
        }
        if lower.contains("refactor") || lower.contains("clean up") || lower.contains("improve") {
            return Self::Refactor;
        }
        if lower.contains("explain") || lower.contains("what does") || lower.contains("how does") {
            return Self::Explain;
        }

        // Default to multi-step for complex requests
        Self::MultiStep
    }
}

pub struct ExampleLibrary {
    examples: HashMap<TaskType, Vec<Example>>,
}

impl ExampleLibrary {
    pub fn new() -> Self {
        let mut examples = HashMap::new();

        // Read file examples
        examples.insert(TaskType::ReadFile, vec![
            Example {
                task_type: TaskType::ReadFile,
                user_request: "Show me the contents of main.rs".to_string(),
                thinking: r#"1. User wants to see file contents
2. I need to use read_file tool
3. The path is main.rs (relative to current directory)
4. This is a simple read operation"#.to_string(),
                tool_call: r#"{"tool": "read_file", "args": {"path": "main.rs"}}"#.to_string(),
                result: "fn main() {\n    println!(\"Hello, world!\");\n}".to_string(),
                follow_up: None,
            },
            Example {
                task_type: TaskType::ReadFile,
                user_request: "What's in the package.json?".to_string(),
                thinking: r#"1. User wants to see package.json contents
2. This is a JSON file at the project root
3. I'll use read_file to get it
4. Should return the full file contents"#.to_string(),
                tool_call: r#"{"tool": "read_file", "args": {"path": "package.json"}}"#.to_string(),
                result: r#"{"name": "my-app", "version": "1.0.0"}"#.to_string(),
                follow_up: None,
            },
        ]);

        // Find files examples
        examples.insert(TaskType::FindFiles, vec![
            Example {
                task_type: TaskType::FindFiles,
                user_request: "Find all TypeScript files".to_string(),
                thinking: r#"1. User wants to list TypeScript files
2. TypeScript files have .ts or .tsx extension
3. I should use glob_files with pattern **/*.ts
4. This will search recursively"#.to_string(),
                tool_call: r#"{"tool": "glob_files", "args": {"pattern": "**/*.ts"}}"#.to_string(),
                result: "src/main.ts\nsrc/utils.ts\nsrc/types.ts".to_string(),
                follow_up: None,
            },
            Example {
                task_type: TaskType::FindFiles,
                user_request: "List all files in the src directory".to_string(),
                thinking: r#"1. User wants to see files in src/
2. I'll use glob_files with path constraint
3. Pattern src/* will get top-level files
4. Use src/**/* for recursive listing"#.to_string(),
                tool_call: r#"{"tool": "glob_files", "args": {"pattern": "**/*", "path": "src"}}"#.to_string(),
                result: "src/main.rs\nsrc/lib.rs\nsrc/utils/mod.rs".to_string(),
                follow_up: None,
            },
        ]);

        // Search code examples
        examples.insert(TaskType::SearchCode, vec![
            Example {
                task_type: TaskType::SearchCode,
                user_request: "Find where the User struct is defined".to_string(),
                thinking: r#"1. User wants to find a struct definition
2. I should search for "struct User"
3. grep_files is the right tool
4. This will show file and line number"#.to_string(),
                tool_call: r#"{"tool": "grep_files", "args": {"pattern": "struct User"}}"#.to_string(),
                result: "src/models.rs:15: pub struct User {".to_string(),
                follow_up: None,
            },
            Example {
                task_type: TaskType::SearchCode,
                user_request: "Search for TODO comments".to_string(),
                thinking: r#"1. User wants to find TODO comments
2. Pattern should match "TODO" case-insensitively
3. Use grep_files with case_insensitive option
4. This will find all TODO markers"#.to_string(),
                tool_call: r#"{"tool": "grep_files", "args": {"pattern": "TODO", "case_insensitive": true}}"#.to_string(),
                result: "src/main.rs:42: // TODO: implement error handling\nsrc/utils.rs:10: // TODO: add tests".to_string(),
                follow_up: None,
            },
        ]);

        // Write file examples
        examples.insert(TaskType::WriteFile, vec![
            Example {
                task_type: TaskType::WriteFile,
                user_request: "Create a new file called hello.txt with 'Hello World'".to_string(),
                thinking: r#"1. User wants to create a new file
2. File name is hello.txt
3. Content should be "Hello World"
4. Use write_file to create it"#.to_string(),
                tool_call: r#"{"tool": "write_file", "args": {"path": "hello.txt", "content": "Hello World"}}"#.to_string(),
                result: "File written successfully: hello.txt".to_string(),
                follow_up: None,
            },
        ]);

        // Edit file examples
        examples.insert(TaskType::EditFile, vec![
            Example {
                task_type: TaskType::EditFile,
                user_request: "Change the function name from 'old_name' to 'new_name' in utils.rs".to_string(),
                thinking: r#"1. User wants to rename a function
2. I need to find and replace the name
3. Use edit_file with old_string and new_string
4. Should replace "old_name" with "new_name""#.to_string(),
                tool_call: r#"{"tool": "edit_file", "args": {"path": "utils.rs", "old_string": "fn old_name", "new_string": "fn new_name"}}"#.to_string(),
                result: "Edit successful: 1 replacement made".to_string(),
                follow_up: None,
            },
            Example {
                task_type: TaskType::EditFile,
                user_request: "Add a comment at the top of main.rs".to_string(),
                thinking: r#"1. User wants to add a comment at the top
2. I need to first read the file to see current content
3. Then prepend the comment
4. Use edit_file to add at the beginning"#.to_string(),
                tool_call: r#"{"tool": "read_file", "args": {"path": "main.rs"}}"#.to_string(),
                result: "fn main() { }".to_string(),
                follow_up: Some(r#"{"tool": "edit_file", "args": {"path": "main.rs", "old_string": "fn main()", "new_string": "// Main entry point\nfn main()"}}"#.to_string()),
            },
        ]);

        // Run command examples
        examples.insert(TaskType::RunCommand, vec![
            Example {
                task_type: TaskType::RunCommand,
                user_request: "Run the tests".to_string(),
                thinking: r#"1. User wants to run tests
2. This is likely a Rust or Node project
3. Try cargo test for Rust, npm test for Node
4. Execute the appropriate test command"#.to_string(),
                tool_call: r#"{"tool": "execute_shell", "args": {"command": "cargo test"}}"#.to_string(),
                result: "running 5 tests\ntest result: ok. 5 passed".to_string(),
                follow_up: None,
            },
            Example {
                task_type: TaskType::RunCommand,
                user_request: "Build the project".to_string(),
                thinking: r#"1. User wants to build the project
2. Need to determine project type
3. Cargo build for Rust, npm run build for Node
4. Start with the most likely command"#.to_string(),
                tool_call: r#"{"tool": "execute_shell", "args": {"command": "cargo build"}}"#.to_string(),
                result: "Compiling my-app v0.1.0\nFinished dev [unoptimized + debuginfo]".to_string(),
                follow_up: None,
            },
        ]);

        // Debug examples
        examples.insert(TaskType::Debug, vec![
            Example {
                task_type: TaskType::Debug,
                user_request: "Fix the error in main.rs".to_string(),
                thinking: r#"1. User reports an error in main.rs
2. I need to first read the file to see the code
3. Then identify the error
4. Start by reading the file"#.to_string(),
                tool_call: r#"{"tool": "read_file", "args": {"path": "main.rs"}}"#.to_string(),
                result: "fn main() {\n    let x = 5\n    println!(\"{}\", x);\n}".to_string(),
                follow_up: Some(r#"{"tool": "edit_file", "args": {"path": "main.rs", "old_string": "let x = 5", "new_string": "let x = 5;"}}"#.to_string()),
            },
        ]);

        // Multi-step examples
        examples.insert(TaskType::MultiStep, vec![
            Example {
                task_type: TaskType::MultiStep,
                user_request: "Create a new Rust file with a hello function and run the tests".to_string(),
                thinking: r#"1. This is a multi-step task
2. Step 1: Create the file with the function
3. Step 2: Run the tests
4. I'll start with creating the file"#.to_string(),
                tool_call: r#"{"tool": "write_file", "args": {"path": "src/hello.rs", "content": "pub fn hello() -> &'static str {\n    \"Hello, World!\"\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn test_hello() {\n        assert_eq!(hello(), \"Hello, World!\");\n    }\n}"}}"#.to_string(),
                result: "File written successfully: src/hello.rs".to_string(),
                follow_up: Some(r#"{"tool": "execute_shell", "args": {"command": "cargo test"}}"#.to_string()),
            },
        ]);

        // Explain examples
        examples.insert(TaskType::Explain, vec![
            Example {
                task_type: TaskType::Explain,
                user_request: "Explain what the main function does".to_string(),
                thinking: r#"1. User wants an explanation
2. I need to read the main function first
3. Then analyze and explain it
4. Start by reading the file"#.to_string(),
                tool_call: r#"{"tool": "read_file", "args": {"path": "src/main.rs"}}"#.to_string(),
                result: "fn main() {\n    let args: Vec<String> = std::env::args().collect();\n    if args.len() > 1 {\n        println!(\"Hello, {}!\", args[1]);\n    }\n}".to_string(),
                follow_up: None,
            },
        ]);

        // Refactor examples
        examples.insert(TaskType::Refactor, vec![
            Example {
                task_type: TaskType::Refactor,
                user_request: "Refactor the duplicated code in utils.rs".to_string(),
                thinking: r#"1. User wants to remove code duplication
2. First I need to read the file
3. Then identify the duplication
4. Finally, extract to a shared function"#.to_string(),
                tool_call: r#"{"tool": "read_file", "args": {"path": "utils.rs"}}"#.to_string(),
                result: "// current file contents".to_string(),
                follow_up: None,
            },
        ]);

        Self { examples }
    }

    /// Get relevant examples for a task
    pub fn get_examples(&self, request: &str, limit: usize) -> Vec<&Example> {
        let task_type = TaskType::classify(request);

        self.examples.get(&task_type)
            .map(|exs| exs.iter().take(limit).collect())
            .unwrap_or_default()
    }

    /// Format examples into a prompt section
    pub fn format_for_prompt(&self, request: &str, limit: usize) -> String {
        let examples = self.get_examples(request, limit);

        if examples.is_empty() {
            return String::new();
        }

        let mut formatted = String::from("\n\nHere are examples of similar tasks:\n");

        for (i, ex) in examples.iter().enumerate() {
            formatted.push_str(&format!("\n--- Example {} ---\n", i + 1));
            formatted.push_str(&format!("User: {}\n\n", ex.user_request));
            formatted.push_str("<thinking>\n");
            formatted.push_str(&ex.thinking);
            formatted.push_str("\n</thinking>\n\n");
            formatted.push_str("<action>\n");
            formatted.push_str(&ex.tool_call);
            formatted.push_str("\n</action>\n\n");
            formatted.push_str(&format!("Result: {}\n", ex.result));

            if let Some(follow_up) = &ex.follow_up {
                formatted.push_str(&format!("\nThen: {}\n", follow_up));
            }
        }

        formatted.push_str("\n--- End Examples ---\n");
        formatted
    }

    /// Get the task type for a request
    pub fn classify(&self, request: &str) -> TaskType {
        TaskType::classify(request)
    }
}

impl Default for ExampleLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_read() {
        assert_eq!(TaskType::classify("show me main.rs"), TaskType::ReadFile);
        assert_eq!(TaskType::classify("read the config file"), TaskType::ReadFile);
    }

    #[test]
    fn test_classify_find() {
        assert_eq!(TaskType::classify("find all rust files"), TaskType::FindFiles);
        assert_eq!(TaskType::classify("where is the main function"), TaskType::FindFiles);
    }

    #[test]
    fn test_classify_search() {
        assert_eq!(TaskType::classify("search for TODO comments"), TaskType::SearchCode);
        assert_eq!(TaskType::classify("grep for errors"), TaskType::SearchCode);
    }

    #[test]
    fn test_classify_multi_step() {
        assert_eq!(TaskType::classify("create a file and run tests"), TaskType::MultiStep);
        assert_eq!(TaskType::classify("read main.rs then update it"), TaskType::MultiStep);
    }

    #[test]
    fn test_get_examples() {
        let library = ExampleLibrary::new();
        let examples = library.get_examples("read the file", 2);
        assert!(!examples.is_empty());
        assert!(examples.len() <= 2);
    }

    #[test]
    fn test_format_for_prompt() {
        let library = ExampleLibrary::new();
        let formatted = library.format_for_prompt("read main.rs", 1);
        assert!(formatted.contains("<thinking>"));
        assert!(formatted.contains("<action>"));
        assert!(formatted.contains("read_file"));
    }
}
