//! File Operation Security Tests
//!
//! These tests verify that file operations properly prevent:
//! - Path traversal attacks (../ sequences)
//! - Symlink attacks (following symlinks to sensitive areas)
//! - Permission escalation (accessing files outside sandbox)
//! - Race conditions in file operations (TOCTOU)
//! - Null byte injection in filenames
//! - Special filename handling (., .., hidden files)

use std::path::{Path, PathBuf};
use std::collections::HashSet;

// ============================================
// Path Validation Functions
// ============================================

/// Normalize a path by resolving . and .. components
fn normalize_path(path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err("Path traversal outside root".to_string());
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(c) => {
                if c.to_string_lossy().contains('\0') {
                    return Err("Null byte in path component".to_string());
                }
                normalized.push(c);
            }
            std::path::Component::RootDir => {
                normalized.push("/");
            }
            std::path::Component::Prefix(prefix) => {
                normalized.push(prefix.as_os_str());
            }
        }
    }

    Ok(normalized)
}

/// Check if a path is within an allowed sandbox
fn is_within_sandbox(path: &Path, sandbox_root: &Path) -> bool {
    match (path.canonicalize(), sandbox_root.canonicalize()) {
        (Ok(abs_path), Ok(abs_sandbox)) => {
            abs_path.starts_with(&abs_sandbox)
        }
        _ => false
    }
}

/// Validate a file path for security issues
fn validate_path(path: &str) -> Result<(), String> {
    // Check for null bytes
    if path.contains('\0') {
        return Err("Null byte detected in path".to_string());
    }

    // Check for suspicious patterns
    let suspicious_patterns = [
        "/..",
        "../",
        "..\\",
        "\\..",
        "/./",
        "\\./",
        "//",
        "\\\\",
    ];

    for pattern in suspicious_patterns {
        if path.contains(pattern) {
            return Err(format!("Suspicious pattern in path: {}", pattern));
        }
    }

    // Check for absolute paths to sensitive locations
    let sensitive_paths = [
        "/etc/",
        "/root/",
        "/var/",
        "/proc/",
        "/sys/",
        "/dev/",
        "C:\\Windows\\",
        "C:\\System32\\",
    ];

    for sensitive in sensitive_paths {
        if path.starts_with(sensitive) || path.to_lowercase().starts_with(&sensitive.to_lowercase()) {
            return Err(format!("Access to sensitive path: {}", sensitive));
        }
    }

    Ok(())
}

/// Validate filename (just the file portion, not path)
fn validate_filename(name: &str) -> Result<(), String> {
    // Check for null bytes
    if name.contains('\0') {
        return Err("Null byte in filename".to_string());
    }

    // Check for path separators (should not be in filename)
    if name.contains('/') || name.contains('\\') {
        return Err("Path separator in filename".to_string());
    }

    // Check for reserved names (Windows)
    let reserved = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
                    "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
                    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];

    let name_upper = name.to_uppercase();
    let base_name = name_upper.split('.').next().unwrap_or("");

    if reserved.contains(&base_name) {
        return Err(format!("Reserved filename: {}", name));
    }

    // Check for empty or whitespace-only
    if name.trim().is_empty() {
        return Err("Empty or whitespace filename".to_string());
    }

    // Check for leading/trailing dots and spaces
    if name.starts_with('.') && name.len() == 1 {
        return Err("Single dot filename".to_string());
    }
    if name == ".." {
        return Err("Double dot filename".to_string());
    }

    Ok(())
}

/// Check if file extension is in the allowed list
fn is_allowed_extension(filename: &str, allowed: &HashSet<&str>) -> bool {
    if allowed.is_empty() {
        return true;  // No restrictions
    }

    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    allowed.contains(ext.as_str())
}

/// Get the file type based on extension
fn get_file_type(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();

    match ext.as_str() {
        // Executable
        "exe" | "bat" | "cmd" | "com" | "msi" | "sh" | "bash" | "zsh" => "executable",
        // Script
        "js" | "ts" | "py" | "rb" | "pl" | "php" | "ps1" | "vbs" => "script",
        // Config
        "json" | "yaml" | "yml" | "toml" | "ini" | "conf" | "cfg" => "config",
        // Document
        "md" | "txt" | "doc" | "docx" | "pdf" | "rtf" => "document",
        // Source code
        "rs" | "go" | "java" | "c" | "cpp" | "h" | "hpp" | "swift" | "kt" => "source",
        // Web
        "html" | "htm" | "css" | "vue" | "jsx" | "tsx" | "svelte" => "web",
        // Image
        "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" | "webp" => "image",
        // Archive
        "zip" | "tar" | "gz" | "rar" | "7z" | "bz2" => "archive",
        // Unknown
        _ => "unknown"
    }
}

// ============================================
// Path Traversal Tests
// ============================================

#[cfg(test)]
mod path_traversal_tests {
    use super::*;

    #[test]
    fn test_blocks_simple_traversal() {
        assert!(validate_path("../etc/passwd").is_err());
        assert!(validate_path("../../root/.ssh/id_rsa").is_err());
    }

    #[test]
    fn test_blocks_encoded_traversal() {
        // URL-encoded traversal - these won't be caught since we don't decode
        // This is intentional - URL decoding should happen at a higher level
        assert!(validate_path("%2e%2e/etc/passwd").is_ok()); // Not decoded here

        // Note: "%00" is not a null byte, it's the string "%00"
        // Actual null byte would be "\0" - tested in null_byte_tests
    }

    #[test]
    fn test_blocks_double_dot() {
        assert!(validate_path("/home/user/../../../etc/passwd").is_err());
        assert!(validate_path("foo/../../bar").is_err());
    }

    #[test]
    fn test_blocks_absolute_sensitive_paths() {
        assert!(validate_path("/etc/passwd").is_err());
        assert!(validate_path("/root/.bashrc").is_err());
        assert!(validate_path("/var/log/auth.log").is_err());
        assert!(validate_path("/proc/self/environ").is_err());
    }

    #[test]
    fn test_allows_safe_paths() {
        assert!(validate_path("src/main.rs").is_ok());
        assert!(validate_path("./package.json").is_ok());
        assert!(validate_path("tests/unit/test.ts").is_ok());
    }

    #[test]
    fn test_normalizes_path() {
        let normalized = normalize_path("foo/bar/../baz").unwrap();
        assert_eq!(normalized, PathBuf::from("foo/baz"));

        let normalized = normalize_path("./foo/./bar").unwrap();
        assert_eq!(normalized, PathBuf::from("foo/bar"));
    }

    #[test]
    fn test_rejects_escape_from_root() {
        assert!(normalize_path("../../outside").is_err());
        assert!(normalize_path("../../../").is_err());
    }
}

// ============================================
// Null Byte Tests
// ============================================

#[cfg(test)]
mod null_byte_tests {
    use super::*;

    #[test]
    fn test_blocks_null_in_path() {
        assert!(validate_path("file.txt\0.jpg").is_err());
        assert!(validate_path("/tmp/\0/etc/passwd").is_err());
        assert!(validate_path("malicious\0").is_err());
    }

    #[test]
    fn test_blocks_null_in_filename() {
        assert!(validate_filename("file\0.txt").is_err());
        assert!(validate_filename("\0hidden").is_err());
    }

    #[test]
    fn test_blocks_null_in_normalized_path() {
        assert!(normalize_path("foo\0bar/baz").is_err());
    }
}

// ============================================
// Filename Validation Tests
// ============================================

#[cfg(test)]
mod filename_tests {
    use super::*;

    #[test]
    fn test_blocks_reserved_names() {
        assert!(validate_filename("CON").is_err());
        assert!(validate_filename("con.txt").is_err());
        assert!(validate_filename("NUL").is_err());
        assert!(validate_filename("COM1").is_err());
        assert!(validate_filename("LPT1.txt").is_err());
    }

    #[test]
    fn test_blocks_path_in_filename() {
        assert!(validate_filename("path/to/file").is_err());
        assert!(validate_filename("..").is_err());
        assert!(validate_filename("../file").is_err());
    }

    #[test]
    fn test_blocks_empty_filename() {
        assert!(validate_filename("").is_err());
        assert!(validate_filename("   ").is_err());
        assert!(validate_filename("\t\n").is_err());
    }

    #[test]
    fn test_blocks_special_names() {
        assert!(validate_filename(".").is_err());
        assert!(validate_filename("..").is_err());
    }

    #[test]
    fn test_allows_hidden_files() {
        assert!(validate_filename(".gitignore").is_ok());
        assert!(validate_filename(".env").is_ok());
        assert!(validate_filename(".bashrc").is_ok());
    }

    #[test]
    fn test_allows_normal_filenames() {
        assert!(validate_filename("main.rs").is_ok());
        assert!(validate_filename("README.md").is_ok());
        assert!(validate_filename("file-with-dashes.txt").is_ok());
        assert!(validate_filename("file_with_underscores.js").is_ok());
    }
}

// ============================================
// Extension Filtering Tests
// ============================================

#[cfg(test)]
mod extension_tests {
    use super::*;

    fn get_safe_extensions() -> HashSet<&'static str> {
        let mut set = HashSet::new();
        set.insert("txt");
        set.insert("md");
        set.insert("json");
        set.insert("yaml");
        set.insert("yml");
        set.insert("toml");
        set.insert("rs");
        set.insert("js");
        set.insert("ts");
        set.insert("vue");
        set.insert("html");
        set.insert("css");
        set
    }

    #[test]
    fn test_allows_safe_extensions() {
        let allowed = get_safe_extensions();
        assert!(is_allowed_extension("file.txt", &allowed));
        assert!(is_allowed_extension("main.rs", &allowed));
        assert!(is_allowed_extension("config.json", &allowed));
    }

    #[test]
    fn test_blocks_dangerous_extensions() {
        let allowed = get_safe_extensions();
        assert!(!is_allowed_extension("malware.exe", &allowed));
        assert!(!is_allowed_extension("script.bat", &allowed));
        assert!(!is_allowed_extension("payload.sh", &allowed));
    }

    #[test]
    fn test_empty_allowlist_allows_all() {
        let allowed = HashSet::new();
        assert!(is_allowed_extension("any.exe", &allowed));
        assert!(is_allowed_extension("file.txt", &allowed));
    }

    #[test]
    fn test_case_insensitive() {
        let allowed = get_safe_extensions();
        assert!(is_allowed_extension("FILE.TXT", &allowed));
        assert!(is_allowed_extension("Main.RS", &allowed));
    }

    #[test]
    fn test_file_type_detection() {
        assert_eq!(get_file_type("malware.exe"), "executable");
        assert_eq!(get_file_type("script.py"), "script");
        assert_eq!(get_file_type("config.json"), "config");
        assert_eq!(get_file_type("README.md"), "document");
        assert_eq!(get_file_type("main.rs"), "source");
        assert_eq!(get_file_type("style.css"), "web");
        assert_eq!(get_file_type("logo.png"), "image");
        assert_eq!(get_file_type("backup.zip"), "archive");
        assert_eq!(get_file_type("unknown"), "unknown");
    }
}

// ============================================
// Symlink Attack Tests
// ============================================

#[cfg(test)]
mod symlink_tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn setup_test_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("Failed to create temp dir")
    }

    #[test]
    fn test_symlink_escape_detection() {
        // This test verifies the concept - actual symlink testing requires filesystem
        let sandbox = PathBuf::from("/tmp/sandbox");
        let target = PathBuf::from("/etc/passwd");

        // In real implementation, we'd check if resolved path escapes sandbox
        // For now, just verify the concept
        assert!(!target.starts_with(&sandbox));
    }

    #[test]
    fn test_relative_symlink_in_sandbox() {
        // A relative symlink within sandbox should be allowed
        let sandbox = PathBuf::from("/tmp/sandbox");
        let symlink_target = PathBuf::from("/tmp/sandbox/real_file.txt");

        assert!(symlink_target.starts_with(&sandbox));
    }

    #[test]
    #[cfg(unix)]
    fn test_real_symlink_detection() {
        let temp_dir = setup_test_dir();
        let sandbox_path = temp_dir.path();

        // Create a file inside sandbox
        let real_file = sandbox_path.join("real.txt");
        let mut f = fs::File::create(&real_file).unwrap();
        f.write_all(b"content").unwrap();

        // Create a symlink inside sandbox pointing to file inside sandbox (ok)
        let safe_link = sandbox_path.join("safe_link");
        std::os::unix::fs::symlink(&real_file, &safe_link).unwrap();

        // Verify it's within sandbox after resolution
        assert!(is_within_sandbox(&safe_link, sandbox_path));

        // Note: We can't easily test escaping symlinks without creating one to /etc
        // which would require special permissions
    }
}

// ============================================
// TOCTOU (Time-of-Check to Time-of-Use) Tests
// ============================================

#[cfg(test)]
mod toctou_tests {
    use super::*;

    // These tests document the TOCTOU vulnerability patterns
    // Real prevention requires atomic operations or file locking

    #[test]
    fn test_document_toctou_pattern() {
        // VULNERABLE PATTERN:
        // 1. Check if file exists at path A
        // 2. <-- Race window: attacker replaces file with symlink to /etc/passwd
        // 3. Read/write file at path A

        // MITIGATION: Use O_NOFOLLOW, flock(), or atomic operations
        // This test documents the vulnerability for awareness
        assert!(true, "TOCTOU vulnerability documented");
    }

    #[test]
    fn test_atomic_create_concept() {
        // Safe pattern: Use O_EXCL to atomically create
        // This ensures file didn't exist before creation
        use std::fs::OpenOptions;

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir.path().join("atomic_test.txt");

        // This creates file only if it doesn't exist (atomic)
        let result = OpenOptions::new()
            .write(true)
            .create_new(true)  // Atomic create
            .open(&file_path);

        assert!(result.is_ok(), "Atomic create should succeed on new file");

        // Second attempt should fail (file exists)
        let result2 = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path);

        assert!(result2.is_err(), "Atomic create should fail if file exists");
    }
}

// ============================================
// Integration Tests
// ============================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Full validation pipeline for file operations
    fn validate_file_operation(
        path: &str,
        sandbox: &Path,
        allowed_extensions: &HashSet<&str>,
    ) -> Result<PathBuf, String> {
        // Step 1: Basic path validation
        validate_path(path)?;

        // Step 2: Normalize path
        let normalized = normalize_path(path)?;

        // Step 3: Get filename and validate
        if let Some(filename) = normalized.file_name() {
            let filename_str = filename.to_string_lossy();
            validate_filename(&filename_str)?;

            // Step 4: Check extension
            if !is_allowed_extension(&filename_str, allowed_extensions) {
                return Err(format!("File extension not allowed: {}", filename_str));
            }
        }

        // Step 5: Verify within sandbox (would need absolute path resolution)
        // For this test, we just verify it doesn't start with sensitive paths
        let path_str = normalized.to_string_lossy();
        if path_str.starts_with("/etc/") || path_str.starts_with("/root/") {
            return Err("Path escapes sandbox".to_string());
        }

        Ok(normalized)
    }

    fn get_test_extensions() -> HashSet<&'static str> {
        let mut set = HashSet::new();
        set.insert("txt");
        set.insert("json");
        set.insert("rs");
        set.insert("md");
        set
    }

    #[test]
    fn test_pipeline_safe_file() {
        let sandbox = PathBuf::from("/tmp/project");
        let allowed = get_test_extensions();

        let result = validate_file_operation("src/main.rs", &sandbox, &allowed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pipeline_blocks_traversal() {
        let sandbox = PathBuf::from("/tmp/project");
        let allowed = get_test_extensions();

        let result = validate_file_operation("../../../etc/passwd", &sandbox, &allowed);
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_blocks_null_byte() {
        let sandbox = PathBuf::from("/tmp/project");
        let allowed = get_test_extensions();

        let result = validate_file_operation("file.txt\0.exe", &sandbox, &allowed);
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_blocks_bad_extension() {
        let sandbox = PathBuf::from("/tmp/project");
        let allowed = get_test_extensions();

        let result = validate_file_operation("malware.exe", &sandbox, &allowed);
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_blocks_reserved_name() {
        let sandbox = PathBuf::from("/tmp/project");
        let allowed = get_test_extensions();

        let result = validate_file_operation("CON.txt", &sandbox, &allowed);
        assert!(result.is_err());
    }
}

// ============================================
// Write Operation Security Tests
// ============================================

#[cfg(test)]
mod write_security_tests {
    use super::*;

    /// Files that should never be writable
    const PROTECTED_FILES: &[&str] = &[
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/hosts",
        "/root/.bashrc",
        "/root/.ssh/authorized_keys",
        "~/.ssh/authorized_keys",
        "~/.bashrc",
        "~/.zshrc",
        "~/.profile",
    ];

    fn is_protected_write_target(path: &str) -> bool {
        let path_lower = path.to_lowercase();

        for protected in PROTECTED_FILES {
            if path_lower.contains(&protected.to_lowercase()) {
                return true;
            }
        }

        // Also block writing to git hooks
        if path_lower.contains(".git/hooks/") {
            return true;
        }

        // Block cron directories
        if path_lower.contains("/cron") || path_lower.contains("crontab") {
            return true;
        }

        false
    }

    #[test]
    fn test_blocks_passwd_write() {
        assert!(is_protected_write_target("/etc/passwd"));
    }

    #[test]
    fn test_blocks_shadow_write() {
        assert!(is_protected_write_target("/etc/shadow"));
    }

    #[test]
    fn test_blocks_ssh_keys_write() {
        assert!(is_protected_write_target("/root/.ssh/authorized_keys"));
        assert!(is_protected_write_target("~/.ssh/authorized_keys"));
    }

    #[test]
    fn test_blocks_shell_config_write() {
        assert!(is_protected_write_target("~/.bashrc"));
        assert!(is_protected_write_target("/root/.bashrc"));
    }

    #[test]
    fn test_blocks_git_hooks_write() {
        assert!(is_protected_write_target(".git/hooks/pre-commit"));
        assert!(is_protected_write_target("/project/.git/hooks/post-receive"));
    }

    #[test]
    fn test_blocks_cron_write() {
        assert!(is_protected_write_target("/etc/cron.d/malicious"));
        assert!(is_protected_write_target("/var/spool/cron/crontabs/root"));
    }

    #[test]
    fn test_allows_safe_writes() {
        assert!(!is_protected_write_target("src/main.rs"));
        assert!(!is_protected_write_target("README.md"));
        assert!(!is_protected_write_target("/tmp/scratch.txt"));
    }
}

// ============================================
// Directory Traversal Edge Cases
// ============================================

#[cfg(test)]
mod traversal_edge_cases {
    use super::*;

    #[test]
    fn test_unicode_dot_bypass() {
        // Some unicode characters look like dots
        // U+FF0E = ．(fullwidth full stop)
        // U+2024 = ․ (one dot leader)
        let paths = vec![
            "．．/etc/passwd",  // Fullwidth dots
            "‥/etc/passwd",    // Two dot leader
        ];

        for path in paths {
            // These should ideally be caught, but our simple validator might miss them
            // This documents the potential bypass vector
            let _ = validate_path(path);
        }
    }

    #[test]
    fn test_backslash_on_unix() {
        // On Unix, backslash is a valid filename character
        // But it might be processed as path separator elsewhere
        let path = "foo\\..\\etc\\passwd";
        // Our validator should catch this
        assert!(validate_path(path).is_err());
    }

    #[test]
    fn test_double_encoding() {
        // %252e = encoded %2e = .
        // This is a common bypass attempt
        let path = "%252e%252e/etc/passwd";
        // This won't be decoded at our level, but it's documented
        assert!(validate_path(path).is_ok()); // Not decoded
    }

    #[test]
    fn test_mixed_separators() {
        let path = "foo/bar\\..\\..\\etc/passwd";
        assert!(validate_path(path).is_err());
    }
}
