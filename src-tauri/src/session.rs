use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

// Global lock to prevent concurrent session saves
lazy_static::lazy_static! {
    static ref SESSION_SAVE_LOCK: Mutex<()> = Mutex::new(());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabState {
    pub id: String,           // UUID string from frontend
    pub kind: String,         // "terminal", "ai", "editor", "developer"
    pub name: String,
    pub pty_id: Option<u32>,  // Only for terminal tabs
    pub cwd: Option<String>,  // Working directory for terminal tabs
    pub file_path: Option<String>, // For editor tabs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub tabs: Vec<TabState>,
    pub active_tab_id: Option<String>,
    pub version: u32,         // For migration compatibility
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            tabs: Vec::new(),
            active_tab_id: None,
            version: 1,
        }
    }

    #[allow(dead_code)]
    pub fn add_tab(&mut self, tab: TabState) {
        self.tabs.push(tab);
    }

    #[allow(dead_code)]
    pub fn remove_tab(&mut self, tab_id: &str) {
        self.tabs.retain(|t| t.id != tab_id);
    }

    #[allow(dead_code)]
    pub fn set_active_tab(&mut self, tab_id: String) {
        self.active_tab_id = Some(tab_id);
    }

    pub fn save(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // ATOMIC WRITE: Write to temp file first, then rename
        // This prevents corruption if the write is interrupted
        let temp_path = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(self)?;

        // Write to temp file
        fs::write(&temp_path, &json)?;

        // Atomically rename temp file to target (atomic on POSIX)
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Save with backup of previous session
    pub fn save_with_backup(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        // Create backup of existing session if it exists
        if path.exists() {
            let backup_path = path.with_extension("json.bak");
            // Copy existing session to backup (don't move, we might need it)
            if let Err(e) = fs::copy(path, &backup_path) {
                eprintln!("[session] Warning: Failed to create backup: {}", e);
                // Continue anyway - backup is nice-to-have
            }
        }

        // Now save using atomic write
        self.save(path)
    }

    pub fn load(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let json = fs::read_to_string(path)?;
        let state: SessionState = serde_json::from_str(&json)?;
        Ok(state)
    }

    /// Load with fallback to backup if main file is corrupted
    pub fn load_with_recovery(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        // Try main file first
        match Self::load(path) {
            Ok(state) => Ok(state),
            Err(main_error) => {
                eprintln!("[session] Main file corrupted: {}, trying backup...", main_error);

                // Try backup file
                let backup_path = path.with_extension("json.bak");
                if backup_path.exists() {
                    match Self::load(&backup_path) {
                        Ok(state) => {
                            eprintln!("[session] Recovered from backup!");
                            // Restore backup to main file
                            if let Err(e) = fs::copy(&backup_path, path) {
                                eprintln!("[session] Warning: Failed to restore backup to main: {}", e);
                            }
                            Ok(state)
                        }
                        Err(backup_error) => {
                            eprintln!("[session] Backup also corrupted: {}", backup_error);
                            Err(main_error)
                        }
                    }
                } else {
                    Err(main_error)
                }
            }
        }
    }

    /// Get default session file path
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(format!("{}/.warp_open/session.json", home))
    }
}

// Tauri commands for session management
#[tauri::command]
pub fn save_session(session_json: String) -> Result<(), String> {
    // Acquire lock to prevent concurrent saves
    let _lock = SESSION_SAVE_LOCK.lock()
        .map_err(|e| format!("Failed to acquire save lock: {}", e))?;

    let session: SessionState = serde_json::from_str(&session_json)
        .map_err(|e| format!("Failed to parse session: {}", e))?;

    let path = SessionState::default_path();

    // Use atomic save with backup for reliability
    session.save_with_backup(&path)
        .map_err(|e| format!("Failed to save session: {}", e))?;

    eprintln!("[session] Saved {} tabs to {:?} (atomic)", session.tabs.len(), path);
    Ok(())
}

#[tauri::command]
pub fn load_session() -> Result<SessionState, String> {
    let path = SessionState::default_path();

    if !path.exists() {
        eprintln!("[session] No session file found at {:?}", path);
        return Ok(SessionState::new());
    }

    // Use load_with_recovery to handle corrupted files
    match SessionState::load_with_recovery(&path) {
        Ok(session) => {
            eprintln!("[session] Loaded {} tabs from {:?}", session.tabs.len(), path);
            Ok(session)
        }
        Err(e) => {
            eprintln!("[session] Failed to load session: {}", e);
            // Return empty session on error (don't crash)
            Ok(SessionState::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn test_session_state_creation() {
        let state = SessionState::new();
        assert_eq!(state.tabs.len(), 0);
        assert!(state.active_tab_id.is_none());
        assert_eq!(state.version, 1);
    }

    #[test]
    fn test_add_tab() {
        let mut state = SessionState::new();
        state.add_tab(TabState {
            id: "test-uuid-1".to_string(),
            kind: "terminal".to_string(),
            name: "Terminal 1".to_string(),
            pty_id: Some(100),
            cwd: Some("/Users/test".to_string()),
            file_path: None,
        });
        assert_eq!(state.tabs.len(), 1);
    }

    #[test]
    fn test_remove_tab() {
        let mut state = SessionState::new();
        state.add_tab(TabState {
            id: "test-uuid-1".to_string(),
            kind: "terminal".to_string(),
            name: "Terminal 1".to_string(),
            pty_id: Some(100),
            cwd: None,
            file_path: None,
        });
        state.remove_tab("test-uuid-1");
        assert_eq!(state.tabs.len(), 0);
    }

    #[test]
    fn test_session_save_load() {
        let mut state = SessionState::new();
        state.add_tab(TabState {
            id: "test-uuid-42".to_string(),
            kind: "terminal".to_string(),
            name: "Test Tab".to_string(),
            pty_id: Some(42),
            cwd: Some("/tmp".to_string()),
            file_path: None,
        });
        state.set_active_tab("test-uuid-42".to_string());

        let temp_path = temp_dir().join("warp_session_test.json");
        state.save(&temp_path).unwrap();

        let loaded_state = SessionState::load(&temp_path).unwrap();
        assert_eq!(loaded_state.tabs.len(), 1);
        assert_eq!(loaded_state.active_tab_id, Some("test-uuid-42".to_string()));
        assert_eq!(loaded_state.tabs[0].name, "Test Tab");
        assert_eq!(loaded_state.tabs[0].kind, "terminal");

        // Cleanup
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_atomic_save_creates_no_temp_file() {
        let mut state = SessionState::new();
        state.add_tab(TabState {
            id: "test-uuid-atomic".to_string(),
            kind: "terminal".to_string(),
            name: "Atomic Test".to_string(),
            pty_id: Some(1),
            cwd: None,
            file_path: None,
        });

        let temp_path = temp_dir().join("warp_atomic_test.json");
        let tmp_temp_path = temp_path.with_extension("json.tmp");

        state.save(&temp_path).unwrap();

        // Temp file should not exist after successful save
        assert!(!tmp_temp_path.exists(), "Temp file should be removed after rename");
        assert!(temp_path.exists(), "Main file should exist");

        // Cleanup
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_save_with_backup_creates_backup() {
        let mut state = SessionState::new();
        state.add_tab(TabState {
            id: "test-uuid-backup-1".to_string(),
            kind: "terminal".to_string(),
            name: "Backup Test 1".to_string(),
            pty_id: Some(1),
            cwd: None,
            file_path: None,
        });

        let temp_path = temp_dir().join("warp_backup_test.json");
        let backup_path = temp_path.with_extension("json.bak");

        // First save
        state.save_with_backup(&temp_path).unwrap();
        assert!(!backup_path.exists(), "No backup on first save");

        // Modify and save again
        state.add_tab(TabState {
            id: "test-uuid-backup-2".to_string(),
            kind: "terminal".to_string(),
            name: "Backup Test 2".to_string(),
            pty_id: Some(2),
            cwd: None,
            file_path: None,
        });
        state.save_with_backup(&temp_path).unwrap();
        assert!(backup_path.exists(), "Backup should exist after second save");

        // Backup should have old data (1 tab)
        let backup_state = SessionState::load(&backup_path).unwrap();
        assert_eq!(backup_state.tabs.len(), 1, "Backup should have old state");

        // Main file should have new data (2 tabs)
        let main_state = SessionState::load(&temp_path).unwrap();
        assert_eq!(main_state.tabs.len(), 2, "Main file should have new state");

        // Cleanup
        let _ = fs::remove_file(&temp_path);
        let _ = fs::remove_file(&backup_path);
    }

    #[test]
    fn test_recovery_from_backup() {
        let mut state = SessionState::new();
        state.add_tab(TabState {
            id: "test-uuid-recovery".to_string(),
            kind: "terminal".to_string(),
            name: "Recovery Test".to_string(),
            pty_id: Some(1),
            cwd: None,
            file_path: None,
        });

        let temp_path = temp_dir().join("warp_recovery_test.json");
        let backup_path = temp_path.with_extension("json.bak");

        // Save valid state to backup
        state.save(&backup_path).unwrap();

        // Write corrupted JSON to main file
        fs::write(&temp_path, "{ invalid json }").unwrap();

        // Load should recover from backup
        let recovered = SessionState::load_with_recovery(&temp_path).unwrap();
        assert_eq!(recovered.tabs.len(), 1);
        assert_eq!(recovered.tabs[0].name, "Recovery Test");

        // After recovery, main file should be restored
        let main_state = SessionState::load(&temp_path).unwrap();
        assert_eq!(main_state.tabs.len(), 1);

        // Cleanup
        let _ = fs::remove_file(&temp_path);
        let _ = fs::remove_file(&backup_path);
    }

    #[test]
    fn test_recovery_fails_gracefully_when_both_corrupted() {
        let temp_path = temp_dir().join("warp_double_corrupt_test.json");
        let backup_path = temp_path.with_extension("json.bak");

        // Write corrupted JSON to both files
        fs::write(&temp_path, "{ invalid }").unwrap();
        fs::write(&backup_path, "also { invalid }").unwrap();

        // Load should return error
        let result = SessionState::load_with_recovery(&temp_path);
        assert!(result.is_err(), "Should fail when both files corrupted");

        // Cleanup
        let _ = fs::remove_file(&temp_path);
        let _ = fs::remove_file(&backup_path);
    }
}
