// src-tauri/src/policy_store.rs
// Phase 5: Adaptive Policy Learning & Multi-Agent Coordination
// Stores versioned policy rules with atomic apply/rollback

use rusqlite::{params, Connection};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use uuid::Uuid;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use anyhow::Result;

// Helper to handle poisoned mutex - recovers lock even after panic
fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        eprintln!("[WARN] PolicyStore mutex was poisoned, recovering...");
        poisoned.into_inner()
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub pattern: String,
    pub effect: String, // "allow" or "deny"
    pub added_by: Option<String>,
    pub confidence: Option<f64>, // Model confidence score
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub version: String,
    pub ts: String,
    pub author: String,
    pub comment: String,
    pub diff: String, // JSON diff
    pub add_ids: Vec<String>, // Track exact IDs added for rollback
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiff {
    pub add: Vec<PolicyDiffAdd>,
    pub remove: Vec<String>, // rule IDs to remove
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiffAdd {
    pub pattern: String,
    pub effect: String,
    pub score: Option<f64>,
}

pub struct PolicyStore {
    conn: Mutex<Connection>,
}

impl PolicyStore {
    pub fn open(db_path: PathBuf) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let store = PolicyStore { conn: Mutex::new(conn) };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Result<()> {
        let conn = lock_or_recover(&self.conn);
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS policy_rules (
                id TEXT PRIMARY KEY,
                pattern TEXT NOT NULL,
                effect TEXT NOT NULL,
                added_by TEXT,
                confidence REAL,
                ts TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_versions (
                version TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                author TEXT NOT NULL,
                comment TEXT,
                diff TEXT NOT NULL,
                add_ids TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_suggestions (
                id TEXT PRIMARY KEY,
                proposed_by TEXT NOT NULL,
                proposed_at TEXT NOT NULL,
                diff_json TEXT NOT NULL,
                status TEXT NOT NULL,
                reviewed_by TEXT,
                reviewed_at TEXT
            );
            "#
        )?;
        eprintln!("[POLICY_STORE] Initialized policy database");
        Ok(())
    }

    pub fn list_rules(&self) -> Result<Vec<PolicyRule>> {
        let conn = lock_or_recover(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, pattern, effect, added_by, confidence, ts FROM policy_rules ORDER BY ts DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PolicyRule {
                id: row.get(0)?,
                pattern: row.get(1)?,
                effect: row.get(2)?,
                added_by: row.get(3).ok(),
                confidence: row.get(4).ok(),
                ts: row.get(5)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn propose_diff(&self, proposed_by: &str, diff_json: &str) -> Result<String> {
        let suggestion_id = Uuid::new_v4().to_string();
        let ts = Utc::now().to_rfc3339();
        
        let conn = lock_or_recover(&self.conn);
        conn.execute(
            "INSERT INTO policy_suggestions (id, proposed_by, proposed_at, diff_json, status) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![suggestion_id, proposed_by, ts, diff_json, "pending"]
        )?;
        
        eprintln!("[POLICY_STORE] Proposed policy diff: {}", suggestion_id);
        Ok(suggestion_id)
    }

    pub fn list_suggestions(&self) -> Result<Vec<serde_json::Value>> {
        let conn = lock_or_recover(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, proposed_by, proposed_at, diff_json, status, reviewed_by, reviewed_at FROM policy_suggestions ORDER BY proposed_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "proposed_by": row.get::<_, String>(1)?,
                "proposed_at": row.get::<_, String>(2)?,
                "diff": serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(3)?).ok(),
                "status": row.get::<_, String>(4)?,
                "reviewed_by": row.get::<_, Option<String>>(5)?,
                "reviewed_at": row.get::<_, Option<String>>(6)?,
            }))
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn apply_diff(&self, suggestion_id: &str, author: &str, comment: &str) -> Result<String> {
        let mut conn = lock_or_recover(&self.conn);
        
        // Get suggestion
        let diff_json: String = conn.query_row(
            "SELECT diff_json FROM policy_suggestions WHERE id = ?1",
            params![suggestion_id],
            |row| row.get(0)
        )?;
        
        let diff: PolicyDiff = serde_json::from_str(&diff_json)?;
        
        // Begin transaction
        let tx = conn.transaction()?;
        let version = Uuid::new_v4().to_string();
        let ts = Utc::now().to_rfc3339();
        let mut add_ids = vec![];
        
        // Apply removes
        for remove_id in &diff.remove {
            tx.execute("DELETE FROM policy_rules WHERE id = ?1", params![remove_id])?;
        }
        
        // Apply adds
        for add in &diff.add {
            let id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO policy_rules (id, pattern, effect, added_by, confidence, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, add.pattern, add.effect, author, add.score, ts]
            )?;
            add_ids.push(id);
        }
        
        // Record version with add_ids for rollback
        let add_ids_json = serde_json::to_string(&add_ids)?;
        tx.execute(
            "INSERT INTO policy_versions (version, ts, author, comment, diff, add_ids) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![version, ts, author, comment, diff_json, add_ids_json]
        )?;
        
        // Mark suggestion as applied
        tx.execute(
            "UPDATE policy_suggestions SET status = 'applied', reviewed_by = ?1, reviewed_at = ?2 WHERE id = ?3",
            params![author, ts, suggestion_id]
        )?;
        
        tx.commit()?;
        
        eprintln!("[POLICY_STORE] Applied policy diff: version {}", version);
        Ok(version)
    }

    pub fn rollback_version(&self, version: &str) -> Result<()> {
        let mut conn = lock_or_recover(&self.conn);
        
        // Get version record and store in variables before transaction
        let (diff_json, add_ids_json): (String, String) = {
            let mut stmt = conn.prepare(
                "SELECT diff, add_ids FROM policy_versions WHERE version = ?1"
            )?;
            stmt.query_row(params![version], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
        };
        
        let _diff: PolicyDiff = serde_json::from_str(&diff_json)?;
        let add_ids: Vec<String> = serde_json::from_str(&add_ids_json)?;
        
        let tx = conn.transaction()?;
        
        // Reverse: remove added rules
        for id in &add_ids {
            tx.execute("DELETE FROM policy_rules WHERE id = ?1", params![id])?;
        }
        
        // Reverse: restore removed rules (if we stored them - simplified version just removes adds)
        // In production, store full rule data in version record for proper rollback
        
        tx.commit()?;
        
        eprintln!("[POLICY_STORE] Rolled back version: {}", version);
        Ok(())
    }

    pub fn reject_suggestion(&self, suggestion_id: &str, author: &str) -> Result<()> {
        let conn = lock_or_recover(&self.conn);
        let ts = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE policy_suggestions SET status = 'rejected', reviewed_by = ?1, reviewed_at = ?2 WHERE id = ?3",
            params![author, ts, suggestion_id]
        )?;
        eprintln!("[POLICY_STORE] Rejected suggestion: {}", suggestion_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_policy_store_init() {
        let tmp_path = std::env::temp_dir().join("test_policy.sqlite");
        let _ = fs::remove_file(&tmp_path);
        
        let store = PolicyStore::open(tmp_path.clone()).unwrap();
        assert!(tmp_path.exists());
        
        let rules = store.list_rules().unwrap();
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_policy_diff_workflow() {
        let tmp_path = std::env::temp_dir().join("test_policy2.sqlite");
        let _ = fs::remove_file(&tmp_path);
        
        let store = PolicyStore::open(tmp_path).unwrap();
        
        // Propose diff
        let diff = PolicyDiff {
            add: vec![PolicyDiffAdd {
                pattern: r"\brm\s+-rf\b".to_string(),
                effect: "deny".to_string(),
                score: Some(0.98),
            }],
            remove: vec![],
            meta: None,
        };
        let diff_json = serde_json::to_string(&diff).unwrap();
        let suggestion_id = store.propose_diff("trainer_v1", &diff_json).unwrap();
        
        // List suggestions
        let suggestions = store.list_suggestions().unwrap();
        assert_eq!(suggestions.len(), 1);
        
        // Apply diff
        let version = store.apply_diff(&suggestion_id, "admin", "Test apply").unwrap();
        
        // Verify rules added
        let rules = store.list_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].effect, "deny");
        
        // Rollback
        store.rollback_version(&version).unwrap();
        let rules_after = store.list_rules().unwrap();
        assert_eq!(rules_after.len(), 0);
    }
}
