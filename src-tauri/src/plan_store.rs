// src-tauri/src/plan_store.rs
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use chrono::{Utc, DateTime};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::path::PathBuf;

// Helper to handle poisoned mutex - recovers lock even after panic
fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        eprintln!("[WARN] PlanStore mutex was poisoned, recovering...");
        poisoned.into_inner()
    })
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Plan {
    pub plan_id: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
    pub agent_ids: Vec<u64>,
    pub task_sequence: Vec<String>, // batch IDs
    pub next_task_index: usize,
    pub metadata: Option<serde_json::Value>,
}

pub struct PlanStore {
    conn: Mutex<Connection>,
}

impl PlanStore {
    pub fn open(db_path: PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;
        let store = PlanStore { conn: Mutex::new(conn) };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> anyhow::Result<()> {
        let conn = lock_or_recover(&self.conn);
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS plans (
                plan_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                agent_ids TEXT,
                task_sequence TEXT,
                next_task_index INTEGER,
                metadata TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_plans_status ON plans(status);
            "#
        )?;
        Ok(())
    }

    pub fn insert_plan(&self, plan: &Plan) -> anyhow::Result<()> {
        let conn = lock_or_recover(&self.conn);
        conn.execute(
            "INSERT INTO plans (plan_id, created_at, status, agent_ids, task_sequence, next_task_index, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                plan.plan_id,
                plan.created_at.to_rfc3339(),
                plan.status,
                serde_json::to_string(&plan.agent_ids)?,
                serde_json::to_string(&plan.task_sequence)?,
                plan.next_task_index as i64,
                plan.metadata.as_ref().map(|v| v.to_string())
            ],
        )?;
        Ok(())
    }

    pub fn update_plan_status(&self, plan_id: &str, status: &str) -> anyhow::Result<()> {
        let conn = lock_or_recover(&self.conn);
        conn.execute(
            "UPDATE plans SET status = ?1 WHERE plan_id = ?2",
            params![status, plan_id],
        )?;
        Ok(())
    }

    pub fn update_plan_index(&self, plan_id: &str, index: usize) -> anyhow::Result<()> {
        let conn = lock_or_recover(&self.conn);
        conn.execute(
            "UPDATE plans SET next_task_index = ?1 WHERE plan_id = ?2",
            params![index as i64, plan_id],
        )?;
        Ok(())
    }

    pub fn get_plan(&self, plan_id: &str) -> anyhow::Result<Option<Plan>> {
        let conn = lock_or_recover(&self.conn);
        let mut stmt = conn.prepare("SELECT plan_id, created_at, status, agent_ids, task_sequence, next_task_index, metadata FROM plans WHERE plan_id = ?1")?;
        let mut rows = stmt.query(params![plan_id])?;
        if let Some(row) = rows.next()? {
            let agent_ids: Vec<u64> = serde_json::from_str(&row.get::<_, String>(3)?)?;
            let task_sequence: Vec<String> = serde_json::from_str(&row.get::<_, String>(4)?)?;
            let metadata: Option<serde_json::Value> = row.get::<_, Option<String>>(6)?.and_then(|s| serde_json::from_str(&s).ok());
            Ok(Some(Plan {
                plan_id: row.get(0)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?).map_err(|e| anyhow::anyhow!("Invalid date: {}", e))?.with_timezone(&Utc),
                status: row.get(2)?,
                agent_ids,
                task_sequence,
                next_task_index: row.get::<_, i64>(5)? as usize,
                metadata,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_pending_plans(&self, limit: usize) -> anyhow::Result<Vec<Plan>> {
        let conn = lock_or_recover(&self.conn);
        let mut stmt = conn.prepare("SELECT plan_id, created_at, status, agent_ids, task_sequence, next_task_index, metadata FROM plans WHERE status = 'pending' OR status = 'running' ORDER BY created_at ASC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let agent_ids: Vec<u64> = serde_json::from_str(&row.get::<_, String>(3)?).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let task_sequence: Vec<String> = serde_json::from_str(&row.get::<_, String>(4)?).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let metadata: Option<serde_json::Value> = row.get::<_, Option<String>>(6)?.map(|s| serde_json::from_str(&s).ok()).flatten();
            Ok(Plan {
                plan_id: row.get(0)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?.with_timezone(&Utc),
                status: row.get(2)?,
                agent_ids,
                task_sequence,
                next_task_index: row.get::<_, i64>(5)? as usize,
                metadata,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn delete_plan(&self, plan_id: &str) -> anyhow::Result<()> {
        let conn = lock_or_recover(&self.conn);
        conn.execute("DELETE FROM plans WHERE plan_id = ?1", params![plan_id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_plan_store_init() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("plans.db");
        let store = PlanStore::open(db_path).unwrap();
        
        let plan = Plan {
            plan_id: "test_plan_1".to_string(),
            created_at: Utc::now(),
            status: "pending".to_string(),
            agent_ids: vec![1, 2],
            task_sequence: vec!["task1".to_string(), "task2".to_string()],
            next_task_index: 0,
            metadata: None,
        };
        
        store.insert_plan(&plan).unwrap();
        let fetched = store.get_plan("test_plan_1").unwrap().unwrap();
        assert_eq!(fetched.plan_id, "test_plan_1");
        assert_eq!(fetched.status, "pending");
        assert_eq!(fetched.agent_ids, vec![1, 2]);
    }

    #[test]
    fn test_plan_workflow() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("plans_workflow.db");
        let store = PlanStore::open(db_path).unwrap();
        
        let plan = Plan {
            plan_id: "workflow_plan".to_string(),
            created_at: Utc::now(),
            status: "pending".to_string(),
            agent_ids: vec![1],
            task_sequence: vec!["task1".to_string(), "task2".to_string(), "task3".to_string()],
            next_task_index: 0,
            metadata: Some(serde_json::json!({"description": "Test workflow"})),
        };
        
        store.insert_plan(&plan).unwrap();
        
        // Update status
        store.update_plan_status("workflow_plan", "running").unwrap();
        let updated = store.get_plan("workflow_plan").unwrap().unwrap();
        assert_eq!(updated.status, "running");
        
        // Update task index
        store.update_plan_index("workflow_plan", 2).unwrap();
        let updated = store.get_plan("workflow_plan").unwrap().unwrap();
        assert_eq!(updated.next_task_index, 2);
        
        // Mark complete
        store.update_plan_status("workflow_plan", "completed").unwrap();
        let updated = store.get_plan("workflow_plan").unwrap().unwrap();
        assert_eq!(updated.status, "completed");
    }
}
