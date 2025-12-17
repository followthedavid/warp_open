// src-tauri/src/telemetry.rs
// Phase 4: Telemetry & Learning System
// Collects structured events for policy training and audit

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use chrono::{Utc, DateTime};
use uuid::Uuid;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub event_type: String,
    pub tab_id: Option<u64>,
    pub batch_id: Option<String>,
    pub tool: Option<String>,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub safety_score: Option<i32>,
    pub safety_label: Option<i32>, // 0=safe, 1=unsafe, 2=unknown
    pub metadata: Option<serde_json::Value>,
}

impl TelemetryEvent {
    pub fn new(event_type: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now(),
            event_type,
            tab_id: None,
            batch_id: None,
            tool: None,
            command: None,
            exit_code: None,
            stdout: None,
            stderr: None,
            safety_score: None,
            safety_label: None,
            metadata: None,
        }
    }

    pub fn with_command(mut self, cmd: String) -> Self {
        self.command = Some(cmd);
        self
    }

    pub fn with_tool(mut self, tool: String) -> Self {
        self.tool = Some(tool);
        self
    }

    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    pub fn with_safety_score(mut self, score: i32) -> Self {
        self.safety_score = Some(score);
        self
    }

    pub fn with_batch_id(mut self, batch_id: String) -> Self {
        self.batch_id = Some(batch_id);
        self
    }
}

pub struct TelemetryStore {
    conn: Mutex<Connection>,
}

impl TelemetryStore {
    pub fn open(db_path: PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;
        let store = TelemetryStore { conn: Mutex::new(conn) };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS telemetry (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                event_type TEXT NOT NULL,
                tab_id INTEGER,
                batch_id TEXT,
                tool TEXT,
                command TEXT,
                exit_code INTEGER,
                stdout TEXT,
                stderr TEXT,
                safety_score INTEGER,
                safety_label INTEGER,
                metadata TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_telemetry_ts ON telemetry(ts);
            CREATE INDEX IF NOT EXISTS idx_telemetry_batch ON telemetry(batch_id);
            CREATE INDEX IF NOT EXISTS idx_telemetry_event_type ON telemetry(event_type);
            "#
        )?;
        eprintln!("[TELEMETRY] Initialized SQLite database");
        Ok(())
    }

    pub fn insert_event(&self, event: &TelemetryEvent) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO telemetry (id, ts, event_type, tab_id, batch_id, tool, command, exit_code, stdout, stderr, safety_score, safety_label, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                event.id,
                event.ts.to_rfc3339(),
                event.event_type,
                event.tab_id,
                event.batch_id,
                event.tool,
                event.command,
                event.exit_code,
                event.stdout,
                event.stderr,
                event.safety_score,
                event.safety_label,
                event.metadata.as_ref().map(|v| v.to_string())
            ],
        )?;
        eprintln!("[TELEMETRY] Inserted event: {} ({})", event.event_type, event.id);
        Ok(())
    }

    // Query recent events with limit
    pub fn query_recent(&self, limit: usize) -> anyhow::Result<Vec<TelemetryEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ts, event_type, tab_id, batch_id, tool, command, exit_code, stdout, stderr, safety_score, safety_label, metadata
             FROM telemetry ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let metadata_s: Option<String> = row.get(12)?;
            Ok(TelemetryEvent {
                id: row.get(0)?,
                ts: chrono::DateTime::parse_from_rfc3339(&row.get::<usize, String>(1)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                event_type: row.get(2)?,
                tab_id: row.get(3).ok(),
                batch_id: row.get(4).ok(),
                tool: row.get(5).ok(),
                command: row.get(6).ok(),
                exit_code: row.get(7).ok(),
                stdout: row.get(8).ok(),
                stderr: row.get(9).ok(),
                safety_score: row.get(10).ok(),
                safety_label: row.get(11).ok(),
                metadata: metadata_s.and_then(|s| serde_json::from_str(&s).ok()),
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        eprintln!("[TELEMETRY] Queried {} recent events", out.len());
        Ok(out)
    }

    // Export all telemetry data to CSV
    pub fn export_csv(&self, out_path: PathBuf) -> anyhow::Result<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM telemetry ORDER BY ts ASC")?;
        let mut rows = stmt.query([])?;
        
        let mut wtr = csv::Writer::from_path(&out_path)?;
        
        // Write header
        wtr.write_record(&[
            "id","ts","event_type","tab_id","batch_id","tool","command",
            "exit_code","stdout","stderr","safety_score","safety_label","metadata"
        ])?;
        
        let mut count = 0;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let ts: String = row.get(1)?;
            let event_type: String = row.get(2)?;
            let tab_id: Option<i64> = row.get(3).ok();
            let batch_id: Option<String> = row.get(4).ok();
            let tool: Option<String> = row.get(5).ok();
            let command: Option<String> = row.get(6).ok();
            let exit_code: Option<i64> = row.get(7).ok();
            let stdout: Option<String> = row.get(8).ok();
            let stderr: Option<String> = row.get(9).ok();
            let safety_score: Option<i64> = row.get(10).ok();
            let safety_label: Option<i64> = row.get(11).ok();
            let metadata: Option<String> = row.get(12).ok();

            wtr.write_record(&[
                &id,
                &ts,
                &event_type,
                &tab_id.map(|v| v.to_string()).unwrap_or_default(),
                &batch_id.unwrap_or_default(),
                &tool.unwrap_or_default(),
                &command.unwrap_or_default(),
                &exit_code.map(|v| v.to_string()).unwrap_or_default(),
                &stdout.unwrap_or_default(),
                &stderr.unwrap_or_default(),
                &safety_score.map(|v| v.to_string()).unwrap_or_default(),
                &safety_label.map(|v| v.to_string()).unwrap_or_default(),
                &metadata.unwrap_or_default(),
            ])?;
            count += 1;
        }
        wtr.flush()?;
        
        let path_str = out_path.to_string_lossy().to_string();
        eprintln!("[TELEMETRY] Exported {} events to {}", count, path_str);
        Ok(path_str)
    }

    // Count total events
    pub fn count_events(&self) -> anyhow::Result<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM telemetry", [], |row| row.get(0))?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_telemetry_store_init() {
        let tmp_path = std::env::temp_dir().join("test_telemetry.sqlite");
        let _ = fs::remove_file(&tmp_path);
        
        let store = TelemetryStore::open(tmp_path.clone()).unwrap();
        assert!(tmp_path.exists());
        
        let count = store.count_events().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_telemetry_insert_and_query() {
        let tmp_path = std::env::temp_dir().join("test_telemetry2.sqlite");
        let _ = fs::remove_file(&tmp_path);
        
        let store = TelemetryStore::open(tmp_path.clone()).unwrap();
        
        let event = TelemetryEvent::new("command_executed".to_string())
            .with_command("echo test".to_string())
            .with_tool("execute_shell".to_string())
            .with_exit_code(0)
            .with_safety_score(100);
        
        store.insert_event(&event).unwrap();
        
        let events = store.query_recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].command, Some("echo test".to_string()));
        assert_eq!(events[0].exit_code, Some(0));
    }

    #[test]
    fn test_telemetry_export_csv() {
        let tmp_db = std::env::temp_dir().join("test_telemetry3.sqlite");
        let tmp_csv = std::env::temp_dir().join("test_telemetry3.csv");
        let _ = fs::remove_file(&tmp_db);
        let _ = fs::remove_file(&tmp_csv);
        
        let store = TelemetryStore::open(tmp_db).unwrap();
        
        let event = TelemetryEvent::new("test_event".to_string())
            .with_command("ls".to_string());
        store.insert_event(&event).unwrap();
        
        let path = store.export_csv(tmp_csv.clone()).unwrap();
        assert!(tmp_csv.exists());
        assert!(path.contains("test_telemetry3.csv"));
        
        let csv_content = fs::read_to_string(&tmp_csv).unwrap();
        assert!(csv_content.contains("test_event"));
        assert!(csv_content.contains("ls"));
    }
}
