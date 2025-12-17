#!/usr/bin/env python3
import sqlite3
import uuid
from datetime import datetime

DB_PATH = "phase1_6_test.db"

def iso_now():
    return datetime.utcnow().isoformat() + "Z"

def create_tables(conn):
    c = conn.cursor()

    # Batches
    c.execute("""
    CREATE TABLE IF NOT EXISTS batches (
        id TEXT PRIMARY KEY,
        phase INTEGER,
        status TEXT,
        created_at TEXT,
        depends_on TEXT
    )
    """)
    
    # Batch entries
    c.execute("""
    CREATE TABLE IF NOT EXISTS batch_entries (
        id TEXT PRIMARY KEY,
        batch_id TEXT,
        tool TEXT,
        command TEXT,
        exit_code INTEGER,
        stdout TEXT,
        stderr TEXT,
        FOREIGN KEY(batch_id) REFERENCES batches(id)
    )
    """)

    # Agents
    c.execute("""
    CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        name TEXT,
        status TEXT,
        current_batch TEXT
    )
    """)

    # Plans
    c.execute("""
    CREATE TABLE IF NOT EXISTS plans (
        id TEXT PRIMARY KEY,
        name TEXT,
        phase INTEGER,
        status TEXT,
        progress INTEGER,
        created_at TEXT
    )
    """)

    # Telemetry
    c.execute("""
    CREATE TABLE IF NOT EXISTS telemetry (
        id TEXT PRIMARY KEY,
        ts TEXT,
        event_type TEXT,
        tab_id INTEGER,
        batch_id TEXT,
        tool TEXT,
        command TEXT,
        exit_code INTEGER,
        stdout TEXT,
        stderr TEXT,
        safety_score INTEGER,
        metadata TEXT
    )
    """)

    conn.commit()

def insert_test_data(conn):
    c = conn.cursor()

    # Phase 1 batch
    batch1_id = str(uuid.uuid4())
    c.execute("INSERT INTO batches VALUES (?,?,?,?,?)",
              (batch1_id, 1, "Completed", iso_now(), None))
    c.execute("INSERT INTO batch_entries VALUES (?,?,?,?,?,?,?)",
              (str(uuid.uuid4()), batch1_id, "execute_shell", "echo Phase1Test", 0, "Phase1Test", ""))
    c.execute("INSERT INTO batch_entries VALUES (?,?,?,?,?,?,?)",
              (str(uuid.uuid4()), batch1_id, "execute_shell", "pwd", 0, "/home/user", ""))

    # Phase 2 batch depends on batch1
    batch2_id = str(uuid.uuid4())
    c.execute("INSERT INTO batches VALUES (?,?,?,?,?)",
              (batch2_id, 2, "Pending", iso_now(), batch1_id))
    c.execute("INSERT INTO batch_entries VALUES (?,?,?,?,?,?,?)",
              (str(uuid.uuid4()), batch2_id, "execute_shell", "whoami", 0, "user", ""))

    # Agents
    agent1_id = str(uuid.uuid4())
    agent2_id = str(uuid.uuid4())
    c.execute("INSERT INTO agents VALUES (?,?,?,?)", (agent1_id, "Agent Alpha", "idle", None))
    c.execute("INSERT INTO agents VALUES (?,?,?,?)", (agent2_id, "Agent Beta", "running", batch1_id))

    # Phase 6 plan
    plan_id = str(uuid.uuid4())
    c.execute("INSERT INTO plans VALUES (?,?,?,?,?,?)",
              (plan_id, "Multi-day Test Plan", 6, "Pending", 0, iso_now()))

    # Sample telemetry for Phase 1 & 2
    for batch_id in [batch1_id, batch2_id]:
        for cmd in ["echo Test", "pwd"]:
            event_id = str(uuid.uuid4())
            c.execute("INSERT INTO telemetry VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (event_id, iso_now(), "tool_execution", None, batch_id,
                       "execute_shell", cmd, 0, "OK", "", 100, "{}"))

    conn.commit()

def main():
    conn = sqlite3.connect(DB_PATH)
    create_tables(conn)
    insert_test_data(conn)
    conn.close()
    print(f"Database '{DB_PATH}' created with pre-populated Phase 1–6 test data.")

if __name__ == "__main__":
    main()
