//! PTY Lifecycle Tests
//!
//! These tests verify proper PTY (pseudo-terminal) lifecycle management:
//! - PTY creation and initialization
//! - Input/output streaming
//! - Resize handling
//! - Graceful shutdown
//! - Cleanup on tab close
//! - Resource leak prevention
//! - Concurrent PTY access

use std::sync::{Arc, Mutex, atomic::{AtomicU32, AtomicBool, Ordering}};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

// ============================================
// Mock PTY Structures
// ============================================

#[derive(Debug, Clone)]
struct PtyInfo {
    id: u32,
    pid: u32,
    shell: String,
    cwd: String,
    rows: u16,
    cols: u16,
    is_alive: bool,
}

#[derive(Debug)]
struct MockPtySession {
    info: PtyInfo,
    output_buffer: Vec<u8>,
    input_buffer: Vec<u8>,
    closed: bool,
}

impl MockPtySession {
    fn new(id: u32, shell: &str, cwd: &str) -> Self {
        Self {
            info: PtyInfo {
                id,
                pid: 1000 + id,
                shell: shell.to_string(),
                cwd: cwd.to_string(),
                rows: 24,
                cols: 80,
                is_alive: true,
            },
            output_buffer: Vec::new(),
            input_buffer: Vec::new(),
            closed: false,
        }
    }

    fn send_input(&mut self, data: &[u8]) -> Result<(), String> {
        if self.closed {
            return Err("PTY is closed".to_string());
        }
        self.input_buffer.extend_from_slice(data);

        // Simulate echo
        self.output_buffer.extend_from_slice(data);
        Ok(())
    }

    fn read_output(&mut self) -> Vec<u8> {
        let output = self.output_buffer.clone();
        self.output_buffer.clear();
        output
    }

    fn resize(&mut self, rows: u16, cols: u16) -> Result<(), String> {
        if self.closed {
            return Err("PTY is closed".to_string());
        }
        if rows == 0 || cols == 0 {
            return Err("Invalid dimensions".to_string());
        }
        self.info.rows = rows;
        self.info.cols = cols;
        Ok(())
    }

    fn close(&mut self) {
        self.closed = true;
        self.info.is_alive = false;
    }
}

#[derive(Debug)]
struct MockPtyRegistry {
    ptys: Arc<Mutex<HashMap<u32, MockPtySession>>>,
    next_id: Arc<AtomicU32>,
    total_created: Arc<AtomicU32>,
    total_destroyed: Arc<AtomicU32>,
}

impl MockPtyRegistry {
    fn new() -> Self {
        Self {
            ptys: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
            total_created: Arc::new(AtomicU32::new(0)),
            total_destroyed: Arc::new(AtomicU32::new(0)),
        }
    }

    fn spawn(&self, shell: Option<&str>, cwd: Option<&str>) -> Result<PtyInfo, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let shell = shell.unwrap_or("/bin/zsh");
        let cwd = cwd.unwrap_or("/tmp");

        let session = MockPtySession::new(id, shell, cwd);
        let info = session.info.clone();

        let mut ptys = self.ptys.lock().unwrap();
        ptys.insert(id, session);
        self.total_created.fetch_add(1, Ordering::SeqCst);

        Ok(info)
    }

    fn send_input(&self, id: u32, data: &[u8]) -> Result<(), String> {
        let mut ptys = self.ptys.lock().unwrap();
        if let Some(pty) = ptys.get_mut(&id) {
            pty.send_input(data)
        } else {
            Err(format!("PTY {} not found", id))
        }
    }

    fn read_output(&self, id: u32) -> Result<Vec<u8>, String> {
        let mut ptys = self.ptys.lock().unwrap();
        if let Some(pty) = ptys.get_mut(&id) {
            Ok(pty.read_output())
        } else {
            Err(format!("PTY {} not found", id))
        }
    }

    fn resize(&self, id: u32, rows: u16, cols: u16) -> Result<(), String> {
        let mut ptys = self.ptys.lock().unwrap();
        if let Some(pty) = ptys.get_mut(&id) {
            pty.resize(rows, cols)
        } else {
            Err(format!("PTY {} not found", id))
        }
    }

    fn close(&self, id: u32) -> Result<(), String> {
        let mut ptys = self.ptys.lock().unwrap();
        if let Some(pty) = ptys.remove(&id) {
            drop(pty); // Explicitly drop
            self.total_destroyed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        } else {
            Err(format!("PTY {} not found", id))
        }
    }

    fn get_info(&self, id: u32) -> Option<PtyInfo> {
        let ptys = self.ptys.lock().unwrap();
        ptys.get(&id).map(|p| p.info.clone())
    }

    fn count(&self) -> usize {
        self.ptys.lock().unwrap().len()
    }

    fn cleanup_dead(&self) -> usize {
        let mut ptys = self.ptys.lock().unwrap();
        let dead: Vec<u32> = ptys.iter()
            .filter(|(_, p)| !p.info.is_alive || p.closed)
            .map(|(id, _)| *id)
            .collect();

        let count = dead.len();
        for id in dead {
            ptys.remove(&id);
            self.total_destroyed.fetch_add(1, Ordering::SeqCst);
        }
        count
    }

    fn cleanup_all(&self) -> usize {
        let mut ptys = self.ptys.lock().unwrap();
        let count = ptys.len();
        ptys.clear();
        self.total_destroyed.fetch_add(count as u32, Ordering::SeqCst);
        count
    }

    fn get_stats(&self) -> (u32, u32, usize) {
        (
            self.total_created.load(Ordering::SeqCst),
            self.total_destroyed.load(Ordering::SeqCst),
            self.count(),
        )
    }
}

// ============================================
// Creation Tests
// ============================================

#[cfg(test)]
mod creation_tests {
    use super::*;

    #[test]
    fn test_spawn_default_shell() {
        let registry = MockPtyRegistry::new();
        let result = registry.spawn(None, None);

        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.id, 1);
        assert!(info.is_alive);
    }

    #[test]
    fn test_spawn_custom_shell() {
        let registry = MockPtyRegistry::new();
        let result = registry.spawn(Some("/bin/bash"), Some("/home/user"));

        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.shell, "/bin/bash");
        assert_eq!(info.cwd, "/home/user");
    }

    #[test]
    fn test_spawn_increments_id() {
        let registry = MockPtyRegistry::new();

        let pty1 = registry.spawn(None, None).unwrap();
        let pty2 = registry.spawn(None, None).unwrap();
        let pty3 = registry.spawn(None, None).unwrap();

        assert_eq!(pty1.id, 1);
        assert_eq!(pty2.id, 2);
        assert_eq!(pty3.id, 3);
    }

    #[test]
    fn test_spawn_default_dimensions() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        assert_eq!(info.rows, 24);
        assert_eq!(info.cols, 80);
    }

    #[test]
    fn test_concurrent_spawn() {
        let registry = Arc::new(MockPtyRegistry::new());
        let mut handles = vec![];

        for _ in 0..100 {
            let r = Arc::clone(&registry);
            handles.push(thread::spawn(move || {
                r.spawn(None, None).unwrap()
            }));
        }

        let infos: Vec<PtyInfo> = handles.into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // All IDs should be unique
        let ids: std::collections::HashSet<_> = infos.iter().map(|i| i.id).collect();
        assert_eq!(ids.len(), 100);
    }
}

// ============================================
// Input/Output Tests
// ============================================

#[cfg(test)]
mod io_tests {
    use super::*;

    #[test]
    fn test_send_input() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        let result = registry.send_input(info.id, b"echo hello");
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_output() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        registry.send_input(info.id, b"test").unwrap();
        let output = registry.read_output(info.id).unwrap();

        assert_eq!(output, b"test");
    }

    #[test]
    fn test_output_cleared_after_read() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        registry.send_input(info.id, b"test").unwrap();
        registry.read_output(info.id).unwrap();
        let second_read = registry.read_output(info.id).unwrap();

        assert!(second_read.is_empty());
    }

    #[test]
    fn test_send_to_invalid_pty() {
        let registry = MockPtyRegistry::new();
        let result = registry.send_input(999, b"test");

        assert!(result.is_err());
    }

    #[test]
    fn test_read_from_invalid_pty() {
        let registry = MockPtyRegistry::new();
        let result = registry.read_output(999);

        assert!(result.is_err());
    }

    #[test]
    fn test_large_input() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        let large_input = vec![b'x'; 100_000];
        let result = registry.send_input(info.id, &large_input);

        assert!(result.is_ok());
    }
}

// ============================================
// Resize Tests
// ============================================

#[cfg(test)]
mod resize_tests {
    use super::*;

    #[test]
    fn test_resize_valid() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        let result = registry.resize(info.id, 40, 120);
        assert!(result.is_ok());

        let updated = registry.get_info(info.id).unwrap();
        assert_eq!(updated.rows, 40);
        assert_eq!(updated.cols, 120);
    }

    #[test]
    fn test_resize_zero_rows() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        let result = registry.resize(info.id, 0, 80);
        assert!(result.is_err());
    }

    #[test]
    fn test_resize_zero_cols() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        let result = registry.resize(info.id, 24, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_resize_invalid_pty() {
        let registry = MockPtyRegistry::new();
        let result = registry.resize(999, 24, 80);

        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_resizes() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        for i in 1..=10 {
            registry.resize(info.id, 20 + i, 80 + i).unwrap();
        }

        let final_info = registry.get_info(info.id).unwrap();
        assert_eq!(final_info.rows, 30);
        assert_eq!(final_info.cols, 90);
    }
}

// ============================================
// Cleanup Tests
// ============================================

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn test_close_pty() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        assert_eq!(registry.count(), 1);

        let result = registry.close(info.id);
        assert!(result.is_ok());

        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_close_nonexistent() {
        let registry = MockPtyRegistry::new();
        let result = registry.close(999);

        assert!(result.is_err());
    }

    #[test]
    fn test_double_close() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        registry.close(info.id).unwrap();
        let result = registry.close(info.id);

        assert!(result.is_err());
    }

    #[test]
    fn test_operations_after_close() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();
        registry.close(info.id).unwrap();

        // All operations should fail
        assert!(registry.send_input(info.id, b"test").is_err());
        assert!(registry.read_output(info.id).is_err());
        assert!(registry.resize(info.id, 24, 80).is_err());
    }

    #[test]
    fn test_cleanup_all() {
        let registry = MockPtyRegistry::new();

        for _ in 0..10 {
            registry.spawn(None, None).unwrap();
        }

        assert_eq!(registry.count(), 10);

        let cleaned = registry.cleanup_all();
        assert_eq!(cleaned, 10);
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let registry = MockPtyRegistry::new();

        for _ in 0..5 {
            registry.spawn(None, None).unwrap();
        }

        registry.close(1).unwrap();
        registry.close(2).unwrap();

        let (created, destroyed, active) = registry.get_stats();
        assert_eq!(created, 5);
        assert_eq!(destroyed, 2);
        assert_eq!(active, 3);
    }
}

// ============================================
// Concurrent Access Tests
// ============================================

#[cfg(test)]
mod concurrent_tests {
    use super::*;

    #[test]
    fn test_concurrent_io() {
        let registry = Arc::new(MockPtyRegistry::new());
        let info = registry.spawn(None, None).unwrap();

        let mut handles = vec![];

        // Multiple writers
        for i in 0..10 {
            let r = Arc::clone(&registry);
            let id = info.id;
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let _ = r.send_input(id, format!("msg_{}_{}\n", i, j).as_bytes());
                }
            }));
        }

        // Reader
        let r = Arc::clone(&registry);
        let id = info.id;
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = r.read_output(id);
                thread::sleep(Duration::from_micros(100));
            }
        }));

        for handle in handles {
            handle.join().unwrap();
        }

        // Should complete without deadlock or panic
    }

    #[test]
    fn test_concurrent_resize() {
        let registry = Arc::new(MockPtyRegistry::new());
        let info = registry.spawn(None, None).unwrap();

        let mut handles = vec![];

        for _ in 0..10 {
            let r = Arc::clone(&registry);
            let id = info.id;
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = r.resize(id, 24, 80);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_spawn_while_closing() {
        let registry = Arc::new(MockPtyRegistry::new());
        let mut handles = vec![];

        // Spawner
        let r1 = Arc::clone(&registry);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = r1.spawn(None, None);
            }
        }));

        // Closer
        let r2 = Arc::clone(&registry);
        handles.push(thread::spawn(move || {
            for id in 1..50 {
                let _ = r2.close(id);
                thread::sleep(Duration::from_micros(100));
            }
        }));

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

// ============================================
// Resource Leak Tests
// ============================================

#[cfg(test)]
mod leak_tests {
    use super::*;

    #[test]
    fn test_no_leak_on_close() {
        let registry = MockPtyRegistry::new();

        for _ in 0..100 {
            let info = registry.spawn(None, None).unwrap();
            registry.close(info.id).unwrap();
        }

        let (created, destroyed, active) = registry.get_stats();
        assert_eq!(created, destroyed, "Created and destroyed counts should match");
        assert_eq!(active, 0, "No active PTYs should remain");
    }

    #[test]
    fn test_cleanup_dead_ptys() {
        let registry = MockPtyRegistry::new();

        for _ in 0..10 {
            registry.spawn(None, None).unwrap();
        }

        // Simulate some PTYs dying
        {
            let mut ptys = registry.ptys.lock().unwrap();
            for (_, pty) in ptys.iter_mut().take(5) {
                pty.info.is_alive = false;
            }
        }

        let cleaned = registry.cleanup_dead();
        assert_eq!(cleaned, 5);
        assert_eq!(registry.count(), 5);
    }
}

// ============================================
// Edge Cases Tests
// ============================================

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        let result = registry.send_input(info.id, b"");
        assert!(result.is_ok());
    }

    #[test]
    fn test_binary_input() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        // Binary data including null bytes
        let binary = vec![0x00, 0x01, 0xFF, 0xFE, 0x00];
        let result = registry.send_input(info.id, &binary);
        assert!(result.is_ok());

        let output = registry.read_output(info.id).unwrap();
        assert_eq!(output, binary);
    }

    #[test]
    fn test_unicode_input() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        let unicode = "Hello 世界 🎉".as_bytes();
        registry.send_input(info.id, unicode).unwrap();

        let output = registry.read_output(info.id).unwrap();
        assert_eq!(String::from_utf8_lossy(&output), "Hello 世界 🎉");
    }

    #[test]
    fn test_very_large_dimensions() {
        let registry = MockPtyRegistry::new();
        let info = registry.spawn(None, None).unwrap();

        let result = registry.resize(info.id, u16::MAX, u16::MAX);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rapid_spawn_close() {
        let registry = MockPtyRegistry::new();

        for _ in 0..1000 {
            let info = registry.spawn(None, None).unwrap();
            registry.close(info.id).unwrap();
        }

        assert_eq!(registry.count(), 0);
    }
}

// ============================================
// Integration Tests
// ============================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_lifecycle() {
        let registry = MockPtyRegistry::new();

        // Create
        let info = registry.spawn(Some("/bin/bash"), Some("/home")).unwrap();
        assert!(info.is_alive);

        // Resize
        registry.resize(info.id, 50, 150).unwrap();
        let resized = registry.get_info(info.id).unwrap();
        assert_eq!(resized.rows, 50);
        assert_eq!(resized.cols, 150);

        // Send input
        registry.send_input(info.id, b"echo hello\n").unwrap();

        // Read output
        let output = registry.read_output(info.id).unwrap();
        assert!(!output.is_empty());

        // Close
        registry.close(info.id).unwrap();
        assert!(registry.get_info(info.id).is_none());
    }

    #[test]
    fn test_multiple_ptys() {
        let registry = MockPtyRegistry::new();

        let pty1 = registry.spawn(Some("/bin/bash"), Some("/home")).unwrap();
        let pty2 = registry.spawn(Some("/bin/zsh"), Some("/tmp")).unwrap();

        registry.send_input(pty1.id, b"bash-command").unwrap();
        registry.send_input(pty2.id, b"zsh-command").unwrap();

        let out1 = registry.read_output(pty1.id).unwrap();
        let out2 = registry.read_output(pty2.id).unwrap();

        // Each PTY should have independent buffers
        assert!(String::from_utf8_lossy(&out1).contains("bash"));
        assert!(String::from_utf8_lossy(&out2).contains("zsh"));
    }
}
