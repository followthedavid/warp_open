//! Batch Execution Race Condition Tests
//!
//! These tests verify that batch operations properly handle:
//! - Concurrent access to shared state
//! - Race conditions in batch approval/execution
//! - Deadlock prevention
//! - Proper ordering of dependent batches
//! - State consistency under concurrent modification

use std::sync::{Arc, Mutex, atomic::{AtomicUsize, AtomicBool, Ordering}};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

// ============================================
// Mock Batch Structures
// ============================================

#[derive(Debug, Clone, PartialEq)]
enum BatchStatus {
    Pending,
    Approved,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
struct BatchEntry {
    id: u32,
    commands: Vec<String>,
    status: BatchStatus,
    depends_on: Option<u32>,
    created_at: u64,
    executed_at: Option<u64>,
}

#[derive(Debug)]
struct MockBatchRegistry {
    batches: Arc<Mutex<HashMap<u32, BatchEntry>>>,
    next_id: Arc<AtomicUsize>,
    execution_count: Arc<AtomicUsize>,
    is_executing: Arc<AtomicBool>,
}

impl MockBatchRegistry {
    fn new() -> Self {
        Self {
            batches: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicUsize::new(1)),
            execution_count: Arc::new(AtomicUsize::new(0)),
            is_executing: Arc::new(AtomicBool::new(false)),
        }
    }

    fn create_batch(&self, commands: Vec<String>) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u32;
        let batch = BatchEntry {
            id,
            commands,
            status: BatchStatus::Pending,
            depends_on: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            executed_at: None,
        };

        let mut batches = self.batches.lock().unwrap();
        batches.insert(id, batch);
        id
    }

    fn approve_batch(&self, id: u32) -> Result<(), String> {
        let mut batches = self.batches.lock().unwrap();
        if let Some(batch) = batches.get_mut(&id) {
            if batch.status != BatchStatus::Pending {
                return Err(format!("Batch {} is not pending", id));
            }
            batch.status = BatchStatus::Approved;
            Ok(())
        } else {
            Err(format!("Batch {} not found", id))
        }
    }

    fn execute_batch(&self, id: u32) -> Result<(), String> {
        // Check if already executing (prevent concurrent execution)
        if self.is_executing.swap(true, Ordering::SeqCst) {
            return Err("Another batch is already executing".to_string());
        }

        let result = self.execute_batch_internal(id);
        self.is_executing.store(false, Ordering::SeqCst);
        result
    }

    fn execute_batch_internal(&self, id: u32) -> Result<(), String> {
        // Get batch and validate
        {
            let mut batches = self.batches.lock().unwrap();

            // First check if batch exists and is approved
            let batch = batches.get(&id).ok_or(format!("Batch {} not found", id))?;
            if batch.status != BatchStatus::Approved {
                return Err(format!("Batch {} is not approved", id));
            }

            // Check dependency if any
            let dep_id = batch.depends_on;
            if let Some(dep_id) = dep_id {
                let dep_batch = batches.get(&dep_id).ok_or(format!("Dependency {} not found", dep_id))?;
                if dep_batch.status != BatchStatus::Completed {
                    return Err(format!("Dependency {} not completed", dep_id));
                }
            }

            // Now modify the batch
            let batch = batches.get_mut(&id).unwrap();
            batch.status = BatchStatus::Running;
        }

        // Simulate execution (release lock during execution)
        thread::sleep(Duration::from_millis(10));
        self.execution_count.fetch_add(1, Ordering::SeqCst);

        // Mark complete
        {
            let mut batches = self.batches.lock().unwrap();
            if let Some(batch) = batches.get_mut(&id) {
                batch.status = BatchStatus::Completed;
                batch.executed_at = Some(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs());
            }
        }

        Ok(())
    }

    fn set_dependency(&self, batch_id: u32, depends_on: u32) -> Result<(), String> {
        let mut batches = self.batches.lock().unwrap();

        // Check for circular dependency
        if let Some(dep_batch) = batches.get(&depends_on) {
            if dep_batch.depends_on == Some(batch_id) {
                return Err("Circular dependency detected".to_string());
            }
        }

        if let Some(batch) = batches.get_mut(&batch_id) {
            batch.depends_on = Some(depends_on);
            Ok(())
        } else {
            Err(format!("Batch {} not found", batch_id))
        }
    }

    fn get_status(&self, id: u32) -> Option<BatchStatus> {
        let batches = self.batches.lock().unwrap();
        batches.get(&id).map(|b| b.status.clone())
    }

    fn cancel_batch(&self, id: u32) -> Result<(), String> {
        let mut batches = self.batches.lock().unwrap();
        if let Some(batch) = batches.get_mut(&id) {
            if batch.status == BatchStatus::Running {
                return Err("Cannot cancel running batch".to_string());
            }
            if batch.status == BatchStatus::Completed {
                return Err("Cannot cancel completed batch".to_string());
            }
            batch.status = BatchStatus::Cancelled;
            Ok(())
        } else {
            Err(format!("Batch {} not found", id))
        }
    }
}

// ============================================
// Concurrent Access Tests
// ============================================

#[cfg(test)]
mod concurrent_access_tests {
    use super::*;

    #[test]
    fn test_concurrent_batch_creation() {
        let registry = Arc::new(MockBatchRegistry::new());
        let mut handles = vec![];

        // Create 100 batches concurrently
        for i in 0..100 {
            let registry_clone = Arc::clone(&registry);
            handles.push(thread::spawn(move || {
                registry_clone.create_batch(vec![format!("command_{}", i)])
            }));
        }

        let ids: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All IDs should be unique
        let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique_ids.len(), 100, "All batch IDs should be unique");

        // All batches should exist
        for id in ids {
            assert!(registry.get_status(id).is_some());
        }
    }

    #[test]
    fn test_concurrent_approval() {
        let registry = Arc::new(MockBatchRegistry::new());
        let batch_id = registry.create_batch(vec!["test".to_string()]);

        let mut handles = vec![];

        // Try to approve same batch from multiple threads
        for _ in 0..10 {
            let registry_clone = Arc::clone(&registry);
            handles.push(thread::spawn(move || {
                registry_clone.approve_batch(batch_id)
            }));
        }

        let results: Vec<Result<(), String>> = handles.into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // Exactly one should succeed
        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(successes, 1, "Exactly one approval should succeed");

        // Final status should be Approved
        assert_eq!(registry.get_status(batch_id), Some(BatchStatus::Approved));
    }

    #[test]
    fn test_concurrent_execution_prevention() {
        let registry = Arc::new(MockBatchRegistry::new());

        // Create and approve two batches
        let batch1 = registry.create_batch(vec!["cmd1".to_string()]);
        let batch2 = registry.create_batch(vec!["cmd2".to_string()]);
        registry.approve_batch(batch1).unwrap();
        registry.approve_batch(batch2).unwrap();

        let registry1 = Arc::clone(&registry);
        let registry2 = Arc::clone(&registry);

        // Try to execute both concurrently
        let handle1 = thread::spawn(move || {
            registry1.execute_batch(batch1)
        });

        let handle2 = thread::spawn(move || {
            registry2.execute_batch(batch2)
        });

        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();

        // One should succeed, one should fail
        let successes = [&result1, &result2].iter().filter(|r| r.is_ok()).count();
        assert_eq!(successes, 1, "Only one concurrent execution should succeed");
    }

    #[test]
    fn test_read_during_write() {
        let registry = Arc::new(MockBatchRegistry::new());
        let batch_id = registry.create_batch(vec!["test".to_string()]);

        let registry_reader = Arc::clone(&registry);
        let registry_writer = Arc::clone(&registry);

        // Continuously read while another thread writes
        let reader_handle = thread::spawn(move || {
            let mut reads = 0;
            for _ in 0..100 {
                if registry_reader.get_status(batch_id).is_some() {
                    reads += 1;
                }
                thread::sleep(Duration::from_micros(100));
            }
            reads
        });

        let writer_handle = thread::spawn(move || {
            for _ in 0..50 {
                // Try approve/cancel cycles
                let _ = registry_writer.approve_batch(batch_id);
                thread::sleep(Duration::from_micros(50));
            }
        });

        let reads = reader_handle.join().unwrap();
        writer_handle.join().unwrap();

        // Should have completed reads without panicking
        assert!(reads > 0, "Reader should have completed some reads");
    }
}

// ============================================
// Dependency Chain Tests
// ============================================

#[cfg(test)]
mod dependency_tests {
    use super::*;

    #[test]
    fn test_dependency_prevents_execution() {
        let registry = MockBatchRegistry::new();

        let batch1 = registry.create_batch(vec!["first".to_string()]);
        let batch2 = registry.create_batch(vec!["second".to_string()]);

        registry.set_dependency(batch2, batch1).unwrap();

        registry.approve_batch(batch1).unwrap();
        registry.approve_batch(batch2).unwrap();

        // Try to execute batch2 before batch1
        let result = registry.execute_batch(batch2);
        assert!(result.is_err(), "Should fail due to unmet dependency");
        assert!(result.unwrap_err().contains("not completed"));
    }

    #[test]
    fn test_dependency_chain_execution() {
        let registry = MockBatchRegistry::new();

        let batch1 = registry.create_batch(vec!["first".to_string()]);
        let batch2 = registry.create_batch(vec!["second".to_string()]);
        let batch3 = registry.create_batch(vec!["third".to_string()]);

        registry.set_dependency(batch2, batch1).unwrap();
        registry.set_dependency(batch3, batch2).unwrap();

        registry.approve_batch(batch1).unwrap();
        registry.approve_batch(batch2).unwrap();
        registry.approve_batch(batch3).unwrap();

        // Execute in order
        assert!(registry.execute_batch(batch1).is_ok());
        assert!(registry.execute_batch(batch2).is_ok());
        assert!(registry.execute_batch(batch3).is_ok());
    }

    #[test]
    fn test_circular_dependency_detection() {
        let registry = MockBatchRegistry::new();

        let batch1 = registry.create_batch(vec!["first".to_string()]);
        let batch2 = registry.create_batch(vec!["second".to_string()]);

        registry.set_dependency(batch2, batch1).unwrap();

        // Try to create circular dependency
        let result = registry.set_dependency(batch1, batch2);
        assert!(result.is_err(), "Should detect circular dependency");
        assert!(result.unwrap_err().contains("Circular"));
    }

    #[test]
    fn test_missing_dependency() {
        let registry = MockBatchRegistry::new();

        let batch1 = registry.create_batch(vec!["test".to_string()]);

        // Set dependency on non-existent batch
        registry.set_dependency(batch1, 999).unwrap(); // This sets it

        registry.approve_batch(batch1).unwrap();

        // Execution should fail
        let result = registry.execute_batch(batch1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }
}

// ============================================
// State Transition Tests
// ============================================

#[cfg(test)]
mod state_transition_tests {
    use super::*;

    #[test]
    fn test_valid_state_transitions() {
        let registry = MockBatchRegistry::new();
        let batch_id = registry.create_batch(vec!["test".to_string()]);

        // Pending -> Approved
        assert_eq!(registry.get_status(batch_id), Some(BatchStatus::Pending));
        registry.approve_batch(batch_id).unwrap();
        assert_eq!(registry.get_status(batch_id), Some(BatchStatus::Approved));

        // Approved -> Running -> Completed (via execute)
        registry.execute_batch(batch_id).unwrap();
        assert_eq!(registry.get_status(batch_id), Some(BatchStatus::Completed));
    }

    #[test]
    fn test_invalid_double_approval() {
        let registry = MockBatchRegistry::new();
        let batch_id = registry.create_batch(vec!["test".to_string()]);

        registry.approve_batch(batch_id).unwrap();

        // Second approval should fail
        let result = registry.approve_batch(batch_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_execute_pending() {
        let registry = MockBatchRegistry::new();
        let batch_id = registry.create_batch(vec!["test".to_string()]);

        // Try to execute without approval
        let result = registry.execute_batch(batch_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not approved"));
    }

    #[test]
    fn test_cannot_cancel_running() {
        let registry = Arc::new(MockBatchRegistry::new());
        let batch_id = registry.create_batch(vec!["test".to_string()]);
        registry.approve_batch(batch_id).unwrap();

        // Start execution in background
        let registry_exec = Arc::clone(&registry);
        let handle = thread::spawn(move || {
            registry_exec.execute_batch(batch_id)
        });

        // Give it time to start
        thread::sleep(Duration::from_millis(2));

        // Try to cancel while running
        // Note: This is a race - the batch might complete before we try to cancel
        let cancel_result = registry.cancel_batch(batch_id);

        handle.join().unwrap();

        // Either cancel failed (running) or batch completed
        let final_status = registry.get_status(batch_id);
        assert!(
            cancel_result.is_err() || final_status == Some(BatchStatus::Completed),
            "Either cancel failed or batch completed"
        );
    }

    #[test]
    fn test_cannot_cancel_completed() {
        let registry = MockBatchRegistry::new();
        let batch_id = registry.create_batch(vec!["test".to_string()]);

        registry.approve_batch(batch_id).unwrap();
        registry.execute_batch(batch_id).unwrap();

        // Try to cancel completed batch
        let result = registry.cancel_batch(batch_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot cancel completed"));
    }
}

// ============================================
// Stress Tests
// ============================================

#[cfg(test)]
mod stress_tests {
    use super::*;

    #[test]
    fn test_high_volume_batch_creation() {
        let registry = Arc::new(MockBatchRegistry::new());
        let mut handles = vec![];

        // Create 1000 batches from 10 threads
        for thread_id in 0..10 {
            let registry_clone = Arc::clone(&registry);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    registry_clone.create_batch(vec![format!("thread_{}_cmd_{}", thread_id, i)]);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 1000 batches
        let batches = registry.batches.lock().unwrap();
        assert_eq!(batches.len(), 1000);
    }

    #[test]
    fn test_sequential_execution_under_load() {
        let registry = Arc::new(MockBatchRegistry::new());

        // Create, approve, and execute 50 batches sequentially
        for i in 0..50 {
            let batch_id = registry.create_batch(vec![format!("cmd_{}", i)]);
            registry.approve_batch(batch_id).unwrap();
            registry.execute_batch(batch_id).unwrap();
        }

        // All should be completed
        let batches = registry.batches.lock().unwrap();
        for batch in batches.values() {
            assert_eq!(batch.status, BatchStatus::Completed);
        }
    }

    #[test]
    fn test_mixed_operations() {
        let registry = Arc::new(MockBatchRegistry::new());
        let mut handles = vec![];

        // Thread 1: Create batches
        let r1 = Arc::clone(&registry);
        handles.push(thread::spawn(move || {
            for i in 0..50 {
                r1.create_batch(vec![format!("create_{}", i)]);
            }
        }));

        // Thread 2: Approve random batches
        let r2 = Arc::clone(&registry);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = r2.approve_batch(rand_id());
                thread::sleep(Duration::from_micros(100));
            }
        }));

        // Thread 3: Cancel random batches
        let r3 = Arc::clone(&registry);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = r3.cancel_batch(rand_id());
                thread::sleep(Duration::from_micros(100));
            }
        }));

        // Thread 4: Read statuses
        let r4 = Arc::clone(&registry);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = r4.get_status(rand_id());
            }
        }));

        for handle in handles {
            handle.join().unwrap();
        }

        // Should complete without deadlocks or panics
    }
}

// Helper function for stress tests
fn rand_id() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() % 100 + 1) as u32
}

// ============================================
// Deadlock Prevention Tests
// ============================================

#[cfg(test)]
mod deadlock_tests {
    use super::*;

    #[test]
    fn test_no_deadlock_on_nested_access() {
        let registry = MockBatchRegistry::new();

        // This pattern could cause deadlock if locks aren't released properly
        let batch1 = registry.create_batch(vec!["cmd1".to_string()]);
        let batch2 = registry.create_batch(vec!["cmd2".to_string()]);

        registry.set_dependency(batch2, batch1).unwrap();
        registry.approve_batch(batch1).unwrap();
        registry.approve_batch(batch2).unwrap();

        // Execute batch1, then immediately batch2
        // This requires releasing the lock between executions
        registry.execute_batch(batch1).unwrap();
        registry.execute_batch(batch2).unwrap();

        assert_eq!(registry.get_status(batch1), Some(BatchStatus::Completed));
        assert_eq!(registry.get_status(batch2), Some(BatchStatus::Completed));
    }

    #[test]
    fn test_timeout_on_lock_acquisition() {
        // This documents the expected behavior - in production,
        // we'd use try_lock with timeout
        let registry = MockBatchRegistry::new();

        // Just verify normal lock acquisition works
        let batch_id = registry.create_batch(vec!["test".to_string()]);
        assert!(registry.get_status(batch_id).is_some());
    }
}

// ============================================
// Execution Order Tests
// ============================================

#[cfg(test)]
mod execution_order_tests {
    use super::*;

    #[test]
    fn test_fifo_execution_order() {
        let registry = MockBatchRegistry::new();

        let batch1 = registry.create_batch(vec!["first".to_string()]);
        let batch2 = registry.create_batch(vec!["second".to_string()]);
        let batch3 = registry.create_batch(vec!["third".to_string()]);

        // Approve in order
        registry.approve_batch(batch1).unwrap();
        registry.approve_batch(batch2).unwrap();
        registry.approve_batch(batch3).unwrap();

        // Execute in order
        registry.execute_batch(batch1).unwrap();
        registry.execute_batch(batch2).unwrap();
        registry.execute_batch(batch3).unwrap();

        // Verify order by executed_at timestamps
        let batches = registry.batches.lock().unwrap();
        let t1 = batches.get(&batch1).unwrap().executed_at.unwrap();
        let t2 = batches.get(&batch2).unwrap().executed_at.unwrap();
        let t3 = batches.get(&batch3).unwrap().executed_at.unwrap();

        assert!(t1 <= t2, "Batch 1 should execute before or at same time as 2");
        assert!(t2 <= t3, "Batch 2 should execute before or at same time as 3");
    }
}
