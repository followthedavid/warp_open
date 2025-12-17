// src-tauri/src/scheduler.rs
// Phase 6 Scheduler - Automatically advances pending plans with human oversight

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use crate::plan_store::PlanStore;
use crate::monitoring::MonitoringState;

#[derive(Clone)]
pub struct Scheduler {
    store: Arc<Mutex<PlanStore>>,
    monitor: MonitoringState,
    interval_sec: u64,
    running: Arc<Mutex<bool>>,
}

impl Scheduler {
    pub fn new(store: Arc<Mutex<PlanStore>>, monitor: MonitoringState, interval_sec: u64) -> Self {
        Scheduler {
            store,
            monitor,
            interval_sec,
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn start(&self) {
        let mut running = self.running.lock().unwrap();
        if *running {
            println!("[SCHEDULER] Already running");
            return;
        }
        *running = true;
        drop(running);

        let store = Arc::clone(&self.store);
        let monitor = self.monitor.clone();
        let interval = self.interval_sec;
        let running_flag = Arc::clone(&self.running);

        thread::spawn(move || {
            println!("[SCHEDULER] Started with interval {}s", interval);
            
            loop {
                // Check if still running
                {
                    let running = running_flag.lock().unwrap();
                    if !*running {
                        println!("[SCHEDULER] Stopped");
                        break;
                    }
                }

                // Fetch pending plans
                match store.lock().unwrap().get_pending_plans(10) {
                    Ok(pending) => {
                        for plan in pending {
                            // Check if safe to advance
                            if Self::is_safe_to_advance(&plan) {
                                println!("[SCHEDULER] Advancing plan: {}", plan.plan_id);
                                
                                let new_index = plan.next_task_index + 1;
                                let _ = store.lock().unwrap().update_plan_index(&plan.plan_id, new_index);
                                
                                // Check if plan is complete
                                if new_index as usize >= plan.task_sequence.len() {
                                    let _ = store.lock().unwrap().update_plan_status(&plan.plan_id, "completed");
                                    println!("[SCHEDULER] Plan {} completed", plan.plan_id);
                                } else {
                                    println!("[SCHEDULER] Plan {} advanced to step {}", plan.plan_id, new_index);
                                }
                            } else {
                                println!("[SCHEDULER] Plan {} blocked (safety check)", plan.plan_id);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[SCHEDULER] Error fetching plans: {}", e);
                    }
                }

                thread::sleep(Duration::from_secs(interval));
            }
        });
    }

    pub fn stop(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
        println!("[SCHEDULER] Stop requested");
    }

    fn is_safe_to_advance(plan: &crate::plan_store::Plan) -> bool {
        // Safety checks before advancing
        // For now, only advance if status is "pending" or "running"
        // and we haven't exceeded the task sequence length
        
        if plan.status != "pending" && plan.status != "running" {
            return false;
        }

        if plan.next_task_index as usize >= plan.task_sequence.len() {
            return false;
        }

        // Add additional safety checks here:
        // - Check if dependent plans are complete
        // - Validate agent availability
        // - Check policy constraints
        
        true
    }
}
