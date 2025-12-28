#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod commands;
mod session;
mod osc_handler;
mod test_bridge;
mod conversation;
mod ai_parser;
mod rollback;
mod telemetry;
mod policy_store;
mod agents;
mod plan_store;
mod monitoring;
mod scheduler;
mod phase1_6_tests;
mod ollama;
mod ssh_session;
mod scaffolding;

use commands::{
    spawn_pty, send_input, resize_pty, read_pty, close_pty, start_pty_output_stream,
    ai_query, ai_query_stream,
    execute_shell, read_file, write_file, list_directory_tree, list_directory, current_working_dir,
    send_test_message, send_user_message,
    get_conversation_state, test_phase2_workflow, test_phase3_workflow, create_batch,
    get_batches, approve_batch, run_batch, get_autonomy_settings, update_autonomy_settings,
    set_batch_dependency, rollback_batch, telemetry_insert_event, telemetry_query_recent,
    telemetry_export_csv, phase4_trigger_trainer, policy_list_rules, policy_propose_diff,
    policy_list_suggestions, policy_apply_suggestion, policy_rollback, policy_reject_suggestion,
    phase5_generate_suggestions, agent_register, agent_update, agent_set_status, agent_list,
    agent_unregister, phase6_create_plan, phase6_get_plan, phase6_get_pending_plans,
    phase6_update_plan_status, phase6_update_plan_index, phase6_delete_plan,
    get_monitoring_events, clear_monitoring_phase, clear_monitoring_all, start_scheduler,
    stop_scheduler, run_phase1_6_auto, PtyRegistry,
    // New features
    edit_file, web_fetch, get_shell_completions, get_ai_completion,
    init_project_context, load_project_context_cmd,
    ssh_connect_password, ssh_connect_key, ssh_send_input, ssh_read_output,
    ssh_resize, ssh_disconnect, ssh_list_sessions, SshState,
    // Glob and Grep for code navigation
    glob_files, grep_files,
    // Scaffolded agent commands
    start_agent_task, list_agent_models, check_ollama_status, execute_agent_tool,
};
use session::{save_session, load_session};
use ollama::{query_ollama_stream, query_ollama, list_ollama_models};

// App version info command
#[tauri::command]
fn get_app_version() -> serde_json::Value {
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": "Warp_Open",
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
        "target": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
}
use tauri::{Manager, Menu, MenuItem, Submenu};
use test_bridge::TestBridge;
use conversation::ConversationState;
use telemetry::TelemetryStore;
use policy_store::PolicyStore;
use agents::AgentCoordinator;
use plan_store::PlanStore;
use monitoring::MonitoringState;
use scheduler::Scheduler;
use std::sync::{Arc, Mutex};
use std::panic;
use std::io::Write;
use std::fs::{File, OpenOptions};
use std::process;

// Custom panic hook for crash reporting
fn setup_panic_handler() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // Get panic location and message
        let location = panic_info.location().map(|l| {
            format!("{}:{}:{}", l.file(), l.line(), l.column())
        }).unwrap_or_else(|| "unknown".to_string());

        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };

        // Write crash log to file
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let crash_log_path = format!("{}/.warp_open/crash.log", home);

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&crash_log_path)
        {
            let timestamp = chrono::Utc::now().to_rfc3339();
            let crash_report = format!(
                "\n=== CRASH REPORT ===\n\
                Timestamp: {}\n\
                Location: {}\n\
                Message: {}\n\
                Version: {}\n\
                OS: {} ({})\n\
                ====================\n",
                timestamp, location, message,
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS, std::env::consts::ARCH
            );
            let _ = file.write_all(crash_report.as_bytes());
            eprintln!("[CRASH] Panic logged to {}", crash_log_path);
        }

        // Call default handler (will print to stderr)
        default_hook(panic_info);
    }));
}

/// Single instance lock - prevents multiple app instances
fn acquire_single_instance_lock() -> Option<File> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let lock_path = format!("{}/.warp_open/warp_open.lock", home);

    // Ensure directory exists
    let _ = std::fs::create_dir_all(format!("{}/.warp_open", home));

    // Try to create/open the lock file with exclusive access
    match OpenOptions::new()
        .write(true)
        .create(true)
        .open(&lock_path)
    {
        Ok(file) => {
            // Try to get exclusive lock using flock
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = file.as_raw_fd();
                let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
                if result != 0 {
                    eprintln!("[SINGLE_INSTANCE] Another instance is already running. Focusing existing window...");
                    return None;
                }
            }

            // Write PID to lock file
            let mut f = file;
            let _ = f.write_all(format!("{}", process::id()).as_bytes());
            Some(f)
        }
        Err(e) => {
            eprintln!("[SINGLE_INSTANCE] Failed to create lock file: {}", e);
            None
        }
    }
}

fn main() {
    // Check for single instance FIRST
    let _lock = match acquire_single_instance_lock() {
        Some(lock) => lock,
        None => {
            eprintln!("[SINGLE_INSTANCE] Warp_Open is already running. Exiting.");
            process::exit(0);
        }
    };

    // Setup crash reporting
    setup_panic_handler();
    // Create menu with DevTools option
    let menu = Menu::new()
        .add_submenu(Submenu::new(
            "View",
            Menu::new()
                .add_native_item(MenuItem::Copy)
                .add_native_item(MenuItem::Paste)
                .add_native_item(MenuItem::SelectAll)
                .add_native_item(MenuItem::Separator)
                .add_item(tauri::CustomMenuItem::new("devtools".to_string(), "Toggle DevTools").accelerator("CmdOrCtrl+Shift+I"))
        ));
    
    // Initialize stores
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let warp_dir = format!("{}/.warp_open", home);
    std::fs::create_dir_all(&warp_dir).expect("Failed to create .warp_open directory");
    
    let telemetry_path = format!("{}/telemetry.sqlite", warp_dir);
    let telemetry_store = TelemetryStore::open(std::path::PathBuf::from(telemetry_path))
        .expect("Failed to open telemetry database");
    
    let policy_path = format!("{}/policy.sqlite", warp_dir);
    let policy_store = PolicyStore::open(std::path::PathBuf::from(policy_path))
        .expect("Failed to open policy database");
    
    let agent_coordinator = AgentCoordinator::new();
    
    let plan_path = format!("{}/plans.sqlite", warp_dir);
    let plan_store = PlanStore::open(std::path::PathBuf::from(plan_path))
        .expect("Failed to open plans database");
    
    let monitoring_state = MonitoringState::new();
    
    let plan_store_arc = Arc::new(Mutex::new(plan_store));
    
    // Initialize scheduler (10 second interval)
    let scheduler = Scheduler::new(
        Arc::clone(&plan_store_arc),
        monitoring_state.clone(),
        10
    );
    
    tauri::Builder::default()
        .menu(menu)
        .on_menu_event(|event| {
            match event.menu_item_id() {
                "devtools" => {
                    #[cfg(debug_assertions)]
                    event.window().open_devtools();
                }
                _ => {}
            }
        })
        .manage(PtyRegistry::new())
        .manage(ConversationState::new())
        .manage(SshState::new())
        .manage(Arc::new(Mutex::new(telemetry_store)))
        .manage(Arc::new(Mutex::new(policy_store)))
        .manage(agent_coordinator)
        .manage(plan_store_arc)
        .manage(monitoring_state)
        .manage(scheduler)
        .setup(|app| {
            // Get the main window and set focus
            if let Some(window) = app.get_window("main") {
                let _ = window.set_focus();
            }
            
            // Start test bridge if enabled
            let bridge = TestBridge::new();
            let app_handle = app.app_handle();
            tauri::async_runtime::spawn(async move {
                bridge.start(app_handle).await;
            });
            
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            spawn_pty,
            send_input,
            resize_pty,
            read_pty,
            close_pty,
            start_pty_output_stream,
            ai_query,
            ai_query_stream,
            execute_shell,
            read_file,
            write_file,
            list_directory_tree,
            list_directory,
            current_working_dir,
            send_test_message,
            send_user_message,
            get_conversation_state,
            test_phase2_workflow,
            test_phase3_workflow,
            create_batch,
            get_batches,
            approve_batch,
            run_batch,
            get_autonomy_settings,
            update_autonomy_settings,
            set_batch_dependency,
            rollback_batch,
            telemetry_insert_event,
            telemetry_query_recent,
            telemetry_export_csv,
            phase4_trigger_trainer,
            policy_list_rules,
            policy_propose_diff,
            policy_list_suggestions,
            policy_apply_suggestion,
            policy_rollback,
            policy_reject_suggestion,
            phase5_generate_suggestions,
            agent_register,
            agent_update,
            agent_set_status,
            agent_list,
            agent_unregister,
            phase6_create_plan,
            phase6_get_plan,
            phase6_get_pending_plans,
            phase6_update_plan_status,
            phase6_update_plan_index,
            phase6_delete_plan,
            get_monitoring_events,
            clear_monitoring_phase,
            clear_monitoring_all,
            start_scheduler,
            stop_scheduler,
            run_phase1_6_auto,
            query_ollama_stream,
            query_ollama,
            list_ollama_models,
            save_session,
            load_session,
            get_app_version,
            // New features for Warp/Claude Code parity
            edit_file,
            web_fetch,
            get_shell_completions,
            get_ai_completion,
            init_project_context,
            load_project_context_cmd,
            // SSH support
            ssh_connect_password,
            ssh_connect_key,
            ssh_send_input,
            ssh_read_output,
            ssh_resize,
            ssh_disconnect,
            ssh_list_sessions,
            // Glob and Grep
            glob_files,
            grep_files,
            // Scaffolded Agent (Claude-like capabilities)
            start_agent_task,
            list_agent_models,
            check_ollama_status,
            execute_agent_tool,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
