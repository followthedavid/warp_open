use std::fs::OpenOptions;
use std::io::Write;

pub fn log_tool_execution(tool_name: &str, tab_id: u64) {
    let log_path = "/tmp/warp_tool_executions.log";
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let timestamp = chrono::Local::now().format("%H:%M:%S%.3f");
        let _ = writeln!(file, "[{}] Tab {} - Tool executed: {}", timestamp, tab_id, tool_name);
    }
}
