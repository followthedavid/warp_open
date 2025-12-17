use tauri::Window;

/// Parse and handle OSC (Operating System Command) sequences
#[allow(dead_code)]
pub fn handle_osc_sequence(window: &Window, sequence: &str) {
    if let Some(osc_data) = sequence.strip_prefix("\x1b]") {
        if let Some(osc_data) = osc_data.strip_suffix("\x07") {
            parse_osc(window, osc_data);
        } else if let Some(osc_data) = osc_data.strip_suffix("\x1b\\") {
            parse_osc(window, osc_data);
        }
    }
}

#[allow(dead_code)]
fn parse_osc(window: &Window, data: &str) {
    // Split on first semicolon to get command and payload
    if let Some((cmd, payload)) = data.split_once(';') {
        match cmd {
            "0" | "2" => {
                // OSC 0 or 2: Set window title
                let _ = window.set_title(payload);
            }
            "4" => {
                // OSC 4: Set/query color palette
                // Format: OSC 4 ; index ; color ST
                // This is a stub - full implementation would parse color codes
                // and potentially update terminal theme dynamically
                println!("OSC 4 color palette update: {}", payload);
            }
            "52" => {
                // OSC 52: Clipboard operations
                // Format: OSC 52 ; c ; <base64-data> ST
                if let Some((clipboard_target, b64_data)) = payload.split_once(';') {
                    if clipboard_target == "c" || clipboard_target == "p" {
                        // Decode base64 clipboard data
                        if let Ok(decoded) = base64_decode(b64_data) {
                            // Note: In full implementation, would emit event to frontend
                            // For now, just log (direct clipboard integration is preferred)
                            println!("OSC 52 clipboard data: {}", decoded);
                        }
                    }
                }
            }
            _ => {
                // Unknown OSC command, ignore
            }
        }
    }
}

#[allow(dead_code)]
fn base64_decode(data: &str) -> Result<String, String> {
    use base64::{engine::general_purpose, Engine as _};
    
    general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|e| format!("Base64 decode error: {}", e))
        .and_then(|bytes| {
            String::from_utf8(bytes)
                .map_err(|e| format!("UTF-8 decode error: {}", e))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        // "Hello" in base64
        let result = base64_decode("SGVsbG8=");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello");
    }

    #[test]
    fn test_base64_decode_invalid() {
        let result = base64_decode("not-valid-base64!!!");
        assert!(result.is_err());
    }
}
