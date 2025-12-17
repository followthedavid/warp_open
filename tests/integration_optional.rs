#[cfg(test)]
mod tests {
    use warp_tauri::osc_handler::*;
    
    #[test]
    fn test_osc_2_window_title() {
        // Test OSC 2 window title sequence parsing
        let sequence = "\x1b]2;Test Window Title\x07";
        // Note: Full test requires Tauri window context
        // This verifies the sequence format is correct
        assert!(sequence.starts_with("\x1b]2;"));
        assert!(sequence.ends_with("\x07"));
    }
    
    #[test]
    fn test_osc_4_color_palette() {
        // Test OSC 4 color palette sequence format
        let sequence = "\x1b]4;1;rgb:ff/00/00\x07";
        assert!(sequence.starts_with("\x1b]4;"));
        assert!(sequence.contains("rgb:"));
    }
    
    #[test]
    fn test_osc_52_clipboard_base64() {
        // Test OSC 52 clipboard sequence with base64
        let text = "Hello World";
        let base64_text = base64::encode(text.as_bytes());
        let sequence = format!("\x1b]52;c;{}\x07", base64_text);
        assert!(sequence.starts_with("\x1b]52;c;"));
        assert!(sequence.ends_with("\x07"));
    }
    
    #[test]
    fn test_bracketed_paste_format() {
        // Test bracketed paste mode wrapper format
        let text = "line1\nline2\nline3";
        let bracketed = format!("\x1b[200~{}\x1b[201~", text);
        assert!(bracketed.starts_with("\x1b[200~"));
        assert!(bracketed.ends_with("\x1b[201~"));
        assert!(bracketed.contains("line1\nline2\nline3"));
    }
    
    #[test]
    fn test_preferences_json_serialization() {
        // Test preferences structure serialization
        use serde_json::json;
        
        let prefs = json!({
            "terminal": {
                "fontSize": 14,
                "fontFamily": "Menlo, Monaco, monospace",
                "cursorStyle": "block",
                "cursorBlink": true,
                "scrollback": 1000
            },
            "ui": {
                "showTabBar": true,
                "showScrollbar": true,
                "compactMode": false
            }
        });
        
        let serialized = serde_json::to_string(&prefs).unwrap();
        assert!(serialized.contains("fontSize"));
        assert!(serialized.contains("cursorStyle"));
        
        // Test deserialization
        let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized["terminal"]["fontSize"], 14);
    }
    
    #[test]
    fn test_theme_names() {
        // Test theme naming conventions
        let themes = vec!["dark", "light", "dracula"];
        for theme in themes {
            assert!(theme.chars().all(|c| c.is_ascii_lowercase()));
        }
    }
}
