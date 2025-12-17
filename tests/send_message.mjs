#!/usr/bin/env node
// Send a message to Warp_Open via Tauri IPC

import { exec } from 'child_process';
import { promisify } from 'util';
import http from 'http';

const execAsync = promisify(exec);

const message = process.argv[2] || 'read my zshrc file';

// Use AppleScript to invoke the Tauri command
const script = `
use framework "Foundation"

tell application "System Events"
    set appPath to POSIX path of (path to application "Warp_Open")
end tell

do shell script "open -a '" & appPath & "' --args --invoke send_test_message '" & "${message.replace(/'/g, "'\\''")}" & "'"
`;

try {
    console.log(`Sending message: "${message}"`);
    
    // Alternative approach: use osascript to run JavaScript that calls the Tauri command
    // For now, we'll use a simpler HTTP-based approach if the app exposes an endpoint,
    // or fall back to AppleScript keyboard simulation
    
    // Try keyboard simulation approach (requires Accessibility permissions)
    const keyboardScript = `
tell application "Warp_Open"
    activate
end tell

delay 1

tell application "System Events"
    tell process "Warp_Open"
        -- Ensure window is frontmost and focused
        set frontmost to true
        delay 0.3
        
        -- Click on the window to ensure focus
        click window 1
        delay 0.3
        
        -- Type the message
        keystroke "${message.replace(/"/g, '\\"')}"
        delay 0.3
        
        -- Press Enter
        key code 36
    end tell
end tell
`;
    
    await execAsync(`osascript -e '${keyboardScript.replace(/'/g, "'\\''")}'`);
    console.log('✓ Message sent');
    process.exit(0);
} catch (error) {
    console.error('✗ Failed to send message:', error.message);
    console.error('\nMake sure:');
    console.error('1. Warp_Open is running');
    console.error('2. Terminal/iTerm has Accessibility permissions');
    console.error('3. A tab is open and ready');
    process.exit(1);
}
