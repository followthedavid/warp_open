// Frida reconnaissance script for ChatGPT Desktop
// Finds classes and methods related to messages/conversations

console.log('[*] ChatGPT Reconnaissance Starting...');

// Enumerate loaded modules
console.log('\n[*] Loaded Modules:');
Process.enumerateModules().forEach(function(module) {
    if (module.name.toLowerCase().includes('chatgpt') ||
        module.name.toLowerCase().includes('livekit') ||
        module.name.toLowerCase().includes('webrtc')) {
        console.log('  - ' + module.name + ' @ ' + module.base);
    }
});

// Enumerate Swift classes (look for conversation/message related ones)
console.log('\n[*] Searching for conversation-related Swift classes...');
const classes = [];
for (const cls of ObjC.classes) {
    const name = cls.$className;
    if (name && (
        name.includes('Message') ||
        name.includes('Conversation') ||
        name.includes('Response') ||
        name.includes('Chat') ||
        name.includes('Text') ||
        name.includes('Content')
    )) {
        classes.push(name);
    }
}

console.log('[*] Found ' + classes.length + ' potentially interesting classes:');
classes.slice(0, 20).forEach(function(name) {
    console.log('  - ' + name);
});

// Hook into common Swift string operations to see data flow
console.log('\n[*] Setting up string operation hooks...');

// Try to hook NSString setters/getters
try {
    const NSString = ObjC.classes.NSString;
    if (NSString) {
        console.log('[+] NSString found, hooking string operations...');

        // Hook stringWithUTF8String to see strings being created
        Interceptor.attach(Module.findExportByName(null, 'objc_msgSend'), {
            onEnter: function(args) {
                const selector = ObjC.selectorAsString(args[1]);
                if (selector === 'stringWithUTF8String:' ||
                    selector === 'initWithUTF8String:') {
                    try {
                        const str = Memory.readUtf8String(args[2]);
                        if (str && str.length > 10 && str.length < 1000) {
                            console.log('[STRING] ' + str.substring(0, 100));
                        }
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {
    console.log('[!] Error hooking NSString: ' + e);
}

console.log('\n[*] Reconnaissance setup complete. Monitoring...');
console.log('[*] Send a message in ChatGPT and watch for intercepted data.');
