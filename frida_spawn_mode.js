// Frida Spawn Mode - Hook ChatGPT from app launch
// Run with: frida --no-pause -f /Applications/ChatGPT.app/Contents/MacOS/ChatGPT -l frida_spawn_mode.js

console.log('[*] ChatGPT Spawn Mode Hook Starting...');
console.log('[*] This hooks the app from the very beginning of execution');

const logFile = '/tmp/spawn_mode_intercept.txt';

// ===== Early Initialization Hooks =====
console.log('[1/3] Setting up early hooks...');

// Hook main() if we can find it
try {
    const mainAddr = Module.findExportByName(null, 'main');
    if (mainAddr) {
        Interceptor.attach(mainAddr, {
            onEnter: function(args) {
                console.log('[MAIN] Application main() called');
                console.log('  argc:', args[0].toInt32());
            }
        });
        console.log('[+] Hooked main()');
    }
} catch (e) {
    console.log('[-] Could not hook main():', e.message);
}

// Hook dyld loading
try {
    const dyld_register = Module.findExportByName(null, '_dyld_register_func_for_add_image');
    if (dyld_register) {
        console.log('[+] Found dyld image registration');
    }
} catch (e) {}

// ===== Hook String Operations Early =====
console.log('[2/3] Hooking string operations before app initializes...');

try {
    const NSString = ObjC.classes.NSString;
    const stringWithUTF8 = NSString['+ stringWithUTF8String:'];

    if (stringWithUTF8) {
        Interceptor.attach(stringWithUTF8.implementation, {
            onEnter: function(args) {
                try {
                    const str = Memory.readUtf8String(args[2]);
                    if (str && str.length > 50 && str.length < 10000) {
                        console.log('\n[Early NSString]', str.substring(0, 200));

                        const file = new File(logFile, 'a');
                        file.write(`\n=== Early String (${new Date().toISOString()}) ===\n${str}\n`);
                        file.close();
                    }
                } catch (e) {}
            }
        });
        console.log('[+] Hooked NSString.stringWithUTF8String (early)');
    }
} catch (e) {
    console.log('[-] Early string hook error:', e.message);
}

// ===== Hook Network Setup =====
console.log('[3/3] Hooking network initialization...');

try {
    // Hook NSURLSession creation
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
        const sessionWithConfig = NSURLSession['+ sessionWithConfiguration:'];
        if (sessionWithConfig) {
            Interceptor.attach(sessionWithConfig.implementation, {
                onEnter: function(args) {
                    console.log('\n[NSURLSession] Session being created');
                },
                onLeave: function(retval) {
                    console.log('[NSURLSession] Session created:', new ObjC.Object(retval));
                }
            });
            console.log('[+] Hooked NSURLSession creation');
        }
    }
} catch (e) {
    console.log('[-] Network hook error:', e.message);
}

// ===== Wait for App to Load, Then Hook More =====
setTimeout(() => {
    console.log('\n[*] App should be initialized now, adding runtime hooks...');

    try {
        // Hook all conversation-related classes
        for (const className of Object.keys(ObjC.classes)) {
            if (className.includes('Conversation') ||
                className.includes('Message') ||
                className.includes('Chat')) {

                console.log(`[+] Found class: ${className}`);

                try {
                    const cls = ObjC.classes[className];
                    const methods = cls.$ownMethods;

                    methods.forEach(method => {
                        if (method.includes('text') ||
                            method.includes('content') ||
                            method.includes('message')) {

                            try {
                                const impl = cls[method];
                                if (impl && impl.implementation) {
                                    Interceptor.attach(impl.implementation, {
                                        onEnter: function(args) {
                                            console.log(`\n[${className}.${method}] called`);
                                        }
                                    });
                                    console.log(`  [+] Hooked ${method}`);
                                }
                            } catch (e) {}
                        }
                    });
                } catch (e) {}
            }
        }
    } catch (e) {
        console.log('[-] Runtime hook error:', e.message);
    }
}, 5000);

console.log('\n' + '='.repeat(80));
console.log('[*] Spawn mode hooks active!');
console.log('[*] App will now launch with hooks in place from the start');
console.log('[*] Send a message and watch for interceptions');
console.log('[*] Logs saved to:', logFile);
console.log('='.repeat(80) + '\n');
