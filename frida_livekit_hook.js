// Frida LiveKitWebRTC Hooking - Target the actual communication layer
console.log('[*] LiveKitWebRTC Interception Starting...');

const logFile = '/tmp/livekit_intercept.txt';

// ===== Find LiveKitWebRTC Framework =====
console.log('[1/3] Searching for LiveKitWebRTC framework...');

const modules = Process.enumerateModules();
let livekitModule = null;

for (const mod of modules) {
    if (mod.name.toLowerCase().includes('livekit') || mod.name.toLowerCase().includes('webrtc')) {
        console.log('[+] Found:', mod.name, 'at', mod.base);
        livekitModule = mod;
        break;
    }
}

if (!livekitModule) {
    console.log('[-] LiveKitWebRTC module not found');
    console.log('[*] Available modules:');
    modules.slice(0, 20).forEach(m => console.log('    -', m.name));
} else {
    console.log('[+] LiveKitWebRTC module loaded:', livekitModule.name);
}

// ===== Hook All Objective-C Methods in LiveKit Classes =====
console.log('\n[2/3] Hooking LiveKit classes...');

try {
    const classList = [];
    for (const className of Object.keys(ObjC.classes)) {
        const lowerName = className.toLowerCase();
        if (lowerName.includes('lk') ||
            lowerName.includes('livekit') ||
            lowerName.includes('data') ||
            lowerName.includes('message') ||
            lowerName.includes('rtc')) {
            classList.push(className);
        }
    }

    console.log(`[+] Found ${classList.length} potential LiveKit classes`);
    classList.slice(0, 20).forEach(name => console.log('    -', name));

    // Hook data-related methods
    for (const className of classList) {
        try {
            const cls = ObjC.classes[className];
            const methods = cls.$ownMethods;

            for (const method of methods) {
                const methodName = method.toLowerCase();
                if (methodName.includes('data') ||
                    methodName.includes('message') ||
                    methodName.includes('receive') ||
                    methodName.includes('text')) {

                    try {
                        const impl = cls[method];
                        if (impl) {
                            Interceptor.attach(impl.implementation, {
                                onEnter: function(args) {
                                    console.log(`\n[LIVEKIT] ${className}.${method}`);

                                    // Try to log arguments
                                    for (let i = 2; i < Math.min(args.length, 6); i++) {
                                        try {
                                            const obj = new ObjC.Object(args[i]);
                                            console.log(`  arg[${i}]:`, obj.toString());
                                        } catch (e) {
                                            try {
                                                const str = Memory.readUtf8String(args[i]);
                                                if (str && str.length > 0 && str.length < 1000) {
                                                    console.log(`  arg[${i}]:`, str.substring(0, 200));
                                                }
                                            } catch (e2) {}
                                        }
                                    }
                                },
                                onLeave: function(retval) {
                                    try {
                                        const obj = new ObjC.Object(retval);
                                        const str = obj.toString();
                                        if (str && str.length > 10) {
                                            console.log(`  return:`, str.substring(0, 200));

                                            const file = new File(logFile, 'a');
                                            file.write(`\n=== ${new Date().toISOString()} ===\n${str}\n`);
                                            file.close();
                                        }
                                    } catch (e) {}
                                }
                            });
                            console.log(`[+] Hooked ${className}.${method}`);
                        }
                    } catch (e) {}
                }
            }
        } catch (e) {}
    }
} catch (e) {
    console.log('[-] LiveKit hooking error:', e.message);
}

// ===== Monitor ALL String Operations =====
console.log('\n[3/3] Monitoring all string operations...');

let stringBuffer = [];
try {
    const NSString = ObjC.classes.NSString;
    const methods = [
        '+ stringWithUTF8String:',
        '- initWithData:encoding:',
        '- initWithBytes:length:encoding:'
    ];

    for (const method of methods) {
        try {
            const impl = NSString[method];
            if (impl) {
                Interceptor.attach(impl.implementation, {
                    onEnter: function(args) {
                        this.tracked = true;
                    },
                    onLeave: function(retval) {
                        if (this.tracked) {
                            try {
                                const str = new ObjC.Object(retval).toString();
                                if (str && str.length > 100 && str.length < 10000) {
                                    // Filter out system strings
                                    if (!str.includes('http://') &&
                                        !str.includes('file://') &&
                                        !str.includes('CFBundle')) {

                                        console.log('\n[STRING]', str.length, 'chars:', str.substring(0, 300));
                                        stringBuffer.push(str);

                                        if (stringBuffer.length > 5) {
                                            const file = new File(logFile, 'a');
                                            file.write('\n=== STRING BUFFER ===\n' + stringBuffer.join('\n---\n') + '\n');
                                            file.close();
                                            stringBuffer = [];
                                        }
                                    }
                                }
                            } catch (e) {}
                        }
                    }
                });
                console.log(`[+] Hooked NSString.${method}`);
            }
        } catch (e) {}
    }
} catch (e) {
    console.log('[-] String monitoring error:', e.message);
}

console.log('\n' + '='.repeat(80));
console.log('[*] LiveKit hooks active!');
console.log('[*] Send a ChatGPT message and watch for intercepts');
console.log('[*] Data will be logged to:', logFile);
console.log('='.repeat(80) + '\n');
