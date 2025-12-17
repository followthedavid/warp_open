// Frida WebRTC + Low-Level Network Interception for ChatGPT
// Hooks system calls and WebRTC to catch all network data

console.log('[*] ChatGPT WebRTC Interception Starting...');
console.log('[*] Hooking low-level network and WebRTC methods');
console.log('');

let responseBuffer = '';
const logFile = '/tmp/chatgpt_intercept.txt';

// ============================================================================
// Part 1: System-Level Network Hooks (catches ALL network data)
// ============================================================================

console.log('[1/4] Hooking system-level network calls...');

// Hook recv() - receives data from sockets
const recvFunc = Module.findExportByName(null, 'recv');
if (recvFunc) {
    console.log('[+] Hooking recv()');
    Interceptor.attach(recvFunc, {
        onEnter: function(args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function(retval) {
            const bytesRead = retval.toInt32();
            if (bytesRead > 0 && bytesRead < 100000) {
                try {
                    const data = Memory.readUtf8String(this.buf, Math.min(bytesRead, 10000));
                    if (data && (data.includes('content') || data.includes('message') || data.includes('text') || data.includes('delta'))) {
                        console.log('\n[RECV] Intercepted data (' + bytesRead + ' bytes):');
                        console.log(data.substring(0, 500));

                        const file = new File(logFile, 'a');
                        file.write('\n=== RECV ' + new Date().toISOString() + ' ===\n');
                        file.write(data);
                        file.close();
                    }
                } catch (e) {}
            }
        }
    });
}

// Hook read() - reads data from file descriptors
const readFunc = Module.findExportByName(null, 'read');
if (readFunc) {
    console.log('[+] Hooking read()');
    Interceptor.attach(readFunc, {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.count = args[2].toInt32();
        },
        onLeave: function(retval) {
            const bytesRead = retval.toInt32();
            if (bytesRead > 100 && bytesRead < 100000 && this.fd > 2) {
                try {
                    const data = Memory.readUtf8String(this.buf, Math.min(bytesRead, 10000));
                    if (data && (data.includes('assistant') || data.includes('content') || data.includes('choices'))) {
                        console.log('\n[READ] FD ' + this.fd + ' (' + bytesRead + ' bytes):');
                        console.log(data.substring(0, 500));

                        const file = new File(logFile, 'a');
                        file.write('\n=== READ ' + new Date().toISOString() + ' ===\n');
                        file.write(data);
                        file.close();
                    }
                } catch (e) {}
            }
        }
    });
}

console.log('');

// ============================================================================
// Part 2: WebRTC Data Channel Hooks
// ============================================================================

console.log('[2/4] Searching for WebRTC/LiveKit classes...');

try {
    // Look for LiveKit classes
    const liveKitClasses = [];
    for (const className of Object.keys(ObjC.classes)) {
        if (className.toLowerCase().includes('livekit') ||
            className.toLowerCase().includes('webrtc') ||
            className.toLowerCase().includes('datachannel') ||
            className.toLowerCase().includes('rtc')) {
            liveKitClasses.push(className);
        }
    }

    if (liveKitClasses.length > 0) {
        console.log('[+] Found ' + liveKitClasses.length + ' WebRTC/LiveKit classes:');
        liveKitClasses.slice(0, 15).forEach(name => console.log('    - ' + name));
    } else {
        console.log('[-] No LiveKit/WebRTC classes found in ObjC');
    }
} catch (e) {
    console.log('[-] Error searching classes:', e.message);
}

console.log('');

// ============================================================================
// Part 3: String Monitoring (catches text as it's processed)
// ============================================================================

console.log('[3/4] Hooking string operations...');

try {
    // Hook NSString creation to catch response text
    const NSString = ObjC.classes.NSString;
    if (NSString) {
        console.log('[+] Monitoring NSString creation');

        // Hook stringWithUTF8String
        const stringWithUTF8 = NSString['+ stringWithUTF8String:'];
        if (stringWithUTF8) {
            Interceptor.attach(stringWithUTF8.implementation, {
                onEnter: function(args) {
                    try {
                        const str = Memory.readUtf8String(args[2]);
                        if (str && str.length > 50 && str.length < 5000) {
                            if (!str.includes('http') && !str.includes('file://') && !str.includes('CFBundle')) {
                                console.log('\n[STRING] Length ' + str.length + ':');
                                console.log(str.substring(0, 300));

                                responseBuffer += str + '\n';
                                if (responseBuffer.length > 1000) {
                                    const file = new File(logFile, 'a');
                                    file.write('\n=== STRING BUFFER ' + new Date().toISOString() + ' ===\n');
                                    file.write(responseBuffer);
                                    file.close();
                                    responseBuffer = '';
                                }
                            }
                        }
                    } catch (e) {}
                }
            });
        }
    }
} catch (e) {
    console.log('[-] String hook error:', e.message);
}

console.log('');

// ============================================================================
// Part 4: JSON Parsing Hooks
// ============================================================================

console.log('[4/4] Hooking JSON parsing...');

try {
    const NSJSONSerialization = ObjC.classes.NSJSONSerialization;
    if (NSJSONSerialization) {
        console.log('[+] Hooking NSJSONSerialization');

        const jsonWithData = NSJSONSerialization['+ JSONObjectWithData:options:error:'];
        if (jsonWithData) {
            Interceptor.attach(jsonWithData.implementation, {
                onEnter: function(args) {
                    try {
                        const data = new ObjC.Object(args[2]);
                        const length = data.length();
                        if (length > 100 && length < 100000) {
                            const bytes = data.bytes();
                            const str = Memory.readUtf8String(bytes, length);

                            if (str && (str.includes('message') || str.includes('content') || str.includes('delta'))) {
                                console.log('\n[JSON] Parsing ' + length + ' bytes:');
                                console.log(str.substring(0, 500));

                                const file = new File(logFile, 'a');
                                file.write('\n=== JSON ' + new Date().toISOString() + ' ===\n');
                                file.write(str);
                                file.close();
                            }
                        }
                    } catch (e) {}
                }
            });
        }
    }
} catch (e) {
    console.log('[-] JSON hook error:', e.message);
}

console.log('');
console.log('=' .repeat(80));
console.log('[*] All hooks active. Monitoring ChatGPT traffic...');
console.log('[*] Intercepted data will be logged to:', logFile);
console.log('[*] Send a message in ChatGPT now!');
console.log('=' .repeat(80));
