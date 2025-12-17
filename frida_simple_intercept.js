// Simple Frida Interception - Focus on Data Processing
console.log('[*] ChatGPT Simple Interception Starting...');

const logFile = '/tmp/chatgpt_intercept.txt';
let buffer = '';

// ===== JSON Parsing Hook =====
console.log('[1/2] Hooking JSON parsing...');
try {
    const NSJSONSerialization = ObjC.classes.NSJSONSerialization;
    if (NSJSONSerialization) {
        const jsonWithData = NSJSONSerialization['+ JSONObjectWithData:options:error:'];
        if (jsonWithData) {
            Interceptor.attach(jsonWithData.implementation, {
                onEnter: function(args) {
                    try {
                        const data = new ObjC.Object(args[2]);
                        const length = data.length();
                        if (length > 50) {
                            const bytes = data.bytes();
                            const str = Memory.readUtf8String(bytes, Math.min(length, 50000));

                            console.log('\n[JSON] ' + length + ' bytes');
                            console.log(str.substring(0, 300));

                            const file = new File(logFile, 'a');
                            file.write('\n=== JSON ' + new Date().toISOString() + ' ===\n' + str + '\n');
                            file.close();
                        }
                    } catch (e) { console.log('JSON error:', e.message); }
                }
            });
            console.log('[+] JSON hook active');
        }
    }
} catch (e) { console.log('[-] JSON hook failed:', e.message); }

// ===== NSData Hooks =====
console.log('[2/2] Hooking NSData...');
try {
    const NSData = ObjC.classes.NSData;
    if (NSData) {
        const initWithBytes = NSData['- initWithBytes:length:'];
        if (initWithBytes) {
            Interceptor.attach(initWithBytes.implementation, {
                onEnter: function(args) {
                    try {
                        const length = args[3].toInt32();
                        if (length > 100 && length < 50000) {
                            const str = Memory.readUtf8String(args[2], Math.min(length, 10000));
                            if (str && str.includes('{')) {
                                console.log('\n[DATA] ' + length + ' bytes');
                                console.log(str.substring(0, 200));
                                buffer += str;
                            }
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] NSData hook active');
        }
    }
} catch (e) { console.log('[-] NSData hook failed:', e.message); }

console.log('\n' + '='.repeat(80));
console.log('[*] Monitoring active. Send a ChatGPT message now!');
console.log('[*] Intercepted data → ' + logFile);
console.log('='.repeat(80) + '\n');

// Periodic buffer flush
setInterval(() => {
    if (buffer.length > 500) {
        const file = new File(logFile, 'a');
        file.write('\n=== BUFFER ' + new Date().toISOString() + ' ===\n' + buffer + '\n');
        file.close();
        console.log('[BUFFER] Flushed ' + buffer.length + ' bytes');
        buffer = '';
    }
}, 5000);
