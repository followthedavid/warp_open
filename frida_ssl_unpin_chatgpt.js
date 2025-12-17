// Frida SSL Unpinning + Response Interception Script for ChatGPT Desktop
// Usage: sudo frida -n ChatGPT -l frida_ssl_unpin_chatgpt.js

console.log('[*] ChatGPT SSL Unpinning + Interception Starting...');
console.log('[*] This script will:');
console.log('    1. Bypass SSL certificate pinning');
console.log('    2. Hook Swift networking methods');
console.log('    3. Intercept ChatGPT API responses');
console.log('');

// ============================================================================
// Part 1: SSL/TLS Certificate Pinning Bypass
// ============================================================================

console.log('[1/3] Attempting SSL certificate unpinning...');

// Method 1: Hook NSURLSession SSL validation
try {
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
        console.log('[+] Found NSURLSession, hooking SSL validation...');

        // Hook the delegate method that validates SSL certificates
        const delegate = ObjC.classes.NSURLSessionDelegate;
        if (delegate) {
            // Intercept: URLSession:didReceiveChallenge:completionHandler:
            Interceptor.attach(
                ObjC.classes.NSURLSessionDelegate['- URLSession:didReceiveChallenge:completionHandler:'].implementation,
                {
                    onEnter: function(args) {
                        console.log('[SSL] Bypassing certificate validation');
                        // args[0] = self
                        // args[1] = selector
                        // args[2] = session
                        // args[3] = challenge
                        // args[4] = completionHandler

                        // Call completion handler with "trust anyway"
                        const completionHandler = new ObjC.Block(args[4]);
                        const NSURLSessionAuthChallengeDisposition = 0; // Use credential
                        const NSURLCredential = ObjC.classes.NSURLCredential;
                        const serverTrust = ObjC.Object(args[3]).protectionSpace().serverTrust();
                        const credential = NSURLCredential.credentialForTrust_(serverTrust);

                        completionHandler.implementation(NSURLSessionAuthChallengeDisposition, credential);
                    }
                }
            );
            console.log('[+] SSL certificate pinning bypassed!');
        }
    }
} catch (e) {
    console.log('[-] NSURLSession hook failed:', e);
}

// Method 2: Hook SecTrustEvaluate (lower-level SSL validation)
try {
    const SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
        console.log('[+] Hooking SecTrustEvaluate...');
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
            console.log('[SSL] SecTrustEvaluate called - forcing success');
            // Set result to 1 (success/trusted)
            Memory.writeU32(result, 1);
            return 0; // errSecSuccess
        }, 'int', ['pointer', 'pointer']));
        console.log('[+] SecTrustEvaluate bypassed!');
    }
} catch (e) {
    console.log('[-] SecTrustEvaluate hook failed:', e);
}

// Method 3: Hook SSL_CTX_set_custom_verify (if using OpenSSL/BoringSSL)
try {
    const SSL_CTX_set_custom_verify = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
    if (SSL_CTX_set_custom_verify) {
        console.log('[+] Hooking SSL_CTX_set_custom_verify...');
        Interceptor.replace(SSL_CTX_set_custom_verify, new NativeCallback(function(ctx, mode, callback) {
            console.log('[SSL] SSL_CTX_set_custom_verify bypassed');
            return;
        }, 'void', ['pointer', 'int', 'pointer']));
    }
} catch (e) {
    console.log('[-] SSL_CTX_set_custom_verify hook failed:', e);
}

console.log('');

// ============================================================================
// Part 2: Network Response Interception
// ============================================================================

console.log('[2/3] Setting up network response interception...');

// Hook NSURLConnection data reception
try {
    const NSURLConnection = ObjC.classes.NSURLConnection;
    if (NSURLConnection) {
        console.log('[+] Hooking NSURLConnection...');

        // Hook connection:didReceiveData:
        const didReceiveData = NSURLConnection['- connection:didReceiveData:'];
        if (didReceiveData) {
            Interceptor.attach(didReceiveData.implementation, {
                onEnter: function(args) {
                    // args[0] = self
                    // args[1] = selector
                    // args[2] = connection
                    // args[3] = data (NSData)
                    try {
                        const data = new ObjC.Object(args[3]);
                        const length = data.length();

                        if (length > 0 && length < 1000000) { // Reasonable size check
                            const bytes = data.bytes();
                            const str = Memory.readUtf8String(bytes, Math.min(length, 10000));

                            // Check if this looks like a ChatGPT response
                            if (str && (str.includes('openai') || str.includes('message') || str.includes('content') || str.includes('choices'))) {
                                console.log('');
                                console.log('=' .repeat(80));
                                console.log('[RESPONSE INTERCEPTED]');
                                console.log('Length:', length);
                                console.log('Preview:', str.substring(0, 500));
                                console.log('=' .repeat(80));
                                console.log('');

                                // Try to save full response
                                const fullStr = Memory.readUtf8String(bytes, length);
                                const file = new File('/tmp/chatgpt_frida_response.txt', 'w');
                                file.write(fullStr);
                                file.close();
                                console.log('[+] Full response saved to /tmp/chatgpt_frida_response.txt');
                            }
                        }
                    } catch (e) {
                        console.log('[-] Error processing response:', e);
                    }
                }
            });
            console.log('[+] NSURLConnection hooked successfully');
        }
    }
} catch (e) {
    console.log('[-] NSURLConnection hook failed:', e);
}

// Hook NSURLSession data tasks
try {
    const NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
    if (NSURLSessionDataTask) {
        console.log('[+] Hooking NSURLSessionDataTask...');

        // This is more complex - we need to hook the completion handler
        // For now, log that we found it
        console.log('[+] NSURLSessionDataTask found (completion handler hooking TBD)');
    }
} catch (e) {
    console.log('[-] NSURLSessionDataTask hook failed:', e);
}

console.log('');

// ============================================================================
// Part 3: Swift Method Discovery & Hooking
// ============================================================================

console.log('[3/3] Discovering Swift classes and methods...');

// Search for message/conversation related Swift classes
const swiftClasses = [];
for (const className of Object.keys(ObjC.classes)) {
    if (className.includes('Message') ||
        className.includes('Conversation') ||
        className.includes('Response') ||
        className.includes('Chat') ||
        className.includes('Content')) {
        swiftClasses.push(className);
    }
}

if (swiftClasses.length > 0) {
    console.log(`[+] Found ${swiftClasses.length} potentially interesting Swift classes:`);
    swiftClasses.slice(0, 10).forEach(name => console.log(`    - ${name}`));
    if (swiftClasses.length > 10) {
        console.log(`    ... and ${swiftClasses.length - 10} more`);
    }
} else {
    console.log('[-] No obvious message-related Swift classes found');
}

console.log('');

// ============================================================================
// Monitoring
// ============================================================================

console.log('=' .repeat(80));
console.log('[*] Interception active. Monitoring ChatGPT traffic...');
console.log('[*] Send a message in ChatGPT to test interception.');
console.log('[*] Responses will be logged here and saved to /tmp/chatgpt_frida_response.txt');
console.log('=' .repeat(80));
console.log('');

// Keep script alive and log any Swift string operations
try {
    const NSString = ObjC.classes.NSString;
    if (NSString) {
        // Hook string creation to catch response text
        Interceptor.attach(Module.findExportByName(null, 'objc_msgSend'), {
            onEnter: function(args) {
                const selector = ObjC.selectorAsString(args[1]);
                if (selector === 'stringWithUTF8String:' || selector === 'initWithUTF8String:') {
                    try {
                        const str = Memory.readUtf8String(args[2]);
                        if (str && str.length > 100 && str.length < 5000) {
                            // Log longer strings that might be responses
                            if (str.includes('assistant') || str.includes('AI') || str.toLowerCase().includes('hello')) {
                                console.log('[STRING]', str.substring(0, 200) + '...');
                            }
                        }
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {
    console.log('[-] String monitoring hook failed:', e);
}
